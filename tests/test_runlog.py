from pathlib import Path

from brain.llm import LlmOutcome
from brain.pipeline import analyze
from brain.runlog import behavior_atlas, build_record, render_dashboard
from brain.webhook import PullRequestEvent
from shared.contract import DetonateResult
from tests.test_intent import meta

FIXTURES = Path(__file__).parent / "fixtures"
R02 = DetonateResult.model_validate_json((FIXTURES / "detonate_real_r02.json").read_text())


def event(title: str = "Add dep") -> PullRequestEvent:
    return PullRequestEvent(
        delivery_id="d", action="opened", installation_id=1, account_login="o", owner="o",
        repo="r", number=12, head_sha="a" * 40, head_clone_url="https://github.com/o/r.git",
        is_fork=False, repo_private=False, title=title,
    )  # fmt: skip


def analysis_for(result: DetonateResult):
    return analyze(result, meta(), "", lambda *a, **k: LlmOutcome("m", error="x"), job_id="j",
                   enrich=lambda r: r)  # fmt: skip


def test_record_summarizes_a_run():
    rec = build_record(event(), analysis_for(R02), "job", "2026-11-02 00:00")
    assert rec["repo"] == "o/r" and rec["pr"] == 12 and rec["verdict"] == "Blocked"
    assert "tinycolor-recon" in rec["packages_ran_scripts"]
    assert "CRED_FILE_ACCESS" in rec["rules"]


def test_dashboard_escapes_untrusted_pr_title_and_rules():
    rec = {
        "ts": "t", "repo": "o/r", "pr": 1, "verdict": "Blocked", "conclusion": "failure",
        "title": "<img src=x onerror=alert(1)> [click](http://evil)", "sha": "abc1234",
        "rules": ["NET_RAW_IP"], "packages_ran_scripts": ["evil<script>"],
        "hosts": ["203.0.113.10"], "binaries": ["curl"], "cost_usd": 0.01, "detonation_s": 2.0,
    }  # fmt: skip
    page = render_dashboard([rec])
    assert "<img src=x" not in page and "<script>" not in page
    assert "&lt;img" in page and "Blocked" in page and "203.0.113.10" in page


def test_atlas_aggregates_hosts_and_binaries_by_package():
    recs = [
        {"packages_ran_scripts": ["p"], "hosts": ["a.com"], "binaries": ["node"]},
        {"packages_ran_scripts": ["p"], "hosts": ["b.com"], "binaries": ["curl"]},
    ]
    atlas = behavior_atlas(recs)
    assert atlas["p"]["hosts"] == {"a.com", "b.com"}
    assert atlas["p"]["binaries"] == {"node", "curl"}


def test_empty_dashboard_renders():
    page = render_dashboard([])
    assert "no runs yet" in page and "PR Detonator" in page
