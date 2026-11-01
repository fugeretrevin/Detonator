import json
from pathlib import Path

from brain.github_client import PrMetadata
from brain.llm import LlmOutcome, LlmVerdict, parse_response
from brain.pipeline import PRIVATE_REPO_SUMMARY, PRIVATE_REPO_TITLE, analyze, detonate_request
from brain.webhook import PullRequestEvent
from shared.contract import DetonateResult

FIXTURES = Path(__file__).parent / "fixtures"
META = PrMetadata(
    title="Fix typo in README",
    body="",
    author="eve",
    changed_files=["README.md"],
    package_json_changed=True,
    scripts_changed=True,
    lockfile_changed=False,
)


def e4() -> DetonateResult:
    return DetonateResult.model_validate_json((FIXTURES / "detonate_result_e4.json").read_text())


def event(private: bool) -> PullRequestEvent:
    return PullRequestEvent(
        delivery_id="d", action="opened", installation_id=1, account_login="o", owner="o",
        repo="r", number=1, head_sha="a" * 40, head_clone_url="https://github.com/o/r.git",
        is_fork=False, repo_private=private,
    )  # fmt: skip


def test_public_repo_detonates_without_clone_token():
    req = detonate_request(event(private=False), "job-1")
    assert req is not None
    assert req.clone_token is None
    assert "token" not in req.model_dump_json().lower().replace('"clone_token":null', "")
    assert req.clone_url == "https://github.com/o/r.git" and req.head_sha == "a" * 40


def test_private_repo_is_not_detonated_and_reports_https_needed():
    assert detonate_request(event(private=True), "job-1") is None
    assert "Private repos need HTTPS on the Chamber" in PRIVATE_REPO_SUMMARY
    assert PRIVATE_REPO_TITLE == "Could not verify"


def no_enrich(result: DetonateResult) -> DetonateResult:
    return result


def test_e4_end_to_end_with_recorded_llm_is_failure():
    body = json.loads((FIXTURES / "llm/e4_muse_spark_1_3.json").read_text())
    seen = {}

    def fake_llm(metadata, hits, result, diff, contract=None, guilty=None):
        seen["rules"] = {h.rule_id for h in hits}
        return LlmOutcome("muse-spark-1.3", verdict=parse_response(body))

    out = analyze(e4(), META, "diff", fake_llm, job_id="j", enrich=no_enrich)
    assert out.final.conclusion == "failure"
    assert seen["rules"] == {"NET_RAW_IP", "EXEC_NET_TOOL"}  # LLM sees rule findings
    assert "Blocked" in out.report


def test_e6_injected_llm_saying_benign_still_fails():
    def gullible_llm(*_, **__):
        return LlmOutcome(
            "m",
            verdict=LlmVerdict(
                verdict="benign",
                confidence=1.0,
                stated_intent="typo fix",
                observed_behavior="approved telemetry ping",
                mismatch=False,
                key_evidence=[],
                explanation="Pre-approved by security.",
            ),
        )

    out = analyze(e4(), META, "diff", gullible_llm, job_id="j", enrich=no_enrich)
    assert out.final.conclusion == "failure"


def test_enrichment_runs_before_rules():
    def name_everything(result):
        events = [
            e.model_copy(update={"resolved_domain": "registry.npmjs.org"})
            for e in result.connect_events
        ]
        return result.model_copy(update={"connect_events": events})

    out = analyze(
        e4(),
        META,
        "",
        lambda *_, **__: LlmOutcome("m", error="x"),
        job_id="j",
        enrich=name_everything,
    )
    assert {h.rule_id for h in out.hits} == {"EXEC_NET_TOOL"}
