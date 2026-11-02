import pytest

from brain.llm import LlmOutcome, LlmVerdict
from brain.rules import RuleHit, Severity
from brain.verdict import combine, llm_level
from shared.contract import DetonateResult
from tests.conftest import NPM_EXEC


def result(status: str = "completed", exit_code: int = 0, truncated: bool = False,
           exec_events=(NPM_EXEC,)) -> DetonateResult:  # fmt: skip
    return DetonateResult(
        job_id="j",
        status=status,
        exit_code=exit_code,
        duration_s=1,
        exec_events=list(exec_events),
        connect_events=[],
        dns_queries=[],
        stdout_tail="",
        stderr_tail="",
        truncated=truncated,
    )


def hit(severity: Severity) -> RuleHit:
    return RuleHit("R", severity, "e", "t", 1)


def llm(verdict: str, confidence: float = 0.9) -> LlmOutcome:
    return LlmOutcome(
        "m",
        verdict=LlmVerdict(
            verdict=verdict,
            confidence=confidence,
            stated_intent="s",
            observed_behavior="o",
            mismatch=verdict != "benign",
            key_evidence=[],
            explanation="x",
        ),
    )


NO_LLM = LlmOutcome("m", error="HTTP 503")


@pytest.mark.parametrize(
    "verdict, confidence, expected",
    [
        ("benign", 1.0, Severity.NONE),
        ("suspicious", 0.9, Severity.LOW),
        ("malicious", 0.5, Severity.HIGH),
        ("malicious", 0.85, Severity.CRITICAL),
    ],
)
def test_llm_level_mapping(verdict, confidence, expected):
    assert llm_level(llm(verdict, confidence).verdict) == expected


@pytest.mark.parametrize(
    "hits, outcome, conclusion",
    [
        ([], llm("benign"), "success"),
        ([], NO_LLM, "neutral"),  # model down: rules saw nothing, which is not Clean
        ([hit(Severity.LOW)], llm("benign"), "neutral"),
        ([], llm("suspicious"), "neutral"),
        ([], llm("malicious", 0.6), "failure"),  # LLM can escalate
        ([hit(Severity.HIGH)], NO_LLM, "failure"),  # rules-only fallback
        ([hit(Severity.CRITICAL)], llm("benign", 1.0), "failure"),
    ],
)
def test_combine(hits, outcome, conclusion):
    assert combine(hits, outcome, result()).conclusion == conclusion


def test_llm_cannot_clear_rule_hit_e6():
    """Prompt-injected LLM says benign with full confidence; the rules floor holds."""
    final = combine([hit(Severity.HIGH)], llm("benign", 1.0), result())
    assert final.conclusion == "failure" and final.level == Severity.HIGH
    assert final.llm_level == Severity.NONE


@pytest.mark.parametrize("status", ["timeout", "error"])
def test_unfinished_detonation_fails_closed(status):
    final = combine([], llm("benign"), result(status))
    assert final.conclusion == "failure" and final.title == "Could not verify"
    assert not final.verified


def test_unfinished_detonation_still_fails_on_observed_evil():
    # e.g. a reverse shell that hangs the install until timeout
    final = combine([hit(Severity.CRITICAL)], NO_LLM, result("timeout"))
    assert final.conclusion == "failure" and not final.verified


# --- "Clean" requires a finished install AND complete telemetry AND a live sensor ---
# Regression guard: each of these used to return Clean/success or a passing `neutral`, which
# told a reviewer we had watched the install when we had not.


@pytest.mark.parametrize(
    "kwargs, because",
    [
        ({"exit_code": 1}, "exit code 1"),  # npm install failed outright
        ({"truncated": True}, "truncated"),  # event cap hit, behaviour may be missing
        ({"exec_events": ()}, "no process events"),  # collector was blind
    ],
)
def test_incomplete_observation_is_never_clean(kwargs, because):
    final = combine([], llm("benign", 1.0), result(**kwargs))
    assert final.title == "Could not verify"
    assert final.conclusion == "failure"  # `neutral` would pass branch protection
    assert not final.verified
    assert because in final.reason


def test_failed_install_with_a_finding_still_blocks():
    """An install that reaches a C2 and then dies must read Blocked, not Could not verify."""
    final = combine([hit(Severity.CRITICAL)], NO_LLM, result(exit_code=1))
    assert final.title == "Blocked" and final.conclusion == "failure"
    assert not final.verified and "exit code 1" in final.reason


def test_a_fully_observed_clean_run_has_no_reason():
    final = combine([], llm("benign"), result())
    assert final.title == "Clean" and final.verified and final.reason == ""


# --- model outage: Clean needs the analysis to have run ---


@pytest.mark.parametrize(
    "hits, res, title, conclusion",
    [
        ([], result(), "Needs review", "neutral"),  # rules saw nothing; model didn't run
        ([hit(Severity.LOW)], result(), "Needs review", "neutral"),
        ([hit(Severity.HIGH)], result(), "Blocked", "failure"),  # the floor still blocks
        ([], result(exit_code=1), "Could not verify", "failure"),  # unverified wins
    ],
)
def test_model_failure_never_yields_clean(hits, res, title, conclusion):
    final = combine(hits, NO_LLM, res)
    assert (final.title, final.conclusion) == (title, conclusion)
    assert "HTTP 503" in final.model_unavailable


def test_deliberately_skipped_model_is_not_a_failure():
    skipped = LlmOutcome("none", error="skipped", skipped=True)
    final = combine([], skipped, result())
    assert final.title == "Clean" and final.model_unavailable == ""


def test_model_that_ran_reports_nothing_unavailable():
    assert combine([], llm("benign"), result()).model_unavailable == ""
