import pytest

from brain.llm import LlmOutcome, LlmVerdict
from brain.rules import RuleHit, Severity
from brain.verdict import combine, llm_level
from shared.contract import DetonateResult


def result(status: str = "completed") -> DetonateResult:
    return DetonateResult(
        job_id="j",
        status=status,
        exit_code=0,
        duration_s=1,
        exec_events=[],
        connect_events=[],
        dns_queries=[],
        stdout_tail="",
        stderr_tail="",
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
        ([], NO_LLM, "success"),
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
def test_unfinished_detonation_never_success(status):
    final = combine([], llm("benign"), result(status))
    assert final.conclusion == "neutral" and final.title == "Could not verify"
    assert not final.verified


def test_unfinished_detonation_still_fails_on_observed_evil():
    # e.g. a reverse shell that hangs the install until timeout
    final = combine([hit(Severity.CRITICAL)], NO_LLM, result("timeout"))
    assert final.conclusion == "failure" and not final.verified
