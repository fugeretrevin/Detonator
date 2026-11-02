"""Best-of-N escalation sampling (brain/sampling.py, docs/WEAKPOINTS.md W2)."""

from brain.llm import LlmOutcome, LlmVerdict
from brain.rules import Severity
from brain.sampling import MODEL_SAMPLES, sample_analysis, worst
from brain.verdict import llm_level


def verdict(kind: str, confidence: float = 0.9) -> LlmVerdict:
    return LlmVerdict(verdict=kind, confidence=confidence, stated_intent="s",
                      observed_behavior="o", mismatch=kind != "benign", key_evidence=[],
                      explanation="x")  # fmt: skip


def outcome(kind: str, confidence: float = 0.9) -> LlmOutcome:
    return LlmOutcome("m", verdict=verdict(kind, confidence))


ERROR = LlmOutcome("m", error="HTTP 503")


def test_default_is_one_sample_so_nothing_changes_until_measured():
    assert MODEL_SAMPLES == 1


def test_worst_keeps_the_most_severe_answer():
    # m12's real behaviour: malicious on some calls, suspicious on others.
    picked = worst([outcome("suspicious"), outcome("malicious"), outcome("suspicious")])
    assert picked.verdict.verdict == "malicious"


def test_worst_prefers_a_real_verdict_over_an_error():
    assert worst([ERROR, outcome("benign"), ERROR]).verdict.verdict == "benign"


def test_worst_stays_an_error_only_when_every_sample_failed():
    """Verdict.py treats a verdict-less outcome as model-unavailable, which caps at ⚠️ —
    so this must not silently become a benign-looking success."""
    assert worst([ERROR, ERROR]).verdict is None


def test_worst_is_monotone_never_below_any_individual_sample():
    """The safety property: keeping the worst of N can never clear what one call would block."""
    samples = [outcome("benign"), outcome("suspicious"), outcome("malicious", 0.95)]
    chosen = llm_level(worst(samples).verdict)
    assert all(chosen >= llm_level(s.verdict) for s in samples)
    assert chosen == Severity.CRITICAL


def test_one_sample_calls_the_model_exactly_once():
    calls = []

    def llm(*a, **k):
        calls.append(1)
        return outcome("benign")

    got = sample_analysis(llm, None, [], None, "", _Contract(), [], samples=1)
    assert len(calls) == 1 and got.verdict.verdict == "benign"


def test_three_samples_call_three_times_and_keep_the_worst():
    answers = iter([outcome("suspicious"), outcome("malicious"), outcome("suspicious")])
    calls = []

    def llm(*a, **k):
        calls.append(1)
        return next(answers)

    got = sample_analysis(llm, None, [], None, "", _Contract(), [], samples=3)
    assert len(calls) == 3
    assert got.verdict.verdict == "malicious"


def test_samples_are_clamped_to_the_maximum():
    calls = []

    def llm(*a, **k):
        calls.append(1)
        return outcome("benign")

    sample_analysis(llm, None, [], None, "", _Contract(), [], samples=99)
    assert len(calls) <= 5


class _Contract:
    def for_prompt(self):
        return None
