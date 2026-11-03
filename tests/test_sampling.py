"""Best-of-N escalation sampling (brain/sampling.py, docs/WEAKPOINTS.md W2)."""

from brain.llm import LlmOutcome, LlmVerdict
from brain.rules import Severity
from brain.sampling import BORDERLINE_TITLES, MODEL_SAMPLES, sample_analysis, worst
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


# --- conditional re-sampling: pay for stability only in the borderline band ---


def test_no_resample_when_the_first_answer_is_not_borderline():
    """Unconditional N=3 measured at $0.045-0.054/PR against a $0.04 budget, so the default
    path must stay a single call on the ~97% of PRs that are not borderline."""
    calls = []

    def llm(*a, **k):
        calls.append(1)
        return outcome("benign")

    got = sample_analysis(llm, None, [], None, "", _Contract(), [],
                          samples=3, needs_more=lambda o: False)  # fmt: skip
    assert len(calls) == 1 and got.verdict.verdict == "benign"


def test_resamples_and_escalates_when_the_first_answer_is_borderline():
    answers = iter([outcome("suspicious"), outcome("malicious"), outcome("suspicious")])
    calls = []

    def llm(*a, **k):
        calls.append(1)
        return next(answers)

    borderline = lambda o: o.verdict.verdict == "suspicious"  # noqa: E731
    got = sample_analysis(llm, None, [], None, "", _Contract(), [],
                          samples=3, needs_more=borderline)  # fmt: skip
    assert len(calls) == 3
    assert got.verdict.verdict == "malicious"  # m12's exact failure mode, stabilised


def test_an_unverified_case_is_in_the_band_because_it_can_never_be_needs_review():
    """gm08-cpu-miner's failure mode. Its install timed out, so `verified` is False and
    `combine` titles it "Could not verify" or "Blocked" - never "Needs review". A band of that
    one title excluded all 7 unverified cases of 142, letting gm08 flip Blocked x4 / Could not
    verify x1 while nominally in the `sampled` arm."""
    from brain.verdict import combine
    from shared.contract import DetonateResult
    from tests.conftest import NPM_EXEC

    timed_out = DetonateResult(job_id="j", status="timeout", exit_code=None, duration_s=1,
                               exec_events=[NPM_EXEC], connect_events=[], dns_queries=[],
                               stdout_tail="", stderr_tail="")  # fmt: skip
    assert combine([], outcome("suspicious"), timed_out).title == "Could not verify"
    assert "Could not verify" in BORDERLINE_TITLES

    answers = iter([outcome("suspicious"), outcome("malicious", 0.95), outcome("suspicious")])
    calls = []

    def llm(*a, **k):
        calls.append(1)
        return next(answers)

    got = sample_analysis(llm, None, [], None, "", _Contract(), [], samples=3,
                          needs_more=lambda o: combine([], o, timed_out).title
                          in BORDERLINE_TITLES)  # fmt: skip
    assert len(calls) == 3
    assert combine([], got, timed_out).title == "Blocked"  # the truthful label, stably


def test_clean_is_never_resampled_because_that_is_where_the_volume_is():
    """The cost gate: Clean measured perfectly stable, and it is ~95% of PRs."""
    from brain.verdict import combine
    from shared.contract import DetonateResult
    from tests.conftest import NPM_EXEC

    ok = DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                        exec_events=[NPM_EXEC], connect_events=[], dns_queries=[],
                        stdout_tail="", stderr_tail="")  # fmt: skip
    assert combine([], outcome("benign"), ok).title == "Clean"
    calls = []

    def llm(*a, **k):
        calls.append(1)
        return outcome("benign")

    sample_analysis(llm, None, [], None, "", _Contract(), [], samples=3,
                    needs_more=lambda o: combine([], o, ok).title in BORDERLINE_TITLES)  # fmt: skip
    assert len(calls) == 1


def test_resampling_can_only_raise_severity_never_lower_it():
    """If every extra sample is milder, the first answer still stands."""
    answers = iter([outcome("malicious", 0.95), outcome("benign"), outcome("benign")])

    def llm(*a, **k):
        return next(answers)

    got = sample_analysis(llm, None, [], None, "", _Contract(), [],
                          samples=3, needs_more=lambda o: True)  # fmt: skip
    assert llm_level(got.verdict) == Severity.CRITICAL
