"""Combine rule severity and LLM verdict into a check conclusion (BUILD_PLAN A5).

final = max(rule_level, llm_level, investigator_level). Model output can raise severity but
never lower a rule hit.

"Clean" is a claim that we *watched* the install and saw nothing bad, so it requires three
independent things to hold. They are tracked separately because they fail for different
reasons and mean different things to a reviewer:

  1. the install finished   - status "completed" AND exit_code 0
  2. the telemetry is whole - not truncated by the event cap
  3. the sensor saw it      - at least one exec event (a real `npm install` always execs;
                              zero events means the collector was blind, not that the
                              install was quiet)

If any of them fails we report "Could not verify" as a *failure*, never "Clean". That is an
absence-of-evidence label, not a malware label, and `reason` says which precondition failed
so the report can explain it. A high/critical finding still Blocks regardless, since observed
maliciousness outranks an incomplete run.
"""

from dataclasses import dataclass

from brain.github_client import Conclusion
from brain.llm import LlmOutcome, LlmVerdict
from brain.rules import RuleHit, Severity, max_severity
from shared.contract import DetonateResult

HIGH_CONFIDENCE = 0.85


@dataclass(frozen=True)
class FinalVerdict:
    level: Severity
    rule_level: Severity
    llm_level: Severity | None  # None when the LLM was unavailable
    conclusion: Conclusion
    title: str
    verified: bool  # False when we could not fully observe a finished install
    reason: str = ""  # why `verified` is False; "" when it is True


def unverified_reason(result: DetonateResult) -> str:
    """Which precondition for a trustworthy "Clean" failed. Empty string means none did."""
    if result.status != "completed":
        return f"the detonation did not finish (status {result.status})"
    if result.exit_code != 0:
        return (
            f"`npm install` failed with exit code {result.exit_code}, so there was no "
            "complete install to observe"
        )
    if result.truncated:
        return "the telemetry hit its event cap and was truncated, so behaviour may be missing"
    if not result.exec_events:
        return "no process events were recorded at all, so the sensor was blind to this run"
    return ""


def llm_level(verdict: LlmVerdict) -> Severity:
    if verdict.verdict == "malicious":
        return Severity.CRITICAL if verdict.confidence >= HIGH_CONFIDENCE else Severity.HIGH
    if verdict.verdict == "suspicious":
        return Severity.LOW
    return Severity.NONE


def combine(
    hits: list[RuleHit],
    llm: LlmOutcome,
    result: DetonateResult,
    extra_level: Severity | None = None,
) -> FinalVerdict:
    """`extra_level` is a further model-derived escalation (the investigator agent). Like the
    LLM verdict it can only raise the level, never lower a rule hit."""
    rule_level = max_severity(hits)
    model_level = llm_level(llm.verdict) if llm.verdict else None
    level = max(rule_level, model_level or Severity.NONE, extra_level or Severity.NONE)
    reason = unverified_reason(result)
    verified = not reason

    if level >= Severity.HIGH:
        # Observed maliciousness outranks an incomplete run: block either way.
        return FinalVerdict(level, rule_level, model_level, "failure", "Blocked", verified, reason)
    if not verified:
        # Fail closed. GitHub treats `neutral` as passing, so anything we could not fully
        # observe must be a `failure` or it slips through branch protection — including a
        # failed install or truncated telemetry, which we previously called Clean.
        return FinalVerdict(
            level, rule_level, model_level, "failure", "Could not verify", verified, reason
        )
    if level == Severity.LOW:
        return FinalVerdict(level, rule_level, model_level, "neutral", "Needs review", verified)
    return FinalVerdict(level, rule_level, model_level, "success", "Clean", verified)
