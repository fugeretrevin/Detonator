"""Combine rule severity and LLM verdict into a check conclusion (BUILD_PLAN A5).

final = max(rule_level, llm_level). The LLM can raise severity but never lower a rule hit.
An unfinished detonation (timeout/error) fails closed: "Could not verify" is a failure.
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
    verified: bool  # False when the detonation didn't complete


def llm_level(verdict: LlmVerdict) -> Severity:
    if verdict.verdict == "malicious":
        return Severity.CRITICAL if verdict.confidence >= HIGH_CONFIDENCE else Severity.HIGH
    if verdict.verdict == "suspicious":
        return Severity.LOW
    return Severity.NONE


def combine(hits: list[RuleHit], llm: LlmOutcome, result: DetonateResult) -> FinalVerdict:
    rule_level = max_severity(hits)
    model_level = llm_level(llm.verdict) if llm.verdict else None
    level = max(rule_level, model_level or Severity.NONE)
    verified = result.status == "completed"

    if level >= Severity.HIGH:
        return FinalVerdict(level, rule_level, model_level, "failure", "Blocked", verified)
    if not verified:
        # Fail closed: GitHub treats `neutral` as passing, so an install that hangs or crashes
        # the sandbox would otherwise slip through branch protection.
        return FinalVerdict(level, rule_level, model_level, "failure", "Could not verify", verified)
    if level == Severity.LOW:
        return FinalVerdict(level, rule_level, model_level, "neutral", "Needs review", verified)
    return FinalVerdict(level, rule_level, model_level, "success", "Clean", verified)
