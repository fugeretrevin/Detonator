"""Telemetry -> enrich -> rules -> LLM -> verdict -> report. Pure orchestration, no Modal."""

from collections.abc import Callable
from dataclasses import dataclass

from brain.enrich import enrich_connects
from brain.github_client import PrMetadata
from brain.llm import LlmOutcome
from brain.report import render
from brain.rules import RuleHit, evaluate
from brain.verdict import FinalVerdict, combine
from shared.contract import DetonateResult

Analyzer = Callable[[PrMetadata, list[RuleHit], DetonateResult, str], LlmOutcome]


@dataclass(frozen=True)
class Analysis:
    final: FinalVerdict
    hits: list[RuleHit]
    llm: LlmOutcome
    result: DetonateResult
    report: str


def analyze(
    result: DetonateResult,
    metadata: PrMetadata,
    diff: str,
    llm: Analyzer,
    *,
    job_id: str,
    allowed_cidrs: tuple[str, ...] = (),
    enrich: Callable[[DetonateResult], DetonateResult] = enrich_connects,
) -> Analysis:
    result = enrich(result)
    hits = evaluate(result, allowed_cidrs=allowed_cidrs)
    outcome = llm(metadata, hits, result, diff)
    final = combine(hits, outcome, result)
    report = render(final, hits, outcome, result, job_id=job_id)
    return Analysis(final, hits, outcome, result, report)
