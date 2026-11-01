"""Telemetry -> enrich -> rules -> LLM -> verdict -> report. Pure orchestration, no Modal."""

from collections.abc import Callable
from dataclasses import dataclass

from brain.enrich import enrich_connects
from brain.github_client import PrMetadata
from brain.llm import LlmOutcome
from brain.report import render
from brain.rules import RuleHit, evaluate
from brain.verdict import FinalVerdict, combine
from brain.webhook import PullRequestEvent
from shared.contract import DetonateRequest, DetonateResult

Analyzer = Callable[[PrMetadata, list[RuleHit], DetonateResult, str], LlmOutcome]

PRIVATE_REPO_TITLE = "Could not verify"
PRIVATE_REPO_SUMMARY = (
    "Private repos need HTTPS on the Chamber. The Brain-to-Chamber link is plain HTTP "
    "(HMAC-signed, not encrypted), so no clone token is sent over it. Until TLS is added, "
    "only public repositories are detonated."
)


def detonate_request(event: PullRequestEvent, job_id: str) -> DetonateRequest | None:
    """None means: don't detonate (private repo would need a token over plain HTTP)."""
    if event.repo_private:
        return None
    # Public repo: clone anonymously. No token ever travels over the unencrypted link.
    return DetonateRequest(
        job_id=job_id, clone_url=event.head_clone_url, head_sha=event.head_sha, clone_token=None
    )


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
