"""Telemetry -> enrich -> rules -> LLM -> verdict -> report. Pure orchestration, no Modal."""

from collections.abc import Callable
from dataclasses import dataclass

from brain.enrich import enrich_connects
from brain.github_client import ChangedFile, PrMetadata
from brain.intent import IntentContract, PredictionOutcome, apply_contract, evaluate_contract
from brain.llm import LlmOutcome
from brain.pinpoint import GuiltyLine, find_guilty_lines, for_prompt, script_runs
from brain.prompt_guard import GuardOutcome, flagged
from brain.report import render
from brain.rules import RuleHit, evaluate
from brain.verdict import FinalVerdict, combine
from brain.webhook import PullRequestEvent
from shared.contract import DetonateRequest, DetonateResult

# (metadata, hits, result, diff, contract, *, guilty=...) -> outcome
Analyzer = Callable[..., LlmOutcome]

PRIVATE_REPO_TITLE = "Could not verify"
PRIVATE_REPO_SUMMARY = (
    "Private repos need TLS on the Brain-to-Chamber link, which is not configured here "
    "(HMAC-signed, not encrypted), so no clone token is sent over it."
)


def detonate_request(
    event: PullRequestEvent, job_id: str, *, private_token: str | None = None
) -> DetonateRequest | None:
    """None means: don't detonate (a private repo without a token we may send).

    Public repos are cloned anonymously. A private repo gets `private_token` (read-only, this
    repo only), which the caller supplies only when the Chamber link is TLS."""
    if event.repo_private and not private_token:
        return None
    return DetonateRequest(
        job_id=job_id,
        clone_url=event.head_clone_url,
        head_sha=event.head_sha,
        clone_token=private_token if event.repo_private else None,
    )


@dataclass(frozen=True)
class Analysis:
    final: FinalVerdict
    hits: list[RuleHit]
    llm: LlmOutcome
    result: DetonateResult
    report: str
    contract: IntentContract
    cleared: list[RuleHit]
    rule_hits: list[RuleHit]  # before the contract cleared anything (for evaluation)
    guilty: list[GuiltyLine]


def analyze(
    result: DetonateResult,
    metadata: PrMetadata,
    diff: str,
    llm: Analyzer,
    *,
    job_id: str,
    prediction: PredictionOutcome | None = None,
    allowed_cidrs: tuple[str, ...] = (),
    enrich: Callable[[DetonateResult], DetonateResult] = enrich_connects,
    files: list[ChangedFile] = (),
    guard: GuardOutcome | None = None,
) -> Analysis:
    result = enrich(result)
    rule_hits = evaluate(result, allowed_cidrs=allowed_cidrs)
    contract = evaluate_contract(prediction, result)
    if flagged(guard):
        # The prediction came from text Prompt Guard flags as an injection: trust none of it.
        hits, cleared = list(rule_hits), []
    else:
        hits, cleared = apply_contract(rule_hits, contract, metadata)
    guilty = find_guilty_lines(hits, result, list(files))
    outcome = llm(metadata, hits, result, diff, contract.for_prompt(),
                  guilty=for_prompt(guilty) or None)  # fmt: skip
    final = combine(hits, outcome, result)
    report = render(final, hits, outcome, result, job_id=job_id, contract=contract,
                    cleared=cleared, guilty=guilty,
                    script_runs=script_runs(hits, result), guard=guard)  # fmt: skip
    return Analysis(final, hits, outcome, result, report, contract, cleared, rule_hits, guilty)
