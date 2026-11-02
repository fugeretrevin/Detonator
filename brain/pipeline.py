"""Telemetry -> enrich -> rules -> LLM -> verdict -> report. Pure orchestration, no Modal."""

from collections.abc import Callable
from dataclasses import dataclass, replace

from brain.decoys import decoy_hits, redact, redact_text
from brain.differential import Differential
from brain.differential import diff as differential_diff
from brain.enrich import enrich_connects
from brain.github_client import ChangedFile, PrMetadata
from brain.intent import IntentContract, PredictionOutcome, apply_contract, evaluate_contract
from brain.llm import LlmOutcome, Usage
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
    usages: list[Usage]  # every model call this PR made (prediction + analysis)
    differential: "Differential | None" = None  # base-vs-head comparison, when the base ran

    @property
    def cost_usd(self) -> float | None:
        costs = [u.cost_usd for u in self.usages if u.cost_usd is not None]
        return sum(costs) if costs else None

    @property
    def model_tokens(self) -> tuple[int, int]:
        return (sum(u.prompt_tokens for u in self.usages),
                sum(u.completion_tokens for u in self.usages))  # fmt: skip


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
    base_result: DetonateResult | None = None,
) -> Analysis:
    result = enrich(result)
    raw_hits = evaluate(result, allowed_cidrs=allowed_cidrs) + decoy_hits(result)
    raw_hits.sort(key=lambda h: (-h.severity, h.ts))
    # Rules see the raw result; everything shown to the model or posted sees decoys redacted.
    rule_hits = [replace(h, evidence=redact_text(h.evidence, result)) for h in raw_hits]
    view = redact(result)
    contract = evaluate_contract(prediction, result)
    if flagged(guard):
        # The prediction came from text Prompt Guard flags as an injection: trust none of it.
        hits, cleared = list(rule_hits), []
    else:
        hits, cleared = apply_contract(rule_hits, contract, metadata)
    differential = None
    if base_result is not None:
        base_view = enrich(base_result)
        base_hits = evaluate(base_view, allowed_cidrs=allowed_cidrs)
        hits, differential = differential_diff(hits, base_hits, result, base_view)
    guilty = find_guilty_lines(hits, result, list(files))
    outcome = llm(metadata, hits, view, diff, contract.for_prompt(),
                  guilty=for_prompt(guilty) or None)  # fmt: skip
    final = combine(hits, outcome, view)
    report = render(final, hits, outcome, view, job_id=job_id, contract=contract,
                    cleared=cleared, guilty=guilty, script_runs=script_runs(hits, view),
                    guard=guard, differential=differential)  # fmt: skip
    usages = [u for u in (getattr(prediction, "usage", None), outcome.usage) if u]
    return Analysis(final, hits, outcome, view, report, contract, cleared, rule_hits, guilty,
                    usages, differential)  # fmt: skip
