"""Telemetry -> enrich -> rules -> LLM -> verdict -> report. Pure orchestration, no Modal."""

from collections.abc import Callable
from dataclasses import dataclass, replace

from brain.decoys import decoy_hits, redact, redact_text
from brain.differential import Differential
from brain.differential import diff as differential_diff
from brain.enrich import enrich_connects
from brain.evidence import Grounding, build_index, corpus_for
from brain.evidence import check as check_evidence
from brain.github_client import ChangedFile, PrMetadata, added_registry_dependencies
from brain.intent import IntentContract, PredictionOutcome, apply_contract, evaluate_contract
from brain.investigator import Investigation
from brain.llm import LlmOutcome, Usage
from brain.newpkg import Resolver, new_package_hits
from brain.pinpoint import GuiltyLine, find_guilty_lines, for_prompt, script_runs
from brain.policy import DEFAULT_TIMEOUT_S, Policy
from brain.prompt_guard import GuardOutcome, flagged
from brain.report import render
from brain.rules import DEFAULT_ALLOWED_DOMAINS, RuleHit, evaluate
from brain.verdict import FinalVerdict, combine
from brain.webhook import PullRequestEvent
from shared.contract import DetonateRequest, DetonateResult

# (metadata, hits, result, diff, contract, *, guilty=...) -> outcome
Analyzer = Callable[..., LlmOutcome]
# (hits, result) -> Investigation | None; only called for a "Needs review" verdict
Investigator = Callable[[list[RuleHit], DetonateResult], "Investigation | None"]

PRIVATE_REPO_TITLE = "Could not verify"
PRIVATE_REPO_SUMMARY = (
    "Private repos need TLS on the Brain-to-Chamber link, which is not configured here "
    "(HMAC-signed, not encrypted), so no clone token is sent over it."
)


def detonate_request(
    event: PullRequestEvent,
    job_id: str,
    *,
    private_token: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S,
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
        timeout_s=timeout_s,
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
    investigation: "Investigation | None" = None  # triage note, only for ⚠️ verdicts
    grounding: "Grounding | None" = None  # the model's claims checked against the record

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
    new_package_resolver: "Resolver | None" = None,
    investigator: Investigator | None = None,
    policy: Policy | None = None,
) -> Analysis:
    result = enrich(result)
    added = added_registry_dependencies(list(files))
    # A repo's own policy (base branch only) may name extra normal hosts. It widens the
    # allowlist the LOW unlisted-domain rule uses; high/critical rules are unaffected.
    policy = policy or Policy()
    domains = DEFAULT_ALLOWED_DOMAINS + policy.allowed_domains
    raw_hits = (
        evaluate(result, allowed_domains=domains, allowed_cidrs=allowed_cidrs)
        + decoy_hits(result)
        + new_package_hits(added, new_package_resolver)
    )
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
    # Code, not the model, decides which of its claims the kernel record supports. Report only.
    grounding = (check_evidence(outcome.verdict, build_index(view), corpus_for(view, diff))
                 if outcome.verdict else None)  # fmt: skip
    # A ⚠️ verdict means a human must decide: give them a triage note. Escalate-only.
    investigation = None
    if investigator is not None and final.title == "Needs review":
        investigation = investigator(hits, view)
        if investigation is not None:
            final = combine(hits, outcome, view, extra_level=investigation.level)
    if policy.requires_model and final.model_unavailable and final.title != "Blocked":
        # The repo requires the AI analysis: without it this commit is unverified, not clean.
        final = replace(final, conclusion="failure", title="Could not verify")
    if policy.blocks_needs_review and final.title == "Needs review":
        # The repo opted into strict mode: a ⚠️ must not be mergeable here.
        final = replace(final, conclusion="failure")
    report = render(final, hits, outcome, view, job_id=job_id, contract=contract,
                    cleared=cleared, guilty=guilty, script_runs=script_runs(hits, view),
                    guard=guard, differential=differential,
                    investigation=investigation, policy=policy,
                    grounding=grounding)  # fmt: skip
    usages = [u for u in (getattr(prediction, "usage", None), outcome.usage) if u]
    if investigation is not None:
        usages += investigation.usages
    return Analysis(final, hits, outcome, view, report, contract, cleared, rule_hits, guilty,
                    usages, differential, investigation, grounding)  # fmt: skip
