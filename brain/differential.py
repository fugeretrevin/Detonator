"""Differential detonation: compare the PR head's behavior with the base branch (P2.1).

Most real PRs are dependency bumps. Detonating the base SHA too lets us report only the
behavior the PR *introduced*, and keep routine bumps quiet: a LOW finding that the base
already produced is pre-existing, not something this PR did, so it is suppressed from the
verdict (shown as context). HIGH/CRITICAL findings are never suppressed — a reverse shell
is blocked whether or not the old version also had one.
"""

from dataclasses import dataclass

from brain.rules import RuleHit, Severity, is_external
from shared.contract import DetonateResult


def _behaviors(result: DetonateResult) -> set[str]:
    """Normalized, comparable behavior identities (order/pids/timestamps dropped)."""
    out: set[str] = set()
    for c in result.connect_events:
        if is_external(c.daddr):
            name = c.resolved_domain or c.daddr
            out.add(f"{c.protocol}:{name}:{c.dport}")
    for e in result.exec_events:
        b = e.binary.rsplit("/", 1)[-1]
        if not e.binary.startswith("/usr/") and b:
            out.add(f"exec:{b}")
    for q in result.dns_queries:
        out.add(f"dns:{q.domain}")
    for f in result.file_events:
        out.add(f"file:{f.path}")
    return out


def _hit_identity(hit: RuleHit) -> tuple[str, str]:
    return (hit.rule_id, hit.target)


@dataclass(frozen=True)
class Differential:
    base_status: str  # the base detonation's status (completed/timeout/error)
    new_behaviors: list[str]  # behavior keys in head but not base
    pre_existing: list[RuleHit]  # LOW head hits the base already produced (suppressed)

    @property
    def available(self) -> bool:
        return True


def diff(
    head_hits: list[RuleHit],
    base_hits: list[RuleHit],
    head: DetonateResult,
    base: DetonateResult,
) -> tuple[list[RuleHit], Differential]:
    """Returns (kept_hits, differential). Only LOW head hits whose (rule, target) the base
    also produced are suppressed, and only when the base detonation completed (else we trust
    nothing it says). The caller evaluates both hit lists on enriched results with the same
    allowlist, so identities are comparable."""
    base_ok = base.status == "completed"
    base_low = {_hit_identity(h) for h in base_hits} if base_ok else set()
    kept, suppressed = [], []
    for h in head_hits:
        if base_ok and h.severity == Severity.LOW and _hit_identity(h) in base_low:
            suppressed.append(h)
        else:
            kept.append(h)
    new = sorted(_behaviors(head) - _behaviors(base)) if base_ok else []
    return kept, Differential(base.status, new, suppressed)
