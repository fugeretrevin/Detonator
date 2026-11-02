"""New / nonexistent dependency signal (HARDENING_PLAN P2.5).

AI coding agents increasingly add dependencies that are brand new, or that don't exist at all
(hallucinated names an attacker can then register — "slopsquatting"). A deterministic npm
registry lookup flags both as LOW ("needs review"): a human should look before it installs.
Never a block on its own; it rides alongside the kernel findings.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import quote

import httpx

from brain.rules import RuleHit, Severity

YOUNG_DAYS = 7
REGISTRY = "https://registry.npmjs.org"
LOOKUP_TIMEOUT_S = 5.0

# A resolver returns the package's first-publish time (ISO) if it exists, "missing" if the
# registry says 404, or None on any error/uncertainty (then we stay silent — fail open to
# avoid false alarms on registry hiccups).
Resolver = Callable[[str], "str | None"]
MISSING = "missing"


def registry_resolver(http: httpx.Client | None = None) -> Resolver:
    client = http or httpx.Client(timeout=LOOKUP_TIMEOUT_S)

    def lookup(name: str) -> str | None:
        try:
            resp = client.get(f"{REGISTRY}/{quote(name, safe='@')}")
            if resp.status_code == 404:
                return MISSING
            resp.raise_for_status()
            return ((resp.json().get("time") or {}).get("created")) or None
        except (httpx.HTTPError, ValueError):
            return None

    return lookup


def _age_days(created: str, now: datetime) -> float | None:
    try:
        ts = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (now - ts).total_seconds() / 86400


def new_package_hits(
    names: list[str],
    resolver: Resolver | None,
    *,
    now: datetime | None = None,
    young_days: int = YOUNG_DAYS,
) -> list[RuleHit]:
    if not resolver:
        return []
    now = now or datetime.now(UTC)
    hits: list[RuleHit] = []
    for name in names:
        created = resolver(name)
        if created is None:
            continue  # lookup failed: stay silent
        if created == MISSING:
            hits.append(RuleHit(
                "DEP_NEW_PACKAGE", Severity.LOW,
                f"dependency '{name}' does not exist on the public npm registry "
                "(possibly hallucinated or typosquatted — a name an attacker could register)",
                "", 0, target=name))  # fmt: skip
            continue
        age = _age_days(created, now)
        if age is not None and age < young_days:
            hits.append(RuleHit(
                "DEP_NEW_PACKAGE", Severity.LOW,
                f"dependency '{name}' was first published {age:.1f} days ago (new packages are "
                "a common supply-chain risk)", "", 0, target=name))  # fmt: skip
    return hits
