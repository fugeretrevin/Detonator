"""Per-repository policy, `.github/detonator.yml` (HARDENING_PLAN P2.3).

**Read from the base branch only.** The PR author controls the head, so a policy read from
there would let an attacker allowlist their own exfil host. The base branch is what the repo
owner (and branch protection) governs.

What a repo may configure:
- `allowed_domains`: extra hosts that are normal for this project (a company CDN, an internal
  mirror). These only ever silence the LOW `NET_UNLISTED_DOMAIN` finding — never a
  high/critical one, so the kernel floor is unchanged.
- `needs_review`: `pass` (default; ⚠️ is a neutral, mergeable check) or `block` (⚠️ fails the
  check too). This is the answer to "needs review is mergeable" for teams who want it strict.
- `timeout_s`: how long the install may run (1..300).

Everything is validated; anything unknown, malformed or out of range is ignored and the
default applies, so a broken policy can never weaken or break a review.
"""

import ipaddress
import re
from dataclasses import dataclass, field

import yaml

POLICY_PATH = ".github/detonator.yml"
MAX_ALLOWED_DOMAINS = 50
MIN_TIMEOUT_S, MAX_TIMEOUT_S = 1, 300
DEFAULT_TIMEOUT_S = 180
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)


@dataclass(frozen=True)
class Policy:
    allowed_domains: tuple[str, ...] = ()
    needs_review: str = "pass"  # "pass" | "block"
    timeout_s: int = DEFAULT_TIMEOUT_S
    source: str | None = None  # where it came from, for the report
    warnings: list[str] = field(default_factory=list)

    @property
    def blocks_needs_review(self) -> bool:
        return self.needs_review == "block"

    @property
    def configured(self) -> bool:
        return bool(self.allowed_domains) or self.blocks_needs_review or self.source is not None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _domains(raw, warnings: list[str]) -> tuple[str, ...]:
    if not isinstance(raw, list):
        if raw is not None:
            warnings.append("allowed_domains must be a list")
        return ()
    out: list[str] = []
    for item in raw[:MAX_ALLOWED_DOMAINS]:
        host = str(item).strip().rstrip(".").lower() if item is not None else ""
        if _is_ip(host):
            # A raw IP here would be misleading: raw-IP connects are HIGH and a policy can
            # only ever silence the LOW named-domain finding.
            warnings.append(f"ignored allowed_domains IP address {host[:60]!r}: use a hostname")
            continue
        if _HOSTNAME_RE.match(host) and host not in out:
            out.append(host)
        elif host:
            warnings.append(f"ignored invalid allowed_domains entry: {host[:60]!r}")
    if isinstance(raw, list) and len(raw) > MAX_ALLOWED_DOMAINS:
        warnings.append(f"only the first {MAX_ALLOWED_DOMAINS} allowed_domains were used")
    return tuple(out)


def parse_policy(text: str | None, source: str = POLICY_PATH) -> Policy:
    """Never raises: a malformed policy yields the defaults plus a warning."""
    if not text or not text.strip():
        return Policy()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return Policy(warnings=[f"could not parse {source} ({type(exc).__name__}); defaults used"])
    if not isinstance(data, dict):
        return Policy(warnings=[f"{source} must be a YAML mapping; defaults used"])

    warnings: list[str] = []
    domains = _domains(data.get("allowed_domains"), warnings)

    needs_review = "pass"
    raw_nr = data.get("needs_review")
    if isinstance(raw_nr, str) and raw_nr.strip().lower() in ("pass", "block"):
        needs_review = raw_nr.strip().lower()
    elif raw_nr is not None:
        warnings.append("needs_review must be 'pass' or 'block'; using 'pass'")

    timeout = DEFAULT_TIMEOUT_S
    raw_t = data.get("timeout_s")
    if isinstance(raw_t, bool) or not isinstance(raw_t, int):
        if raw_t is not None:
            warnings.append("timeout_s must be an integer; using the default")
    elif MIN_TIMEOUT_S <= raw_t <= MAX_TIMEOUT_S:
        timeout = raw_t
    else:
        warnings.append(f"timeout_s must be {MIN_TIMEOUT_S}..{MAX_TIMEOUT_S}; using the default")

    unknown = sorted(set(data) - {"allowed_domains", "needs_review", "timeout_s"})
    if unknown:
        warnings.append(f"ignored unknown keys: {', '.join(unknown[:5])}")

    return Policy(domains, needs_review, timeout, source, warnings)
