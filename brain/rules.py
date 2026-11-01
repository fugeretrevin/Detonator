"""Deterministic severity rules over Chamber telemetry (BUILD_PLAN A3, solo rule set).

These set the verdict floor: the LLM can escalate but never clear a hit. All inputs here
are attacker-influenced (args, binaries), so evidence strings must be escaped when rendered.
"""

import ipaddress
import re
import shlex
from dataclasses import dataclass
from enum import IntEnum

from shared.contract import ConnectEvent, DetonateResult, ExecEvent

DEFAULT_ALLOWED_DOMAINS: tuple[str, ...] = (
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
    "nodejs.org",
)
RDNS_PREFIX = "rdns:"
MAX_HITS = 50
MAX_EVIDENCE_ARGS = 160

NET_TOOLS = frozenset(
    {"curl", "wget", "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat", "telnet"}
)
SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ash", "ksh"})
DEV_SOCKET_RE = re.compile(r"/dev/(tcp|udp)/")
BASE64_DECODE_RE = re.compile(r"\bbase64\s+(?:-\w*d\w*|--decode)\b")
PIPE_TO_SHELL_RE = re.compile(r"\|\s*(?:/\S*/)?(?:ba|da|z|k)?sh\b")
EVAL_DECODED_RE = re.compile(r"\beval\b.*(?:base64|atob\(|Buffer\.from\()")


# Destinations that are not "the internet". Everything else counts as external, including
# documentation ranges like TEST-NET-3 (203.0.113.0/24) used for safe demo payloads, which
# Python's ip.is_global would wrongly exclude.
INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def is_external(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not any(ip in net for net in INTERNAL_NETWORKS if net.version == ip.version)


class Severity(IntEnum):
    NONE = 0
    LOW = 1
    HIGH = 2
    CRITICAL = 3


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    severity: Severity
    evidence: str
    ts: str
    pid: int


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _clip(text: str) -> str:
    return text if len(text) <= MAX_EVIDENCE_ARGS else text[:MAX_EVIDENCE_ARGS] + "..."


def _tokens(args: str) -> list[str]:
    try:
        return shlex.split(args)
    except ValueError:  # unbalanced quotes in attacker-controlled args
        return args.split()


def domain_allowed(domain: str, allowed: tuple[str, ...]) -> bool:
    domain = domain.removeprefix(RDNS_PREFIX).rstrip(".").lower()
    return any(domain == d or domain.endswith("." + d) for d in allowed)


# --- network rules ---


def _connect_hits(
    event: ConnectEvent,
    allowed_domains: tuple[str, ...],
    allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> list[RuleHit]:
    if not is_external(event.daddr):
        return []
    if any(ipaddress.ip_address(event.daddr) in net for net in allowed_networks):
        return []

    target = f"{event.daddr}:{event.dport}"
    who = f"{_basename(event.binary)} (pid {event.pid})"
    if event.resolved_domain is None:
        return [
            RuleHit(
                "NET_RAW_IP",
                Severity.HIGH,
                f"{who} connected to {target} with no DNS lookup or verified reverse name",
                event.ts,
                event.pid,
            )
        ]
    if not domain_allowed(event.resolved_domain, allowed_domains):
        return [
            RuleHit(
                "NET_UNLISTED_DOMAIN",
                Severity.LOW,
                f"{who} connected to {event.resolved_domain} ({target}), not in allowlist",
                event.ts,
                event.pid,
            )
        ]
    return []


# --- exec rules ---


def _interactive_shell_flag(tokens: list[str]) -> bool:
    """True if a shell's own option cluster (before -c / the script) contains -i."""
    for tok in tokens:
        if not tok.startswith("-") or tok.startswith("--") or tok == "-":
            return False
        if "i" in tok[1:]:
            return True
        if "c" in tok[1:]:
            return False
    return False


def _exec_hits(event: ExecEvent) -> list[RuleHit]:
    hits: list[RuleHit] = []
    name = _basename(event.binary)
    args = event.args
    cmd = _clip(f"{event.binary} {args}".strip())

    def hit(rule_id: str, severity: Severity, why: str) -> None:
        hits.append(
            RuleHit(rule_id, severity, f"{why}: {cmd} (pid {event.pid})", event.ts, event.pid)
        )

    if name in NET_TOOLS:
        hit("EXEC_NET_TOOL", Severity.HIGH, f"network tool {name} executed during install")

    if DEV_SOCKET_RE.search(args):
        hit("EXEC_INTERACTIVE_SHELL", Severity.CRITICAL, "/dev/tcp or /dev/udp socket redirect")
    elif name in SHELLS and _interactive_shell_flag(_tokens(args)):
        hit("EXEC_INTERACTIVE_SHELL", Severity.CRITICAL, f"interactive shell {name} -i")

    if (BASE64_DECODE_RE.search(args) and PIPE_TO_SHELL_RE.search(args)) or EVAL_DECODED_RE.search(
        args
    ):
        hit("EXEC_DECODE_PIPE", Severity.HIGH, "decoded payload piped into a shell")

    return hits


def evaluate(
    result: DetonateResult,
    allowed_domains: tuple[str, ...] = DEFAULT_ALLOWED_DOMAINS,
    allowed_cidrs: tuple[str, ...] = (),
) -> list[RuleHit]:
    networks = tuple(ipaddress.ip_network(c, strict=False) for c in allowed_cidrs)
    hits: list[RuleHit] = []
    for exec_event in result.exec_events:
        hits.extend(_exec_hits(exec_event))
    for connect_event in result.connect_events:
        hits.extend(_connect_hits(connect_event, allowed_domains, networks))
    if result.truncated:
        # Events past the caps were dropped; a flood could be hiding a payload.
        hits.append(
            RuleHit(
                "TELEMETRY_TRUNCATED",
                Severity.LOW,
                "event caps were hit; some runtime behavior was not captured",
                "",
                0,
            )
        )
    hits.sort(key=lambda h: (-h.severity, h.ts))
    return hits[:MAX_HITS]


def max_severity(hits: list[RuleHit]) -> Severity:
    return max((h.severity for h in hits), default=Severity.NONE)
