"""Deterministic severity rules over Chamber telemetry (BUILD_PLAN A3, solo rule set).

These set the verdict floor: the LLM can escalate but never clear a hit. All inputs here
are attacker-influenced (args, binaries), so evidence strings must be escaped when rendered.
"""

import ipaddress
import re
import shlex
from dataclasses import dataclass
from enum import IntEnum

from brain.process_tree import lifecycle_exec
from shared import exfil_services
from shared.contract import ConnectEvent, DetonateResult, DnsQuery, ExecEvent

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

SANDBOX_RESOLVER = ("10.250.0.1", 53)  # chamber/provision/dnsmasq.conf
METADATA_ADDRS = frozenset({"169.254.169.254", "fd00:ec2::254", "169.254.170.2"})
# Data smuggled out in DNS names: long labels that look like encoding, not words. Benign
# installs in the eval topped out at 17-char labels; DNS allows 63.
# Writable places a payload drops a downloaded binary into. Packages' own binaries run from
# node_modules (esbuild, lefthook, prebuild-install in the eval), never from these. npm's
# cache (npx) lives under /tmp/.npm in the sandbox.
DROP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/")
NPM_CACHE_DIR = "/tmp/.npm/"
MIN_ENCODED_LABEL = 40
ENCODED_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

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
    target: str = ""  # destination host/IP for network hits


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


def _internal_hit(event: ConnectEvent) -> list[RuleHit]:
    """An install has no business on link-local or private ranges (metadata, the VPC, the
    host). The Chamber's iptables refuse these, but the attempt itself is the signal.

    One case is downgraded, never cleared: when a *public* domain's own DNS answer points into
    an RFC1918 range, the install reached the address its resolver chose, not a hardcoded
    internal host. Some real vendor/CDN endpoints publish private IPs in public DNS (e.g.
    `taro.jd.com` -> 172.x), so this is Needs-review, not Blocked. Two things keep their HIGH
    severity even with a domain attached, so nothing dangerous is laundered down:
      - cloud-metadata and link-local targets (a DNS-rebinding attempt at the metadata service
        resolves a name straight to 169.254.169.254; that must still block), and
      - a raw private-IP literal with no forward DNS name (`resolved_domain` is None), which is
        a direct internal pivot.
    `resolved_domain` on an internal IP comes only from a lookup the Chamber actually observed
    (enrich never names internal IPs), so a present name here is forward-confirmed."""
    if (event.daddr, event.dport) == SANDBOX_RESOLVER:
        return []  # DNS over TCP to the Chamber's logging resolver
    try:
        ip = ipaddress.ip_address(event.daddr)
    except ValueError:
        return []
    if ip.is_loopback:
        return []  # install-time tests talking to their own localhost server
    is_metadata = event.daddr in METADATA_ADDRS
    pinned_high = is_metadata or ip.is_link_local  # metadata / link-local never downgrade
    domain = (event.resolved_domain or "").rstrip(".")
    via_public_domain = bool(domain) and not domain.startswith(RDNS_PREFIX) and not pinned_high
    if via_public_domain:
        return [
            RuleHit(
                "NET_INTERNAL_TARGET",
                Severity.LOW,
                f"{_basename(event.binary)} (pid {event.pid}) connected to "
                f"{event.daddr}:{event.dport}, a private address that {domain} resolves to",
                event.ts,
                event.pid,
                target=event.daddr,
            )
        ]
    what = "the cloud metadata service" if is_metadata else "an internal address"
    return [
        RuleHit(
            "NET_INTERNAL_TARGET",
            Severity.HIGH,
            f"{_basename(event.binary)} (pid {event.pid}) tried to reach {what} "
            f"{event.daddr}:{event.dport}",
            event.ts,
            event.pid,
            target=event.daddr,
        )
    ]


def _connect_hits(
    event: ConnectEvent,
    allowed_domains: tuple[str, ...],
    allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> list[RuleHit]:
    if event.protocol != "tcp":
        # The Chamber rejects all non-TCP egress (DNS reaches its resolver another way), so
        # this is a payload trying a side channel: UDP exfil, ICMP, DNS to a public resolver.
        port = f":{event.dport}" if event.dport else ""
        name = f" ({event.resolved_domain})" if event.resolved_domain else ""
        return [
            RuleHit(
                "NET_NON_TCP_EGRESS",
                Severity.HIGH,
                f"{event.protocol.upper()} packet to {event.daddr}{port}{name} from the "
                "sandbox (blocked by the Chamber firewall)",
                event.ts,
                event.pid,
                target=event.daddr,
            )
        ]
    if not is_external(event.daddr):
        return _internal_hit(event)
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
                target=event.resolved_domain,
            )
        ]
    return []


def _looks_encoded(label: str) -> bool:
    if len(label) < MIN_ENCODED_LABEL or not ENCODED_LABEL_RE.match(label):
        return False
    digits = sum(ch.isdigit() for ch in label)
    hexish = all(ch in "0123456789abcdefABCDEF" for ch in label)
    return hexish or digits / len(label) >= 0.2


def _dns_hits(query: DnsQuery) -> list[RuleHit]:
    if not any(_looks_encoded(label) for label in query.domain.split(".")):
        return []
    return [
        RuleHit(
            "DNS_ENCODED_LABEL",
            Severity.HIGH,
            f"DNS lookup with an encoded-looking label (data exfiltration via DNS): "
            f"{_clip(query.domain)}",
            query.ts,
            0,
            target=query.domain,
        )
    ]


def _exfil_service_hits(result: DetonateResult) -> list[RuleHit]:
    """One hit per service: by the connecting process if it connected, else by the lookup.
    The Chamber sinkholes these names, so the attempt is recorded but nothing leaves."""
    hits: dict[str, RuleHit] = {}
    for c in result.connect_events:
        if c.resolved_domain and (m := exfil_services.match(c.resolved_domain)):
            service, kind = m
            hits.setdefault(service, RuleHit(
                "NET_EXFIL_SERVICE", Severity.HIGH,
                f"{_basename(c.binary)} (pid {c.pid}) connected to {c.resolved_domain} "
                f"({kind})", c.ts, c.pid, target=service))  # fmt: skip
    for q in result.dns_queries:
        if (m := exfil_services.match(q.domain)) and m[0] not in hits:
            service, kind = m
            hits[service] = RuleHit(
                "NET_EXFIL_SERVICE", Severity.HIGH,
                f"looked up {_clip(q.domain)} ({kind})", q.ts, 0, target=service)  # fmt: skip
    return list(hits.values())


def _is_npm_process(pid: int, execs: list[ExecEvent]) -> bool:
    """npm/npx reading ~/.npmrc is config, not theft, even when a dependency's install script
    spawned a nested `npm run ...` (seen with re2's install-from-cache)."""
    e = next((e for e in execs if e.pid == pid), None)
    if not e:
        return False
    return _basename(e.binary) in {"npm", "npx"} or "npm-cli.js" in e.args or "/npm/bin/" in e.args


def _credential_hits(result: DetonateResult) -> list[RuleHit]:
    """Bait credential files opened by an install script. Excluded: npm itself (top-level or a
    nested `npm run`), which reads ~/.npmrc as config. A real theft reads it from the
    dependency's own code (a plain node process, not npm)."""
    hits: list[RuleHit] = []
    seen: set[str] = set()
    for f in result.file_events:
        if f.path in seen or not lifecycle_exec(f.pid, result.exec_events):
            continue
        if _is_npm_process(f.pid, result.exec_events):
            continue
        seen.add(f.path)
        where = f.path.replace("/home/runner", "~")
        why = f"{_basename(f.binary)} (pid {f.pid}) opened {where} (a planted fake credential)"
        hits.append(RuleHit("CRED_FILE_ACCESS", Severity.HIGH, f"{why} from an install script",
                            f.ts, f.pid, target=f.path))  # fmt: skip
    return hits


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

    if event.binary.startswith(DROP_DIRS) and not event.binary.startswith(NPM_CACHE_DIR):
        hit("EXEC_DROPPED_BINARY", Severity.HIGH,
            "ran a program from a temp/home directory (dropped at install time)")  # fmt: skip

    if DEV_SOCKET_RE.search(args):
        hit("EXEC_INTERACTIVE_SHELL", Severity.CRITICAL, "/dev/tcp or /dev/udp socket redirect")
    elif name in SHELLS and _interactive_shell_flag(_tokens(args)):
        hit("EXEC_INTERACTIVE_SHELL", Severity.CRITICAL, f"interactive shell {name} -i")

    if (BASE64_DECODE_RE.search(args) and PIPE_TO_SHELL_RE.search(args)) or EVAL_DECODED_RE.search(
        args
    ):
        hit("EXEC_DECODE_PIPE", Severity.HIGH, "decoded payload piped into a shell")

    return hits


# rt08: a bare CPU loop leaves no exec, connect or file trace, only CPU time. Off (None) until
# calibrated on the benign set: native builds and big unzips burn real CPU too. Builds are
# exempt when a compiler/build tool ran; anything left is LOW (a human looks), never a block.
CPU_REVIEW_THRESHOLD_S: float | None = None
BUILD_TOOLS = frozenset({"cc", "gcc", "g++", "c++", "clang", "clang++", "make", "cmake", "ld",
                         "cc1", "cc1plus", "rustc", "cargo", "go", "node-gyp"})  # fmt: skip


def _cpu_hits(result: DetonateResult, threshold: float | None = None) -> list[RuleHit]:
    threshold = CPU_REVIEW_THRESHOLD_S if threshold is None else threshold
    usage = result.resources
    if threshold is None or usage is None or usage.cpu_s is None or usage.cpu_s < threshold:
        return []
    if any(_basename(e.binary) in BUILD_TOOLS for e in result.exec_events):
        return []
    why = (f"the install used {usage.cpu_s:.1f}s of CPU with no compiler or build tool "
           "running (possible local miner)")  # fmt: skip
    return [RuleHit("RES_CPU_HEAVY", Severity.LOW, why, "", 0)]


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
    for query in result.dns_queries:
        hits.extend(_dns_hits(query))
    hits.extend(_exfil_service_hits(result))
    hits.extend(_credential_hits(result))
    hits.extend(_cpu_hits(result))
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
