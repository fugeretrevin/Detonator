"""Deterministic severity rules over Chamber telemetry.

These set the verdict floor: the LLM can escalate but never clear a hit. All inputs here
are attacker-influenced (args, binaries), so evidence strings must be escaped when rendered.
"""

import ipaddress
import posixpath
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
# Programs that run a script *file* given as an operand (`sh /tmp/x.sh`, `node /tmp/x.js`):
# the kernel sees the interpreter's path, so the dropped file only shows up in the args.
INTERPRETERS = SHELLS | {"node", "nodejs", "python", "python3", "perl", "ruby", "php"}
# Per interpreter: after these, the next token is inline code or a module, not a script file.
# (Per interpreter because `bash -e` is "exit on error", while `node -e` is inline code.)
INLINE_CODE_FLAGS = {
    **{s: frozenset({"-c"}) for s in SHELLS},
    "node": frozenset({"-e", "-p", "--eval", "--print"}),
    "nodejs": frozenset({"-e", "-p", "--eval", "--print"}),
    "python": frozenset({"-c", "-m"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "php": frozenset({"-r"}),
}
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
# All-hex labels get a lower floor (W15). The 40-char floor exists to avoid flagging legitimate
# long labels — CDN cache keys, content hashes — which have digits but are rarely pure hex. An
# *all-hex* label is a much stronger exfil signal: measured across all 742 recorded installs,
# the only hex DNS labels of 16+ chars belong to attack cases (m11 at 60, the held-out bc08 at
# 24), while the longest benign hex label is a 14-char CDN hash. The floor is 20 — above that
# observed benign hex length with margin, below bc08 — so bc08 and m11 are caught with 0 benign
# false positives on the recorded corpus. That corpus is 742 installs, not the world: a benign
# host with a 20+ char all-hex subdomain would be flagged, so this stays a HIGH rule (human
# review), never an irreversible block on its own. See docs/WEAKPOINTS.md W15.
MIN_HEX_LABEL = 20
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
    if not ENCODED_LABEL_RE.match(label):
        return False
    hexish = all(ch in "0123456789abcdefABCDEF" for ch in label)
    # All-hex is a strong signal, so it gets the lower floor; the weaker digit-fraction
    # heuristic keeps the conservative 40-char floor to spare long benign cache keys.
    if hexish:
        return len(label) >= MIN_HEX_LABEL
    if len(label) < MIN_ENCODED_LABEL:
        return False
    digits = sum(ch.isdigit() for ch in label)
    return digits / len(label) >= 0.2


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


# Paths reported by `chamber/policies/credential-files.yaml`: planted fakes, so an open is
# theft, not configuration.
BAIT_FILE_PREFIXES = (
    "/home/runner/.npmrc",
    "/home/runner/.aws/",
    "/home/runner/.ssh/",
    "/home/runner/.git-credentials",
)
# Paths reported by `chamber/policies/persistence-files.yaml`: files whose only purpose is to
# make code run after the install is over. `tests/test_persistence_files.py` asserts these two
# tuples cover every prefix those policies actually select, so a path cannot be traced by the
# Chamber and then silently mislabelled here.
PERSISTENCE_FILE_PREFIXES = (
    "/home/runner/.bashrc",
    "/home/runner/.zshrc",
    "/home/runner/.profile",
    "/home/runner/.bash_profile",
    "/home/runner/.bash_login",
    "/home/runner/.zshenv",
    "/home/runner/.config/fish/",
    "/etc/profile.d/",
    "/etc/bash.bashrc",
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/var/spool/cron/",
    "/etc/systemd/system/",
    "/home/runner/.config/systemd/",
)

# HIGH, earned by measurement on Nov 3 rather than assumed. The rule shipped at LOW first,
# because it cannot fire until `persistence-files.yaml` is loaded on the Chamber and so had no
# false-positive evidence at all. The policy was then deployed and the measurement run:
#
#   - **0 of 104** benign controls open any of these paths from an install script, re-detonated
#     live against the registry with the policy loaded.
#   - `gm04-rcfile-persist` (`~/.bashrc` + `~/.zshrc`) and `rt06-persist-rcfile` (`~/.bashrc`)
#     both raise it. Before this they fired **no rule at all** and scored Clean.
#   - `truncated` stayed False on all 106 runs, so the policy does not flood the event cap -
#     which matters because truncation fails closed and would turn verdicts into
#     "Could not verify" rather than failing loudly.
#   - Validity, checked before the result: every one of the 104 records carries `file_events`
#     (npm reads ~/.npmrc on every install), 0 had a blind collector and 0 failed the sensor
#     witness - so a zero count means "nothing opened these paths", not "tracing was dead".
#
# Known and accepted: the policy is host-global, so host shell startups reading
# `/etc/bash.bashrc` also post events (7 observed, all `/bin/bash` outside any container). The
# Chamber's parser filters to the job's container, so they cannot reach a verdict.
FILE_PERSISTENCE_SEVERITY = Severity.HIGH


def _classify_file(path: str) -> str | None:
    if path.startswith(BAIT_FILE_PREFIXES):
        return "bait"
    if path.startswith(PERSISTENCE_FILE_PREFIXES):
        return "persistence"
    return None


def _credential_hits(result: DetonateResult) -> list[RuleHit]:
    """Files opened by an install script that the Chamber's tracing policies single out.

    Two classes, deliberately not one rule: a planted credential is theft, a shell startup file
    is persistence, and calling a `.bashrc` "a planted fake credential" would be a false
    statement in the comment a reviewer reads.

    Excluded from the credential class: npm itself (top-level or a nested `npm run`), which
    reads ~/.npmrc as config. A real theft reads it from the dependency's own code - a plain
    node process, not npm. That exemption is **not** extended to persistence paths: npm has no
    reason to write a shell startup file or a cron entry, so there is nothing to excuse.
    """
    hits: list[RuleHit] = []
    seen: set[str] = set()
    for f in result.file_events:
        kind = _classify_file(f.path)
        if kind is None or f.path in seen or not lifecycle_exec(f.pid, result.exec_events):
            continue
        if kind == "bait" and _is_npm_process(f.pid, result.exec_events):
            continue
        seen.add(f.path)
        where = f.path.replace("/home/runner", "~")
        who = f"{_basename(f.binary)} (pid {f.pid})"
        if kind == "bait":
            hits.append(RuleHit("CRED_FILE_ACCESS", Severity.HIGH,
                                f"{who} opened {where} (a planted fake credential) "
                                "from an install script", f.ts, f.pid, target=f.path))  # fmt: skip
        else:
            hits.append(RuleHit("FILE_PERSISTENCE", FILE_PERSISTENCE_SEVERITY,
                                f"{who} opened {where} from an install script — a file whose "
                                "purpose is to run code after the install ends",
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


def _script_operand(event: ExecEvent) -> str | None:
    """The script file an interpreter was asked to run, resolved against the kernel-recorded
    cwd (string-only, never touching the host filesystem), or None for inline code."""
    name = _basename(event.binary)
    family = re.sub(r"[\d.]+$", "", name)  # python3.11 -> python
    if family not in INTERPRETERS:
        return None
    inline = INLINE_CODE_FLAGS.get(family, frozenset())
    for tok in _tokens(event.args):
        if tok in inline:
            return None
        if tok.startswith("-") and not tok.startswith("--") and name in SHELLS and "c" in tok:
            return None  # a shell option cluster with -c (e.g. -ec): inline command
        if tok.startswith("-"):
            continue
        if tok.startswith("/"):
            return posixpath.normpath(tok)
        return posixpath.normpath(posixpath.join(event.cwd, tok)) if event.cwd else None
    return None


# Install-time scheduling. A package has no reason to register a cron job, a systemd unit or an
# `at` job while installing: the point of the technique is code that runs *after* the install is
# over, when nothing is watching. That makes it persistence, not configuration.
#
# Measured before being written, across every recorded install available (3342 exec events in
# 742 installs: the 142 eval cases plus the 100- and 500-package registry sweeps, 604 of which
# are uncurated packages straight off the npm feed). Exactly one match -
# `gm05-cron-inject` - and **zero** among the 104 popular packages or the 604 uncurated ones.
#
# Also measured and deliberately *not* turned into rules, so the negative results are on record:
#   - `chmod +x`              2 uncurated false positives (a real package marking a vendored
#                             binary executable). Rejected.
#   - `curl|sh` / `wget|sh`   3 attack matches, 0 false positives - but all three already Block
#                             on EXEC_NET_TOOL or EXEC_DECODE_PIPE, so a rule buys no new catch.
#   - `~/.bashrc`, `authorized_keys`, `nohup`, `LD_PRELOAD`, history tampering
#                             no matches at all, including in the four red-team cases that do
#                             exactly these things: they use node's `fs` API, not a shell, so
#                             argv cannot see them. Closing that needs general file-write
#                             telemetry in the Chamber (see docs/WEAKPOINTS.md W5), not a rule.
# Matched in *command position* - start of string, or after a shell separator or quote - and
# not as a substring of a path or package name. A plain `\bcrontab\b` also fires on
# `docs/crontab-format.md`, which a package shipping cron documentation would ship; that was a
# real false positive, caught by this rule's own test before it shipped. Likewise `at` needs a
# following `now`/`-f`, so `npm run at-build` and the words "scheduled at build time" are not
# scheduling, and `systemctl` needs `enable`/`start`, so reading status is not registering.
_CMD_START = r"(?:^|[\s;&|(`'\"])"
SCHEDULE_PERSIST_RE = re.compile(
    rf"{_CMD_START}(?:crontab|systemd-run)(?=\s|$)"
    r"|/etc/cron[./]|/var/spool/cron"
    rf"|{_CMD_START}systemctl\s+(?:--user\s+)?(?:enable|start)\b"
    rf"|{_CMD_START}at\s+(?:now\b|-f\b)"
)
# Binaries whose mere execution is the scheduling call, so a path prefix is fine here.
SCHEDULER_BINARIES = frozenset({"crontab", "systemd-run"})

# W14: `git config` writes that arrange code to run on *later* git activity. An install has no
# reason to touch any of these, and they are dormant at install time, so no behavioural rule
# (connect, dropped binary) catches them — the egress fires on the next git use. Found by the
# held-out blind corpus (bc04 git alias, bc10 http.proxy); see docs/WEAKPOINTS.md W14 and
# eval/BLIND_RESULTS.md.
#
# Measured before shipping, exactly like EXEC_SCHEDULED_PERSISTENCE: across all 742 recorded
# installs (142 eval + 100- and 500-package uncurated sweeps), `git config` appears **zero**
# times, dangerous or otherwise. A normal `npm install` never runs it, so this is clean
# separation with 0 false positives, not a guess.
#
# Scope note: this is defence in depth. The *full pipeline* already flags bc04/bc10 (the model
# reads the visible command); this makes the catch deterministic and independent of a model
# draw, and turns bc10 from mergeable needs-review into a block. It does NOT cover bc03 (a
# `.git/hooks/` file write, which needs a Chamber tracing-policy change) — that stays gated.
GIT_CONFIG_PERSIST_RE = re.compile(
    r"\bgit\s+config\b(?:(?!\n).)*?"
    r"(?:http\.proxy|https\.proxy|core\.hookspath|core\.fsmonitor"
    r"|alias\.[\w-]+\s+['\"]?\s*!"  # an alias whose value is a shell command (`!...`)
    r"|url\.[^\s]+\.insteadof)",
    re.I,
)


def _exec_hits(event: ExecEvent) -> list[RuleHit]:
    hits: list[RuleHit] = []
    name = _basename(event.binary)
    args = event.args
    full = f"{event.binary} {args}".strip()  # unclipped: a match can sit past the evidence cap
    cmd = _clip(full)

    def hit(rule_id: str, severity: Severity, why: str) -> None:
        hits.append(
            RuleHit(rule_id, severity, f"{why}: {cmd} (pid {event.pid})", event.ts, event.pid)
        )

    if name in NET_TOOLS:
        hit("EXEC_NET_TOOL", Severity.HIGH, f"network tool {name} executed during install")

    if event.binary.startswith(DROP_DIRS) and not event.binary.startswith(NPM_CACHE_DIR):
        hit("EXEC_DROPPED_BINARY", Severity.HIGH,
            "ran a program from a temp/home directory (dropped at install time)")  # fmt: skip
    elif (
        (script := _script_operand(event))
        and script.startswith(DROP_DIRS)
        and not (script.startswith(NPM_CACHE_DIR))
    ):
        hit("EXEC_DROPPED_BINARY", Severity.HIGH,
            f"{name} ran a script from a temp/home directory ({_clip(script)})")  # fmt: skip

    if DEV_SOCKET_RE.search(args):
        hit("EXEC_INTERACTIVE_SHELL", Severity.CRITICAL, "/dev/tcp or /dev/udp socket redirect")
    elif name in SHELLS and _interactive_shell_flag(_tokens(args)):
        hit("EXEC_INTERACTIVE_SHELL", Severity.CRITICAL, f"interactive shell {name} -i")

    if (BASE64_DECODE_RE.search(args) and PIPE_TO_SHELL_RE.search(args)) or EVAL_DECODED_RE.search(
        args
    ):
        hit("EXEC_DECODE_PIPE", Severity.HIGH, "decoded payload piped into a shell")

    if name in SCHEDULER_BINARIES or SCHEDULE_PERSIST_RE.search(full):
        hit("EXEC_SCHEDULED_PERSISTENCE", Severity.HIGH,
            "registered a scheduled job during install (runs after the install ends)")  # fmt: skip

    if GIT_CONFIG_PERSIST_RE.search(full):
        hit("EXEC_GIT_CONFIG_PERSIST", Severity.HIGH,
            "wrote a git config that runs code or reroutes traffic on later git use")  # fmt: skip

    return hits


# rt08: a bare CPU loop leaves no exec, connect or file trace, only CPU time. Builds are exempt
# when a compiler/build tool ran; anything left would be LOW (a human looks), never a block.
#
# Deliberately OFF, and now for a measured reason rather than caution. With cgroup sampling on
# all 142 eval cases, `rt08-local-miner` used **8.16 s** of CPU and **eight benign packages used
# more**: playwright-chromium 26.0, prisma 25.1, puppeteer 21.3, parcel 13.3, electron 9.7,
# nx 9.6, cypress 9.1, @swc/cli 8.3. Any threshold low enough to catch rt08 flags the most
# popular install-script packages in the ecosystem, and the build-tool exemption does not save
# them (they download prebuilt binaries, they don't invoke a compiler). A threshold near 30 s
# would catch `gm08-cpu-miner` (36.3 s) with nothing benign above it, but the model already
# catches gm08 because it forks a detached worker — so the rule would buy nothing there either.
#
# Conclusion: CPU time alone cannot close the rt08 gap at an acceptable false-review cost. Any
# future attempt needs a second signal (process ancestry, lifetime, no-op syscall profile), not
# a bigger number. `cpu_s` is still recorded for every run, so this can be re-tested cheaply.
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
