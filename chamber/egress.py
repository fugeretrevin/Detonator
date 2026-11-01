"""Non-TCP egress attempts from the sandbox, from the kernel firewall log.

Tetragon traces TCP connects only. Every other protocol leaving det0 (UDP to anything but
our resolver, ICMP, …) hits a LOG + REJECT pair in iptables.sh, so nothing gets out and each
attempt is recorded. Format verified on the Chamber (tests/fixtures/kernel_nontcp.log):
`DETONATOR-NONTCP IN=det0 OUT=ens5 … SRC=10.250.0.10 DST=203.0.113.10 … PROTO=UDP SPT=… DPT=9999`.
Attribution is by the sandbox's fixed IP (one job at a time), like the DNS log.
"""

import re
import subprocess
from collections.abc import Iterable

from shared.contract import ConnectEvent

LOG_PREFIX = "DETONATOR-NONTCP"
_LINE_RE = re.compile(
    r"^(?P<ts>\S+) .*"
    + LOG_PREFIX
    + r" .*\bSRC=(?P<src>\S+) DST=(?P<dst>\S+) .*\bPROTO=(?P<proto>\S+)"
    r"(?:.*\bDPT=(?P<dport>\d+))?"
)


def parse_kernel_log(lines: Iterable[str], sandbox_ip: str, limit: int) -> list[ConnectEvent]:
    events: list[ConnectEvent] = []
    seen: set[tuple[str, str, int]] = set()
    for line in lines:
        m = _LINE_RE.match(line.strip())
        if not m or m["src"] != sandbox_ip:
            continue
        proto, dport = m["proto"].lower(), int(m["dport"] or 0)
        key = (proto, m["dst"], dport)
        if key in seen:
            continue
        seen.add(key)
        if len(events) >= limit:
            break
        events.append(
            ConnectEvent(
                ts=m["ts"],
                pid=0,
                binary="",
                daddr=m["dst"],
                dport=dport,
                family="AF_INET",
                resolved_domain=None,
                protocol=proto,
            )  # fmt: skip
        )
    return events


def read_kernel_log(since_epoch: float, until_epoch: float) -> list[str]:
    """Kernel log lines for the run window (journald). Empty on any failure."""
    try:
        out = subprocess.run(
            ["journalctl", "-k", "-o", "short-iso", "--no-pager", "-g", LOG_PREFIX,
             "--since", f"@{int(since_epoch)}", "--until", f"@{int(until_epoch) + 1}"],
            capture_output=True, text=True, timeout=15,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return []
    return out.stdout.splitlines()
