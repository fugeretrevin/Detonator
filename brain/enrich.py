"""Fill ConnectEvent.resolved_domain without a DNS log (solo-mode replacement for dnsmasq, B4).

1. Forward-resolve allowlisted domains: their IPs map straight to the domain.
2. Otherwise reverse-resolve the IP, but only keep the name if it is forward-confirmed
   (the name resolves back to the same IP). An attacker controls the PTR record for their
   own IP and could otherwise claim to be registry.npmjs.org.
Unresolvable or unconfirmed IPs stay None, which is what NET_RAW_IP keys on.
"""

import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait

from brain.rules import DEFAULT_ALLOWED_DOMAINS, RDNS_PREFIX, is_external
from shared.contract import DetonateResult

MAX_LOOKUPS = 50
LOOKUP_TIMEOUT_S = 5.0

ForwardResolver = Callable[[str], set[str]]
ReverseResolver = Callable[[str], str | None]


def forward_resolve(name: str) -> set[str]:
    try:
        return {info[4][0] for info in socket.getaddrinfo(name, None)}
    except OSError:
        return set()


def reverse_resolve(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def _confirmed_ptr(ip: str, forward: ForwardResolver, reverse: ReverseResolver) -> str | None:
    name = (reverse(ip) or "").rstrip(".").lower()
    if name and ip in forward(name):
        return f"{RDNS_PREFIX}{name}"
    return None


def enrich_connects(
    result: DetonateResult,
    allowed_domains: tuple[str, ...] = DEFAULT_ALLOWED_DOMAINS,
    *,
    forward: ForwardResolver = forward_resolve,
    reverse: ReverseResolver = reverse_resolve,
) -> DetonateResult:
    pending = sorted(
        {
            e.daddr
            for e in result.connect_events
            if e.resolved_domain is None and is_external(e.daddr)
        }
    )
    if not pending:
        return result

    known: dict[str, str] = {}
    # No `with`: its exit joins all threads, and a hung lookup would block the job.
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        futures = {pool.submit(forward, d): d for d in allowed_domains}
        done, _ = wait(futures, timeout=LOOKUP_TIMEOUT_S)
        for fut in done:
            for ip in fut.result():
                known.setdefault(ip, futures[fut])

        unknown = [ip for ip in pending if ip not in known][:MAX_LOOKUPS]
        futures = {pool.submit(_confirmed_ptr, ip, forward, reverse): ip for ip in unknown}
        done, _ = wait(futures, timeout=LOOKUP_TIMEOUT_S)
        for fut in done:
            if name := fut.result():
                known[futures[fut]] = name
    finally:
        # Lookups still running past the timeout are abandoned; those IPs stay None.
        pool.shutdown(wait=False, cancel_futures=True)

    events = [
        e.model_copy(update={"resolved_domain": known.get(e.daddr)})
        if e.resolved_domain is None
        else e
        for e in result.connect_events
    ]
    return result.model_copy(update={"connect_events": events})
