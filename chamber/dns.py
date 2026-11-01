"""dnsmasq query log -> contract DNS records for one sandbox (BUILD_PLAN B4).

Format verified on the Chamber (tests/fixtures/dnsmasq_probe.log, dnsmasq 2.92 with
log-queries=extra): every line of one lookup shares a serial number, and a CNAME chain is
logged as `reply <asked> is <CNAME>` followed by the target's answers under that serial.
Answers are attributed to the name the process *asked for*, so an attacker's domain that
CNAMEs to a trusted host is still reported under the attacker's name.
"""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from shared.contract import MAX_DNS_QUERIES, ConnectEvent, DnsQuery

MAX_ANSWERS_PER_DOMAIN = 32

LINE_RE = re.compile(
    r"^(?P<ts>\w{3} +\d{1,2} \d\d:\d\d:\d\d) dnsmasq\[\d+\]: (?P<serial>\d+) "
    r"(?P<client>[0-9a-fA-F.:]+)/\d+ (?:query\[\w+\] (?P<qname>\S+) from \S+"
    r"|(?:reply|config) \S+ is (?P<answer>\S+))$"  # config: answered locally (sinkhole)
)


@dataclass
class ParsedDns:
    queries: list[DnsQuery]
    truncated: bool

    def ip_to_domain(self) -> dict[str, str]:
        """First domain whose answers contained the IP wins."""
        names: dict[str, str] = {}
        for q in self.queries:
            for ip in q.answers:
                names.setdefault(ip, q.domain)
        return names


def _ip(text: str) -> str | None:
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return None  # <CNAME>, NXDOMAIN, NODATA-IPv6, ...


def _iso(ts: str, year: int) -> str:
    # dnsmasq logs syslog-style local time with no year; the Chamber unit runs it with TZ=UTC.
    parsed = datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
    return parsed.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


def parse_dns_log(lines: Iterable[str], client_ip: str, year: int | None = None) -> ParsedDns:
    year = year or datetime.now(UTC).year
    by_serial: dict[str, str] = {}  # lookup serial -> asked name
    found: dict[str, DnsQuery] = {}  # one record per asked name, A and AAAA merged
    truncated = False

    for line in lines:
        m = LINE_RE.match(line.strip())
        if not m or m["client"] != client_ip:
            continue
        if m["qname"]:
            domain = m["qname"].rstrip(".").lower()
            by_serial[m["serial"]] = domain
            if domain not in found:
                if len(found) >= MAX_DNS_QUERIES:
                    truncated = True
                    continue
                found[domain] = DnsQuery(ts=_iso(m["ts"], year), domain=domain, answers=[])
            continue
        domain = by_serial.get(m["serial"])
        ip = _ip(m["answer"])
        record = found.get(domain or "")
        if ip and record and ip not in record.answers:
            if len(record.answers) < MAX_ANSWERS_PER_DOMAIN:
                record.answers.append(ip)

    return ParsedDns(list(found.values()), truncated)


def name_connects(connects: list[ConnectEvent], dns: ParsedDns) -> list[ConnectEvent]:
    """Set resolved_domain from the sandbox's own lookups; None still means no lookup seen."""
    names = dns.ip_to_domain()
    return [
        c.model_copy(update={"resolved_domain": names.get(_ip(c.daddr) or c.daddr)})
        if c.resolved_domain is None
        else c
        for c in connects
    ]
