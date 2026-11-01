from pathlib import Path

from chamber.dns import MAX_ANSWERS_PER_DOMAIN, name_connects, parse_dns_log
from shared.contract import MAX_DNS_QUERIES, ConnectEvent

FIXTURE = Path(__file__).parent / "fixtures/dnsmasq_probe.log"
SANDBOX = "10.250.0.10"


def lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def parsed():
    return parse_dns_log(lines(), SANDBOX, year=2026)


def connect(daddr: str, domain: str | None = None) -> ConnectEvent:
    return ConnectEvent(ts="t", pid=1, binary="/usr/local/bin/node", daddr=daddr, dport=443,
                        family="AF_INET", resolved_domain=domain)  # fmt: skip


def test_fixture_queries_merge_a_and_aaaa():
    queries = parsed().queries
    assert [q.domain for q in queries] == [
        "registry.npmjs.org",
        "storage.googleapis.com",
        "nonexistent-zz9.example",
        "www.github.com",
        "abc.oast.fun",  # sinkholed (second probe, appended)
    ]
    npm = queries[0]
    assert npm.ts == "2026-11-01T13:53:26Z"
    assert "104.16.2.34" in npm.answers and "2606:4700::6810:822" in npm.answers
    assert len(npm.answers) == 14


def test_nxdomain_is_recorded_without_answers():
    nx = next(q for q in parsed().queries if q.domain == "nonexistent-zz9.example")
    assert nx.answers == []


def test_cname_answers_belong_to_the_name_that_was_asked():
    # www.github.com CNAMEs to github.com; the process asked for www.github.com.
    www = next(q for q in parsed().queries if q.domain == "www.github.com")
    assert www.answers == ["140.82.114.4"]
    assert "github.com" not in {q.domain for q in parsed().queries}


def test_other_clients_ignored():
    other = "Nov  1 13:53:26 dnsmasq[1]: 99 10.250.0.11/5000 query[A] evil.example from 10.250.0.11"
    assert parse_dns_log([other], SANDBOX).queries == []


def test_reply_for_unknown_serial_ignored():
    stray = "Nov  1 13:53:26 dnsmasq[1]: 99 10.250.0.10/5000 reply x.example is 203.0.113.10"
    assert parse_dns_log([stray], SANDBOX).queries == []


def test_connects_named_from_the_sandbox_lookups():
    named = name_connects(
        [connect("104.16.2.34"), connect("172.253.122.207"), connect("203.0.113.10")], parsed()
    )
    assert [c.resolved_domain for c in named] == [
        "registry.npmjs.org",
        "storage.googleapis.com",
        None,  # no lookup returned this IP: stays a raw-IP connect
    ]


def test_ipv6_connect_matched_after_normalization():
    named = name_connects([connect("2606:4700:0:0:0:0:6810:822")], parsed())
    assert named[0].resolved_domain == "registry.npmjs.org"


def test_existing_names_kept():
    assert name_connects([connect("104.16.2.34", "x")], parsed())[0].resolved_domain == "x"


def _query(i: int, serial: int | None = None) -> list[str]:
    s = serial if serial is not None else i
    return [
        f"Nov  1 13:53:26 dnsmasq[1]: {s} {SANDBOX}/1 query[A] h{i}.example from {SANDBOX}",
        f"Nov  1 13:53:26 dnsmasq[1]: {s} {SANDBOX}/1 reply h{i}.example is 198.51.100.{i % 250}",
    ]


def test_query_cap_sets_truncated():
    log = [line for i in range(MAX_DNS_QUERIES + 5) for line in _query(i)]
    result = parse_dns_log(log, SANDBOX)
    assert len(result.queries) == MAX_DNS_QUERIES and result.truncated


def test_repeat_lookups_do_not_count_against_the_cap():
    log = [line for _ in range(MAX_DNS_QUERIES + 5) for line in _query(1)]
    result = parse_dns_log(log, SANDBOX)
    assert len(result.queries) == 1 and not result.truncated


def test_answers_per_domain_capped():
    head = f"Nov  1 13:53:26 dnsmasq[1]: 1 {SANDBOX}/1 query[A] big.example from {SANDBOX}"
    replies = [
        f"Nov  1 13:53:26 dnsmasq[1]: 1 {SANDBOX}/1 reply big.example is 198.51.100.{i}"
        for i in range(100)
    ]
    assert len(parse_dns_log([head, *replies], SANDBOX).queries[0].answers) == (
        MAX_ANSWERS_PER_DOMAIN
    )


def test_sinkholed_answer_is_recorded():
    # dnsmasq logs locally answered (sinkhole) lookups as `config`, not `reply`.
    oast = next(q for q in parsed().queries if q.domain == "abc.oast.fun")
    assert oast.answers == ["198.51.100.66"]
