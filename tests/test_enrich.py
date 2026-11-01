import time

from brain.enrich import enrich_connects
from brain.rules import evaluate
from shared.contract import ConnectEvent, DetonateResult

ALLOWED = ("registry.npmjs.org", "github.com")


def result(*addrs: str, domain: str | None = None) -> DetonateResult:
    return DetonateResult(
        job_id="t",
        status="completed",
        exit_code=0,
        duration_s=1.0,
        exec_events=[],
        connect_events=[
            ConnectEvent(
                ts="t",
                pid=1,
                binary="/usr/local/bin/node",
                daddr=a,
                dport=443,
                family="AF_INET",
                resolved_domain=domain,
            )
            for a in addrs
        ],
        dns_queries=[],
        stdout_tail="",
        stderr_tail="",
    )


def fake_dns(forward_map: dict[str, set[str]], reverse_map: dict[str, str]):
    return (lambda name: forward_map.get(name, set()), lambda ip: reverse_map.get(ip))


def domains(res: DetonateResult) -> list[str | None]:
    return [e.resolved_domain for e in res.connect_events]


def test_allowlisted_domain_ips_map_by_forward_resolution():
    fwd, rev = fake_dns({"registry.npmjs.org": {"104.16.24.34"}}, {})
    out = enrich_connects(result("104.16.24.34"), ALLOWED, forward=fwd, reverse=rev)
    assert domains(out) == ["registry.npmjs.org"]
    assert evaluate(out, ALLOWED) == []


def test_forward_confirmed_ptr_is_kept():
    fwd, rev = fake_dns(
        {"lb-140-82-112-3-iad.github.com": {"140.82.112.3"}},
        {"140.82.112.3": "lb-140-82-112-3-iad.github.com."},
    )
    out = enrich_connects(result("140.82.112.3"), ALLOWED, forward=fwd, reverse=rev)
    assert domains(out) == ["rdns:lb-140-82-112-3-iad.github.com"]
    assert evaluate(out, ALLOWED) == []


def test_spoofed_ptr_is_rejected_and_raw_ip_still_fires():
    # Attacker sets the PTR for their IP to an allowlisted name; the name doesn't resolve back.
    fwd, rev = fake_dns(
        {"registry.npmjs.org": {"104.16.24.34"}}, {"203.0.113.10": "registry.npmjs.org"}
    )
    out = enrich_connects(result("203.0.113.10"), ALLOWED, forward=fwd, reverse=rev)
    assert domains(out) == [None]
    assert [h.rule_id for h in evaluate(out, ALLOWED)] == ["NET_RAW_IP"]


def test_no_ptr_stays_none():
    fwd, rev = fake_dns({}, {})
    out = enrich_connects(result("203.0.113.10"), ALLOWED, forward=fwd, reverse=rev)
    assert domains(out) == [None]


def test_existing_domains_and_internal_ips_untouched():
    calls = []

    def fwd(name):
        calls.append(name)
        return set()

    out = enrich_connects(result("10.0.0.1"), ALLOWED, forward=fwd, reverse=lambda ip: "x")
    assert domains(out) == [None] and calls == []

    res = result("203.0.113.10", domain="already.example")
    assert enrich_connects(res, ALLOWED, forward=fwd, reverse=lambda ip: "x") is res


def test_hung_lookup_does_not_block(monkeypatch):
    monkeypatch.setattr("brain.enrich.LOOKUP_TIMEOUT_S", 0.2)

    def slow_reverse(ip):
        time.sleep(3)
        return "late.example"

    start = time.monotonic()
    out = enrich_connects(
        result("203.0.113.10"), ALLOWED, forward=lambda n: set(), reverse=slow_reverse
    )
    assert time.monotonic() - start < 1.5
    assert domains(out) == [None]
