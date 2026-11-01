from pathlib import Path

from brain.rules import Severity, evaluate
from chamber.egress import parse_kernel_log
from shared.contract import DetonateResult

FIXTURE = Path(__file__).parent / "fixtures/kernel_nontcp.log"  # real line from the Chamber
SANDBOX = "10.250.0.10"
REAL = FIXTURE.read_text().splitlines()
# Same shape for ICMP (no ports) and a public-resolver DNS bypass.
ICMP = REAL[0].replace("PROTO=UDP SPT=43303 DPT=9999 LEN=18", "PROTO=ICMP TYPE=8 CODE=0 ID=7 SEQ=1")
DNS = REAL[0].replace("DST=203.0.113.10", "DST=8.8.8.8").replace("DPT=9999", "DPT=53")


def test_real_udp_line_parsed():
    [e] = parse_kernel_log(REAL, SANDBOX, 10)
    assert (e.protocol, e.daddr, e.dport, e.pid, e.binary) == ("udp", "203.0.113.10", 9999, 0, "")
    assert e.ts.startswith("2026-11-01T16:36:46")


def test_icmp_and_dns_bypass_parsed_and_deduplicated():
    events = parse_kernel_log([*REAL, ICMP, DNS, *REAL], SANDBOX, 10)
    assert [(e.protocol, e.daddr, e.dport) for e in events] == [
        ("udp", "203.0.113.10", 9999),
        ("icmp", "203.0.113.10", 0),
        ("udp", "8.8.8.8", 53),
    ]


def test_other_sources_and_noise_ignored_and_capped():
    other = REAL[0].replace("SRC=10.250.0.10", "SRC=10.250.0.11")
    assert parse_kernel_log([other, "kernel: unrelated", ""], SANDBOX, 10) == []
    assert len(parse_kernel_log([REAL[0], ICMP, DNS], SANDBOX, 2)) == 2


def test_non_tcp_egress_is_high_and_only_that_rule():
    res = DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                         exec_events=[], connect_events=parse_kernel_log(REAL, SANDBOX, 10),
                         dns_queries=[], stdout_tail="", stderr_tail="")  # fmt: skip
    hits = evaluate(res)
    assert [(h.rule_id, h.severity) for h in hits] == [("NET_NON_TCP_EGRESS", Severity.HIGH)]
    assert "UDP packet to 203.0.113.10:9999" in hits[0].evidence
