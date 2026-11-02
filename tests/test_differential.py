from brain.differential import diff
from brain.rules import RuleHit, Severity, evaluate
from shared.contract import ConnectEvent, DetonateResult


def result(connects=(), status="completed") -> DetonateResult:
    return DetonateResult(job_id="j", status=status, exit_code=0, duration_s=1,
                          exec_events=[], connect_events=list(connects), dns_queries=[],
                          stdout_tail="", stderr_tail="")  # fmt: skip


def conn(daddr, domain=None, dport=443, proto="tcp") -> ConnectEvent:
    return ConnectEvent(ts="t", pid=1, binary="/usr/local/bin/node", daddr=daddr, dport=dport,
                        family="AF_INET", resolved_domain=domain, protocol=proto)  # fmt: skip


def low(rule, target) -> RuleHit:
    return RuleHit(rule, Severity.LOW, "e", "t", 1, target=target)


def high(rule, target) -> RuleHit:
    return RuleHit(rule, Severity.HIGH, "e", "t", 1, target=target)


def test_low_finding_present_on_base_is_suppressed():
    head_hits = [low("NET_UNLISTED_DOMAIN", "cdn.example")]
    base = result([conn("93.1.1.1", "cdn.example")])  # base also hit cdn.example (low)
    base_hits = evaluate(base)
    kept, d = diff(head_hits, base_hits, result([conn("93.1.1.1", "cdn.example")]), base)
    assert kept == [] and [h.target for h in d.pre_existing] == ["cdn.example"]


def test_high_finding_is_never_suppressed_even_if_on_base():
    head_hits = [high("NET_RAW_IP", "203.0.113.10")]
    base = result([conn("203.0.113.10")])
    kept, d = diff(head_hits, evaluate(base), result([conn("203.0.113.10")]), base)
    assert [h.rule_id for h in kept] == ["NET_RAW_IP"] and d.pre_existing == []


def test_new_low_finding_not_on_base_is_kept():
    head_hits = [low("NET_UNLISTED_DOMAIN", "new.example")]
    base = result([conn("93.1.1.1", "old.example")])
    kept, d = diff(head_hits, evaluate(base), result([conn("93.2.2.2", "new.example")]), base)
    assert [h.target for h in kept] == ["new.example"]


def test_new_behaviors_lists_only_what_the_head_added():
    head = result([conn("203.0.113.10", dport=4444), conn("104.1.1.1", "registry.npmjs.org")])
    base = result([conn("104.1.1.1", "registry.npmjs.org")])
    _, d = diff([], evaluate(base), head, base)
    assert d.new_behaviors == ["tcp:203.0.113.10:4444"]


def test_nothing_suppressed_when_base_did_not_complete():
    head_hits = [low("NET_UNLISTED_DOMAIN", "cdn.example")]
    base = result([conn("93.1.1.1", "cdn.example")], status="timeout")
    kept, d = diff(head_hits, evaluate(base), result(), base)
    assert kept == head_hits and d.new_behaviors == [] and "timeout" in d.base_status
