import json

import httpx

from brain.investigator import Investigation, _host_info, _registry_info, investigate
from brain.llm import LlmClient, LlmOutcome
from brain.pipeline import analyze
from brain.rules import RuleHit, Severity
from shared.contract import ConnectEvent, DetonateResult, ExecutedScript
from tests.conftest import NPM_EXEC
from tests.test_intent import meta

LOW = RuleHit("NET_UNLISTED_DOMAIN", Severity.LOW, "node connected to cdn.example", "t", 1,
              target="cdn.example")  # fmt: skip


def result(scripts=()) -> DetonateResult:
    conn = ConnectEvent(ts="t", pid=1, binary="/usr/local/bin/node", daddr="93.1.1.1",
                        dport=443, family="AF_INET", resolved_domain="cdn.example")  # fmt: skip
    return DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                          exec_events=[NPM_EXEC], connect_events=[conn], dns_queries=[],
                          stdout_tail="", stderr_tail="",
                          executed_scripts=list(scripts))  # fmt: skip


def client(handler) -> LlmClient:
    http = httpx.Client(base_url="https://api.test", transport=httpx.MockTransport(handler))
    return LlmClient("k", model="muse-spark-1.3", http=http, attempts=1)


def reply(message: dict) -> httpx.Response:
    usage = {"prompt_tokens": 10, "completion_tokens": 5}
    return httpx.Response(200, json={"choices": [{"message": message}], "usage": usage})


def triage(risk: str, note="n", facts=("f",)) -> dict:
    return {"content": json.dumps({"risk": risk, "note": note, "facts": list(facts)})}


# --- tools ---


def test_host_info_classifies_our_own_lists():
    assert _host_info("registry.npmjs.org")["allowlisted_registry_or_github"]
    assert _host_info("storage.googleapis.com")["shared_hosting_suffix"] == "storage.googleapis.com"
    assert "request catcher" in _host_info("webhook.site")["known_exfil_service"]
    assert _host_info("binaries.prisma.sh")["known_package_cdn"]


def test_registry_info_reports_age_maintainers_and_install_hooks():
    doc = {
        "dist-tags": {"latest": "2.0.0"},
        "time": {"created": "2020-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
                 "1.0.0": "2020-01-01T00:00:00.000Z", "2.0.0": "2026-01-01T00:00:00.000Z"},
        "versions": {
            "1.0.0": {"maintainers": [{"name": "alice"}]},
            "2.0.0": {"maintainers": [{"name": "bob"}], "scripts": {"postinstall": "node x"}},
        },
    }  # fmt: skip
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=doc)))
    info = _registry_info("pkg", http)
    assert info["maintainers_changed"] and info["maintainers_previous"] == ["alice"]
    assert info["declares_install_scripts"] == ["postinstall"]
    assert info["first_published_days_ago"] > 2000


def test_registry_info_404_reports_nonexistent():
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    assert _registry_info("nope", http) == {"name": "nope", "exists": False}


# --- the loop ---


def test_tool_loop_runs_tools_then_returns_triage():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        if len(calls) == 1:
            return reply({"tool_calls": [{"id": "1", "type": "function", "function": {
                "name": "host_info", "arguments": '{"host": "cdn.example"}'}}]})  # fmt: skip
        return reply(triage("benign", note="vendor CDN, nothing new"))

    inv = investigate(client(handler), [LOW], result())
    assert inv.risk == "benign" and inv.level == Severity.NONE
    assert len(inv.tool_log) == 1 and inv.tool_log[0][0].startswith("host_info(")
    # the tool result was fed back as a tool-role message
    assert any(m.get("role") == "tool" for m in calls[1]["messages"])


def test_malicious_triage_escalates_suspicious_does_not():
    assert investigate(client(lambda r: reply(triage("malicious"))), [LOW], result()).level == (
        Severity.HIGH
    )
    assert investigate(client(lambda r: reply(triage("suspicious"))), [LOW], result()).level == (
        Severity.LOW
    )


def test_tool_call_budget_is_capped():
    def handler(request):  # always asks for another tool call
        return reply({"tool_calls": [{"id": "x", "type": "function", "function": {
            "name": "host_info", "arguments": '{"host": "a.example"}'}}]})  # fmt: skip

    inv = investigate(client(handler), [LOW], result(), max_calls=3)
    assert len(inv.tool_log) == 3


def test_model_failure_leaves_no_risk():
    inv = investigate(client(lambda r: httpx.Response(503)), [LOW], result())
    assert inv.risk is None and inv.level == Severity.NONE and inv.error == "HTTP 503"


def test_executed_script_tool_returns_captured_content():
    script = ExecutedScript(path="/work/node_modules/p/install.js", package="p", sha256="a" * 64,
                            content="require('net').connect(4444)")  # fmt: skip

    def handler(request):
        body = json.loads(request.content)
        if not any(m.get("role") == "tool" for m in body["messages"]):
            return reply({"tool_calls": [{"id": "1", "type": "function", "function": {
                "name": "get_executed_script",
                "arguments": '{"path": "node_modules/p/install.js"}'}}]})  # fmt: skip
        return reply(triage("malicious"))

    inv = investigate(client(handler), [LOW], result([script]))
    assert "connect" in inv.tool_log[0][1] and inv.risk == "malicious"


# --- pipeline wiring: only ⚠️, escalate-only ---


def no_llm(*a, **k):
    return LlmOutcome("m", error="x")


def test_investigator_runs_only_for_needs_review_and_can_escalate():
    seen = []

    def spy(hits, res):
        seen.append(hits)
        return Investigation("m", risk="malicious", note="bad")

    low_res = result()  # one unlisted domain -> LOW -> Needs review
    out = analyze(low_res, meta(), "", no_llm, job_id="j", enrich=lambda r: r, investigator=spy)
    assert len(seen) == 1 and out.final.title == "Blocked"  # escalated
    assert out.investigation.risk == "malicious" and "Triage" in out.report


def test_investigator_never_lowers_a_verdict():
    def benign_triage(hits, res):
        return Investigation("m", risk="benign", note="fine")

    out = analyze(result(), meta(), "", no_llm, job_id="j", enrich=lambda r: r,
                  investigator=benign_triage)  # fmt: skip
    assert out.final.title == "Needs review"  # still LOW: benign triage cannot clear it


def test_investigator_skipped_when_nothing_to_triage():
    clean = DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                           exec_events=[NPM_EXEC], connect_events=[], dns_queries=[],
                           stdout_tail="", stderr_tail="")  # fmt: skip
    seen = []
    analyze(clean, meta(), "", no_llm, job_id="j", enrich=lambda r: r,
            investigator=lambda h, r: seen.append(1))  # fmt: skip
    assert seen == []
