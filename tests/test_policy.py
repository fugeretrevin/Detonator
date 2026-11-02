from brain.llm import LlmOutcome
from brain.pipeline import analyze, detonate_request
from brain.policy import DEFAULT_TIMEOUT_S, MAX_ALLOWED_DOMAINS, Policy, parse_policy
from shared.contract import ConnectEvent, DetonateResult
from tests.test_intent import meta
from tests.test_pipeline import event


def result(domain="cdn.corp.example") -> DetonateResult:
    conn = ConnectEvent(ts="t", pid=1, binary="/usr/local/bin/node", daddr="93.1.1.1",
                        dport=443, family="AF_INET", resolved_domain=domain)  # fmt: skip
    return DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                          exec_events=[], connect_events=[conn], dns_queries=[],
                          stdout_tail="", stderr_tail="")  # fmt: skip


def no_llm(*a, **k):
    return LlmOutcome("m", error="x")


# --- parsing ---


def test_valid_policy_parsed():
    p = parse_policy("allowed_domains:\n  - cdn.corp.example\nneeds_review: block\ntimeout_s: 60")
    assert p.allowed_domains == ("cdn.corp.example",)
    assert p.blocks_needs_review and p.timeout_s == 60 and p.warnings == []


def test_missing_or_empty_policy_is_defaults():
    for text in (None, "", "   \n"):
        p = parse_policy(text)
        assert p == Policy()  # no source, no warnings, defaults


def test_malformed_yaml_and_non_mapping_fall_back_with_a_warning():
    assert parse_policy("allowed_domains: [unclosed").warnings
    assert parse_policy("just a string").warnings
    assert parse_policy("just a string").allowed_domains == ()


def test_invalid_values_are_ignored_not_obeyed():
    p = parse_policy(
        "allowed_domains:\n  - 'not a host'\n  - 203.0.113.10\n  - '*.wild.example'\n"
        "  - ok.example.com\nneeds_review: maybe\ntimeout_s: 9999\nsurprise: 1"
    )
    assert p.allowed_domains == ("ok.example.com",)  # raw IP and wildcard rejected
    assert not p.blocks_needs_review  # bad enum -> default 'pass'
    assert p.timeout_s == DEFAULT_TIMEOUT_S  # out of range -> default
    assert any("unknown keys" in w for w in p.warnings)


def test_allowed_domains_capped():
    many = "allowed_domains:\n" + "\n".join(f"  - h{i}.example.com" for i in range(80))
    p = parse_policy(many)
    assert len(p.allowed_domains) == MAX_ALLOWED_DOMAINS


def test_timeout_bool_rejected():
    assert parse_policy("timeout_s: true").timeout_s == DEFAULT_TIMEOUT_S


# --- effect on the verdict ---


def test_allowed_domain_silences_only_the_low_unlisted_finding():
    without = analyze(result(), meta(), "", no_llm, job_id="j", enrich=lambda r: r)
    assert without.final.title == "Needs review"
    policy = parse_policy("allowed_domains:\n  - cdn.corp.example")
    with_policy = analyze(result(), meta(), "", no_llm, job_id="j", enrich=lambda r: r,
                          policy=policy)  # fmt: skip
    assert with_policy.final.title == "Clean"


def test_policy_cannot_silence_a_high_finding():
    raw_ip = result(domain=None)  # NET_RAW_IP, high
    policy = parse_policy("allowed_domains:\n  - cdn.corp.example")
    out = analyze(raw_ip, meta(), "", no_llm, job_id="j", enrich=lambda r: r, policy=policy)
    assert out.final.title == "Blocked"


def test_needs_review_block_makes_a_warning_fail_the_check():
    policy = parse_policy("needs_review: block")
    out = analyze(result(), meta(), "", no_llm, job_id="j", enrich=lambda r: r, policy=policy)
    assert out.final.title == "Needs review" and out.final.conclusion == "failure"
    assert "not mergeable here" in out.report


def test_needs_review_block_does_not_touch_a_clean_verdict():
    clean = DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                           exec_events=[], connect_events=[], dns_queries=[], stdout_tail="",
                           stderr_tail="")  # fmt: skip
    out = analyze(clean, meta(), "", no_llm, job_id="j", enrich=lambda r: r,
                  policy=parse_policy("needs_review: block"))  # fmt: skip
    assert out.final.conclusion == "success"


def test_policy_timeout_reaches_the_detonate_request():
    req = detonate_request(event(private=False), "job-1", timeout_s=60)
    assert req.timeout_s == 60
    assert detonate_request(event(private=False), "job-1").timeout_s == DEFAULT_TIMEOUT_S
