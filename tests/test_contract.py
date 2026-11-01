from pathlib import Path

import pytest
from pydantic import ValidationError

from shared import signing
from shared.contract import MAX_CONNECT_EVENTS, DetonateRequest, DetonateResult

FIXTURES = Path(__file__).parent / "fixtures"


def load_e4() -> DetonateResult:
    return DetonateResult.model_validate_json((FIXTURES / "detonate_result_e4.json").read_text())


def test_result_fixture_round_trips():
    result = load_e4()
    assert DetonateResult.model_validate_json(result.model_dump_json()) == result


def test_request_defaults():
    req = DetonateRequest(job_id="j", clone_url="https://x/y.git", head_sha="abc")
    assert req.command == ["npm", "install", "--no-audit", "--no-fund"]
    assert req.timeout_s == 180
    assert req.clone_token is None


def test_event_caps_enforced():
    result = load_e4()
    data = result.model_dump()
    data["connect_events"] = [data["connect_events"][0]] * (MAX_CONNECT_EVENTS + 1)
    with pytest.raises(ValidationError):
        DetonateResult.model_validate(data)


def test_tail_cap_enforced():
    data = load_e4().model_dump()
    data["stdout_tail"] = "x" * 4001
    with pytest.raises(ValidationError):
        DetonateResult.model_validate(data)


def test_signing_round_trip():
    body = b'{"job_id":"j"}'
    headers = signing.signed_headers("s3cret", body, now=1_000_000)
    ts, sig = headers[signing.TIMESTAMP_HEADER], headers[signing.SIGNATURE_HEADER]
    assert signing.verify("s3cret", ts, sig, body, now=1_000_100)


def test_signing_rejects_tamper_wrong_secret_and_stale():
    body = b'{"job_id":"j"}'
    headers = signing.signed_headers("s3cret", body, now=1_000_000)
    ts, sig = headers[signing.TIMESTAMP_HEADER], headers[signing.SIGNATURE_HEADER]
    assert not signing.verify("s3cret", ts, sig, body + b" ", now=1_000_000)
    assert not signing.verify("other", ts, sig, body, now=1_000_000)
    assert not signing.verify("s3cret", ts, sig, body, now=1_000_000 + 301)
    assert not signing.verify("s3cret", "nope", sig, body, now=1_000_000)
    assert not signing.verify("s3cret", None, sig, body, now=1_000_000)
