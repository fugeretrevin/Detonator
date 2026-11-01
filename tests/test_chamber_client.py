import time
from pathlib import Path

import httpx
import pytest

from brain.chamber_client import ChamberIntegrityError, HttpChamberClient, MockChamberClient
from shared import signing
from shared.contract import DetonateRequest, DetonateResult

FIXTURES = Path(__file__).parent / "fixtures"
REQ = DetonateRequest(job_id="job-1", clone_url="https://x/y.git", head_sha="abc")


def test_mock_returns_fixture_with_job_id():
    result = MockChamberClient(FIXTURES / "detonate_result_e4.json").detonate(REQ)
    assert result.job_id == "job-1"
    assert any(e.resolved_domain is None for e in result.connect_events)


SECRET = "chamber-secret"


def result_body(job_id: str = "job-1") -> bytes:
    result = DetonateResult.model_validate_json((FIXTURES / "detonate_result_e4.json").read_text())
    return result.model_copy(update={"job_id": job_id}).model_dump_json().encode()


def signed_response(body: bytes, job_id: str = "job-1", now: int | None = None) -> httpx.Response:
    return httpx.Response(200, content=body,
                          headers=signing.response_headers(SECRET, job_id, body, now))  # fmt: skip


def client_returning(response: httpx.Response) -> HttpChamberClient:
    http = httpx.Client(base_url="http://chamber.test",
                        transport=httpx.MockTransport(lambda r: response))  # fmt: skip
    return HttpChamberClient("http://chamber.test", SECRET, http=http)


def test_signed_response_for_this_job_is_accepted():
    assert client_returning(signed_response(result_body())).detonate(REQ).job_id == "job-1"


def test_tampered_body_fails_closed():
    good = signed_response(result_body())
    clean = result_body().replace(b'"203.0.113.10"', b'"104.16.1.34"')  # rewrite the evidence
    tampered = httpx.Response(200, content=clean, headers=good.headers)
    with pytest.raises(ChamberIntegrityError):
        client_returning(tampered).detonate(REQ)


def test_replayed_response_from_another_job_fails_closed():
    old_clean = signed_response(result_body("job-0"), job_id="job-0")  # validly signed, old job
    with pytest.raises(ChamberIntegrityError):
        client_returning(old_clean).detonate(REQ)


def test_stale_response_fails_closed():
    stale = signed_response(result_body(), now=int(time.time()) - 301)
    with pytest.raises(ChamberIntegrityError):
        client_returning(stale).detonate(REQ)


def test_unsigned_response_fails_closed():
    with pytest.raises(ChamberIntegrityError):
        client_returning(httpx.Response(200, content=result_body())).detonate(REQ)


def test_signature_for_this_job_but_body_for_another_fails_closed():
    mixed = signed_response(result_body("job-0"), job_id="job-1")
    with pytest.raises(ChamberIntegrityError):
        client_returning(mixed).detonate(REQ)


def test_http_client_signs_and_retries_on_409():
    fixture = result_body()
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        assert signing.verify(
            "chamber-secret",
            request.headers[signing.TIMESTAMP_HEADER],
            request.headers[signing.SIGNATURE_HEADER],
            request.content,
        )
        if len(attempts) == 1:
            return httpx.Response(409, json={"detail": "busy"})
        return signed_response(fixture)

    http = httpx.Client(base_url="http://chamber.test", transport=httpx.MockTransport(handler))
    client = HttpChamberClient("http://chamber.test", "chamber-secret", http=http, busy_backoff_s=0)
    result = client.detonate(REQ)
    assert len(attempts) == 2
    assert result.status == "completed"


def test_busy_wait_is_capped_and_fits_the_job_timeout(monkeypatch):
    slept = []
    monkeypatch.setattr("brain.chamber_client.time.sleep", slept.append)
    http = httpx.Client(base_url="http://chamber.test",
                        transport=httpx.MockTransport(lambda r: httpx.Response(409)))  # fmt: skip
    client = HttpChamberClient("http://chamber.test", "s", http=http)
    try:
        client.detonate(DetonateRequest(job_id="j", clone_url="https://github.com/o/r",
                                        head_sha="0" * 40))  # fmt: skip
    except httpx.HTTPStatusError:
        pass  # still busy after the last retry: the job fails closed
    assert max(slept) == 20 and 300 < sum(slept) < 450  # detonate_job timeout is 600 s


def test_tls_only_with_https_and_a_pinned_cert():
    from brain.chamber_client import HttpChamberClient as C

    assert not C("http://1.2.3.4:8443", "s").tls
    assert not C("https://1.2.3.4:8443", "s").tls  # no pinned cert: not trusted for tokens
    pem = (Path(__file__).parent / "fixtures/selfsigned_test_cert.pem").read_text()
    assert C("https://1.2.3.4:8443", "s", ca_pem=pem).tls


def health_client(response) -> HttpChamberClient:
    def handler(request):
        if isinstance(response, Exception):
            raise response
        return response

    http = httpx.Client(base_url="http://chamber.test", transport=httpx.MockTransport(handler))
    return HttpChamberClient("http://chamber.test", SECRET, http=http)


def test_health_ok_only_when_every_service_is_up():
    up = {"tetragon": True, "docker": True, "dns": True, "disk_free_gb": 24.7, "busy": False}
    assert health_client(httpx.Response(200, json=up)).health()["ok"]
    down = health_client(httpx.Response(200, json={**up, "dns": False})).health()
    assert down == {"ok": False, "detail": "down: dns"}


def test_health_unreachable_is_down():
    status = health_client(httpx.ConnectError("refused")).health()
    assert not status["ok"] and "unreachable" in status["detail"]
