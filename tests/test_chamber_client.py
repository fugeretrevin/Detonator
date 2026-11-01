from pathlib import Path

import httpx

from brain.chamber_client import HttpChamberClient, MockChamberClient
from shared import signing
from shared.contract import DetonateRequest

FIXTURES = Path(__file__).parent / "fixtures"
REQ = DetonateRequest(job_id="job-1", clone_url="https://x/y.git", head_sha="abc")


def test_mock_returns_fixture_with_job_id():
    result = MockChamberClient(FIXTURES / "detonate_result_e4.json").detonate(REQ)
    assert result.job_id == "job-1"
    assert any(e.resolved_domain is None for e in result.connect_events)


def test_http_client_signs_and_retries_on_409():
    fixture = (FIXTURES / "detonate_result_e4.json").read_bytes()
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
        return httpx.Response(200, content=fixture)

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
