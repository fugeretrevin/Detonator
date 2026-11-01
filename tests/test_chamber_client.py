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
