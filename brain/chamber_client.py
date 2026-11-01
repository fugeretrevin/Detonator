"""Brain -> Chamber client. Mock mode replays a recorded DetonateResult fixture."""

import os
import ssl
import time
from pathlib import Path
from typing import Protocol

import httpx

from shared.contract import DetonateRequest, DetonateResult
from shared.signing import signed_headers

FIXTURE_DIRS = (Path("/root/fixtures"), Path(__file__).resolve().parent.parent / "tests/fixtures")


class ChamberClient(Protocol):
    def detonate(self, request: DetonateRequest) -> DetonateResult: ...


class MockChamberClient:
    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = fixture_path

    def detonate(self, request: DetonateRequest) -> DetonateResult:
        result = DetonateResult.model_validate_json(self.fixture_path.read_text(encoding="utf-8"))
        return result.model_copy(update={"job_id": request.job_id})


class HttpChamberClient:
    def __init__(
        self,
        base_url: str,
        secret: str,
        *,
        http: httpx.Client | None = None,
        busy_retries: int = 20,
        busy_backoff_s: float = 10.0,
        max_backoff_s: float = 20.0,
        ca_pem: str | None = None,
    ) -> None:
        # One detonation at a time on the Chamber: queued PRs wait ~6.5 min in total
        # (10 s, then 20 s steps), inside detonate_job's 10 min timeout. A PR that still
        # can't get a slot fails closed ("Could not verify"), never passes.
        self._secret = secret
        # TLS: trust exactly the Chamber's self-signed cert, nothing else.
        self.tls = base_url.startswith("https://") and bool(ca_pem)
        verify = ssl.create_default_context(cadata=ca_pem) if ca_pem else True
        self._http = http or httpx.Client(
            base_url=base_url.rstrip("/"), timeout=600.0, verify=verify
        )
        self._busy_retries = busy_retries
        self._busy_backoff_s = busy_backoff_s
        self._max_backoff_s = max_backoff_s

    def detonate(self, request: DetonateRequest) -> DetonateResult:
        body = request.model_dump_json().encode()
        for attempt in range(self._busy_retries + 1):
            # Re-sign each attempt so the timestamp stays inside the replay window.
            headers = {"Content-Type": "application/json", **signed_headers(self._secret, body)}
            resp = self._http.post("/detonate", content=body, headers=headers)
            if resp.status_code == 409 and attempt < self._busy_retries:
                time.sleep(min(self._busy_backoff_s * (attempt + 1), self._max_backoff_s))
                continue
            resp.raise_for_status()
            return DetonateResult.model_validate_json(resp.content)
        raise RuntimeError("unreachable")


def _find_fixture(name: str) -> Path:
    for directory in FIXTURE_DIRS:
        if (directory / name).is_file():
            return directory / name
    raise FileNotFoundError(f"mock chamber fixture {name!r} not found")


def chamber_client_from_env() -> ChamberClient:
    mode = os.environ.get("CHAMBER_MODE", "mock")
    if mode == "mock":
        return MockChamberClient(
            _find_fixture(os.environ.get("MOCK_CHAMBER_FIXTURE", "detonate_result_e4.json"))
        )
    if mode == "http":
        return HttpChamberClient(
            os.environ["CHAMBER_URL"],
            os.environ["CHAMBER_SECRET"],
            ca_pem=os.environ.get("CHAMBER_CA_PEM") or None,
        )
    raise ValueError(f"unknown CHAMBER_MODE {mode!r}")
