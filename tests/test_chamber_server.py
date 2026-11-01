import json
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chamber import detonate, server
from shared import signing
from shared.contract import DetonateRequest, DetonateResult

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "chamber-test-secret"
SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("CHAMBER_SECRET", SECRET)
    return TestClient(server.app)


def body(**overrides) -> bytes:
    req = {"job_id": "job-1", "clone_url": "https://github.com/o/r.git", "head_sha": SHA}
    req.update(overrides)
    return json.dumps(req).encode()


def signed(raw: bytes, secret: str = SECRET, now: int | None = None) -> dict:
    return {"Content-Type": "application/json", **signing.signed_headers(secret, raw, now)}


def fake_run(req: DetonateRequest, cfg=None) -> DetonateResult:
    result = DetonateResult.model_validate_json((FIXTURES / "detonate_result_e4.json").read_text())
    return result.model_copy(update={"job_id": req.job_id})


def test_signed_request_runs_and_the_response_is_signed_for_that_job(client, monkeypatch):
    monkeypatch.setattr(detonate, "run", fake_run)
    resp = client.post("/detonate", content=body(), headers=signed(body()))
    assert resp.status_code == 200
    assert DetonateResult.model_validate(resp.json()).job_id == "job-1"
    ts, sig = resp.headers[signing.TIMESTAMP_HEADER], resp.headers[signing.SIGNATURE_HEADER]
    assert signing.verify_response(SECRET, ts, sig, "job-1", resp.content)
    assert not signing.verify_response(SECRET, ts, sig, "job-2", resp.content)


def test_unsigned_rejected(client):
    assert client.post("/detonate", content=body()).status_code == 401


def test_wrong_secret_rejected(client):
    assert client.post("/detonate", content=body(), headers=signed(body(), "x")).status_code == 401


def test_stale_timestamp_rejected(client):
    headers = signed(body(), now=int(time.time()) - 301)
    assert client.post("/detonate", content=body(), headers=headers).status_code == 401


def test_tampered_body_rejected(client):
    headers = signed(body())
    resp = client.post("/detonate", content=body(job_id="job-2"), headers=headers)
    assert resp.status_code == 401


def test_empty_server_secret_rejects_everything(client, monkeypatch):
    monkeypatch.setenv("CHAMBER_SECRET", "")
    assert client.post("/detonate", content=body(), headers=signed(body(), "")).status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"job_id": "../../etc"},
        {"head_sha": "main"},
        {"clone_url": "file:///etc/passwd"},
        {"clone_url": "https://evil.example/o/r.git"},
        {"clone_url": "https://github.com/o/r.git --upload-pack=touch /tmp/x"},
        {"command": ["sh", "-c", "id"]},
        {"timeout_s": 10_000},
    ],
)
def test_invalid_requests_rejected_before_running(client, monkeypatch, overrides):
    monkeypatch.setattr(detonate, "run", lambda *a: pytest.fail("must not run"))
    raw = body(**overrides)
    assert client.post("/detonate", content=raw, headers=signed(raw)).status_code == 422


def test_concurrent_request_gets_409(client, monkeypatch):
    started, release = threading.Event(), threading.Event()

    def slow_run(req, cfg=None):
        started.set()
        release.wait(5)
        return fake_run(req)

    monkeypatch.setattr(detonate, "run", slow_run)
    results = {}
    first = threading.Thread(
        target=lambda: results.update(
            first=client.post("/detonate", content=body(), headers=signed(body())).status_code
        )
    )
    first.start()
    assert started.wait(5)
    raw = body(job_id="job-2")
    assert client.post("/detonate", content=raw, headers=signed(raw)).status_code == 409
    release.set()
    first.join(5)
    assert results["first"] == 200


def test_health_shape(client):
    data = client.get("/health").json()
    assert set(data) == {"tetragon", "docker", "dns", "disk_free_gb", "busy"}


def test_docker_args_are_hardened():
    req = DetonateRequest(
        job_id="j", clone_url="https://github.com/o/r", head_sha=SHA, clone_token="ghs_secret"
    )
    args = detonate.docker_run_args(req, detonate.Config(), "det-j", Path("/jobs/j/src"))
    joined = " ".join(args)
    for flag in (
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--read-only",
        "--user 10001:10001",
        "--network detonator",
        "--pids-limit 256",
        "--ip 10.250.0.10",  # DNS log lines are attributed by this address
        "--dns 10.250.0.1",  # the logging resolver, not a public one
    ):
        assert flag in joined
    assert "ghs_secret" not in joined  # token never reaches the container
    # HOME must be writable by the sandbox user (puppeteer etc. cache browsers there)
    assert "/home/runner:rw,exec,size=1g,uid=10001,gid=10001" in joined
    assert "--privileged" not in joined and "docker.sock" not in joined


def test_bait_credentials_mounted_read_only(tmp_path):
    (tmp_path / "npmrc").write_text("bait")
    cfg = detonate.Config(bait_dir=str(tmp_path))
    req = DetonateRequest(job_id="j", clone_url="https://github.com/o/r", head_sha=SHA)
    joined = " ".join(detonate.docker_run_args(req, cfg, "det-j", Path("/jobs/j/src")))
    assert f"{tmp_path / 'npmrc'}:/home/runner/.npmrc:ro" in joined
    assert ".aws" not in joined  # only files that exist are mounted
