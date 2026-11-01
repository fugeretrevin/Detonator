"""Chamber HTTP API (BUILD_PLAN B8). Run: uvicorn chamber.server:app --host 0.0.0.0 --port 8443"""

import os
import shutil
import subprocess
import threading

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from chamber import detonate
from shared.contract import DetonateRequest
from shared.signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, verify

app = FastAPI(title="PR Detonator Chamber", docs_url=None, redoc_url=None, openapi_url=None)
# One detonation at a time: keeps event attribution trivial and the VM from being overrun.
LOCK = threading.Lock()


def _secret() -> str:
    return os.environ.get("CHAMBER_SECRET", "")


def _active(unit: str) -> bool:
    try:
        out = subprocess.run(
            ["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5
        )
        return out.stdout.strip() == "active"
    except (OSError, subprocess.TimeoutExpired):
        return False


@app.get("/health")
def health() -> dict:
    disk = shutil.disk_usage("/")
    return {
        "tetragon": _active("tetragon"),
        "docker": _active("docker"),
        "disk_free_gb": round(disk.free / 1e9, 1),
        "busy": LOCK.locked(),
    }


@app.post("/detonate")
async def detonate_endpoint(request: Request) -> JSONResponse:
    body = await request.body()
    if not verify(
        _secret(),
        request.headers.get(TIMESTAMP_HEADER),
        request.headers.get(SIGNATURE_HEADER),
        body,
    ):
        return JSONResponse({"detail": "unauthorized"}, status_code=401)

    try:
        req = DetonateRequest.model_validate_json(body)
        detonate.validate(req)
    except (ValidationError, detonate.InvalidRequest) as exc:
        return JSONResponse({"detail": f"invalid request: {exc}"[:500]}, status_code=422)

    if not LOCK.acquire(blocking=False):
        return JSONResponse({"detail": "busy"}, status_code=409)
    try:
        result = await run_in_threadpool(detonate.run, req)
    finally:
        LOCK.release()
    return JSONResponse(result.model_dump(mode="json"))
