"""Run every eval case through the local Chamber API. Runs ON the Chamber VM, as root:

  sudo /opt/pr-detonator/venv/bin/python run_chamber.py <manifest.json> <repo-url> <sha> <out-dir>

Signs with the Chamber's own secret from /etc/pr-detonator/env, so it never leaves the VM.
Only needs the `shared` package that setup.sh installs in /opt/pr-detonator.
"""

import json
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, "/opt/pr-detonator")
from shared.contract import DetonateRequest  # noqa: E402
from shared.signing import signed_headers  # noqa: E402

API = "https://127.0.0.1:8443/detonate"
TLS_CERT = "/etc/pr-detonator/tls/cert.pem"  # the Chamber's self-signed cert (setup.sh)
TIMEOUT_S = 240


def secret() -> str:
    for line in Path("/etc/pr-detonator/env").read_text().splitlines():
        if line.startswith("CHAMBER_SECRET="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("CHAMBER_SECRET missing")


def detonate(key: str, repo: str, sha: str, command: list[str]) -> dict:
    req = DetonateRequest(job_id=str(uuid.uuid4()), clone_url=repo, head_sha=sha,
                          command=command, timeout_s=TIMEOUT_S)  # fmt: skip
    body = req.model_dump_json().encode()
    http = urllib.request.Request(
        API, data=body, method="POST",
        headers={"Content-Type": "application/json", **signed_headers(key, body)},
    )  # fmt: skip
    ctx = ssl.create_default_context(cafile=TLS_CERT)
    with urllib.request.urlopen(http, timeout=TIMEOUT_S + 60, context=ctx) as resp:
        return json.loads(resp.read())


def main(manifest: str, repo: str, sha: str, out: str) -> None:
    key, out_dir = secret(), Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for case in json.loads(Path(manifest).read_text()):
        dest = out_dir / f"{case['id']}.json"
        if dest.exists():
            continue  # resumable
        started = time.monotonic()
        try:
            result = detonate(key, repo, sha, case["command"])
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"{case['id']:<22} ERROR {exc}", flush=True)
            continue
        dest.write_text(json.dumps(result, indent=1))
        print(f"{case['id']:<22} {result['status']:<9} exit={result['exit_code']} "
              f"{time.monotonic() - started:5.1f}s exec={len(result['exec_events'])} "
              f"conn={len(result['connect_events'])} dns={len(result['dns_queries'])}",
              flush=True)  # fmt: skip


if __name__ == "__main__":
    main(*sys.argv[1:5])
