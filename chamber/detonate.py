"""Clone on the host, run the install in a hardened container, collect telemetry (B6).

The clone token is used only by git on the host (as an HTTP header, never written to disk)
and never enters the container. Inputs are validated because the Brain forwards
PR-derived values (clone URL, SHA).
"""

import base64
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from chamber.telemetry import LogTail, parse_events
from shared.contract import MAX_TAIL_CHARS, DetonateRequest, DetonateResult

JOB_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CLONE_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(\.git)?$")
ALLOWED_COMMAND_HEADS = (["npm", "install"], ["npm", "ci"])
MAX_TIMEOUT_S = 300
SANDBOX_UID = 10001
FLUSH_WAIT_S = 2.0


@dataclass(frozen=True)
class Config:
    image: str = os.environ.get("SANDBOX_IMAGE", "detonator-sandbox:latest")
    network: str = os.environ.get("SANDBOX_NETWORK", "detonator")
    tetragon_log: str = os.environ.get("TETRAGON_LOG", "/var/log/tetragon/tetragon.log")
    jobs_dir: str = os.environ.get("JOBS_DIR", "/var/lib/pr-detonator/jobs")


class InvalidRequest(ValueError):
    pass


def validate(req: DetonateRequest) -> None:
    if not JOB_ID_RE.match(req.job_id):
        raise InvalidRequest("bad job_id")
    if not SHA_RE.match(req.head_sha):
        raise InvalidRequest("head_sha must be a full 40-char hex SHA")
    if not CLONE_URL_RE.match(req.clone_url):
        raise InvalidRequest("clone_url must be https://github.com/<owner>/<repo>")
    if not any(req.command[: len(h)] == h for h in ALLOWED_COMMAND_HEADS):
        raise InvalidRequest("command must start with npm install / npm ci")
    if not 1 <= req.timeout_s <= MAX_TIMEOUT_S:
        raise InvalidRequest(f"timeout_s must be 1..{MAX_TIMEOUT_S}")


def _tail(text: str) -> str:
    return text[-MAX_TAIL_CHARS:]


def _git(*args: str, cwd: Path | None = None, token: str | None = None) -> None:
    cmd = ["git", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null"]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cmd += ["-c", f"http.extraHeader=Authorization: Basic {basic}"]
    env = {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0", "HOME": "/nonexistent"}
    subprocess.run(cmd + list(args), cwd=cwd, env=env, check=True, capture_output=True, timeout=120)


def clone(req: DetonateRequest, dest: Path) -> None:
    _git(
        "clone",
        "--filter=blob:none",
        "--no-checkout",
        req.clone_url,
        str(dest),
        token=req.clone_token,
    )
    try:
        _git("checkout", "--detach", req.head_sha, cwd=dest, token=req.clone_token)
    except subprocess.CalledProcessError:
        # PR head not on a cloned branch (e.g. force-pushed): fetch the exact commit.
        _git("fetch", "origin", req.head_sha, cwd=dest, token=req.clone_token)
        _git("checkout", "--detach", req.head_sha, cwd=dest, token=req.clone_token)
    shutil.rmtree(dest / ".git")


def _chown_tree(root: Path, uid: int) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        os.chown(dirpath, uid, uid)
        for name in dirnames + filenames:
            os.lchown(os.path.join(dirpath, name), uid, uid)


def docker_run_args(req: DetonateRequest, cfg: Config, name: str, src: Path) -> list[str]:
    return [
        "docker", "run", "-d", "--name", name,
        "--network", cfg.network, "--dns", "1.1.1.1", "--dns", "8.8.8.8",
        "--user", f"{SANDBOX_UID}:{SANDBOX_UID}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "2g", "--cpus", "1.5",
        "--read-only",
        # tmpfs mounts default to root-owned; the sandbox user must own its HOME, or any
        # package (or payload) writing to ~ fails and the run proves nothing.
        "--tmpfs", "/tmp:rw,exec,size=512m,mode=1777",
        "--tmpfs", f"/home/runner:rw,exec,size=1g,uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0755",
        "-v", f"{src}:/work:rw", "-w", "/work",
        "-e", "HOME=/home/runner", "-e", "npm_config_cache=/tmp/.npm",
        "-e", "npm_config_update_notifier=false",
        cfg.image, *req.command,
    ]  # fmt: skip


def _docker(*args: str, timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def run(req: DetonateRequest, cfg: Config | None = None) -> DetonateResult:
    cfg = cfg or Config()
    validate(req)
    job_dir = Path(cfg.jobs_dir) / req.job_id
    src = job_dir / "src"
    name = f"det-{req.job_id}"
    started = time.monotonic()
    status, exit_code, error = "completed", None, None
    stdout = stderr = ""
    execs, connects, truncated = [], [], False

    def result() -> DetonateResult:
        return DetonateResult(
            job_id=req.job_id, status=status, exit_code=exit_code,
            duration_s=round(time.monotonic() - started, 2), exec_events=execs,
            connect_events=connects, dns_queries=[], stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr), truncated=truncated, error=error,
        )  # fmt: skip

    try:
        job_dir.mkdir(parents=True, exist_ok=False)
        try:
            clone(req, src)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            status, error = "error", f"clone failed ({type(exc).__name__})"
            return result()
        _chown_tree(src, SANDBOX_UID)

        tail = LogTail(cfg.tetragon_log)
        tail.start()
        started = time.monotonic()  # duration measures the detonation itself
        proc = _docker(*docker_run_args(req, cfg, name, src)[1:])
        if proc.returncode != 0:
            status, error = "error", f"docker run failed: {proc.stderr.strip()[:300]}"
            return result()
        container_id = proc.stdout.strip()

        try:
            waited = _docker("wait", name, timeout=req.timeout_s)
            exit_code = int(waited.stdout.strip() or -1)
        except subprocess.TimeoutExpired:
            status = "timeout"
            _docker("kill", name)

        logs = subprocess.run(["docker", "logs", name], capture_output=True, timeout=30)
        stdout = logs.stdout.decode("utf-8", errors="replace")
        stderr = logs.stderr.decode("utf-8", errors="replace")

        time.sleep(FLUSH_WAIT_S)  # let Tetragon flush the last events
        lines, rotated = tail.read_new()
        parsed = parse_events(lines, container_id)
        execs, connects = parsed.exec_events, parsed.connect_events
        truncated = parsed.truncated or rotated
        if rotated:
            error = "tetragon log rotated during run; early events may be missing"
        return result()
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
        shutil.rmtree(job_dir, ignore_errors=True)
