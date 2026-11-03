"""Clone on the host, run the install in a hardened container, collect telemetry (B6).

The clone token is used only by git on the host (as an HTTP header, never written to disk)
and never enters the container. Inputs are validated because the Brain forwards
PR-derived values (clone URL, SHA).
"""

import base64
import os
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from chamber.decoys import DECOY_BIN, decoy_env, make_decoys, write_bait_files
from chamber.dns import name_connects, parse_dns_log
from chamber.egress import parse_kernel_log, read_kernel_log
from chamber.resources import CgroupSampler
from chamber.scripts import collect_executed_scripts
from chamber.telemetry import LogTail, parse_events, witness_command
from shared.contract import (
    MAX_CONNECT_EVENTS,
    MAX_TAIL_CHARS,
    DetonateRequest,
    DetonateResult,
    SensorWitness,
)

# Must start alphanumeric: a leading hyphen is not exploitable today (job_id only ever reaches
# a Path join and a container name that is always prefixed `det-`, so it can never be read as a
# CLI flag) but it costs nothing to exclude, and real job ids are uuid4 which always start hex.
JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CLONE_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(\.git)?$")
ALLOWED_COMMAND_HEADS = (["npm", "install"], ["npm", "ci"])
# Everything after the head is checked token by token. An allowlist, so an npm flag we have
# not considered fails closed instead of quietly changing what the sandbox does: the worst case
# is `--ignore-scripts`, which would make a detonation prove nothing at all, since install
# hooks are the entire thing being watched for.
ALLOWED_BARE_FLAGS = frozenset({"--no-audit", "--no-fund", "--no-progress"})
# Flags taking a value, each with its own constraint on that value. `--prefix` is used by the
# eval harness to install a payload fixture into a subdirectory of the work tree, so the value
# must stay relative and inside it - `--prefix /etc` is the thing to keep out.
ALLOWED_VALUE_FLAGS = ("--prefix",)
# `lodash@4.17.21`, `@babel/core@7.0.0`: eval/registry_sweep.py pins one package per run.
PKG_SPEC_RE = re.compile(r"^(?:@[a-z0-9~-][\w.-]*/)?[a-z0-9~-][\w.-]*(?:@[\w.^~<>=*|-]+)?$")
SAFE_REL_PATH_RE = re.compile(r"^[A-Za-z0-9._][\w./@+-]*$")
MAX_TIMEOUT_S = 300
SANDBOX_UID = 10001
FLUSH_WAIT_S = 2.0


@dataclass(frozen=True)
class Config:
    image: str = os.environ.get("SANDBOX_IMAGE", "detonator-sandbox:latest")
    network: str = os.environ.get("SANDBOX_NETWORK", "detonator")
    tetragon_log: str = os.environ.get("TETRAGON_LOG", "/var/log/tetragon/tetragon.log")
    jobs_dir: str = os.environ.get("JOBS_DIR", "/var/lib/pr-detonator/jobs")
    # dnsmasq on det0 is the sandbox's only resolver; iptables rejects any other port 53.
    resolver: str = os.environ.get("SANDBOX_RESOLVER", "10.250.0.1")
    dns_log: str = os.environ.get("DNS_LOG", "/var/log/pr-detonator/dns.log")
    # Fixed address (one job at a time) so DNS log lines can be attributed to this sandbox.
    sandbox_ip: str = os.environ.get("SANDBOX_IP", "10.250.0.10")
    # Fake credentials mounted read-only into the sandbox's home; the credential-files
    # Tetragon policy reports any open of them.
    bait_dir: str = os.environ.get("BAIT_DIR", "/opt/pr-detonator/chamber/sandbox/bait")
    # Decoy CLIs (gh, aws, claude, gemini, trufflehog) that do nothing; their exec is the signal.
    decoy_bin: str = os.environ.get("DECOY_BIN", "/opt/pr-detonator/chamber/sandbox/decoys/bin")


# bait file -> where a victim's real one would live
BAIT_FILES = {
    "npmrc": "/home/runner/.npmrc",
    "aws_credentials": "/home/runner/.aws/credentials",
    "ssh_id_ed25519": "/home/runner/.ssh/id_ed25519",
    "git-credentials": "/home/runner/.git-credentials",
}


def bait_mounts(bait_dir: str, per_run: dict[str, Path] | None = None) -> list[str]:
    """Static bait from bait_dir; per-run files (carrying this run's decoys) win."""
    args: list[str] = []
    for name, target in BAIT_FILES.items():
        source = (per_run or {}).get(name) or Path(bait_dir) / name
        if source.is_file():
            args += ["-v", f"{source}:{target}:ro"]
    return args


def decoy_args(cfg: "Config", decoys: dict[str, str] | None) -> list[str]:
    if not decoys:
        return []
    args = [a for k, v in decoy_env(decoys).items() for a in ("-e", f"{k}={v}")]
    if Path(cfg.decoy_bin).is_dir():
        args += ["-v", f"{cfg.decoy_bin}:{DECOY_BIN}:ro"]
    return args


class InvalidRequest(ValueError):
    pass


def _safe_rel_path(value: str) -> bool:
    """Relative, inside the work tree, no traversal."""
    return (
        bool(SAFE_REL_PATH_RE.match(value))
        and ".." not in value.split("/")
        and not value.startswith("/")
    )


def _validate_command_tail(tail: list[str]) -> None:
    """Each token after `npm install` must be an allowed flag, an allowed flag's value, or a
    package spec. Checking only the head left `npm install --ignore-scripts` valid."""
    i = 0
    while i < len(tail):
        tok = tail[i]
        if tok in ALLOWED_VALUE_FLAGS:
            if i + 1 >= len(tail):
                raise InvalidRequest(f"command flag {tok} needs a value")
            if not _safe_rel_path(tail[i + 1]):
                raise InvalidRequest(f"command flag {tok} value must be a relative path")
            i += 2
            continue
        if tok.startswith("-"):
            if tok not in ALLOWED_BARE_FLAGS:
                raise InvalidRequest(f"command flag not allowed: {tok[:40]!r}")
        elif not PKG_SPEC_RE.match(tok):
            raise InvalidRequest(f"command argument is not a package spec: {tok[:40]!r}")
        i += 1


def validate(req: DetonateRequest) -> None:
    if not JOB_ID_RE.match(req.job_id):
        raise InvalidRequest("bad job_id")
    if not SHA_RE.match(req.head_sha):
        raise InvalidRequest("head_sha must be a full 40-char hex SHA")
    if not CLONE_URL_RE.match(req.clone_url):
        raise InvalidRequest("clone_url must be https://github.com/<owner>/<repo>")
    head = next((h for h in ALLOWED_COMMAND_HEADS if req.command[: len(h)] == h), None)
    if head is None:
        raise InvalidRequest("command must start with npm install / npm ci")
    _validate_command_tail(req.command[len(head) :])
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


def docker_run_args(
    req: DetonateRequest,
    cfg: Config,
    name: str,
    src: Path,
    decoys: dict[str, str] | None = None,
    bait: dict[str, Path] | None = None,
    nonce: str | None = None,
) -> list[str]:
    command = witness_command(req.command, nonce) if nonce else req.command
    return [
        "docker", "run", "-d", "--name", name,
        "--network", cfg.network, "--ip", cfg.sandbox_ip,
        "--dns", cfg.resolver, "--dns-search", ".",
        "--user", f"{SANDBOX_UID}:{SANDBOX_UID}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "2g", "--cpus", "1.5",
        "--read-only",
        # tmpfs mounts default to root-owned; the sandbox user must own its HOME, or any
        # package (or payload) writing to ~ fails and the run proves nothing.
        "--tmpfs", "/tmp:rw,exec,size=512m,mode=1777",
        "--tmpfs", f"/home/runner:rw,exec,size=1g,uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0755",
        "-v", f"{src}:/work:rw", "-w", "/work", *bait_mounts(cfg.bait_dir, bait),
        "-e", "HOME=/home/runner", "-e", "npm_config_cache=/tmp/.npm",
        "-e", "npm_config_update_notifier=false",
        # Fake, per-run: none of these is a real credential (chamber/decoys.py).
        *decoy_args(cfg, decoys),
        cfg.image, *command,
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
    execs, connects, queries, files, scripts, truncated = [], [], [], [], [], False
    decoys = make_decoys()
    nonce = secrets.token_hex(8)  # per job; marks the sensor witness execs (SensorWitness)
    sensor = resources = None

    def result() -> DetonateResult:
        return DetonateResult(
            job_id=req.job_id, status=status, exit_code=exit_code,
            duration_s=round(time.monotonic() - started, 2), exec_events=execs,
            connect_events=connects, dns_queries=queries, file_events=files,
            executed_scripts=scripts, decoys=decoys,
            stdout_tail=_tail(stdout), stderr_tail=_tail(stderr), truncated=truncated,
            error=error, sensor=sensor, resources=resources,
        )  # fmt: skip

    try:
        job_dir.mkdir(parents=True, exist_ok=False)
        try:
            clone(req, src)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            status, error = "error", f"clone failed ({type(exc).__name__})"
            return result()
        _chown_tree(src, SANDBOX_UID)
        bait = write_bait_files(job_dir / "bait", decoys)  # outside src: not in /work

        tail, dns_tail = LogTail(cfg.tetragon_log), LogTail(cfg.dns_log)
        tail.start()
        dns_tail.start()
        started = time.monotonic()  # duration measures the detonation itself
        wall_start = time.time()
        proc = _docker(*docker_run_args(req, cfg, name, src, decoys, bait, nonce)[1:])
        if proc.returncode != 0:
            status, error = "error", f"docker run failed: {proc.stderr.strip()[:300]}"
            return result()
        container_id = proc.stdout.strip()
        sampler = CgroupSampler(container_id).start()

        try:
            waited = _docker("wait", name, timeout=req.timeout_s)
            exit_code = int(waited.stdout.strip() or -1)
        except subprocess.TimeoutExpired:
            status = "timeout"
            _docker("kill", name)
        resources = sampler.stop()

        logs = subprocess.run(["docker", "logs", name], capture_output=True, timeout=30)
        stdout = logs.stdout.decode("utf-8", errors="replace")
        stderr = logs.stderr.decode("utf-8", errors="replace")

        time.sleep(FLUSH_WAIT_S)  # let Tetragon flush the last events
        lines, rotated = tail.read_new()
        parsed = parse_events(lines, container_id, nonce)
        sensor = SensorWitness(pre_seen=parsed.witness_pre, post_seen=parsed.witness_post)
        dns_lines, dns_rotated = dns_tail.read_new()
        dns = parse_dns_log(dns_lines, cfg.sandbox_ip)
        execs, queries, files = parsed.exec_events, dns.queries, parsed.file_events
        room = MAX_CONNECT_EVENTS - len(parsed.connect_events)
        blocked = parse_kernel_log(read_kernel_log(wall_start - 1, time.time()),
                                   cfg.sandbox_ip, room)  # fmt: skip
        connects = name_connects(parsed.connect_events + blocked, dns)
        active = {c.pid for c in connects if c.pid} | {f.pid for f in files}
        scripts = collect_executed_scripts(execs, src, active)
        truncated = parsed.truncated or rotated or dns.truncated or dns_rotated
        if rotated or dns_rotated:
            error = "telemetry log rotated during run; early events may be missing"
        return result()
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
        shutil.rmtree(job_dir, ignore_errors=True)
