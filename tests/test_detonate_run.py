"""`chamber.detonate.run` - the sandbox orchestration, which had no tests.

`validate` (the input boundary) and `docker_run_args` (the hardening flags) are covered in
`test_detonate_validate.py` and `test_chamber_server.py`. The control flow *between* them was
not: the order of clone -> chown -> tail -> start -> wait -> collect, what each failure path
reports, and whether the container and job directory are always cleaned up.

That order is load-bearing in ways a reading of the function does not make obvious:

- the log tails must `start()` **before** the container does, or the first events are missed;
- the tree must be chowned **before** the container starts, or the install cannot write and
  the detonation proves nothing while still exiting 0;
- every failure must end as `status != "completed"`, so the reviewer is told what actually
  happened rather than being handed an event-free run that reads like a clean install;
- the `finally` must run on *every* path, since one leaked container holds the fixed sandbox
  IP (`--ip 10.250.0.10`) and every subsequent detonation then fails to start.

Everything here fakes `subprocess.run` in the module under test, so the real `_docker` wrapper
and its argv slicing are exercised rather than stubbed out.

Mutation results (8 defects injected into `run()`; "rest" = the whole suite minus this file):

| Injected defect | this file | rest |
|---|---|---|
| log tails start *after* the container | caught | missed |
| work tree never chowned to the sandbox uid | caught | missed |
| `docker run` failure left as `completed` | caught | missed |
| clone failure left as `completed` | caught | missed |
| container never removed in the `finally` | caught | missed |
| argv slice drops a token | caught | missed |
| timeout does not kill the container | caught | missed |
| rotated-log warning dropped | caught | missed |

On severity, measured rather than assumed: the two `completed`-mislabelling defects are **not**
fail-open to the merge gate. `brain.verdict.unverified_reason` rejects both independently
(`exit_code` is None, so `!= 0`), and rejects even a `completed`/exit-0 result that carries no
exec events as "the sensor was blind to this run". These tests therefore localise a defect at
the layer that owns it; they are not the only thing standing between it and a passing check.
"""

import subprocess
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from chamber import detonate
from shared.contract import DetonateRequest

SHA = "0123456789abcdef0123456789abcdef01234567"
CONTAINER_ID = "c0ffee1234567890"


class FakeDocker:
    """Stands in for `detonate.subprocess.run`, recording every argv in order.

    `_docker` passes `text=True`, but `docker logs` is called through a bare `subprocess.run`
    and its output is `.decode()`d - so `logs` must answer in bytes and everything else in str.
    Getting that backwards is exactly the kind of mistake these tests should catch, so the fake
    keys off the real `text` keyword rather than guessing.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.run_rc = 0
        self.wait_timeout = False
        self.wait_stdout = "0"
        self.logs_stdout = b"added 1 package in 2s"
        self.logs_stderr = b""

    @property
    def subcommands(self) -> list[str]:
        return [c[1] for c in self.calls if len(c) > 1]

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub == "run":
            if self.run_rc != 0:
                return CompletedProcess(cmd, self.run_rc, "", "no such image: detonator-sandbox")
            return CompletedProcess(cmd, 0, f"{CONTAINER_ID}\n", "")
        if sub == "wait":
            if self.wait_timeout:
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 0))
            return CompletedProcess(cmd, 0, self.wait_stdout, "")
        if sub == "logs":
            assert not kw.get("text"), "docker logs output is decoded by hand; must stay bytes"
            return CompletedProcess(cmd, 0, self.logs_stdout, self.logs_stderr)
        return CompletedProcess(cmd, 0, "", "")


class Harness:
    def __init__(self, cfg: detonate.Config, docker: FakeDocker, tmp: Path) -> None:
        self.cfg, self.docker, self.tmp = cfg, docker, tmp
        self.chowned: list[tuple[Path, int]] = []
        self.bait_dirs: list[Path] = []
        self.order: list[str] = []  # coarse lifecycle order, for the ordering assertions
        self.clone_error: Exception | None = None

    def job_dir(self, job_id: str = "job-1") -> Path:
        return Path(self.cfg.jobs_dir) / job_id


@pytest.fixture
def h(monkeypatch, tmp_path) -> Harness:
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    # Real, empty log files: a *missing* log means "rotated" (see LogTail.read_new), which is a
    # separate behaviour with its own test below.
    tetragon = tmp_path / "tetragon.log"
    tetragon.write_text("")
    dns = tmp_path / "dns.log"
    dns.write_text("")
    cfg = detonate.Config(
        jobs_dir=str(jobs), tetragon_log=str(tetragon), dns_log=str(dns),
        bait_dir=str(tmp_path / "no-bait"), decoy_bin=str(tmp_path / "no-decoys"),
    )  # fmt: skip
    docker = FakeDocker()
    harness = Harness(cfg, docker, tmp_path)

    def fake_clone(req, dest: Path) -> None:
        harness.order.append("clone")
        if harness.clone_error is not None:
            raise harness.clone_error
        dest.mkdir(parents=True)
        (dest / "package.json").write_text('{"name":"demo"}')

    def fake_chown(root: Path, uid: int) -> None:
        harness.order.append("chown")
        harness.chowned.append((root, uid))

    real_bait = detonate.write_bait_files

    def fake_bait(directory: Path, decoys):
        harness.bait_dirs.append(directory)
        return real_bait(directory, decoys)

    class RecordingTail(detonate.LogTail):
        def start(self) -> None:
            harness.order.append(f"tail:{Path(self.path).name}")
            super().start()

    def fake_run(cmd, **kw):
        if list(cmd)[:2] == ["docker", "run"]:
            harness.order.append("container")
        return docker(cmd, **kw)

    monkeypatch.setattr(detonate, "clone", fake_clone)
    monkeypatch.setattr(detonate, "_chown_tree", fake_chown)  # os.chown needs root (and POSIX)
    monkeypatch.setattr(detonate, "write_bait_files", fake_bait)
    monkeypatch.setattr(detonate, "LogTail", RecordingTail)
    monkeypatch.setattr(detonate, "read_kernel_log", lambda *a: [])  # would shell out to dmesg
    monkeypatch.setattr(detonate.subprocess, "run", fake_run)
    monkeypatch.setattr(detonate.time, "sleep", lambda s: None)  # FLUSH_WAIT_S
    return harness


def req(**over) -> DetonateRequest:
    base = dict(job_id="job-1", clone_url="https://github.com/o/r.git", head_sha=SHA)
    return DetonateRequest(**{**base, **over})


# --- the happy path -----------------------------------------------------------------------


def test_a_successful_run_reports_completed_and_the_containers_exit_code(h):
    h.docker.wait_stdout = "0"
    res = detonate.run(req(), h.cfg)
    assert (res.status, res.exit_code) == ("completed", 0)
    assert res.job_id == "job-1"
    assert "added 1 package" in res.stdout_tail
    assert res.error is None


def test_a_nonzero_install_is_still_a_completed_run(h):
    """A failed `npm install` is a real observation, not a Chamber error - the Brain decides
    what a non-zero exit means. Conflating the two would turn every broken package into
    'could not verify'."""
    h.docker.wait_stdout = "1"
    res = detonate.run(req(), h.cfg)
    assert (res.status, res.exit_code) == ("completed", 1)


def test_an_unreadable_exit_code_becomes_minus_one_rather_than_crashing(h):
    h.docker.wait_stdout = ""
    assert detonate.run(req(), h.cfg).exit_code == -1


# --- ordering: the parts that silently ruin a detonation if they slip ----------------------


def test_the_log_tails_start_before_the_container_does(h):
    """Events emitted between container start and tail start are lost for good. `LogTail.start`
    records the file's current size, so starting it late silently skips the first execs."""
    detonate.run(req(), h.cfg)
    assert h.order.index("tail:tetragon.log") < h.order.index("container")
    assert h.order.index("tail:dns.log") < h.order.index("container")


def test_the_work_tree_is_chowned_to_the_sandbox_user_before_the_container_starts(h):
    """If /work is still root-owned the unprivileged install cannot write, so the package's
    install hooks never run and the detonation reports a clean, event-free run."""
    detonate.run(req(), h.cfg)
    assert h.order.index("chown") < h.order.index("container")
    assert h.chowned == [(h.job_dir() / "src", detonate.SANDBOX_UID)]


def test_the_bait_files_are_written_outside_the_mounted_work_tree(h):
    """Bait lands in job_dir/bait, which is mounted individually read-only. Putting it under
    src would expose it inside /work, where the PR's own code could read or rewrite it."""
    detonate.run(req(), h.cfg)
    assert h.bait_dirs == [h.job_dir() / "bait"]
    src = h.job_dir() / "src"
    assert src not in h.bait_dirs[0].parents and h.bait_dirs[0] != src


# --- the argv actually handed to docker ----------------------------------------------------


def test_the_docker_argv_survives_the_slice_that_strips_its_own_name(h):
    """`run` calls `_docker(*docker_run_args(...)[1:])` and `_docker` prepends "docker" again.
    An off-by-one there drops `run` or duplicates `docker`, and either way the detonation dies
    in a way no other test would localise."""
    r = req()
    detonate.run(r, h.cfg)
    argv = next(c for c in h.docker.calls if c[1] == "run")
    assert argv[:5] == ["docker", "run", "-d", "--name", "det-job-1"]
    assert argv.count("docker") == 1
    # The validated command goes last and intact, wrapped by the sensor witness: the tail is
    # `<image> /bin/sh -c <script> detonator-witness <command...>`, so the command arrives as
    # argv after $0 rather than being interpolated into the script (see test_witness.py).
    n = len(r.command)
    assert argv[-n:] == list(r.command)
    assert argv[-n - 1] == "detonator-witness"  # $0, not a shell word of the script
    assert argv[-n - 4 : -n - 2] == ["/bin/sh", "-c"]
    assert argv[-n - 5] == h.cfg.image


def test_the_container_name_is_derived_from_the_job_id(h):
    detonate.run(req(job_id="abc123"), h.cfg)
    assert all("det-abc123" in c or c[1] in ("logs",) for c in h.docker.calls if len(c) > 2)


# --- failure paths: each must be distinguishable from a clean run --------------------------


def test_a_clone_failure_is_an_error_and_never_starts_a_container(h):
    h.clone_error = subprocess.CalledProcessError(128, ["git", "clone"])
    res = detonate.run(req(), h.cfg)
    assert res.status == "error"
    assert "clone failed" in res.error and "CalledProcessError" in res.error
    assert "run" not in h.docker.subcommands
    assert res.exit_code is None


def test_a_clone_timeout_is_also_an_error(h):
    h.clone_error = subprocess.TimeoutExpired(["git", "clone"], 120)
    res = detonate.run(req(), h.cfg)
    assert res.status == "error" and "TimeoutExpired" in res.error


def test_the_clone_error_does_not_leak_git_output(h):
    """git's stderr can contain the clone URL with the token-bearing header echoed back. The
    message is deliberately just the exception type."""
    h.clone_error = subprocess.CalledProcessError(
        128, ["git", "clone"], stderr=b"fatal: Authorization: Basic eC1hY2Nlc3M6ghs_SECRET"
    )
    res = detonate.run(req(clone_token="ghs_SECRET"), h.cfg)
    assert "ghs_SECRET" not in (res.error or "")
    assert "ghs_SECRET" not in res.stderr_tail + res.stdout_tail


def test_a_container_that_will_not_start_is_an_error_not_a_clean_run(h):
    h.docker.run_rc = 125
    res = detonate.run(req(), h.cfg)
    assert res.status == "error"
    assert "docker run failed" in res.error and "no such image" in res.error
    assert res.exec_events == [] and res.connect_events == []
    assert "wait" not in h.docker.subcommands


def test_a_timeout_kills_the_container_and_reports_timeout(h):
    h.docker.wait_timeout = True
    res = detonate.run(req(timeout_s=5), h.cfg)
    assert res.status == "timeout"
    assert res.exit_code is None  # never exited on its own
    assert "kill" in h.docker.subcommands


def test_telemetry_is_still_collected_after_a_timeout(h):
    """A payload that hangs on purpose is the interesting case: whatever it did before the
    timeout must still reach the Brain, so `logs` and the tails run on this path too."""
    h.docker.wait_timeout = True
    h.docker.logs_stdout = b"downloading stage two"
    res = detonate.run(req(timeout_s=5), h.cfg)
    assert "downloading stage two" in res.stdout_tail
    assert res.sensor is not None  # the witness was evaluated, not skipped


# --- fail-closed on a blind sensor --------------------------------------------------------


def test_a_missing_tetragon_log_is_reported_rather_than_read_as_clean(h):
    """If Tetragon is not running, its log is absent and the sandbox is unobserved. `LogTail`
    reports that as rotated, which must surface as an error - an unobserved run with no events
    looks exactly like a clean one."""
    blind = detonate.Config(**{**h.cfg.__dict__, "tetragon_log": str(h.tmp / "gone.log")})
    res = detonate.run(req(), blind)
    assert res.truncated is True
    assert res.error is not None and "rotated" in res.error


# --- cleanup: a leaked container holds the one sandbox IP ----------------------------------


def test_a_successful_run_removes_the_container_and_the_job_directory(h):
    detonate.run(req(), h.cfg)
    assert ["docker", "rm", "-f", "det-job-1"] in h.docker.calls
    assert not h.job_dir().exists()


@pytest.mark.parametrize(
    "setup",
    [
        pytest.param(
            lambda h: setattr(h, "clone_error", subprocess.CalledProcessError(1, "g")),
            id="clone-failed",
        ),  # fmt: skip
        pytest.param(lambda h: setattr(h.docker, "run_rc", 125), id="container-would-not-start"),
        pytest.param(lambda h: setattr(h.docker, "wait_timeout", True), id="timed-out"),
    ],
)
def test_every_failure_path_still_removes_the_container_and_job_directory(h, setup):
    setup(h)
    detonate.run(req(), h.cfg)
    assert ["docker", "rm", "-f", "det-job-1"] in h.docker.calls
    assert not h.job_dir().exists()


def test_an_unexpected_exception_still_cleans_up_and_is_not_swallowed(h, monkeypatch):
    """Anything the `except` clauses do not name - a parser bug, an OSError reading the log -
    must still release the container, and must not be reported as a completed run."""
    monkeypatch.setattr(detonate, "parse_events", lambda *a, **k: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        detonate.run(req(), h.cfg)
    assert ["docker", "rm", "-f", "det-job-1"] in h.docker.calls
    assert not h.job_dir().exists()


def test_an_invalid_request_is_rejected_before_any_directory_or_container_exists(h):
    """`validate` runs before the try block, so nothing has been created yet and the cleanup
    `finally` must not fire - in particular it must not `docker rm -f` a name built from an
    unvalidated job_id."""
    with pytest.raises(detonate.InvalidRequest):
        detonate.run(req(head_sha="main"), h.cfg)
    assert h.docker.calls == []


def test_a_job_directory_that_already_exists_is_refused(h):
    """`mkdir(exist_ok=False)` is deliberate: reusing a directory would mix a previous job's
    files into /work.

    Note the interaction with the cleanup `finally`, which runs on this path too and deletes
    the very directory the refusal protected - so an immediate retry of the same job_id would
    succeed. Harmless as deployed (job ids are uuid4, and `chamber/server.py` serialises jobs
    behind a busy lock that 409s a second request), and pinned here so the behaviour is a
    recorded choice rather than a surprise."""
    h.job_dir().mkdir(parents=True)
    with pytest.raises(FileExistsError):
        detonate.run(req(), h.cfg)
    assert not h.job_dir().exists()  # the finally cleaned up the directory it refused to reuse


# --- duration -----------------------------------------------------------------------------


def test_duration_measures_the_detonation_not_the_clone(h, monkeypatch):
    """`started` is reset once the container is about to launch. Measuring from the top would
    fold a slow shallow clone into the dwell time the report shows the reviewer."""
    # First reading is taken at the top of `run`; the second is the reset just before the
    # container launches, 60s of shallow clone later.
    ticks = iter([100.0, 160.0, 161.0])
    monkeypatch.setattr(detonate.time, "monotonic", lambda: next(ticks, 161.0))
    res = detonate.run(req(), h.cfg)
    assert res.duration_s == 1.0  # not 61: the clone is not dwell time
