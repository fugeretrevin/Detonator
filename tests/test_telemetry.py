import json
from pathlib import Path

from chamber.telemetry import LogTail, parse_events
from shared.contract import MAX_EXEC_EVENTS

FIXTURE = Path(__file__).parent / "fixtures/tetragon_smoke.jsonl"
# Full 64-char ID as `docker run -d` prints it; Tetragon reports the first 31 chars.
CONTAINER = "5b6394642a944d98bf868995b125a5f" + "0" * 33


def lines() -> list[str]:
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def test_smoke_fixture_parses_container_events_only():
    parsed = parse_events(lines(), CONTAINER)
    assert [(e.binary, e.pid) for e in parsed.exec_events] == [
        ("/bin/sh", 19649),
        ("/usr/bin/wget", 19671),
        ("/usr/bin/wget", 19675),
    ]
    assert [(c.daddr, c.dport) for c in parsed.connect_events] == [
        ("172.66.147.243", 80),
        ("203.0.113.10", 80),
    ]
    assert not parsed.truncated


def test_host_noise_excluded():
    parsed = parse_events(lines(), CONTAINER)
    binaries = {e.binary for e in parsed.exec_events} | {c.binary for c in parsed.connect_events}
    assert "/usr/bin/dockerd" not in binaries and "/usr/bin/docker" not in binaries


def test_exec_fields_mapped():
    wget = parse_events(lines(), CONTAINER).exec_events[1]
    assert wget.args == "-q -T 5 -O- http://example.com"
    assert wget.ppid == 19649 and wget.parent_binary == "/bin/sh"
    assert wget.uid == 0 and wget.ts.startswith("2026-11-01T05:51:29")
    assert wget.cwd == "/"


def test_connect_fields_mapped():
    testnet = parse_events(lines(), CONTAINER).connect_events[1]
    assert testnet.binary == "/usr/bin/wget" and testnet.pid == 19675
    assert testnet.family == "AF_INET" and testnet.resolved_domain is None


def test_other_container_events_excluded():
    assert parse_events(lines(), "f" * 64).exec_events == []


def test_garbage_and_partial_lines_skipped():
    parsed = parse_events(["", "not json", '{"process_exec": {"process": ', *lines()], CONTAINER)
    assert len(parsed.exec_events) == 3


def _variant(line: str, i: int) -> str:
    event = json.loads(line)
    event["process_exec"]["process"]["arguments"] = f"-c step {i}"
    return json.dumps(event)


def test_exec_cap_sets_truncated():
    one = next(line for line in lines() if "process_exec" in line and 'docker":"5b' in line)
    parsed = parse_events([_variant(one, i) for i in range(MAX_EXEC_EVENTS + 5)], CONTAINER)
    assert len(parsed.exec_events) == MAX_EXEC_EVENTS and parsed.truncated


def test_duplicates_collapsed_so_noise_cannot_hide_payload():
    registry = next(line for line in lines() if '172.66.147.243","sport' in line)
    payload = next(line for line in lines() if '203.0.113.10","sport' in line)
    parsed = parse_events([registry] * 1000 + [payload], CONTAINER)
    assert [c.daddr for c in parsed.connect_events] == ["172.66.147.243", "203.0.113.10"]
    assert not parsed.truncated


def test_loopback_connect_dropped():
    event = json.loads(next(line for line in lines() if '203.0.113.10","sport' in line))
    event["process_kprobe"]["args"][0]["sock_arg"]["daddr"] = "127.0.0.1"
    assert parse_events([json.dumps(event)], CONTAINER).connect_events == []


def test_log_tail_reads_only_appended_bytes(tmp_path):
    log = tmp_path / "tetragon.log"
    log.write_text("old-1\nold-2\n")
    tail = LogTail(str(log))
    tail.start()
    with log.open("a") as f:
        f.write("new-1\nnew-2\n")
    assert tail.read_new() == (["new-1", "new-2"], False)


def test_log_tail_detects_rotation(tmp_path):
    log = tmp_path / "tetragon.log"
    log.write_text("old\n" * 100)
    tail = LogTail(str(log))
    tail.start()
    log.rename(tmp_path / "tetragon.log.1")
    log.write_text("after-rotate\n")
    new_lines, rotated = tail.read_new()
    assert new_lines == ["after-rotate"] and rotated


def test_log_tail_missing_file(tmp_path):
    tail = LogTail(str(tmp_path / "nope.log"))
    tail.start()
    assert tail.read_new() == ([], True)
