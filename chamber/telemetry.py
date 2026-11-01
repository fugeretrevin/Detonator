"""Tetragon export log -> contract events for one container (BUILD_PLAN B7).

Shapes verified in the B1 spike (tests/fixtures/tetragon_smoke.jsonl): container processes
carry process.docker = first 31 chars of the container ID; host processes have none.
"""

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass

from shared.contract import (
    MAX_CONNECT_EVENTS,
    MAX_EXEC_EVENTS,
    ConnectEvent,
    ExecEvent,
)

LOOPBACK_PREFIXES = ("127.", "::1")


@dataclass
class ParsedTelemetry:
    exec_events: list[ExecEvent]
    connect_events: list[ConnectEvent]
    truncated: bool


def _in_container(process: dict, container_id: str) -> bool:
    short = process.get("docker")
    return bool(short) and container_id.startswith(short)


def parse_events(lines: Iterable[str], container_id: str) -> ParsedTelemetry:
    execs: list[ExecEvent] = []
    connects: list[ConnectEvent] = []
    truncated = False
    # Collapse repeats (npm opens many identical registry connections; builds spawn many
    # identical compiler execs) so legitimate noise can't push a payload past the caps.
    seen_execs: set[tuple[str, str]] = set()
    seen_connects: set[tuple[str, str, int]] = set()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue  # partial line at a read boundary

        if "process_exec" in event:
            body = event["process_exec"]
            proc, parent = body.get("process", {}), body.get("parent") or {}
            if not _in_container(proc, container_id):
                continue
            key = (proc.get("binary", ""), proc.get("arguments", ""))
            if key in seen_execs:
                continue
            seen_execs.add(key)
            if len(execs) >= MAX_EXEC_EVENTS:
                truncated = True
                continue
            execs.append(
                ExecEvent(
                    ts=proc.get("start_time") or event.get("time", ""),
                    pid=int(proc.get("pid", 0)),
                    ppid=parent.get("pid"),
                    binary=proc.get("binary", ""),
                    args=proc.get("arguments", ""),
                    parent_binary=parent.get("binary"),
                    uid=proc.get("uid"),
                )
            )

        elif "process_kprobe" in event:
            body = event["process_kprobe"]
            proc = body.get("process", {})
            if body.get("function_name") != "tcp_connect" or not _in_container(proc, container_id):
                continue
            sock = next((a["sock_arg"] for a in body.get("args", []) if "sock_arg" in a), None)
            if not sock or str(sock.get("daddr", "")).startswith(LOOPBACK_PREFIXES):
                continue
            key = (proc.get("binary", ""), str(sock.get("daddr", "")), int(sock.get("dport", 0)))
            if key in seen_connects:
                continue
            seen_connects.add(key)
            if len(connects) >= MAX_CONNECT_EVENTS:
                truncated = True
                continue
            connects.append(
                ConnectEvent(
                    ts=event.get("time", ""),
                    pid=int(proc.get("pid", 0)),
                    binary=proc.get("binary", ""),
                    daddr=sock.get("daddr", ""),
                    dport=int(sock.get("dport", 0)),
                    family=sock.get("family", ""),
                    resolved_domain=None,  # filled by the Brain's enrichment (no DNS log)
                )
            )

    return ParsedTelemetry(execs, connects, truncated)


class LogTail:
    """Read only the bytes appended to the export log since start()."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._inode: int | None = None
        self._offset = 0

    def start(self) -> None:
        try:
            st = os.stat(self.path)
            self._inode, self._offset = st.st_ino, st.st_size
        except FileNotFoundError:
            self._inode, self._offset = None, 0

    def read_new(self) -> tuple[list[str], bool]:
        """Returns (lines, rotated). If the log rotated mid-run, earlier events are lost."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return [], True
        rotated = self._inode is not None and st.st_ino != self._inode
        offset = 0 if rotated or st.st_size < self._offset else self._offset
        with open(self.path, "rb") as f:
            f.seek(offset)
            data = f.read()
        return data.decode("utf-8", errors="replace").splitlines(), rotated
