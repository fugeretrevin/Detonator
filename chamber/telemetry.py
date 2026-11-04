"""Tetragon export log -> contract events for one container.

Shapes verified in the B1 spike (tests/fixtures/tetragon_smoke.jsonl): container processes
carry process.docker = first 31 chars of the container ID; host processes have none.
"""

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field

from shared.contract import (
    MAX_CONNECT_EVENTS,
    MAX_EXEC_EVENTS,
    MAX_FILE_EVENTS,
    ConnectEvent,
    ExecEvent,
    FileEvent,
)

LOOPBACK_PREFIXES = ("127.", "::1")


@dataclass
class ParsedTelemetry:
    exec_events: list[ExecEvent]
    connect_events: list[ConnectEvent]
    truncated: bool
    file_events: list[FileEvent] = field(default_factory=list)
    witness_pre: bool = False  # saw `/bin/true pre-<nonce>` from this container
    witness_post: bool = False


def _in_container(process: dict, container_id: str) -> bool:
    short = process.get("docker")
    return bool(short) and container_id.startswith(short)


def witness_command(command: list[str], nonce: str) -> list[str]:
    """Wrap the install so the container execs a harmless marker before and after it.
    `/bin/true` by path: a bare `true` is a shell builtin and execs nothing. The wrapper
    exits with the install's own status."""
    script = f'/bin/true pre-{nonce}; "$@"; rc=$?; /bin/true post-{nonce}; exit $rc'
    return ["/bin/sh", "-c", script, "detonator-witness", *command]


def _is_wrapper(proc: dict, parent: dict, container_id: str, nonce: str, roots: set[int]) -> bool:
    """Our witness shell, carrying both markers, started at the top of the container.

    "At the top" means its parent is either outside the container (the runtime started it
    directly) or is itself a container root — the sandbox image declares an ENTRYPOINT, so the
    real tree is `docker-entrypoint.sh` → our shell → `/bin/true`, and requiring the parent to
    be outside missed it entirely.

    This is what a payload cannot forge. `roots` only ever contains processes whose own parent
    was outside the container, and everything a payload starts descends from the install
    command, which is already a child of this wrapper — so a payload's `sh` can never have a
    root (or external) parent, however it quotes the nonce."""
    return (
        proc.get("binary", "").rsplit("/", 1)[-1] in ("sh", "dash", "bash")
        and (not _in_container(parent, container_id) or parent.get("pid") in roots)
        and f"pre-{nonce}" in proc.get("arguments", "")
        and f"post-{nonce}" in proc.get("arguments", "")
    )


def parse_events(lines: Iterable[str], container_id: str, nonce: str = "") -> ParsedTelemetry:
    execs: list[ExecEvent] = []
    connects: list[ConnectEvent] = []
    truncated = False
    # Collapse repeats (npm opens many identical registry connections; builds spawn many
    # identical compiler execs) so legitimate noise can't push a payload past the caps.
    seen_execs: set[tuple[str, str]] = set()
    seen_connects: set[tuple[str, str, int]] = set()
    files: list[FileEvent] = []
    seen_files: set[tuple[int, str]] = set()
    pre = post = False
    wrapper_pids: set[int] = set()
    # Container roots: in-container processes whose own parent is outside it. Tetragon logs a
    # parent before its child, so collecting these as we go is enough to spot the wrapper that
    # the image's ENTRYPOINT starts.
    root_pids: set[int] = set()

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
            args = proc.get("arguments", "")
            if not _in_container(parent, container_id):
                root_pids.add(int(proc.get("pid", 0)))
            if nonce and _is_wrapper(proc, parent, container_id, nonce, root_pids):
                # Our witness shell: this is about the sensor, not about the install.
                wrapper_pids.add(int(proc.get("pid", 0)))
                continue
            if (
                nonce
                and parent.get("pid") in wrapper_pids
                and proc.get("binary", "").endswith("/true")
            ):
                if args in (f"pre-{nonce}", f"post-{nonce}"):
                    pre = pre or args == f"pre-{nonce}"
                    post = post or args == f"post-{nonce}"
                    continue
            # Anything else is kept, nonce or not: sandbox code can read the nonce, and must
            # not be able to hide its own execs by quoting it.
            key = (proc.get("binary", ""), args)
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
                    cwd=proc.get("cwd"),
                )
            )

        elif "process_kprobe" in event:
            body = event["process_kprobe"]
            proc = body.get("process", {})
            if not _in_container(proc, container_id):
                continue
            if body.get("function_name") == "security_file_open":
                # credential-files policy: only bait paths are reported (shape verified on the
                # Chamber: args[0].file_arg.path).
                path = next((a["file_arg"].get("path", "") for a in body.get("args", [])
                             if "file_arg" in a), "")  # fmt: skip
                key_f = (int(proc.get("pid", 0)), path)
                if path and key_f not in seen_files:
                    seen_files.add(key_f)
                    if len(files) >= MAX_FILE_EVENTS:
                        truncated = True
                    else:
                        binary = proc.get("binary", "")
                        ts = event.get("time", "")
                        files.append(FileEvent(ts=ts, pid=key_f[0], binary=binary, path=path))
                continue
            if body.get("function_name") != "tcp_connect":
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
                    resolved_domain=None,  # filled from the DNS log (chamber.dns)
                )
            )

    return ParsedTelemetry(execs, connects, truncated, files, pre, post)


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
