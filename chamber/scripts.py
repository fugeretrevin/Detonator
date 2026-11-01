"""Copy out the files install-time processes executed (HARDENING_PLAN P1.1).

A dependency attack's diff is one version-bump line; the code that ran lives in
node_modules. After the run (the container has stopped), read the script files named in exec
arguments, resolved against each process's kernel-recorded cwd, from the job's own source
directory on the host.

Safety: everything in the job directory was written by untrusted code. A candidate must
resolve (symlinks followed) to a regular file *inside* the job directory, so a planted
symlink to a host file is never read; binaries (NUL bytes) are skipped; at most
MAX_EXECUTED_SCRIPTS files of MAX_SCRIPT_CHARS each.
"""

import hashlib
import os
import posixpath
import shlex
from pathlib import Path

from shared.contract import MAX_EXECUTED_SCRIPTS, MAX_SCRIPT_CHARS, ExecEvent, ExecutedScript

SANDBOX_ROOT = "/work"
MAX_READ_BYTES = 1_000_000  # hash at most this much; larger files are truncated anyway


def _package(path: str) -> str | None:
    parts = path.split("/")
    if "node_modules" not in parts:
        return None
    i = len(parts) - 1 - parts[::-1].index("node_modules")
    rest = parts[i + 1 :]
    if len(rest) < 2:  # the file itself is the next part: no package dir
        return None
    return f"{rest[0]}/{rest[1]}" if rest[0].startswith("@") and len(rest) > 2 else rest[0]


def _tokens(args: str) -> list[str]:
    try:
        return shlex.split(args)
    except ValueError:
        return args.split()


def _ancestry(pids: set[int], execs: list[ExecEvent]) -> set[int]:
    parent = {e.pid: e.ppid for e in execs}
    out: set[int] = set()
    for pid in pids:
        while pid and pid not in out:
            out.add(pid)
            pid = parent.get(pid) or 0
    return out


def _candidates(execs: list[ExecEvent], active_pids: set[int] = frozenset()) -> list[str]:
    """Sandbox paths of files named in exec args, deduplicated. Processes that connected out
    or touched bait (and their ancestors) come first, so benign scripts that ran earlier
    can't push a payload past the cap."""
    hot = _ancestry(set(active_pids), execs)
    ordered = [e for e in execs if e.pid in hot] + [e for e in execs if e.pid not in hot]
    seen: list[str] = []
    for e in ordered:
        cwd = e.cwd or ""
        if not cwd.startswith(SANDBOX_ROOT):
            continue
        for tok in _tokens(e.args):
            if not tok or tok.startswith("-") or "\n" in tok:
                continue
            path = posixpath.normpath(tok if tok.startswith("/") else posixpath.join(cwd, tok))
            if path.startswith(SANDBOX_ROOT + "/") and path not in seen:
                seen.append(path)
    return seen


def collect_executed_scripts(
    execs: list[ExecEvent], src_dir: Path, active_pids: set[int] = frozenset()
) -> list[ExecutedScript]:
    root = os.path.realpath(src_dir)
    out: list[ExecutedScript] = []
    seen_real: set[str] = set()
    for sandbox_path in _candidates(execs, active_pids):
        if len(out) >= MAX_EXECUTED_SCRIPTS:
            break
        host = os.path.join(root, sandbox_path[len(SANDBOX_ROOT) + 1 :])
        real = os.path.realpath(host)
        if real in seen_real or os.path.commonpath([root, real]) != root:
            continue  # outside the job directory (e.g. a planted symlink): never read
        if not os.path.isfile(real):
            continue
        with open(real, "rb") as f:
            data = f.read(MAX_READ_BYTES)
        if not data or b"\0" in data[:8192]:
            continue  # empty (e.g. a failed download) or a binary, not a script
        seen_real.add(real)
        text = data.decode("utf-8", errors="replace")
        out.append(
            ExecutedScript(
                path=sandbox_path,
                package=_package(sandbox_path),
                sha256=hashlib.sha256(data).hexdigest(),
                content=text[:MAX_SCRIPT_CHARS],
                truncated=len(text) > MAX_SCRIPT_CHARS or len(data) == MAX_READ_BYTES,
            )
        )
    return out
