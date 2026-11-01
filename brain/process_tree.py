"""Process ancestry over exec events: which npm lifecycle script a process descends from."""

from shared.contract import ExecEvent

MAX_CHAIN_DEPTH = 12
SHELLS = frozenset({"sh", "bash", "dash"})
NPM_PROCESSES = frozenset({"node", "npm", "npx"})


def base(path: str | None) -> str:
    return (path or "").rsplit("/", 1)[-1]


def ancestors(pid: int, execs: list[ExecEvent]) -> list[ExecEvent]:
    by_pid = {e.pid: e for e in execs}  # last exec per pid: its final image
    chain, seen = [], set()
    current = by_pid.get(pid)
    while current and current.pid not in seen and len(chain) < MAX_CHAIN_DEPTH:
        chain.append(current)
        seen.add(current.pid)
        current = by_pid.get(current.ppid) if current.ppid is not None else None
    return chain


def is_lifecycle_shell(e: ExecEvent) -> bool:
    return (
        base(e.binary) in SHELLS
        and base(e.parent_binary) in NPM_PROCESSES
        and (e.args.startswith("-c "))
    )


def lifecycle_exec(pid: int, execs: list[ExecEvent]) -> ExecEvent | None:
    """npm's `sh -c <script>` that the process at pid descends from (the outermost one)."""
    found = None
    for e in ancestors(pid, execs):
        if is_lifecycle_shell(e):
            found = e  # keep walking: a payload's own `sh -c` sits below npm's
    return found
