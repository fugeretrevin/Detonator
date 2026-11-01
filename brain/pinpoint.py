"""Point blocking findings at the diff lines that caused them (ROADMAP P1, "guilty line").

Deterministic, from kernel facts:
1. Walk the offending process up to the npm lifecycle `sh -c <script>` that started it and
   find the added package.json line declaring exactly that script.
2. If that script runs a file the PR adds or changes (`node scripts/x.js`), also point at
   the first added line there that spawns processes, evaluates code, opens connections, or
   decodes data.
3. If npm ran that script from node_modules/<pkg> (the kernel-recorded cwd), the culprit is
   a dependency: point at the PR line that adds or bumps <pkg> (package.json, else the
   lockfile) instead of the project's own scripts.
4. Any added line containing the raw IP a flagged process connected to.
The model may explain a line afterwards; it never chooses one.
"""

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace

from brain.github_client import ChangedFile
from brain.rules import RuleHit, Severity
from shared.contract import DetonateResult, ExecEvent

MAX_GUILTY_LINES = 3
MAX_CHAIN_DEPTH = 12
SHELLS = frozenset({"sh", "bash", "dash"})
NPM_PROCESSES = frozenset({"node", "npm", "npx"})

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_LIFECYCLE_RE = re.compile(
    r'^\s*"(preinstall|install|postinstall|prepare|preprepare|postprepare)"\s*:\s*"(.*)"\s*,?\s*$'
)
# Most to least specific: where the payload runs beats where it is decoded or imported.
SUSPICIOUS = (
    ("runs a process", re.compile(r"\b(spawn|spawnSync|exec|execSync|execFile|fork)\s*\(")),
    ("evaluates code", re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")),
    (
        "opens a connection",
        re.compile(
            r"/dev/tcp|\bnet\.(connect|createConnection)|\bhttps?\.(request|get)\s*\(|"
            r"\bfetch\s*\(|\bdgram\b"
        ),
    ),  # fmt: skip
    ("decodes data", re.compile(r"Buffer\.from\s*\(|\batob\s*\(|base64")),
    ("loads child_process", re.compile(r"child_process")),
)


@dataclass(frozen=True)
class GuiltyLine:
    path: str
    line: int  # line number in the PR head (the RIGHT side of the diff)
    code: str  # untrusted: escape before rendering
    reason: str
    rule_ids: tuple[str, ...]
    pid: int  # the flagged process, for the chain in the comment
    package: str | None = None  # dependency whose install script ran (None: the project's)


def for_prompt(lines: list[GuiltyLine]) -> list[dict]:
    """Ids are list positions; the model's line_explanations refer back to them."""
    return [
        {"id": i, "path": g.path, "line": g.line, "code": g.code.strip()[:400],
         "why_flagged": g.reason, "rules": list(g.rule_ids),
         **({"dependency_that_ran_the_script": g.package} if g.package else {})}
        for i, g in enumerate(lines)
    ]  # fmt: skip


def added_lines(patch: str | None) -> list[tuple[int, str]]:
    """(head line number, text) for every '+' line of a unified diff patch."""
    out: list[tuple[int, str]] = []
    line = 0
    for raw in (patch or "").splitlines():
        if m := _HUNK_RE.match(raw):
            line = int(m.group(1))
        elif raw.startswith("+"):
            out.append((line, raw[1:]))
            line += 1
        elif raw.startswith(" "):
            line += 1
        # '-' lines and '\ No newline' don't exist in the head file
    return out


def _base(path: str | None) -> str:
    return (path or "").rsplit("/", 1)[-1]


def _ancestors(pid: int, execs: list[ExecEvent]) -> list[ExecEvent]:
    by_pid = {e.pid: e for e in execs}  # last exec per pid: its final image
    chain, seen = [], set()
    current = by_pid.get(pid)
    while current and current.pid not in seen and len(chain) < MAX_CHAIN_DEPTH:
        chain.append(current)
        seen.add(current.pid)
        current = by_pid.get(current.ppid) if current.ppid is not None else None
    return chain


def _is_lifecycle_shell(e: ExecEvent) -> bool:
    return (
        _base(e.binary) in SHELLS
        and _base(e.parent_binary) in NPM_PROCESSES
        and e.args.startswith("-c ")
    )


def lifecycle_exec(pid: int, execs: list[ExecEvent]) -> ExecEvent | None:
    """npm's `sh -c <script>` that the process at pid descends from (the outermost one)."""
    found = None
    for e in _ancestors(pid, execs):
        if _is_lifecycle_shell(e):
            found = e  # keep walking: a payload's own `sh -c` sits below npm's
    return found


def script_text(e: ExecEvent) -> str:
    script = e.args[3:].strip()
    if len(script) >= 2 and script[0] == script[-1] == '"':
        script = script[1:-1]  # Tetragon wraps the argument in quotes, inner ones untouched
    return script


def lifecycle_script(pid: int, execs: list[ExecEvent]) -> str | None:
    e = lifecycle_exec(pid, execs)
    return script_text(e) if e else None


def package_from_cwd(cwd: str | None) -> str | None:
    """`.../node_modules/@scope/name` -> `@scope/name`; None for the project's own scripts.

    npm sets this cwd before any package code runs, so a payload can't forge it.
    """
    parts = (cwd or "").rstrip("/").split("/")
    if "node_modules" not in parts:
        return None
    i = len(parts) - 1 - parts[::-1].index("node_modules")  # innermost: nested deps
    rest = parts[i + 1 :]
    if not rest:
        return None
    if rest[0].startswith("@") and len(rest) > 1:
        return f"{rest[0]}/{rest[1]}"
    return rest[0]


@dataclass(frozen=True)
class ScriptRun:
    """One install-time script npm ran: the project's own (package None) or a dependency's."""

    package: str | None
    script: str  # untrusted
    pid: int
    flagged: bool


def script_runs(hits: list[RuleHit], result: DetonateResult) -> list[ScriptRun]:
    flagged = {
        e.pid
        for h in hits
        if h.severity >= Severity.HIGH and h.pid
        if (e := lifecycle_exec(h.pid, result.exec_events))
    }
    runs: dict[tuple[str | None, str], ScriptRun] = {}
    for e in result.exec_events:
        # Only npm's own shells: a payload's `sh -c` under node also matches the shape.
        if not _is_lifecycle_shell(e) or (
            e.ppid is not None and lifecycle_exec(e.ppid, result.exec_events)
        ):
            continue
        key = (package_from_cwd(e.cwd), script_text(e))
        prior = runs.get(key)
        runs[key] = ScriptRun(*key, e.pid, e.pid in flagged or bool(prior and prior.flagged))
    return list(runs.values())


def _norm(text: str) -> str:
    return " ".join(text.split())


def _json_string(raw: str) -> str:
    try:
        return json.loads(f'"{raw}"')
    except ValueError:
        return raw


def _script_files(script: str, files: dict[str, ChangedFile]) -> list[str]:
    tokens = (t.strip("'\"").removeprefix("./") for t in script.split())
    return [t for t in tokens if t in files]


def _first_suspicious(lines: Iterable[tuple[int, str]]) -> tuple[int, str, str] | None:
    lines = list(lines)
    for reason, pattern in SUSPICIOUS:
        for number, text in lines:
            if pattern.search(text):
                return number, text, reason
    return None


def _dependency_lines(
    package: str, by_path: dict[str, ChangedFile]
) -> list[tuple[str, int, str, str]]:
    """The PR's own lines that add or change `package`: package.json first, else the lockfile."""
    name = re.escape(package)
    direct = re.compile(rf'^\s*"{name}"\s*:\s*"')
    locked = re.compile(rf'^\s*"(?:[^"]*/)?node_modules/{name}"\s*:')
    reason = f"brings in {package}, whose install script ran"
    for wanted, pattern in (("package.json", direct), ("package-lock.json", locked)):
        hits = [
            (path, number, text, reason)
            for path, f in by_path.items()
            if _base(path) == wanted
            for number, text in added_lines(f.patch)
            if pattern.match(text)
        ]
        if hits:
            return hits
    return []


def find_guilty_lines(
    hits: list[RuleHit], result: DetonateResult, files: list[ChangedFile]
) -> list[GuiltyLine]:
    by_path = {f.filename: f for f in files if f.patch}
    found: dict[tuple[str, int], GuiltyLine] = {}

    def add(path: str, line: int, code: str, reason: str, hit: RuleHit,
            package: str | None = None) -> None:  # fmt: skip
        key = (path, line)
        if key in found:
            g = found[key]
            if hit.rule_id not in g.rule_ids:
                found[key] = replace(g, rule_ids=(*g.rule_ids, hit.rule_id))
        elif len(found) < MAX_GUILTY_LINES:
            found[key] = GuiltyLine(path, line, code, reason, (hit.rule_id,), hit.pid, package)

    for hit in hits:
        if hit.severity < Severity.HIGH or not hit.pid:
            continue
        npm_shell = lifecycle_exec(hit.pid, result.exec_events)
        package = package_from_cwd(npm_shell.cwd) if npm_shell else None
        if package:
            # A dependency's script: blame the line that brought that dependency in, never
            # the project's own scripts (a dependency's `node install.js` could coincide).
            for path, number, text, reason in _dependency_lines(package, by_path):
                add(path, number, text, reason, hit, package)
        elif npm_shell:
            script = script_text(npm_shell)
            for path, f in by_path.items():
                if _base(path) != "package.json":
                    continue
                for number, text in added_lines(f.patch):
                    m = _LIFECYCLE_RE.match(text)
                    if m and _norm(_json_string(m.group(2))) == _norm(script):
                        add(path, number, text, f"`{m.group(1)}` script npm ran", hit)
            for path in _script_files(script, by_path):
                if spot := _first_suspicious(added_lines(by_path[path].patch)):
                    number, text, reason = spot
                    add(path, number, text, reason, hit)
        if hit.rule_id == "NET_RAW_IP":
            ips = {c.daddr for c in result.connect_events if c.pid == hit.pid}
            for path, f in by_path.items():
                for number, text in added_lines(f.patch):
                    if any(ip in text for ip in ips):
                        add(path, number, text, "contains the address it connected to", hit)

    return sorted(found.values(), key=lambda g: (g.path, g.line))
