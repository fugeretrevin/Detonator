"""Point blocking findings at the diff lines that caused them (ROADMAP P1, "guilty line").

Deterministic, from kernel facts:
1. Walk the offending process up to the npm lifecycle `sh -c <script>` that started it and
   find the added package.json line declaring exactly that script.
2. If that script runs a file the PR adds or changes (`node scripts/x.js`), also point at
   the first added line there that spawns processes, evaluates code, opens connections, or
   decodes data.
3. Any added line containing the raw IP a flagged process connected to.
The model may explain a line afterwards; it never chooses one.
"""

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass

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


def for_prompt(lines: list[GuiltyLine]) -> list[dict]:
    """Ids are list positions; the model's line_explanations refer back to them."""
    return [
        {"id": i, "path": g.path, "line": g.line, "code": g.code.strip()[:400],
         "why_flagged": g.reason, "rules": list(g.rule_ids)}
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


def lifecycle_script(pid: int, execs: list[ExecEvent]) -> str | None:
    """The script npm ran (`sh -c <script>` whose parent is npm), for the process at pid."""
    script = None
    for e in _ancestors(pid, execs):
        if (
            _base(e.binary) in SHELLS
            and _base(e.parent_binary) in NPM_PROCESSES
            and e.args.startswith("-c ")
        ):
            script = e.args[3:].strip()  # keep walking: the outermost one is npm's
    if script and len(script) >= 2 and script[0] == script[-1] == '"':
        script = script[1:-1]  # Tetragon wraps the argument in quotes, inner ones untouched
    return script


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


def find_guilty_lines(
    hits: list[RuleHit], result: DetonateResult, files: list[ChangedFile]
) -> list[GuiltyLine]:
    by_path = {f.filename: f for f in files if f.patch}
    found: dict[tuple[str, int], GuiltyLine] = {}

    def add(path: str, line: int, code: str, reason: str, hit: RuleHit) -> None:
        key = (path, line)
        if key in found:
            g = found[key]
            if hit.rule_id not in g.rule_ids:
                found[key] = GuiltyLine(path, line, g.code, g.reason, (*g.rule_ids, hit.rule_id),
                                        g.pid)  # fmt: skip
        elif len(found) < MAX_GUILTY_LINES:
            found[key] = GuiltyLine(path, line, code, reason, (hit.rule_id,), hit.pid)

    for hit in hits:
        if hit.severity < Severity.HIGH or not hit.pid:
            continue
        script = lifecycle_script(hit.pid, result.exec_events)
        if script:
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
