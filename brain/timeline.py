"""What the install did, in order: one causal narrative from four kernel event streams.

The report already showed rule findings, process ancestry and network activity as three
separate sections, leaving the reviewer to reassemble the story. The story is the evidence.
For the Shai-Hulud reconstruction the kernel recorded, in this order:

    +0.00s  install started
    +0.52s  npm ran the `postinstall` script of the package
    +0.57s  node opened /home/runner/.aws/credentials
    +0.62s  node connected to github.com:443
    +0.64s  node connected to release-assets.githubusercontent.com:443
    +3.93s  node connected to webhook.site:443

Read as a list of findings that is four facts. Read in order it is an attack: read the
credentials, fetch the payload, post the result. Nothing here is inferred - every step is one
recorded event, and the ordering is the kernel's nanosecond timestamps, not a reconstruction.

**This is report-only, by construction.** It is built after `combine()` in `brain/pipeline.py`
and flows only into the rendered comment, exactly like `brain/evidence.py` grounding, so it
cannot move a verdict. It describes; it never judges. No step says "malicious", "suspicious" or
"exfiltration" - the rule findings section is where severity lives, and a reviewer reading a
neutral sequence and drawing their own conclusion is the point.

Two honest limits, surfaced rather than smoothed over:
  - `dns_queries` carry one-second resolution, while exec/connect/file carry nanoseconds. A DNS
    step's position *within* its second is not precise, so `coarse` marks it and the renderer
    says so rather than implying strict ordering.
  - `file_events` only covers the planted bait credential files, not general file I/O, so this
    is not a complete record of what the install touched. See `docs/WEAKPOINTS.md` W5.
"""

import re
from dataclasses import dataclass
from datetime import datetime

from brain.process_tree import base, is_lifecycle_shell, lifecycle_exec
from shared.contract import DetonateResult, ExecEvent

MAX_STEPS = 14
# npm's own bootstrap, before any package code can run. Collapsed into one "install started"
# step: it is identical on every run and says nothing about this package.
BOOTSTRAP = frozenset({"docker-entrypoint.sh", "npm", "node", "sh", "dash", "detonator-witness"})
MAX_DETAIL = 120


@dataclass(frozen=True)
class Step:
    """One recorded event. `actor`, `detail` and `package` are untrusted (they come from a
    sandbox that ran untrusted code) and MUST be escaped by the renderer; `action` is one of a
    fixed set of phrases chosen by this module, so it is safe."""

    offset_s: float | None  # seconds after the first event; None if timestamps were unusable
    kind: str  # install | script | exec | connect | dns | file
    actor: str  # basename of the process, e.g. "node", "curl"
    action: str  # code-chosen phrase, never from the record
    detail: str  # the specific thing: "github.com:443", a path, an args excerpt
    pid: int | None = None
    package: str | None = None  # node_modules/<pkg> whose lifecycle script this descends from
    coarse: bool = False  # the timestamp has only one-second resolution (DNS)


_TS_RE = re.compile(
    r"^(?P<whole>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"  # to the second
    r"(?:\.(?P<frac>\d+))?"  # optional fraction, any number of digits
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"  # optional zone
)


def _parse(ts: str | None) -> datetime | None:
    """RFC3339, tolerating the nine fractional digits Tetragon emits.

    The `[:6]` truncation to microseconds is explicit rather than load-bearing: CPython 3.11's
    own `fromisoformat` already truncates a longer fraction, which a mutation test confirmed by
    surviving its removal. It is kept because the parse should not depend on that, and because
    earlier versions raised instead. Returns None for anything unparseable; the caller keeps
    input order for those rather than inventing a time.
    """
    if not ts:
        return None
    m = _TS_RE.match(ts.strip())
    if not m:
        return None
    frac = (m.group("frac") or "").ljust(6, "0")[:6]
    tz = m.group("tz") or "Z"
    tz = "+00:00" if tz == "Z" else tz
    try:
        return datetime.fromisoformat(f"{m.group('whole')}.{frac}{tz}")
    except ValueError:  # pragma: no cover - the regex already constrains the shape
        return None


def _truncate(text: str, limit: int = MAX_DETAIL) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _script_label(e: ExecEvent) -> str:
    """The command npm's `sh -c` was given, without the `-c ` and surrounding quotes."""
    args = e.args.removeprefix("-c ").strip()
    if len(args) >= 2 and args[0] == args[-1] and args[0] in "\"'":
        args = args[1:-1]
    return _truncate(args)


def _package_of(pid: int | None, execs: list[ExecEvent]) -> str | None:
    """Which node_modules/<pkg> lifecycle script this pid descends from, via the kernel-recorded
    cwd that npm sets before any package code runs (see brain/pinpoint.py)."""
    if pid is None:
        return None
    life = lifecycle_exec(pid, execs)
    cwd = (life.cwd if life else None) or ""
    marker = "node_modules/"
    if marker not in cwd:
        return None
    rest = cwd.split(marker)[-1].strip("/")
    if not rest:
        return None
    parts = rest.split("/")
    # Scoped packages are two segments: @scope/name.
    return "/".join(parts[:2]) if parts[0].startswith("@") and len(parts) > 1 else parts[0]


def build_timeline(result: DetonateResult) -> list[Step]:
    """Merge the event streams into one ordered narrative.

    Pass the *redacted* view (`brain.redact`), not the raw result: a bait file's path and the
    decoy values are redacted there, and this must not reintroduce them.
    """
    execs = list(result.exec_events)
    raw: list[tuple[datetime | None, int, Step]] = []
    seq = 0

    def add(ts: str | None, step: Step) -> None:
        nonlocal seq
        raw.append((_parse(ts), seq, step))
        seq += 1

    bootstrap_seen = False
    for e in execs:
        name = base(e.binary)
        # `is_lifecycle_shell` is true of a payload's *own* `sh -c` too, because its parent is
        # the node process npm started. Attributing a payload's reverse shell to npm would be
        # a false statement about who did what, so only the outermost lifecycle shell for a
        # process gets that label; a nested one is reported as the shell it is. Observed on the
        # e5 fixture, where `bash -i >& /dev/tcp/...` was being called an npm install script.
        if is_lifecycle_shell(e):
            outer = lifecycle_exec(e.pid, execs)
            if outer is not None and outer.pid == e.pid and outer.ts == e.ts:
                pkg = _package_of(e.pid, execs)
                add(e.ts, Step(None, "script", "npm", "ran the install script",
                               _script_label(e), e.pid, pkg))  # fmt: skip
                continue
            add(e.ts, Step(None, "exec", name, "ran", _truncate(e.args), e.pid,
                           _package_of(e.pid, execs)))  # fmt: skip
            continue
        if name in BOOTSTRAP and not bootstrap_seen:
            # One step for npm's own startup, however many execs it takes.
            bootstrap_seen = True
            add(e.ts, Step(None, "install", "npm", "install started", "", e.pid))
            continue
        if name in BOOTSTRAP:
            continue
        add(e.ts, Step(None, "exec", name, "ran", _truncate(e.args), e.pid,
                       _package_of(e.pid, execs)))  # fmt: skip

    for c in result.connect_events:
        where = c.resolved_domain or c.daddr
        add(c.ts, Step(None, "connect", base(c.binary) or "?", "connected to",
                       f"{_truncate(where, 80)}:{c.dport}", c.pid,
                       _package_of(c.pid, execs)))  # fmt: skip

    for f in result.file_events:
        add(f.ts, Step(None, "file", base(f.binary) or "?", "opened",
                       _truncate(f.path), f.pid, _package_of(f.pid, execs)))  # fmt: skip

    for q in result.dns_queries:
        answers = ", ".join(q.answers[:3])
        detail = f"{_truncate(q.domain, 80)}" + (f" → {_truncate(answers, 60)}" if answers else "")
        add(q.ts, Step(None, "dns", "resolver", "resolved", detail, coarse=True))

    if not raw:
        return []

    # A DNS timestamp names only a second, so it truncates to that second's boundary and sorted
    # *before* "install started" - which cannot have happened. Clamping a coarse event to no
    # earlier than the first precisely-timed event removes an ordering we know to be false
    # without inventing precision we do not have: all it asserts is that nothing in this run
    # preceded the run's own first recorded event. The step stays marked `coarse`.
    fine = [t for t, _, s in raw if t is not None and not s.coarse]
    first_fine = min(fine) if fine else None
    clamped: list[tuple[datetime | None, int, Step]] = []
    for ts, order, step in raw:
        if step.coarse and ts is not None and first_fine is not None and ts < first_fine:
            ts = first_fine
        clamped.append((ts, order, step))

    dated = [t for t, _, _ in clamped if t is not None]
    first = min(dated) if dated else None
    last = max(dated) if dated else None

    def key(item: tuple[datetime | None, int, Step]) -> tuple[int, object, int]:
        ts, order, step = item
        if ts is None:
            # Undated events sort last rather than pretending to be at t=0.
            return (1, last or order, order)
        # Within one timestamp, a coarse event sits after precise ones: we know only its
        # second, so claiming it came first would be the same false ordering again.
        return (0, (ts, 1 if step.coarse else 0), order)

    ordered = sorted(clamped, key=key)
    out: list[Step] = []
    for ts, _, step in ordered:
        offset = (ts - first).total_seconds() if (ts is not None and first is not None) else None
        out.append(Step(offset, step.kind, step.actor, step.action, step.detail,
                        step.pid, step.package, step.coarse))  # fmt: skip
    return out


def truncated_count(steps: list[Step]) -> int:
    """How many steps a renderer capped at MAX_STEPS would have to leave out."""
    return max(0, len(steps) - MAX_STEPS)
