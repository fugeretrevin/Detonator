"""Replay a recorded detonation offline: the real rules on a real kernel record, with no keys.

The full pipeline needs the Chamber VM, GitHub and the Meta Model API. This needs none of them.
It loads a `DetonateResult` the Chamber really returned (`tests/fixtures/detonate_real_*.json`),
runs the same rule engine and verdict code the Brain runs, and prints the install as a timeline
with each finding under the event that caused it. It is how someone without credentials can
watch the kernel half of PR Detonator work, in seconds.

  python -m brain.replay              # list the recordings
  python -m brain.replay dep          # replay one (a name below, or a path to a result JSON)
  python -m brain.replay dep --live   # at the recording's own pace, for a demo
  python -m brain.replay --all        # every recording; exit 1 if any verdict changed

What it leaves out, so the output never claims more than it ran:
- Muse. The verdict shown is the rules-only one, as in the evaluation's rules-only arm. In the
  real pipeline the model can raise it, and can never lower a high or critical finding.
- Reverse-DNS enrichment, which needs the network. A connect the sandbox never looked up stays
  a raw IP, which is also what enrichment concludes when the reverse name doesn't confirm.
- The Intent Contract, the base-branch differential and the guilty line, which need the PR's
  text and diff.
"""

import json
import posixpath
import sys
import textwrap
import time
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from brain.decoys import decoy_hits, redact, redact_text
from brain.llm import LlmOutcome
from brain.rules import RuleHit, evaluate
from brain.sbom import terminal_safe
from brain.verdict import FinalVerdict, combine
from shared.contract import DetonateResult

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
MAX_LIVE_PAUSE_S = 1.5
TIME_COL = 9  # width of the "+0.000s" column


@dataclass(frozen=True)
class Recording:
    name: str
    title: str
    expected: str  # the rules-only verdict this run produces; --all fails if it changes


RECORDINGS = {
    r.name: r
    for r in (
        Recording(
            "dep",
            "Bump color-helper from 1.0.0 to 1.0.1 (new version opens a raw socket)",
            "Blocked",
        ),
        Recording("e4", "Fix typo in README (postinstall posts env to a raw IP)", "Blocked"),
        Recording("e5", "Add install-time telemetry opt-out (base64 reverse shell)", "Blocked"),
        Recording(
            "r01", "ua-parser-js 0.7.29, the 2021 hijack (reconstructed, defanged)", "Blocked"
        ),
        Recording("r02", "Shai-Hulud worm, 2025 (reconstructed, defanged)", "Blocked"),
        Recording("re2", "Add re2 (benign: downloads a prebuilt binary at install)", "Clean"),
    )
}


@dataclass(frozen=True)
class Line:
    at: datetime
    exact: bool  # False for DNS answers, which the resolver logs to the second
    kind: str
    text: str
    key: tuple[str, int] | None  # (ts, pid) that rule hits carry, to attach them here


@dataclass(frozen=True)
class Replay:
    recording: Recording | None
    source: Path
    result: DetonateResult  # decoy values redacted, as everything shown or posted is
    hits: list[RuleHit]
    final: FinalVerdict


def _when(ts: str) -> datetime:
    """Kernel timestamps carry nanoseconds; datetime takes six digits at most."""
    ts = ts.rstrip("Z")
    if "." in ts:
        whole, frac = ts.split(".", 1)
        ts = f"{whole}.{frac[:6]}"
    return datetime.fromisoformat(ts)


def resolve(target: str) -> tuple[Recording | None, Path]:
    if target in RECORDINGS:
        return RECORDINGS[target], FIXTURES / f"detonate_real_{target}.json"
    return None, Path(target)


def replay(target: str) -> Replay:
    recording, source = resolve(target)
    raw = DetonateResult.model_validate(json.loads(source.read_text(encoding="utf-8")))
    # As in brain.pipeline: rules see the raw record, everything displayed sees decoys redacted.
    hits = evaluate(raw) + decoy_hits(raw)
    hits.sort(key=lambda h: (-h.severity, h.ts))
    hits = [replace(h, evidence=redact_text(h.evidence, raw)) for h in hits]
    final = combine(hits, LlmOutcome(model="not run in replay", skipped=True), raw)
    return Replay(recording, source, redact(raw), hits, final)


def _where(cwd: str | None) -> str:
    if cwd and "node_modules/" in cwd:
        return "  in node_modules/" + cwd.split("node_modules/", 1)[1]
    return ""


def _command(binary: str, args: str) -> str:
    """Tetragon's args sometimes repeat the binary's own path; show it once, by name."""
    if args.startswith(binary):
        args = args[len(binary) :].lstrip()
    return f"{posixpath.basename(binary)} {args}".rstrip()


def timeline(result: DetonateResult) -> list[Line]:
    lines = [
        Line(_when(e.ts), True, "exec", _command(e.binary, e.args) + _where(e.cwd), (e.ts, e.pid))
        for e in result.exec_events
    ]
    for c in result.connect_events:
        if c.protocol != "tcp":
            text = f"{c.protocol} to {c.daddr}:{c.dport}  rejected by the sandbox firewall"
        else:
            dest = c.resolved_domain or c.daddr
            lookup = "" if c.resolved_domain else "  no DNS lookup"
            text = f"{posixpath.basename(c.binary)} -> {dest}:{c.dport}{lookup}"
        lines.append(Line(_when(c.ts), True, "connect", text, (c.ts, c.pid)))
    for f in result.file_events:
        lines.append(
            Line(
                _when(f.ts),
                True,
                "file",
                f"{posixpath.basename(f.binary)} opened {f.path}",
                (f.ts, f.pid),
            )
        )
    for q in result.dns_queries:
        answers = ", ".join(q.answers[:3]) + (" ..." if len(q.answers) > 3 else "")
        lines.append(Line(_when(q.ts), False, "dns", f"lookup {q.domain} -> {answers}", None))
    return sorted(lines, key=lambda line: line.at)


def _offset(line: Line, start: datetime) -> str:
    if not line.exact:
        return "~".rjust(TIME_COL - 2).ljust(TIME_COL)
    return f"+{(line.at - start).total_seconds():.3f}s".rjust(TIME_COL)


def _hit(h: RuleHit) -> str:
    evidence = terminal_safe(h.evidence, 240)
    return f"{'':{TIME_COL}}  ! {h.rule_id} ({h.severity.name.lower()}) {evidence}"


def render(r: Replay, live: bool = False, out=print) -> None:
    """Print the replay. Every value from the record is untrusted (it came from a sandbox that
    ran attacker code), so all of it goes through `terminal_safe`."""
    safe = lambda s: terminal_safe(str(s), 160)  # noqa: E731
    title = r.recording.title if r.recording else r.source.name
    res = r.result
    out(f"PR Detonator replay: {safe(title)}")
    out(
        f"Recorded by the Chamber: job {safe(res.job_id[:8])}, {res.duration_s}s, "
        f"exit {res.exit_code}. Kernel events from Tetragon, DNS from the sandbox resolver."
    )
    out("")

    lines = timeline(res)
    start = next((line.at for line in lines if line.exact), None)
    by_event: dict[tuple[str, int], list[RuleHit]] = {}
    for h in r.hits:
        by_event.setdefault((h.ts, h.pid), []).append(h)
    previous = start
    for line in lines:
        if live and line.exact and previous is not None:
            time.sleep(min(MAX_LIVE_PAUSE_S, max(0.0, (line.at - previous).total_seconds())))
            previous = line.at
        out(f"{_offset(line, start)}  {line.kind:<8} {safe(line.text)}")
        for h in by_event.pop(line.key, []) if line.key else []:
            out(_hit(h))
    for h in (h for hits in by_event.values() for h in hits):  # findings with no single event
        out(_hit(h))

    f = r.final
    out("")
    out(f"Rules fired: {', '.join(sorted({h.rule_id for h in r.hits})) or 'none'}")
    out(f"Verdict, rules only: {f.title} (severity {f.level.name.lower()})")
    if f.reason:
        out(f"  Not verified: {safe(f.reason)}")
    out(
        textwrap.fill(
            "Muse did not run: that needs a Meta API key. In the full pipeline it predicts the "
            "install's behavior before it runs and explains the result after. It can raise this "
            "verdict, never lower a high or critical finding.",
            width=100,
        )
    )


def _list(out=print) -> None:
    out(__doc__.split("\n\n")[0])
    out("")
    out("Recordings (python -m brain.replay <name>):")
    for r in RECORDINGS.values():
        out(f"  {r.name:<5} {r.title}")


def _all(out=print) -> int:
    changed = 0
    out(f"{'name':<5}  {'verdict':<17}  rules fired")
    for name, rec in RECORDINGS.items():
        r = replay(name)
        ok = r.final.title == rec.expected
        changed += not ok
        fired = ", ".join(sorted({h.rule_id for h in r.hits})) or "none"
        flag = "" if ok else f"   CHANGED: expected {rec.expected}"
        out(f"{name:<5}  {r.final.title:<17}  {fired}{flag}")
    total = len(RECORDINGS)
    out("")
    out(f"{total - changed} of {total} recordings reproduce their verdict from the rules alone.")
    return 1 if changed else 0


def _main(argv: list[str]) -> int:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
    live = "--live" in argv
    args = [a for a in argv if a != "--live"]
    if args == ["--all"]:
        return _all()
    if len(args) != 1 or args[0].startswith("-"):
        _list()
        return 0 if not args else 2
    recording, source = resolve(args[0])
    if recording is None and not source.is_file():
        print(f"No recording named {args[0]!r} and no such file.", file=sys.stderr)
        print(f"Recordings: {', '.join(RECORDINGS)}", file=sys.stderr)
        return 2
    render(replay(args[0]), live=live)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
