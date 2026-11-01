"""Markdown forensic report for the PR comment and check-run summary (BUILD_PLAN A6).

Every string that came from the PR, the sandbox, or the LLM is attacker-influenced, so it
goes through esc(): punctuation becomes HTML entities, which GitHub renders literally and
never parses as markdown, links, @mentions, or HTML.
"""

import unicodedata

from brain.github_client import COMMENT_MARKER
from brain.intent import IntentContract
from brain.llm import LlmOutcome
from brain.pinpoint import GuiltyLine, ScriptRun
from brain.rules import RuleHit, Severity
from brain.verdict import FinalVerdict
from shared.contract import DetonateResult, ExecEvent

HEADERS = {
    "Blocked": "🛑 Blocked",
    "Needs review": "⚠️ Needs review",
    "Could not verify": "⚠️ Could not verify",
    "Clean": "✅ Clean",
}
MAX_CELL = 160
MAX_ROWS = 15
MAX_CHAIN_DEPTH = 8


def esc(text: str | None, limit: int = MAX_CELL) -> str:
    if not text:
        return ""
    text = " ".join(text.split())
    clipped = len(text) > limit
    out = []
    for ch in text[:limit]:
        if unicodedata.category(ch) in ("Cc", "Cf"):  # control chars, bidi overrides
            continue
        out.append(ch if ch.isalnum() or ch == " " else f"&#{ord(ch)};")
    return "".join(out) + ("…" if clipped else "")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def process_chain(pid: int, execs: list[ExecEvent]) -> str:
    """e.g. `npm install → sh -c curl ... → curl -s ...`, newest last."""
    by_pid = {e.pid: e for e in execs}
    chain: list[ExecEvent] = []
    seen: set[int] = set()
    current = by_pid.get(pid)
    while current and current.pid not in seen and len(chain) < MAX_CHAIN_DEPTH:
        chain.append(current)
        seen.add(current.pid)
        current = by_pid.get(current.ppid) if current.ppid is not None else None
    steps = [esc(f"{_basename(e.binary)} {e.args}", 80) for e in reversed(chain)]
    return " → ".join(steps)


def _rule_rows(hits: list[RuleHit]) -> list[str]:
    icon = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.LOW: "🟡"}
    rows = ["| Severity | Rule | Evidence |", "|---|---|---|"]
    for h in hits[:MAX_ROWS]:
        rows.append(
            f"| {icon.get(h.severity, '')} {h.severity.name.lower()} | `{h.rule_id}` "
            f"| {esc(h.evidence, 240)} |"
        )
    if len(hits) > MAX_ROWS:
        rows.append(f"| | | …and {len(hits) - MAX_ROWS} more |")
    return rows


def _network_rows(result: DetonateResult) -> list[str]:
    rows = ["| Time | Process | Destination | Name |", "|---|---|---|---|"]
    for c in result.connect_events[:MAX_ROWS]:
        name = esc(c.resolved_domain) if c.resolved_domain else "**no DNS lookup preceded this**"
        rows.append(
            f"| {esc(c.ts, 40)} | {esc(_basename(c.binary), 40)} ({c.pid}) "
            f"| {esc(c.daddr, 60)}&#58;{c.dport} | {name} |"
        )
    if len(result.connect_events) > MAX_ROWS:
        rows.append(f"| | | …and {len(result.connect_events) - MAX_ROWS} more | |")
    return rows


STATUS_ICON = {"explained": "✅ predicted", "unexplained": "❌ **unexplained**"}


def _contract_section(contract: IntentContract, cleared: list[RuleHit]) -> list[str]:
    lines = ["### Intent contract", ""]
    p = contract.prediction
    if not p:
        return lines + [f"Prediction unavailable ({esc(contract.error, 80)}).", ""]
    lines += [
        "*Predicted from the PR's title, description and file list, before the sandbox ran:* "
        + esc(p.summary, 300),
        "",
    ]
    shown = [i for i in contract.items if i.status != "baseline"]
    baseline = len(contract.items) - len(shown)
    if shown:
        lines += ["| Observed at runtime | Contract |", "|---|---|"]
        for i in shown[:MAX_ROWS]:
            note = f" ({esc(i.note, 40)})" if i.note and i.status == "unexplained" else ""
            lines.append(f"| {i.kind} {esc(i.observed, 80)} | {STATUS_ICON[i.status]}{note} |")
        lines.append("")
    summary = f"{len(contract.unexplained)} unexplained, {len(contract.explained)} predicted"
    lines += [f"{summary}, {baseline} normal npm behavior.", ""]
    if cleared:
        hosts = ", ".join(esc(h.target, 60) for h in cleared)
        lines += [f"Cleared low-severity findings explained by the stated intent: {hosts}.", ""]
    return lines


def _line_explanation(llm: LlmOutcome, index: int) -> str | None:
    return llm.verdict.line_explanation(index) if llm.verdict else None


def _guilty_section(guilty: list[GuiltyLine], llm: LlmOutcome) -> list[str]:
    lines = ["### Where it came from", ""]
    for i, g in enumerate(guilty):
        # Paths are PR-controlled: escaped, so never inside a code span (entities show raw).
        lines.append(f"- **{esc(g.path, 120)}** line {g.line} ({esc(g.reason, 60)}): "
                     f"{esc(g.code.strip(), 200)}")  # fmt: skip
        if what := _line_explanation(llm, i):
            lines.append(f"  - *What it does:* {esc(what, 300)}")
    return lines + [""]


def render_line_comment(g: GuiltyLine, index: int, llm: LlmOutcome, result: DetonateResult) -> str:
    """Body of the review comment placed on the guilty line itself."""
    rules = ", ".join(f"`{r}`" for r in g.rule_ids)  # our own rule ids, not PR data
    if g.package:
        head = (
            f"🛑 **PR Detonator:** this line brings in the dependency "
            f"**{esc(g.package, 100)}**, whose install script ran during `npm install` "
            f"and triggered {rules}."
        )
    else:
        head = f"🛑 **PR Detonator:** this line ran during `npm install` and triggered {rules}."
    lines = [head, ""]
    if what := _line_explanation(llm, index):
        lines += [f"**What it does:** {esc(what, 300)}", ""]
    if chain := process_chain(g.pid, result.exec_events):
        lines += [f"**Observed process chain:** {chain}", ""]
    lines.append("<sub>Kernel-traced in a sandbox. Full report in the PR comment.</sub>")
    return "\n".join(lines)


def _script_runs_section(runs: list[ScriptRun]) -> list[str]:
    """Every install-time script, benign or not: who ran code on this machine."""
    lines = ["### Packages that ran install scripts", ""]
    for r in runs[:MAX_ROWS]:
        who = f"dependency **{esc(r.package, 100)}**" if r.package else "this project"
        mark = "🛑 " if r.flagged else ""
        lines.append(f"- {mark}{who}: {esc(r.script, 120)}")
    if len(runs) > MAX_ROWS:
        lines.append(f"- …and {len(runs) - MAX_ROWS} more")
    return lines + [""]


def render(
    final: FinalVerdict,
    hits: list[RuleHit],
    llm: LlmOutcome,
    result: DetonateResult,
    *,
    job_id: str,
    contract: IntentContract | None = None,
    cleared: list[RuleHit] | None = None,
    guilty: list[GuiltyLine] | None = None,
    script_runs: list[ScriptRun] | None = None,
) -> str:
    lines = [f"## PR Detonator: {HEADERS[final.title]}", ""]

    if not final.verified:
        lines += [
            f"> The sandboxed install did not finish (`{result.status}`), so this PR could "
            "not be fully verified. Behavior observed before it stopped is shown below.",
            "",
        ]

    v = llm.verdict
    if v:
        lines += [
            "| | |",
            "|---|---|",
            f"| **Stated intent** | {esc(v.stated_intent, 300)} |",
            f"| **Observed behavior** | {esc(v.observed_behavior, 300)} |",
            f"| **Mismatch** | {'yes' if v.mismatch else 'no'} |",
            "",
            esc(v.explanation, 900),
            "",
        ]
        if v.injection_attempt:
            lines += [
                "> ⚠️ **Prompt-injection attempt detected.** The PR content tries to instruct "
                "the AI reviewer. It was treated as data; deterministic rules still apply.",
                "",
            ]

    if guilty:
        lines += _guilty_section(guilty, llm)

    if script_runs:
        lines += _script_runs_section(script_runs)

    if contract is not None:
        lines += _contract_section(contract, cleared or [])

    if hits:
        lines += ["### Rule findings", "", *_rule_rows(hits), ""]
        chains = []
        for h in hits:
            if h.rule_id.startswith("EXEC_") or h.rule_id == "NET_RAW_IP":
                chain = process_chain(h.pid, result.exec_events)
                if chain and chain not in chains:
                    chains.append(chain)
        if chains:
            lines += ["### Process tree", ""]
            lines += [f"- {c}" for c in chains[:5]]
            lines += [""]
    else:
        lines += ["No deterministic rule fired.", ""]

    if result.connect_events:
        lines += ["### Network activity", "", *_network_rows(result), ""]

    model_note = llm.model if v else f"{llm.model} (unavailable: {esc(llm.error, 80)}; rules only)"
    lines += [
        "---",
        f"<sub>Detonated `npm install` in {result.duration_s:.1f}s · "
        f"{len(result.exec_events)} exec / {len(result.connect_events)} connect events"
        f"{' (truncated)' if result.truncated else ''} · model {model_note} · job `{job_id}`"
        "</sub>",
        "",
        COMMENT_MARKER,
    ]
    return "\n".join(lines)
