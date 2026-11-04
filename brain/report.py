"""Markdown forensic report for the PR comment and check-run summary.

Every string that came from the PR, the sandbox, or the LLM is attacker-influenced, so it
goes through esc(): punctuation becomes HTML entities, which GitHub renders literally and
never parses as markdown, links, @mentions, or HTML.
"""

import json
import re
import unicodedata

from brain.differential import Differential
from brain.evidence import Grounding
from brain.github_client import COMMENT_MARKER
from brain.intent import IntentContract
from brain.investigator import Investigation
from brain.llm import LlmOutcome
from brain.pinpoint import GuiltyLine, ScriptRun
from brain.policy import POLICY_PATH, Policy
from brain.prompt_guard import GuardOutcome, flagged
from brain.rules import RuleHit, Severity
from brain.timeline import MAX_STEPS as MAX_TIMELINE_STEPS
from brain.timeline import Step
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
        who = f"{esc(_basename(c.binary), 40)} ({c.pid})" if c.binary else "unknown (firewall log)"
        proto = "" if c.protocol == "tcp" else f" {esc(c.protocol.upper(), 8)}, blocked"
        rows.append(
            f"| {esc(c.ts, 40)} | {who} | {esc(c.daddr, 60)}&#58;{c.dport}{proto} | {name} |"
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
        where = f"**{esc(g.path, 120)}** line {g.line}"
        if not g.in_diff:
            digest = esc((g.sha256 or "")[:16], 16)
            where = (f"inside dependency **{esc(g.package, 100)}**: {where} "
                     f"(sha256 {digest}…, captured from the sandbox)")  # fmt: skip
        lines.append(f"- {where} ({esc(g.reason, 60)}): {esc(g.code.strip(), 200)}")
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


RUNS_MARKER = "pr-detonator-runs:"
MAX_RUNS = 10
_RUNS_RE = re.compile(r"<!-- " + re.escape(RUNS_MARKER) + r" (\[.*?\]) -->")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def parse_runs(previous_body: str | None) -> list[tuple[str, str]]:
    """(sha, verdict title) pairs from our own earlier comment, strictly validated. PR content
    in that comment is entity-encoded, so it can't forge the marker; this checks anyway."""
    m = _RUNS_RE.search(previous_body or "")
    if not m:
        return []
    try:
        raw = json.loads(m.group(1))
    except ValueError:
        return []
    return [
        (r["sha"], r["v"])
        for r in raw
        if isinstance(r, dict) and _SHA_RE.match(str(r.get("sha", ""))) and r.get("v") in HEADERS
    ][:MAX_RUNS]


def with_run_history(body: str, previous_body: str | None, sha: str, title: str) -> str:
    """Append "Previous runs" (newest first, excluding this one) and the hidden history."""
    runs = [(sha, title)] + [r for r in parse_runs(previous_body) if r[0] != sha]
    runs = runs[:MAX_RUNS]
    earlier = runs[1:]
    lines = [body]
    if earlier:
        shown = " · ".join(f"`{s[:7]}` {HEADERS[v]}" for s, v in earlier)
        lines.append(f"<sub>Previous runs: {shown}</sub>")
    lines.append(f"<!-- {RUNS_MARKER} {json.dumps([{'sha': s, 'v': v} for s, v in runs])} -->")
    return "\n\n".join(lines)


def _guard_note(guard: GuardOutcome | None) -> str:
    if guard is None:
        return ""
    if guard.error:
        return f" · Prompt Guard 2 unavailable ({esc(guard.error, 40)})"
    score = guard.top.score if guard.top else 0.0
    return f" · Prompt Guard 2 max {score:.2f}"


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


def _differential_section(diff: "Differential") -> list[str]:
    """What the PR changed versus the base branch (only shown when the base detonated)."""
    if diff.base_unverified or diff.base_status != "completed":
        why = diff.base_unverified or f"status `{esc(diff.base_status, 20)}`"
        lines = ["### Compared to the base branch", "",
                 f"The base branch could not be used for comparison ({esc(why, 160)}), so "
                 "no behavior was suppressed as pre-existing.", ""]  # fmt: skip
        return lines
    lines = ["### Compared to the base branch", ""]
    if diff.new_behaviors:
        lines.append("**New at install in this PR** (not seen on the base):")
        lines += [f"- `{esc(b, 100)}`" for b in diff.new_behaviors[:MAX_ROWS]]
    else:
        lines.append("No new install-time behavior versus the base branch.")
    if diff.pre_existing:
        hosts = ", ".join(esc(h.target, 60) for h in diff.pre_existing)
        lines += ["", f"Pre-existing low-severity findings the base already produced "
                  f"(not counted against this PR): {hosts}."]  # fmt: skip
    return lines + [""]


RISK_ICON = {"benign": "🟢", "unclear": "🟡", "suspicious": "🟠", "malicious": "🔴"}


def _investigation_section(inv: "Investigation") -> list[str]:
    """Triage note for a ⚠️ PR, with the agent's tool calls collapsed underneath."""
    if inv.error or not inv.risk:
        why = esc(inv.error or "no result", 60)
        return ["### Triage", "",
                f"The investigator agent was unavailable ({why}); the findings above stand.",
                ""]  # fmt: skip
    lines = [
        "### Triage",
        "",
        f"{RISK_ICON.get(inv.risk, '')} **{esc(inv.risk, 20)}** — {esc(inv.note, 600)}",
        "",
    ]
    if inv.facts:
        lines += [f"- {esc(f, 200)}" for f in inv.facts[:5]] + [""]
    if inv.tool_log:
        lines += ["<details><summary>What the agent checked "
                  f"({len(inv.tool_log)} tool calls)</summary>", ""]  # fmt: skip
        for call, out in inv.tool_log:
            lines.append(f"- `{esc(call, 120)}` → {esc(out, 200)}")
        lines += ["", "</details>", ""]
    return lines


def _grounding_section(g: "Grounding") -> list[str]:
    """The AI's evidence, as checked by code: each supported claim is shown as the kernel's
    own record of the cited event; the model only supplies the reason it matters."""
    if not g.claims and not g.unsupported_mentions:
        return []
    lines = ["<details><summary>Evidence the AI cited, checked against the kernel record "
             f"({len(g.supported)} of {g.claims} supported)</summary>", ""]  # fmt: skip
    for c in g.supported[:MAX_ROWS]:
        if c.kind == "source_inferred":
            lines.append(f"- 📄 *seen in source, not observed running* — {esc(c.why, 200)}")
            continue
        for item in c.items[:2]:
            lines.append(f"- 🔬 `{esc(item.text, 160)}` — {esc(c.why, 200)}")
    if g.rejected:
        lines.append(f"- {len(g.rejected)} claim(s) left out: they cited no matching kernel "
                     "event, so they are not presented as fact.")  # fmt: skip
    if g.unsupported_mentions:
        names = ", ".join(f"`{esc(m, 60)}`" for m in g.unsupported_mentions[:5])
        lines.append(f"- ⚠️ The AI's summary mentions {names}, which appear in neither the "
                     "kernel record nor the diff.")  # fmt: skip
    return lines + ["", "</details>", ""]


_TIMELINE_ICON = {
    "install": "▶",
    "script": "📜",
    "exec": "⚙",
    "connect": "🌐",
    "file": "📂",
    "dns": "🔎",
}


def _timeline_section(steps: "list[Step]") -> list[str]:
    """What the install did, in order. Report-only and deliberately verdict-free: the severity
    lives in the rule findings above, and a reviewer reading a neutral sequence and drawing
    their own conclusion is the whole point. Every value here came from a sandbox running
    untrusted code, so actor/detail/package are escaped; `action` is chosen by
    `brain/timeline.py`, never taken from the record."""
    if len(steps) < 2:  # a single "install started" line is not a narrative
        return []
    shown, hidden = steps[:MAX_TIMELINE_STEPS], max(0, len(steps) - MAX_TIMELINE_STEPS)
    lines = ["### What happened, in order", ""]
    for s in shown:
        when = f"`+{s.offset_s:.2f}s`" if s.offset_s is not None else "`?`"
        icon = _TIMELINE_ICON.get(s.kind, "·")
        parts = [when, icon, f"**{esc(s.actor, 40)}**", s.action]
        if s.detail:
            parts.append(f"`{esc(s.detail, 120)}`")
        if s.package:
            parts.append(f"— from `{esc(s.package, 60)}`")
        if s.coarse:
            parts.append("*(±1s)*")
        lines.append("- " + " ".join(parts))
    if hidden:
        lines.append(f"- … {hidden} further event(s) not shown.")
    notes = [
        "Ordering is the kernel's own timestamps, not a reconstruction. DNS records only "
        "resolve to the second, so those lines are marked *(±1s)* and are placed no earlier "
        "than the run's first precisely-timed event.",
    ]
    if any(s.kind == "file" for s in steps):
        notes.append(
            "File lines cover the planted bait credential files only, not every file the "
            "install touched."
        )
    return lines + ["", f"<sub>{' '.join(notes)}</sub>", ""]


def _policy_section(policy: "Policy", final: FinalVerdict) -> list[str]:
    """What this repository's own policy contributed (read from the base branch)."""
    lines = ["### Repository policy", "",
             f"From `{esc(policy.source or POLICY_PATH, 80)}` on the base branch."]  # fmt: skip
    if policy.allowed_domains:
        hosts = ", ".join(esc(d, 60) for d in policy.allowed_domains)
        lines.append(f"- Extra hosts treated as normal for this project: {hosts} "
                     "(low-severity only; kernel findings are unaffected).")  # fmt: skip
    if policy.blocks_needs_review:
        extra = " — this check fails rather than passing" if final.title == "Needs review" else ""
        lines.append(f"- `needs_review: block`: a ⚠️ verdict is not mergeable here{extra}.")
    if policy.requires_model:
        lines.append("- `model_requirement: required`: without the AI analysis this check fails.")
    for w in policy.warnings[:5]:
        lines.append(f"- ⚠️ {esc(w, 160)}")
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
    guard: GuardOutcome | None = None,
    differential: "Differential | None" = None,
    investigation: "Investigation | None" = None,
    policy: "Policy | None" = None,
    grounding: "Grounding | None" = None,
    timeline: "list[Step] | None" = None,
) -> str:
    lines = [f"## PR Detonator: {HEADERS[final.title]}", ""]

    if not final.verified:
        why = final.reason or f"the sandboxed install did not finish (`{result.status}`)"
        lines += [
            f"> **This PR could not be fully verified**, because {why}. That is an absence of "
            "evidence, not a finding against this change: we are saying we could not watch the "
            "whole install, so we will not call it clean. Whatever *was* observed is shown "
            "below.",
            "",
        ]
    if final.model_unavailable and final.title != "Blocked":
        required = policy is not None and policy.requires_model
        consequence = ("this repository requires it, so the check fails"
                       if required else "so this result is capped at ⚠️ Needs review")  # fmt: skip
        lines += [
            f"> **Reduced coverage:** {esc(final.model_unavailable, 160)}. Only the "
            "deterministic rules ran, and some attacks are only caught by the analysis, "
            f"{consequence}. This is not a finding against the change.",
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
        if grounding is not None:
            lines += _grounding_section(grounding)

    if top := flagged(guard):
        lines += [
            f"> ⚠️ **Llama Prompt Guard 2 flagged the PR {esc(top.source, 10)}** "
            f"({top.score:.2f}) as a jailbreak attempt: "
            f"“{esc(top.snippet, 160)}”. The Intent Contract cleared nothing for this PR.",
            "",
        ]

    if investigation is not None:
        lines += _investigation_section(investigation)

    if differential is not None:
        lines += _differential_section(differential)

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

    if timeline:
        lines += _timeline_section(timeline)

    if result.connect_events:
        lines += ["### Network activity", "", *_network_rows(result), ""]

    if policy is not None and (policy.configured or policy.warnings):
        lines += _policy_section(policy, final)

    model_note = llm.model if v else f"{llm.model} (unavailable: {esc(llm.error, 80)}; rules only)"
    cpu = result.resources.cpu_s if result.resources else None
    sensor = result.sensor
    witness = ""
    if sensor is not None:
        witness = " · sensor witness " + ("✓" if sensor.pre_seen and sensor.post_seen else "✗")
    lines += [
        "---",
        f"<sub>Detonated `npm install` in {result.duration_s:.1f}s · "
        f"{len(result.exec_events)} exec / {len(result.connect_events)} connect events"
        f"{' (truncated)' if result.truncated else ''}"
        f"{f' · {cpu:.1f}s CPU' if cpu is not None else ''}{witness} · model {model_note}"
        f"{_guard_note(guard)} · job `{job_id}`"
        "</sub>",
        "",
        COMMENT_MARKER,
    ]
    return "\n".join(lines)
