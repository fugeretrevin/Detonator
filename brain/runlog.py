"""Per-run summary records and the read-only dashboard (HARDENING_PLAN P1.6).

Every detonation writes one record (best effort, never fails the job). The dashboard renders
recent runs, verdict counts, and a behavior atlas (package -> hosts seen, binaries run): the
"behavioral SBOM" vision, made visible. Everything shown is attacker-influenced, so the page
entity-encodes every value exactly as the PR comments do.
"""

import html
from typing import TYPE_CHECKING

from brain.rules import is_external

if TYPE_CHECKING:
    from brain.pipeline import Analysis
    from brain.webhook import PullRequestEvent

MAX_RECORDS = 200
CONCLUSION_ICON = {"success": "✅", "neutral": "⚠️", "failure": "🛑"}


def build_record(
    event: "PullRequestEvent", analysis: "Analysis", job_id: str, ts: str
) -> dict | None:
    """A compact, structured summary, or None for a private repo.

    The dashboard is public and unauthenticated, so a private repo must never produce a record
    at all: its name, PR title and the hosts its install contacted would otherwise be stored and
    served to anyone. Filtering at render time would be too late — the data would already be in
    the shared Dict. Returning None here makes the refusal unit-testable and keeps any future
    caller from forgetting it.

    No free-form untrusted text is stored except the PR title, which the dashboard escapes on
    render like everything else."""
    if event.repo_private:
        return None
    r = analysis.result
    hosts = sorted({c.resolved_domain or c.daddr for c in r.connect_events if is_external(c.daddr)})
    packages = sorted({s.package for s in r.executed_scripts if s.package})
    binaries = sorted(
        {e.binary.rsplit("/", 1)[-1] for e in r.exec_events if not e.binary.startswith("/usr/")}
    )
    return {
        "ts": ts,
        "repo": f"{event.owner}/{event.repo}",
        "pr": event.number,
        "title": event.title[:200],
        "sha": event.head_sha[:7],
        "verdict": analysis.final.title,
        "conclusion": analysis.final.conclusion,
        "rules": sorted({h.rule_id for h in analysis.hits}),
        "packages_ran_scripts": packages,
        "hosts": hosts[:20],
        "binaries": binaries[:20],
        "cost_usd": analysis.cost_usd,
        "detonation_s": r.duration_s,
    }


def _esc(text: object) -> str:
    return html.escape(str(text))


def behavior_atlas(records: list[dict]) -> dict[str, dict[str, set]]:
    """package -> {hosts, binaries} aggregated across runs that ran its install scripts."""
    atlas: dict[str, dict[str, set]] = {}
    for rec in records:
        for pkg in rec.get("packages_ran_scripts", []):
            entry = atlas.setdefault(pkg, {"hosts": set(), "binaries": set()})
            entry["hosts"].update(rec.get("hosts", []))
            entry["binaries"].update(rec.get("binaries", []))
    return atlas


def render_dashboard(records: list[dict]) -> str:
    """Self-contained HTML. Every interpolated value is escaped (PR content is untrusted)."""
    recent = sorted(records, key=lambda r: r.get("ts", ""), reverse=True)[:MAX_RECORDS]
    counts: dict[str, int] = {}
    for rec in recent:
        counts[rec.get("verdict", "?")] = counts.get(rec.get("verdict", "?"), 0) + 1
    tally = " · ".join(f"{_esc(v)}: {n}" for v, n in sorted(counts.items())) or "no runs yet"

    rows = []
    for rec in recent:
        icon = CONCLUSION_ICON.get(rec.get("conclusion", ""), "")
        cost = f"${rec['cost_usd']:.4f}" if rec.get("cost_usd") is not None else "—"
        rules = ", ".join(_esc(r) for r in rec.get("rules", [])) or "—"
        rows.append(
            "<tr>"
            f"<td>{_esc(rec.get('ts', ''))}</td>"
            f"<td>{_esc(rec.get('repo', ''))} #{_esc(rec.get('pr', ''))}</td>"
            f"<td title='{_esc(rec.get('title', ''))}'>{_esc(rec.get('title', '')[:60])}</td>"
            f"<td>{icon} {_esc(rec.get('verdict', ''))}</td>"
            f"<td class='rules'>{rules}</td>"
            f"<td>{_esc(rec.get('detonation_s', ''))}s</td><td>{cost}</td>"
            "</tr>"
        )

    atlas_rows = []
    for pkg, e in sorted(behavior_atlas(recent).items()):
        hosts = ", ".join(_esc(h) for h in sorted(e["hosts"])) or "—"
        bins = ", ".join(_esc(b) for b in sorted(e["binaries"])) or "—"
        atlas_rows.append(f"<tr><td>{_esc(pkg)}</td><td>{hosts}</td><td>{bins}</td></tr>")

    return _PAGE.format(
        tally=tally,
        count=len(recent),
        run_rows="\n".join(rows) or "<tr><td colspan=7>no runs yet</td></tr>",
        atlas_rows="\n".join(atlas_rows) or "<tr><td colspan=3>no install scripts seen</td></tr>",
    )


_PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>PR Detonator</title><style>
:root{{color-scheme:light dark}}
body{{font:15px/1.5 system-ui,sans-serif;margin:0;background:#10151f;color:#eef0f3}}
main{{max-width:1100px;margin:0 auto;padding:32px 16px}}
h1{{font-size:24px;margin:0 0 4px}} .sub{{color:#8fa0b8;margin:0 0 24px}}
table{{width:100%;border-collapse:collapse;margin:12px 0 32px;font-size:13px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #26303f;vertical-align:top}}
th{{color:#8fa0b8;font-weight:600}} td.rules{{color:#f29a4a;font-family:ui-monospace,monospace}}
h2{{font-size:18px;margin:24px 0 0}}
</style></head><body><main>
<h1>PR Detonator</h1>
<p class=sub>Model predicts · kernel verifies · rules set the floor.<br>
{count} recent runs — {tally}</p>
<h2>Recent runs</h2>
<table><tr><th>Time (UTC)</th><th>PR</th><th>Title</th><th>Verdict</th><th>Rules fired</th>
<th>Detonation</th><th>Model cost</th></tr>
{run_rows}</table>
<h2>Behavior atlas — what packages did at install</h2>
<p class=sub>Hosts contacted and binaries run by packages whose install scripts executed.
A per-version behavioral record: lockfiles pin bytes, this pins behavior.</p>
<table><tr><th>Package</th><th>Hosts contacted</th><th>Binaries run</th></tr>
{atlas_rows}</table>
</main></body></html>"""
