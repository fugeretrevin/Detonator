"""Score recorded Chamber results with the production pipeline, three ways:

  rules     deterministic rules only
  contract  rules + Intent Contract (model predicts from title/body/file names)
  full      rules + contract + Prompt Guard 2 + model analysis (what the GitHub App runs)

  python -m eval.run_brain <results-dir> [out-prefix]    # writes <out>.md and <out>.json

Needs LLAMA_API_KEY (or the probe_llama key lookup) and the deployed Modal app. The output
records the commit and time it was scored at, and whether the tree had uncommitted changes.
"""

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import truststore

truststore.inject_into_ssl()  # local machine only: Norton re-signs TLS

import modal  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from probe_llama import api_key  # noqa: E402

from brain import prompt_guard as pg  # noqa: E402
from brain.enrich import github_meta_cidrs  # noqa: E402
from brain.intent import predict  # noqa: E402
from brain.llm import LlmClient, LlmOutcome  # noqa: E402
from brain.pinpoint import script_runs  # noqa: E402
from brain.pipeline import Analysis, analyze  # noqa: E402
from eval.cases import CASES, Case  # noqa: E402
from shared.contract import DetonateResult  # noqa: E402

CONFIGS = ("rules", "contract", "full")
ICON = {"Clean": "✅", "Needs review": "⚠️", "Blocked": "❌", "Could not verify": "⏱️"}


def no_llm(*_, **__) -> LlmOutcome:
    return LlmOutcome("none", error="skipped")


def guard_scan(meta, diff) -> pg.GuardOutcome:
    """The deployed Prompt Guard 2 class, exactly as the GitHub App calls it."""
    try:
        cls = modal.Cls.from_name("pr-detonator", "PromptGuard")
        return cls().scan.remote(pg.guard_inputs(meta, diff))
    except Exception as exc:  # noqa: BLE001 - recorded, like production
        return pg.GuardOutcome(error=type(exc).__name__)


def score(case: Case, result: DetonateResult, client: LlmClient, cidrs) -> dict:
    meta, diff, files = case.metadata(), case.diff(), case.changed_files()
    prediction = predict(client, meta)
    guard = guard_scan(meta, diff)
    common = dict(job_id=case.id, allowed_cidrs=cidrs, files=files)
    runs: dict[str, Analysis] = {
        "rules": analyze(result, meta, diff, no_llm, **common),
        "contract": analyze(result, meta, diff, no_llm, prediction=prediction, **common),
        "full": analyze(
            result, meta, diff, client.analyze, prediction=prediction, guard=guard, **common
        ),  # fmt: skip
    }
    full = runs["full"]
    return {
        "id": case.id,
        "kind": case.kind,
        "note": case.note,
        "status": result.status,
        "exit_code": result.exit_code,
        "outcomes": {k: a.final.title for k, a in runs.items()},
        "rules_fired": sorted({h.rule_id for h in runs["rules"].hits}),
        "cleared": sorted({h.target for h in runs["contract"].cleared}),
        "predicted_domains": prediction.prediction.expected_domains
        if prediction.prediction
        else None,
        "prediction_error": prediction.error,
        "llm_verdict": full.llm.verdict.verdict if full.llm.verdict else None,
        "llm_error": full.llm.error,
        "injection_flagged": bool(full.llm.verdict and full.llm.verdict.injection_attempt),
        "prompt_guard_max": guard.top.score if guard.top else None,
        "prompt_guard_error": guard.error,
        "guilty_lines": [f"{g.path}:{g.line}" for g in full.guilty],
        "script_runs": sorted(
            {r.package or "(project)" for r in script_runs(full.hits, full.result)}
        ),
        "domains": sorted({c.resolved_domain or f"RAW {c.daddr}" for c in result.connect_events}),
    }


def summarize(rows: list[dict]) -> list[str]:
    out = ["| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked | ⏱️ Could not verify |",
           "|---|---|---|---|---|---|"]  # fmt: skip
    for kind in ("benign", "malicious"):
        subset = [r for r in rows if r["kind"] == kind]
        for cfg in CONFIGS:
            counts = {t: sum(r["outcomes"][cfg] == t for r in subset) for t in ICON}
            cells = " | ".join(f"{counts[t]}/{len(subset)}" for t in ICON)
            out.append(f"| {kind} ({len(subset)}) | {cfg} | {cells} |")
    return out


def details(rows: list[dict]) -> list[str]:
    out = ["| Case | Kind | Rules | +Contract | Full | Fired | Notes |",
           "|---|---|---|---|---|---|---|"]  # fmt: skip
    for r in rows:
        o = r["outcomes"]
        notes = []
        if r["cleared"]:
            notes.append("cleared " + ", ".join(r["cleared"]))
        if r["injection_flagged"]:
            notes.append("injection flagged")
        if r["status"] != "completed" or r["exit_code"]:
            notes.append(f"install {r['status']} exit={r['exit_code']}")
        if r["note"]:
            notes.append(r["note"])
        out.append(
            f"| {r['id']} | {r['kind']} | {ICON[o['rules']]} | {ICON[o['contract']]} "
            f"| {ICON[o['full']]} | {' '.join(r['rules_fired']) or '-'} | {'; '.join(notes)} |"
        )
    return out


def provenance() -> dict:
    """Which code produced these numbers. A dirty tree is recorded, never hidden."""

    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()  # fmt: skip

    return {
        "commit": git("rev-parse", "--short", "HEAD"),
        "dirty": bool(git("status", "--porcelain", "--", "brain", "shared", "chamber", "eval")),
        "scored_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    }


def main(results_dir: str, out_prefix: str = "eval/results") -> None:
    client = LlmClient(api_key(), base_url="https://api.meta.ai/v1")
    cidrs = github_meta_cidrs()
    jobs = []
    for case in CASES.values():
        path = Path(results_dir) / f"{case.id}.json"
        if path.exists():
            jobs.append((case, DetonateResult.model_validate_json(path.read_text())))
    stamp = provenance()
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda job: score(*job, client, cidrs), jobs))
    Path(f"{out_prefix}.json").write_text(json.dumps({**stamp, "rows": rows}, indent=1))
    header = (f"Scored {stamp['scored_at']} at commit `{stamp['commit']}`"
              f"{' (UNCOMMITTED CHANGES)' if stamp['dirty'] else ''} with {client.model}; "
              f"detonations from `{Path(results_dir).name}`.")  # fmt: skip
    md = ["# Evaluation results", "", header, "", *summarize(rows), "", "## Per case", "",
          *details(rows), ""]  # fmt: skip
    Path(f"{out_prefix}.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(summarize(rows)))


if __name__ == "__main__":
    main(*sys.argv[1:3])
