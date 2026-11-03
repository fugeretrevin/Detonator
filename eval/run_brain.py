"""Score recorded Chamber results with the production pipeline, four ways:

  rules     deterministic rules only
  contract  rules + Intent Contract (model predicts from title/body/file names)
  analysis  rules + model analysis of the telemetry, with NO Intent Contract
  full      rules + contract + Prompt Guard 2 + model analysis (what the GitHub App runs)

`analysis` is the isolating arm: comparing it against `contract` and `full` separates what the
*pre-execution prediction* contributes from what *post-execution reasoning over the telemetry*
contributes, instead of only showing the combined lift over `rules`.

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

CONFIGS = ("rules", "contract", "analysis", "full")
ICON = {"Clean": "✅", "Needs review": "⚠️", "Blocked": "❌", "Could not verify": "⏱️"}


def no_llm(*_, **__) -> LlmOutcome:
    return LlmOutcome("none", error="skipped", skipped=True)


def _score_explanation(case: Case, full) -> tuple[bool | None, bool | None]:
    """P1.5: did Muse decode the payload and name the right source? None when no ground truth."""
    truth = case.truth
    if not truth:
        return None, None
    v = full.llm.verdict
    blob = " ".join(
        [v.explanation, *[e.explanation for e in v.line_explanations]] if v else []
    ).lower()
    decoded = None
    if "decoded" in truth:
        decoded = all(tok.lower() in blob for tok in truth["decoded"]) if v else False
    attributed = None
    if "attributes_to" in truth:
        want = truth["attributes_to"].lower()
        in_guilty = any(want in (g.package or "").lower() or want in g.path.lower()
                        for g in full.guilty)  # fmt: skip
        attributed = in_guilty or want in blob
    return decoded, attributed


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
        # No `prediction`: the model reasons over the telemetry without being told what the PR
        # claimed, which isolates the Intent Contract's contribution.
        "analysis": analyze(result, meta, diff, client.analyze, guard=guard, **common),
        "full": analyze(
            result, meta, diff, client.analyze, prediction=prediction, guard=guard, **common
        ),  # fmt: skip
    }
    full = runs["full"]
    prompt_tok, completion_tok = full.model_tokens
    explain_decoded, explain_attributed = _score_explanation(case, full)
    return {
        "id": case.id,
        "kind": case.kind,
        "note": case.note,
        "status": result.status,
        "exit_code": result.exit_code,
        "detonation_s": result.duration_s,
        "model_latency_s": round(sum(u.latency_s for u in full.usages), 2),
        "model_prompt_tokens": prompt_tok,
        "model_completion_tokens": completion_tok,
        "cost_usd": full.cost_usd,
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
        "explain_decoded": explain_decoded,
        "explain_attributed": explain_attributed,
        "grounding": full.grounding.summary() if full.grounding else None,
        # v3 Chamber only (None from older runs): calibrates CPU_REVIEW_THRESHOLD_S (rt08).
        "cpu_s": result.resources.cpu_s if result.resources else None,
        "sensor_witness": (result.sensor.pre_seen and result.sensor.post_seen)
        if result.sensor
        else None,
        "guilty_lines": [f"{g.path}:{g.line}" for g in full.guilty],
        "script_runs": sorted(
            {r.package or "(project)" for r in script_runs(full.hits, full.result)}
        ),
        "domains": sorted({c.resolved_domain or f"RAW {c.daddr}" for c in result.connect_events}),
    }


def summarize(rows: list[dict]) -> list[str]:
    out = ["| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked | ⏱️ Could not verify |",
           "|---|---|---|---|---|---|"]  # fmt: skip
    for kind in ("benign", "malicious", "incident", "redteam", "redteam-ind"):
        subset = [r for r in rows if r["kind"] == kind]
        for cfg in CONFIGS:
            counts = {t: sum(r["outcomes"][cfg] == t for r in subset) for t in ICON}
            cells = " | ".join(f"{counts[t]}/{len(subset)}" for t in ICON)
            out.append(f"| {kind} ({len(subset)}) | {cfg} | {cells} |")
    return out


def _pctl(values: list[float], p: float) -> float:
    s = sorted(values)
    return round(s[min(len(s) - 1, int(p * len(s)))], 2) if s else 0.0


def cost_latency(rows: list[dict]) -> list[str]:
    det = [r["detonation_s"] for r in rows]
    lat = [r["model_latency_s"] for r in rows]
    costs = [r["cost_usd"] for r in rows if r.get("cost_usd") is not None]
    prompt = sum(r["model_prompt_tokens"] for r in rows)
    completion = sum(r["model_completion_tokens"] for r in rows)
    n = max(len(costs), 1)
    return [
        "### Cost and latency (full pipeline)",
        "",
        f"- Detonation: p50 {_pctl(det, 0.5)}s, p95 {_pctl(det, 0.95)}s",
        f"- Model latency per PR (prediction + analysis): p50 {_pctl(lat, 0.5)}s, "
        f"p95 {_pctl(lat, 0.95)}s",
        f"- Tokens per PR: {prompt // len(rows)} in / {completion // len(rows)} out (mean)",
        f"- **Cost per PR: ${sum(costs) / n:.4f} mean** (muse-spark-1.3 at $1.25/1M in, "
        f"$4.25/1M out); ${sum(costs):.3f} for all {len(rows)} cases",
        "",
    ]


def explanation_quality(rows: list[dict]) -> list[str]:
    dec = [r for r in rows if r.get("explain_decoded") is not None]
    att = [r for r in rows if r.get("explain_attributed") is not None]
    if not dec and not att:
        return []
    out = ["### What Muse explained (P1.5 ground truth)", ""]
    if dec:
        ok = sum(bool(r["explain_decoded"]) for r in dec)
        miss = [r["id"] for r in dec if not r["explain_decoded"]]
        out.append(f"- Decoded the payload correctly in **{ok}/{len(dec)}** obfuscated attacks"
                   + (f" (missed: {', '.join(miss)})" if miss else ""))  # fmt: skip
    if att:
        ok = sum(bool(r["explain_attributed"]) for r in att)
        miss = [r["id"] for r in att if not r["explain_attributed"]]
        tail = f" (missed: {', '.join(miss)})" if miss else ""
        out.append(
            f"- Attributed to the right package/file in **{ok}/{len(att)}** "
            f"dependency-delivered attacks{tail}"
        )
    return out + [""]


def details(rows: list[dict]) -> list[str]:
    out = ["| Case | Kind | Rules | +Contract | +Analysis | Full | Fired | Notes |",
           "|---|---|---|---|---|---|---|---|"]  # fmt: skip
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
            f"| {ICON[o['analysis']]} | {ICON[o['full']]} "
            f"| {' '.join(r['rules_fired']) or '-'} | {'; '.join(notes)} |"
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


def grounding_quality(rows: list[dict]) -> list[str]:
    """How many of Muse's evidence claims the kernel record backs (brain/evidence.py)."""
    g = [r["grounding"] for r in rows if r.get("grounding")]
    claims = sum(x["claims"] for x in g)
    if not claims:
        return []
    supported = sum(x["supported"] for x in g)
    rejected = sum(x["rejected"] for x in g)
    inferred = sum(x["source_inferred"] for x in g)
    mentions = [r["id"] for r in rows if (r.get("grounding") or {}).get("unsupported_mentions")]
    uncited = [r["id"] for r in rows if (r.get("grounding") or {}).get("uncited")]
    return [
        "### Evidence grounding (full pipeline)",
        "",
        f"- **{supported}/{claims}** evidence claims cite a real kernel event of the right type "
        f"({inferred} labelled source-only); **{rejected}** rejected "
        f"({rejected / claims:.0%} unsupported-claim rate).",
        f"- Cases whose summary names a host/IP absent from the record and diff: "
        f"{len(mentions)}" + (f" ({', '.join(mentions[:10])})" if mentions else ""),
        f"- Cases asserting a file path or port in prose that the record contradicts "
        f"(uncited, so the citation check above would not see it): {len(uncited)}"
        + (f" ({', '.join(uncited[:10])})" if uncited else ""),
        "",
    ]


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
    md = ["# Evaluation results", "", header, "", *summarize(rows), "",
          *explanation_quality(rows), *grounding_quality(rows), *cost_latency(rows),
          "## Per case", "", *details(rows), ""]  # fmt: skip
    Path(f"{out_prefix}.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(summarize(rows)))


if __name__ == "__main__":
    main(*sys.argv[1:3])
