"""Repeatability: re-score the same frozen telemetry N times and report how much Muse moves.

Temperature 0 is not determinism. A single scored run can't tell a stable verdict from a lucky
one, so this re-runs the model arms on identical recorded detonations and reports, per case,
every outcome seen. The headline numbers are the *worst* cases, not the mean:

- flip rate: cases whose outcome differed between trials;
- unsafe passes: attack trials that came out Clean or Needs review (mergeable by default);
- benign blocks: benign trials that came out Blocked;
- evidence grounding summed over all trials (brain/evidence.py).

  python -m eval.repeat <results-dir> [--trials 5] [--arms full,analysis] [--only id,id]
                        [--out eval/REPEAT]

Cost: each trial of `full` is two Muse calls (prediction + analysis), `analysis` is one; at
~$0.015 per call, 142 cases x 5 trials x full is roughly $20. Prompt Guard is a deterministic
classifier, so it runs once per case. Needs LLAMA_API_KEY and the deployed Modal app.
"""

import argparse
import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path

LENIENCY = {"Clean": 0, "Needs review": 1, "Could not verify": 2, "Blocked": 3}
MERGEABLE = ("Clean", "Needs review")


def run_trials(
    case,
    result,
    trials: int,
    arms: tuple[str, ...],
    analyze_fn: Callable,
    llm: Callable,
    predict_fn: Callable,
    guard,
    common: dict,
) -> dict:
    """One case, `trials` times per arm. The model functions are injected (tests use fakes)."""
    meta, diff = case.metadata(), case.diff()
    outcomes: dict[str, list[str]] = {a: [] for a in arms}
    grounding: list[dict] = []
    errors = 0
    for _ in range(trials):
        prediction = predict_fn(meta) if "full" in arms else None
        for arm in arms:
            kwargs = dict(common, guard=guard)
            if arm == "full":
                kwargs["prediction"] = prediction
            a = analyze_fn(result, meta, diff, llm, **kwargs)
            outcomes[arm].append(a.final.title)
            errors += a.llm.error is not None
            if arm == "full" and a.grounding is not None:
                grounding.append(a.grounding.summary())
    return {"id": case.id, "kind": case.kind, "outcomes": outcomes, "grounding": grounding,
            "llm_errors": errors}  # fmt: skip


def case_stats(row: dict, arm: str) -> dict:
    seen = row["outcomes"][arm]
    counts = Counter(seen)
    attack = row["kind"] != "benign"
    return {
        "flipped": len(counts) > 1,
        "most_lenient": min(seen, key=LENIENCY.__getitem__),
        "unsafe_trials": sum(o in MERGEABLE for o in seen) if attack else 0,
        "benign_block_trials": seen.count("Blocked") if not attack else 0,
        "counts": dict(counts),
    }


def summarize(rows: list[dict], arm: str, trials: int) -> list[str]:
    stats = {r["id"]: case_stats(r, arm) for r in rows}
    attacks = [r for r in rows if r["kind"] != "benign"]
    benign = [r for r in rows if r["kind"] == "benign"]
    flipped = [i for i, s in stats.items() if s["flipped"]]
    unsafe = [r["id"] for r in attacks if stats[r["id"]]["unsafe_trials"]]
    blocked = [r["id"] for r in benign if stats[r["id"]]["benign_block_trials"]]
    out = [
        f"### `{arm}`: {len(rows)} cases × {trials} trials",
        "",
        f"- **Flip rate:** {len(flipped)}/{len(rows)} cases gave more than one outcome"
        + (f" ({', '.join(flipped[:12])})" if flipped else ""),
        f"- **Unsafe passes (worst case):** {len(unsafe)}/{len(attacks)} attacks were mergeable "
        "(Clean or Needs review) in at least one trial"
        + (f" ({', '.join(unsafe[:12])})" if unsafe else ""),
        f"- **Benign blocks (worst case):** {len(blocked)}/{len(benign)} benign cases were "
        "Blocked in at least one trial" + (f" ({', '.join(blocked[:12])})" if blocked else ""),
    ]
    g = [x for r in rows for x in r["grounding"]] if arm == "full" else []
    claims = sum(x["claims"] for x in g)
    if claims:
        rejected = sum(x["rejected"] for x in g)
        out.append(f"- **Evidence grounding:** {claims - rejected}/{claims} claims supported "
                   f"across all trials ({rejected / claims:.0%} unsupported)")  # fmt: skip
    errors = sum(r["llm_errors"] for r in rows)
    if errors:
        out.append(f"- Model errors across all trials: {errors} (scored as the pipeline does)")
    out += ["", "| Case | Kind | Outcomes | Most lenient |", "|---|---|---|---|"]
    for r in rows:
        s = stats[r["id"]]
        if s["flipped"] or s["unsafe_trials"] or s["benign_block_trials"]:
            seen = ", ".join(f"{k} ×{v}" for k, v in sorted(s["counts"].items()))
            out.append(f"| {r['id']} | {r['kind']} | {seen} | {s['most_lenient']} |")
    return out + [""]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("results_dir")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--arms", default="full")
    parser.add_argument("--only", default="")
    parser.add_argument("--out", default="eval/REPEAT")
    args = parser.parse_args(argv)
    arms = tuple(a for a in args.arms.split(",") if a in ("full", "analysis"))

    # Heavy imports here so the summary logic above stays importable in tests.
    from concurrent.futures import ThreadPoolExecutor

    from brain.enrich import github_meta_cidrs
    from brain.intent import predict
    from brain.llm import LlmClient
    from brain.pipeline import analyze
    from eval.cases import CASES
    from eval.run_brain import api_key, guard_scan, provenance
    from shared.contract import DetonateResult

    client = LlmClient(api_key(), base_url="https://api.meta.ai/v1")
    cidrs = github_meta_cidrs()
    wanted = set(filter(None, args.only.split(",")))
    jobs = []
    for case in CASES.values():
        path = Path(args.results_dir) / f"{case.id}.json"
        if path.exists() and (not wanted or case.id in wanted):
            jobs.append((case, DetonateResult.model_validate_json(path.read_text())))

    def one(job):
        case, result = job
        common = dict(job_id=case.id, allowed_cidrs=cidrs, files=case.changed_files())
        guard = guard_scan(case.metadata(), case.diff())
        return run_trials(case, result, args.trials, arms, analyze, client.analyze,
                          lambda m: predict(client, m), guard, common)  # fmt: skip

    stamp = provenance()
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(one, jobs))
    Path(f"{args.out}.json").write_text(
        json.dumps({**stamp, "trials": args.trials, "arms": arms, "rows": rows}, indent=1)
    )
    dirty = " (UNCOMMITTED CHANGES)" if stamp["dirty"] else ""
    header = f"Scored {stamp['scored_at']} at commit `{stamp['commit']}`{dirty} with {client.model}."
    md = ["# Repeatability", "", header, ""]
    for arm in arms:
        md += summarize(rows, arm, args.trials)
    Path(f"{args.out}.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
