"""Score recorded telemetry with the deterministic rules only - no model, no Modal, no network.

**Why this exists.** `eval/run_brain.py` is the full four-arm harness: it imports `modal`, needs
`LLAMA_API_KEY`, and costs real money per run. That is the right tool for publishing numbers and
the wrong tool for the question asked most often while changing a rule:

    does this change hard-block anything benign?

That question is answered entirely by `brain.rules.evaluate` plus `brain.verdict.combine` with
no model outcome, so it can be answered offline, free, in about a second, against all 142
recorded cases. Without that, a rule change could only be justified by argument - which is
exactly what `docs/WEAKPOINTS.md` refuses to accept for anything touching a verdict.

**Trust comes from reproducing a known answer.** `--verify` re-scores the rules arm and compares
it against the `outcomes.rules` column already stamped in `eval/results.json`. If this harness
cannot reproduce the committed numbers from the committed telemetry, nothing it says about a
*change* is worth anything either. Run `--verify` before trusting a diff.

    python -m eval.score_rules <telemetry-dir> --verify
    python -m eval.score_rules <telemetry-dir>                  # tally + every finding
    python -m eval.score_rules <telemetry-dir> --baseline b.json
    python -m eval.score_rules <telemetry-dir> --compare b.json # what my change moved

Telemetry is one `<case-id>.json` DetonateResult per file, pulled off the Chamber.
The contents are untrusted (a sandbox ran attacker code to produce them), so
this module only ever parses and reads them.
"""

import argparse
import json
import sys
from pathlib import Path

from brain.enrich import enrich_connects
from brain.llm import LlmOutcome
from brain.rules import DEFAULT_ALLOWED_DOMAINS, evaluate
from brain.verdict import combine
from shared.contract import DetonateResult

ROOT = Path(__file__).resolve().parent.parent
# The rules arm has no model, so `combine` must be given an outcome that stands for "the model
# did not run" rather than one that stands for "the model said it was fine".
NO_MODEL = LlmOutcome("none", error="rules-only scoring", skipped=True)


def load(directory: Path) -> dict[str, DetonateResult]:
    out: dict[str, DetonateResult] = {}
    for path in sorted(directory.rglob("*.json")):
        try:
            out[path.stem] = DetonateResult.model_validate_json(
                path.read_text(encoding="utf-8", errors="replace")
            )
        except Exception as exc:  # noqa: BLE001 - a bad record should not kill the run
            print(f"  ! {path.name}: unreadable ({type(exc).__name__})", file=sys.stderr)
    return out


def score(result: DetonateResult, allowed_cidrs: tuple[str, ...] = ()) -> dict:
    """The rules arm exactly as `eval/run_brain.py` computes it, minus the model."""
    view = enrich_connects(result, allowed_cidrs) if allowed_cidrs else result
    hits = evaluate(view, allowed_domains=DEFAULT_ALLOWED_DOMAINS)
    final = combine(hits, NO_MODEL, view)
    return {
        "verdict": final.title,
        "conclusion": final.conclusion,
        "rules": sorted({h.rule_id for h in hits}),
        "severities": sorted({h.severity.value for h in hits}),
    }


def score_all(directory: Path) -> dict[str, dict]:
    return {case: score(res) for case, res in load(directory).items()}


def stamped_rules_arm() -> dict[str, str]:
    """The `rules` column from the committed, stamped evaluation."""
    data = json.loads((ROOT / "eval" / "results.json").read_text(encoding="utf-8"))
    return {r["id"]: r["outcomes"]["rules"] for r in data["rows"] if "rules" in r["outcomes"]}


def kinds() -> dict[str, str]:
    data = json.loads((ROOT / "eval" / "results.json").read_text(encoding="utf-8"))
    return {r["id"]: r["kind"] for r in data["rows"]}


# Cases where the rules in this tree intentionally disagree with the stamped evaluation,
# because a rule was added or changed after `eval/results.json` was scored. Every entry needs
# the stamped verdict, the current one, and why - and `--verify` is strict in both directions:
# an unlisted disagreement fails, and so does a listed one that no longer disagrees, so this
# cannot quietly become a place to park regressions.
KNOWN_DRIFT: dict[str, tuple[str, str, str]] = {
    "gm05-cron-inject": (
        "Clean",
        "Blocked",
        "EXEC_SCHEDULED_PERSISTENCE added after the stamp. Measured 0 matches in 604 uncurated "
        "packages and 0 of 104 benign controls; the `full` arm already Blocked this case, so no "
        "headline figure changes. A re-score would update the rules/contract columns only.",
    ),
}


def verify(scored: dict[str, dict]) -> int:
    """Reproduce the stamped rules column. Returns a process exit code."""
    stamped = stamped_rules_arm()
    shared = sorted(set(scored) & set(stamped))
    missing = sorted(set(stamped) - set(scored))
    print(f"Comparing {len(shared)} cases present in both the telemetry and the stamped eval.")
    if missing:
        print(f"  not in this telemetry directory ({len(missing)}): {', '.join(missing[:8])}"
              + (" …" if len(missing) > 8 else ""))  # fmt: skip

    unexpected, expected, stale = [], [], []
    for case in shared:
        now, was = scored[case]["verdict"], stamped[case]
        drift = KNOWN_DRIFT.get(case)
        if now != was:
            (expected if drift and drift[:2] == (was, now) else unexpected).append(case)
        elif drift:
            stale.append(case)

    for case in expected:
        was, now, why = KNOWN_DRIFT[case]
        print(f"  known drift {case}: {was} -> {now}")
        print(f"      {why}")
    for case in unexpected:
        fired = ", ".join(scored[case]["rules"]) or "none"
        print(f"  MISMATCH {case}: stamped {stamped[case]!r}, recomputed "
              f"{scored[case]['verdict']!r} (rules: {fired})")  # fmt: skip
    for case in stale:
        print(f"  STALE KNOWN_DRIFT entry for {case}: it now agrees with the stamp, so the "
              "entry should be removed.")  # fmt: skip

    if unexpected or stale:
        print(f"\n{len(unexpected)} unexplained disagreement(s), {len(stale)} stale entr(ies). "
              "Do not trust this harness to measure a change until both are zero.")  # fmt: skip
        return 1
    agreed = len(shared) - len(expected)
    print(f"\n{agreed} of {len(shared)} agree with the stamped `rules` column; "
          f"{len(expected)} differ for a recorded reason. The harness reproduces the committed "
          "result, so a diff against it is meaningful.")  # fmt: skip
    return 0


def tally(scored: dict[str, dict]) -> None:
    by_kind = kinds()
    groups: dict[str, dict[str, int]] = {}
    for case, row in sorted(scored.items()):
        kind = by_kind.get(case, "unknown")
        groups.setdefault(kind, {})
        groups[kind][row["verdict"]] = groups[kind].get(row["verdict"], 0) + 1
    print(f"{'cohort':12s} {'n':>4s}  verdicts (rules only)")
    print("-" * 78)
    for kind, counts in sorted(groups.items()):
        n = sum(counts.values())
        detail = ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda x: -x[1]))
        print(f"{kind:12s} {n:4d}  {detail}")
    print()
    flagged = {c: r for c, r in sorted(scored.items()) if r["rules"]}
    print(f"{len(flagged)} of {len(scored)} cases fired at least one rule:")
    for case, row in flagged.items():
        print(f"  {by_kind.get(case, '?'):11s} {case:30s} {row['verdict']:16s} "
              f"{', '.join(row['rules'])}")  # fmt: skip


def compare(scored: dict[str, dict], baseline_path: Path) -> int:
    """What a change moved, relative to a baseline this script wrote earlier."""
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    by_kind = kinds()
    moved = []
    for case in sorted(set(scored) & set(baseline)):
        before, after = baseline[case], scored[case]
        if before["verdict"] != after["verdict"] or before["rules"] != after["rules"]:
            moved.append((case, before, after))
    if not moved:
        print(f"No change across {len(scored)} cases.")
        return 0
    print(f"{len(moved)} case(s) changed:\n")
    regressions = 0
    for case, before, after in moved:
        kind = by_kind.get(case, "unknown")
        worse = kind == "benign" and after["verdict"] != before["verdict"] != "Blocked"
        if kind == "benign" and after["verdict"] == "Blocked":
            regressions += 1
            flag = "  *** BENIGN NOW BLOCKED ***"
        elif worse:
            flag = "  (benign verdict moved)"
        else:
            flag = ""
        print(f"  {kind:11s} {case:30s} {before['verdict']} -> {after['verdict']}{flag}")
        gained = sorted(set(after["rules"]) - set(before["rules"]))
        lost = sorted(set(before["rules"]) - set(after["rules"]))
        if gained:
            print(f"{'':44s} + {', '.join(gained)}")
        if lost:
            print(f"{'':44s} - {', '.join(lost)}")
    if regressions:
        print(f"\n{regressions} benign package(s) would be hard-blocked by this change.")
        return 1
    print("\nNo benign package is hard-blocked by this change.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("telemetry", type=Path, help="directory of <case-id>.json DetonateResults")
    ap.add_argument("--verify", action="store_true",
                    help="check this reproduces the stamped rules column")  # fmt: skip
    ap.add_argument("--baseline", type=Path, help="write the scores to this file")
    ap.add_argument("--compare", type=Path, help="diff against a baseline written earlier")
    args = ap.parse_args(argv)

    if not args.telemetry.is_dir():
        print(f"not a directory: {args.telemetry}", file=sys.stderr)
        return 2
    scored = score_all(args.telemetry)
    if not scored:
        print("no readable DetonateResult JSON found", file=sys.stderr)
        return 2
    print(f"Scored {len(scored)} case(s) from {args.telemetry} with the rules only.\n")

    if args.baseline:
        args.baseline.write_text(json.dumps(scored, indent=1, sort_keys=True), encoding="utf-8")
        print(f"baseline written to {args.baseline}\n")
    if args.verify:
        return verify(scored)
    if args.compare:
        return compare(scored, args.compare)
    tally(scored)
    return 0


if __name__ == "__main__":
    sys.exit(main())
