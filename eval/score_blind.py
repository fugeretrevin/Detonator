"""Score the detonated blind corpus with the deterministic rules (no model).

The held-out set exists to measure what the tool misses, so this prints, per case, the
rules-floor verdict, the rules that fired, and what the kernel observed — so a MISS (the rules
clear it) can be read against whether the behaviour was even captured. Runs offline against the
committed telemetry in `eval/blind_telemetry/`; see `eval/BLIND_RESULTS.md` for the writeup.

    python -m eval.score_blind                 # committed telemetry
    python -m eval.score_blind <other-dir>     # a fresh detonation

This is the rules floor. The full pipeline adds the model analysis, which reads the install
script source and may catch some of the misses (notably the visible `git config` commands); the
number here is "what gets past the deterministic layer", which is the honest floor for a set the
rules were not written against.
"""

import sys
from pathlib import Path

from brain.llm import LlmOutcome
from brain.rules import evaluate
from brain.verdict import combine
from shared.contract import DetonateResult

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DIR = ROOT / "eval" / "blind_telemetry"
NO_MODEL = LlmOutcome("none", error="rules-only", skipped=True)


def score(directory: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in sorted(directory.glob("*.json")):
        r = DetonateResult.model_validate_json(p.read_text(encoding="utf-8"))
        hits = evaluate(r)
        out[p.stem] = {
            "verdict": combine(hits, NO_MODEL, r).title,
            "rules": sorted({h.rule_id for h in hits}),
            "exec": len(r.exec_events),
            "connect": len(r.connect_events),
            "file": len(r.file_events),
            "dns": len(r.dns_queries),
        }
    return out


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    directory = Path(argv[0]) if argv else DEFAULT_DIR
    if not directory.is_dir():
        print(f"not a directory: {directory}", file=sys.stderr)
        return 2
    scored = score(directory)
    if not scored:
        print(f"no telemetry in {directory}", file=sys.stderr)
        return 2
    caught = sum(1 for v in scored.values() if v["verdict"] in ("Blocked", "Needs review"))
    missed = len(scored) - caught
    print(f"{len(scored)} blind cases, rules floor: {caught} caught, {missed} missed\n")
    for cid, v in scored.items():
        mark = "catch" if v["verdict"] in ("Blocked", "Needs review") else "MISS "
        obs = f"exec {v['exec']} conn {v['connect']} file {v['file']} dns {v['dns']}"
        rules = v["rules"] or "none"
        print(f"  [{mark}] {cid:22s} {v['verdict']:16s} rules={rules}  ({obs})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
