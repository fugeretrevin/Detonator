"""W2 round 2, measured offline: simulate the borderline-band sampler from recorded trials.

`docs/WEAKPOINTS.md` W2 ships best-of-N sampling **off** because the round-2 re-run was
abandoned unmeasured when the provider throttled, leaving acceptance 1 (flip rate 0 on attacks)
and acceptance 3 (benign Blocked stays 0) unmeasured *for the widened band*. The gate says all
four conditions must pass on a measured run, so the default stayed `MODEL_SAMPLES = 1`.

This recovers what can be recovered without spending another API call, from
`eval/REPEAT_W2.json`: 42 cases x 5 trials x 2 arms, already committed.

**How the band is reconstructed.** `brain/sampling.py` draws one sample, and re-samples only if
that sample's verdict is borderline, combining with `max`. So per trial:

    band = sampled_arm[i]  if full_arm[i] in BORDERLINE_TITLES  else full_arm[i]

where `full` is the recorded N=1 arm and `sampled` the recorded worst-of-3 arm.

**What that is and is not.** The two arms were scored as separate runs, so `full[i]` is not
literally the first of `sampled[i]`'s three draws - it is an independent draw from the same
distribution. This is therefore a **Monte Carlo estimate over 5 trials, not a replay of the
band itself**, and 5 trials cannot distinguish a flip rate of 0 from one of a few percent. It is
evidence, not the measured run the gate asks for, and this module says so rather than letting
the number imply more.

**One thing here is a proof rather than an estimate.** The band is monotone: it either keeps the
single sample's verdict or raises it with `max`. So no attack can become *more* mergeable under
the band than at N=1, for any N, on any corpus - independent of these trials. That is the
safety property that mattered, and it does not depend on the simulation at all.

Run: `python -m eval.band_sim`
"""

import json
from collections import Counter
from pathlib import Path

from brain.sampling import BORDERLINE_TITLES

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "eval" / "REPEAT_W2.json"
ATTACK_KINDS = {"malicious", "incident", "redteam", "redteam-ind"}
# A verdict a reviewer can merge past. GitHub treats `neutral` as passing.
MERGEABLE = {"Clean", "Needs review"}
# The packages W2 names as the population at risk from widening the band: their installs do not
# finish, so they sit in the band permanently and get 3x the chance of drawing `malicious`.
AT_RISK_BENIGN = ("better-sqlite3", "argon2", "cpu-features", "node-pty", "biome", "cypress")


def load() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def band_outcomes(row: dict) -> list[str]:
    """The widened band's per-trial outcome, reconstructed from the two recorded arms."""
    full, sampled = row["outcomes"]["full"], row["outcomes"]["sampled"]
    return [s if f in BORDERLINE_TITLES else f for f, s in zip(full, sampled, strict=True)]


def flips(outcomes: list[str]) -> bool:
    return len(set(outcomes)) > 1


def report() -> dict:
    data = load()
    rows = data["rows"]
    attacks = [r for r in rows if r["kind"] in ATTACK_KINDS]
    benign = [r for r in rows if r["kind"] == "benign"]

    arms = {
        "full (N=1, recorded)": {r["id"]: r["outcomes"]["full"] for r in rows},
        "sampled (worst of 3, recorded)": {r["id"]: r["outcomes"]["sampled"] for r in rows},
        "band (reconstructed)": {r["id"]: band_outcomes(r) for r in rows},
    }

    print(f"Source: eval/REPEAT_W2.json  commit={data['commit']}  "
          f"trials={data['trials']}  cases={len(rows)}")  # fmt: skip
    print(f"Borderline titles that trigger re-sampling: {', '.join(BORDERLINE_TITLES)}\n")

    print(f"{'arm':34s} {'attack flips':>13s} {'attacks mergeable':>18s} {'benign blocked':>15s}")
    print("-" * 84)
    summary: dict[str, dict] = {}
    for label, by_id in arms.items():
        flipped = [r["id"] for r in attacks if flips(by_id[r["id"]])]
        worst = max(
            sum(1 for r in attacks if by_id[r["id"]][i] in MERGEABLE) for i in range(data["trials"])
        )
        blocked = [r["id"] for r in benign if "Blocked" in by_id[r["id"]]]
        summary[label] = {"flipped": flipped, "worst_mergeable": worst, "benign_blocked": blocked}
        print(f"{label:34s} {len(flipped):>8d}/{len(attacks):<4d} "
              f"{worst:>13d}/{len(attacks):<4d} {len(blocked):>10d}/{len(benign):<4d}")  # fmt: skip
    print()

    for label, s in summary.items():
        if s["flipped"]:
            print(f"  {label}: flipped -> {', '.join(s['flipped'])}")
        if s["benign_blocked"]:
            print(f"  {label}: benign BLOCKED -> {', '.join(s['benign_blocked'])}")
    print()

    print("Per-case detail where the band differs from N=1:")
    any_diff = False
    for r in rows:
        full, band = r["outcomes"]["full"], band_outcomes(r)
        if full != band:
            any_diff = True
            print(f"  {r['kind']:12s} {r['id']:26s} {Counter(full)} -> {Counter(band)}")
    if not any_diff:
        print("  (none)")
    print()

    present = {r["id"] for r in rows}
    missing = [p for p in AT_RISK_BENIGN if p not in present]
    print("Acceptance 3's at-risk population (W2: benign 'Could not verify' native builds):")
    for pkg in AT_RISK_BENIGN:
        print(f"  {pkg:20s} {'in this corpus' if pkg in present else 'ABSENT'}")
    if missing:
        print(f"\n  {len(missing)} of {len(AT_RISK_BENIGN)} are absent, so acceptance 3 CANNOT be "
              "settled from this data:\n  these are exactly the cases the widening puts at risk, "
              "and none of them is here.")  # fmt: skip
    print(f"\n  benign cases present: {', '.join(sorted(r['id'] for r in benign))}")
    return summary


def main() -> None:
    summary = report()
    band = summary["band (reconstructed)"]
    print("\n" + "=" * 84)
    print("Monotonicity (a proof, not an estimate): the band keeps the single sample's verdict")
    print("or raises it with max, so no attack can become more mergeable than at N=1, for any N")
    print("on any corpus. Acceptance 1's *safety* direction holds by construction.")
    print()
    print(f"Simulated attack flip rate: {len(band['flipped'])}/38 over 5 trials"
          + (f" ({', '.join(band['flipped'])})" if band["flipped"] else ""))  # fmt: skip
    print("Five trials cannot distinguish 0 from a few percent, so this is evidence toward")
    print("acceptance 1, not the measured run the gate requires.")
    print()
    print("Acceptance 3 remains UNMEASURED: the 6 benign native-build packages it concerns are")
    print("not in this 42-case corpus. Settling it needs those 6 re-scored, 5 trials, sampled")
    print("arm only - about 90 analysis calls (~$1.20), not the $25 full re-score:")
    print("  python -m eval.repeat <dir> --trials 5 --arms sampled   # with max_workers=1")
    print("W2 therefore stays OFF at MODEL_SAMPLES = 1.")


if __name__ == "__main__":
    main()
