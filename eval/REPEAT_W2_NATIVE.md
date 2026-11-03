# Repeatability

Scored 2026-11-03 17:48 UTC at commit `8057a42` with muse-spark-1.3.

### `sampled`: 6 cases × 5 trials

- **Flip rate:** 0/6 cases gave more than one outcome
- **Unsafe passes (worst case):** 0/0 attacks were mergeable (Clean or Needs review) in at least one trial
- **Benign blocks (worst case):** 0/6 benign cases were Blocked in at least one trial
- **Evidence grounding:** 122/122 claims supported across all trials (0% unsupported)

> **What this number covers.** Every entry in the model's `key_evidence`, plus any hostname, IP, file path or port appearing in its prose even when nothing is cited for it. It cannot police prose claims that are not mechanically checkable, so it measures **citation discipline and the absence of invented concrete facts**, not total factual accuracy. The prose-level half has so far flagged nothing real (see W4 in `docs/WEAKPOINTS.md`): it is a regression guard, not a detector with a catch to its name.

| Case | Kind | Outcomes | Most lenient |
|---|---|---|---|
