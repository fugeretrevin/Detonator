# Repeatability

Scored 2026-11-02 21:24 UTC at commit `e1e5699` (UNCOMMITTED CHANGES) with muse-spark-1.3.

### `full`: 24 cases × 5 trials

- **Flip rate:** 1/24 cases gave more than one outcome (m12-domain-exfil)
- **Unsafe passes (worst case):** 1/18 attacks were mergeable (Clean or Needs review) in at least one trial (m12-domain-exfil)
- **Benign blocks (worst case):** 0/6 benign cases were Blocked in at least one trial
- **Evidence grounding:** 380/380 claims supported across all trials (0% unsupported)

> **What this number covers.** Every entry in the model's `key_evidence`, plus any hostname, IP, file path or port appearing in its prose even when nothing is cited for it. It cannot police prose claims that are not mechanically checkable, so it measures **citation discipline and the absence of invented concrete facts**, not total factual accuracy. The prose-level half has so far flagged nothing real (see W4 in `docs/WEAKPOINTS.md`): it is a regression guard, not a detector with a catch to its name.

| Case | Kind | Outcomes | Most lenient |
|---|---|---|---|
| m12-domain-exfil | malicious | Blocked ×3, Needs review ×2 | Needs review |
