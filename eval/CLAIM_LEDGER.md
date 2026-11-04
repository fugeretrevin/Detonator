# Claim ledger

Every public claim, with the artifact that supports it, its scope, and what it does **not**
establish. Proposed by an independent audit on 2026-11-03 so that a reader can check any
statement without reconstructing the evidence trail, and so that a claim cannot quietly outlive
the measurement behind it.

**Scope column reads as:** what the number is *about*. **Limit column:** the inference it does
not license. Where a claim is machine-checkable, the Test column names the test that recomputes
it from the stamped artifact — those cannot drift. Prose conclusions still need human review.

Stamped evaluation: commit `a96c8a1`, scored 2026-11-02 22:39 UTC, 142 cases.
Code baseline for this ledger: `453374e`.

## Detection and verdict claims

| # | Claim | Source artifact | Scope | Limit | Test |
|---|---|---|---|---|---|
| C1 | 0 of 104 benign controls hard-blocked | `eval/results.json` | A curated set of popular packages, full pipeline | Not a false-positive *rate* for npm; 95% upper bound 3.5%; 6 of the 104 were unverifiable | `test_the_benign_cohort_is_still_104_cases`, `test_the_submission_states_the_stamped_benign_tally` |
| C2 | 16 of 16 designed attacks blocked | `eval/results.json` | Author-written attack PRs, one scored draw | Consistent with a true rate as low as **79.4%**; 15 of 16 at rules level | `test_the_attack_cohorts_block_as_claimed` |
| C3 | 2 of 2 incident reconstructions blocked | `eval/results.json` | Defanged ua-parser-js and Shai-Hulud | 95% lower bound **15.8%** — statistically near-worthless; two illustrative patterns | `test_the_attack_cohorts_block_as_claimed` |
| C4 | 19 of 20 red-team cases blocked | `eval/REDTEAM.json` | 10 author + 10 model-suggested | `rt08` is an open miss; the "independent" set was suggested, not administered, by a third party | — |
| C5 | 6 of 104 benign unverifiable | `eval/results.json` | The Nov 2 run | **Not a fixed rate.** Re-detonated Nov 3: 4. `biome`/`cypress` are install-timeout variance; only the 4 native builds reproduce | `test_every_unverifiable_package_named_in_the_submission_really_is_one` |
| C6 | 73 of 73 that installed came back clean; 1 of the other 27 blocked | `eval/SWEEP.json` | 100 uncurated packages off the change feed | **Two denominators.** The flagged package timed out and is not among the 73 | `test_the_headline_sweep_claim_does_not_mix_denominators` |
| C7 | 413 of 421 that installed clean, 1 blocked | `eval/SWEEP500.json` | 500 uncurated packages | **Unlabelled corpus** — an alert rate, not accuracy. The blocked one installed cleanly and fetched a Python toolchain; may be legitimate | `test_the_demo_script_does_not_claim_the_500_sweep_had_no_benign_blocks` |
| C8 | One real unreported install-time RCE exposure found | `eval/SWEEP.md`, source review | A single package, privately reported 2026-11-02 | **Not malware.** No maintainer response, no fix. Found by behaviour; the vulnerability was established by reading source afterwards | — |

## Model-contribution claims

| # | Claim | Source artifact | Scope | Limit | Test |
|---|---|---|---|---|---|
| M1 | Intent Contract cuts benign needs-review 4 → 3 | `eval/results.json` arms | One case: `prisma` | **One case.** Published as 5 → 3 until 2026-11-03, which overstated it 2× | `test_no_document_overstates_the_intent_contract`, `test_the_contract_moves_exactly_one_benign_case` |
| M2 | Post-run analysis blocks 1 attack the rules cannot | `eval/results.json` arms | One case: `m12` | **Unstable.** `m12` is Blocked ×4 / needs-review ×1 over 5 identical-telemetry trials | `test_no_attack_flips_under_the_reconstructed_band` (band), `eval/REPEAT_W2.json` (N=1) |
| M3 | 452 of 452 cited claims resolve to a real kernel event of the right type | `eval/results.md` | Typed citations plus concrete entities in prose | **Citation discipline, not semantic correctness.** Cannot police uncited abstract prose. The prose half has flagged nothing real | `test_every_published_grounding_number_carries_its_caveat` |
| M4 | Payload decoded in 5 of 5 obfuscated attacks | `eval/README.md` | 5 selected cases, hand-checked | Tiny sample; selected, not held out | — |
| M5 | Right package and file attributed in 2 of 2 dependency attacks | `eval/README.md` | 2 selected cases | Two cases, both our own reconstructions, hand-checked and not held out. 95% lower bound 15.8% | — |
| M6 | No model output can lower a rule severity | `brain/verdict.py` | `combine()` takes `max(rule, model, extra)` | **One documented exception:** the Contract may clear a LOW `NET_UNLISTED_DOMAIN` hit, and only when the host is also on a list the PR author cannot write to | `test_high_and_critical_hits_are_never_cleared`, `test_an_attacker_registered_domain_cannot_clear_its_own_low_hit` |

## Cost, latency and engineering claims

| # | Claim | Source artifact | Scope | Limit | Test |
|---|---|---|---|---|---|
| E1 | $0.0181 per PR mean | `eval/results.json` | **Model API spend only** | Excludes detonation-host compute and network, which dominates at this volume | `test_the_published_cost_per_pr_matches_the_stamped_runs`, `test_the_cost_figure_is_scoped_to_model_spend` |
| E2 | Detonation p50 5.9 s, model p50 36.5 s | `eval/results.md` | 142 scored cases | End-to-end is roughly the **sum**, not the max: the analysis reads telemetry so it cannot overlap. Model took longer than detonation in 132 of 142 | `test_no_document_carries_the_superseded_latency_figures`, `test_nothing_claims_the_model_is_fully_overlapped_with_the_sandbox` |
| E3 | 938 automated tests pass | local + fresh clone | This commit | 3 skipped (Linux-only symlink, Modal-dependent). 929/6 from an extracted archive with no `.git` | — |
| E4 | 19 deterministic rules | `brain/*.py` | Rule ids defined in source | Counted from source, not asserted in prose | `test_the_documented_rule_count_matches_the_code` |
| E5 | Reproducible from a fresh clone | manual verification | `origin/main`, new venv | Also verified with the Modal SDK unimportable: 750 passed / 5 skipped | — |
| E6 | `FILE_PERSISTENCE` has 0 false positives on 104 benign | `eval/PERSISTENCE.md` | Live re-detonation with the policy loaded | 104 curated controls only; validity confirmed first (every record carried file events) | `test_it_is_high_and_that_severity_was_measured_not_assumed` |
| E7 | `EXEC_SCHEDULED_PERSISTENCE` has 0 false positives on 604 uncurated packages | `docs/WEAKPOINTS.md` W5 | 3342 exec events across 742 installs | Argv-based; cannot see what a payload does through node's `fs` API | `tests/test_schedule_persistence.py` |

## Claims deliberately **not** made

Recorded because the temptation exists and an audit asked for it explicitly.

| Not claimed | Why not |
|---|---|
| "Zero false positives on npm" | 0/104 is zero hard blocks on a curated control set. Review verdicts and unverifiable outcomes exist; the registry sweeps are unlabelled |
| "We catch all supply-chain attacks" | Install-time only. Import-time and runtime payloads (the event-stream class) are out of scope entirely |
| "The sandbox is isolated" / "blocks all exfiltration" | Egress permits arbitrary public TCP after blocking private ranges, the metadata address and non-TCP. It is a detector with partial containment |
| "We run in a microVM" | It is a hardened Docker container on a shared EC2 host. Docker is not a VM boundary |
| "The AI found the vulnerability" | Deterministic runtime observation produced the lead; a human read the source to establish the vulnerable path |
| "The maintainer fixed it" | No response and no fix as of this commit |
| "We beat Socket / OpenSSF Package Analysis" | No head-to-head has been run. Dynamic package analysis is established prior art |
| "The model never hallucinates" | 452/452 measures citation validity, not semantic truth |
| "Everything in the repo is live" | `docs/HANDOFF.md` §5b/§5c enumerate what is deployed versus committed; `scripts/release_ledger.py` prints the identifiers |
| "Sampling improves stability, so it is on" | It ships **off**. Acceptance 1 is unmeasured for the band, and the cost gate rejected the unconditional version |
