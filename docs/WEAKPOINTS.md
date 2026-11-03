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
| W2 | `m12` verdict is a coin flip | High (our headline number) | Before, if measured |
| W3 | 6 of 104 benign unverifiable | Medium | After |
| W4 | Grounding metric narrower than it sounds | Medium (we overstated it) | Before (wording), After (checker) |
| W5 | `rt08` open miss | Medium | After |
| W6 | Single Chamber VM, no tested restore | **High** (demo-day risk) | Before |
| W7 | Reconciler deployed but never fired | Medium | Before |
| W8 | Sandbox egress is open TCP | Medium (honestly documented) | After |
| W9 | Private-repo path never exercised | Low–Medium | Before (cheap) |
| W10 | Modal token not rotated | Medium | Before (1 min) |
| W11 | Disclosed package unfixed; name in git history | Medium (ethical) | Ongoing |
| W12 | Red-team set is not blind | Medium (claim hygiene) | After |

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

---

## W3 — 6 of 104 benign packages cannot be verified

**Why it matters.** `better-sqlite3`, `argon2`, `cpu-features` and `node-pty` exit 1 because
`chamber/sandbox/Dockerfile` is `node:20-slim` plus curl/wget/netcat/git/python3 — **there is no
C toolchain**, so `node-gyp` cannot build. `biome` and `cypress` hit the install timeout. That
is ~6% of mainstream packages on which we return no answer.

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

**Plan (post-judging).** An egress broker: allow the npm registry and a vetted vendor-download
list, drop everything else **after logging the attempt**, so the attempt remains evidence rather
than vanishing. Then measure install success and review rate on the *same* 104 benign set plus a
fresh 100-package sweep, before and after.

**Acceptance.** Zero unapproved public transmission in a controlled test; benign install success
within 2 packages of today's baseline; connect *attempts* still recorded in telemetry; a
documented rollback to the current rules.

**Gate: after judging.** Changing egress two days out risks breaking benign installs across the
whole control set with no time to re-validate — and the honest documentation is already there.

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

**Gate: after judging.** Until then the phrasing stays "suggested by a model that had not seen
the rules", never "independently validated".

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
