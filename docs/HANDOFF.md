# Handoff — to the workstation that has the `.env`

**Written 2026-11-02 (evening), for the next session on the workstation.** Submission
deadline: **Wed 2026-11-04, 9:00 pm ET**. Plan to submit by mid-afternoon Nov 4.

**State at this commit:** `main` is pushed and clean; **1043 tests pass**, `ruff check` clean
(Windows; one symlink test only runs on Linux). Two feature branches are pushed and **not
merged** (§3). **`main` is ahead of what is deployed** — §5b (Chamber) and §5c (Brain) name
every divergence and say what each one would change; neither blocks submitting. Run
`python scripts/release_ledger.py` for the current identifiers instead of trusting a SHA
quoted in prose: an earlier version of this line named a Brain commit that §5c superseded.

Read this file top to bottom once. Then `CLAUDE.md` (working rules), `BUILD_PLAN.md`,
`HARDENING_PLAN.md`, and `docs/REVIEW_BRIEF.md` for the full technical picture.

---

## 1. First 15 minutes on the workstation

```powershell
git pull                                  # main at the commit that added this file
python -m venv .venv
.venv\Scripts\python -m pip install --use-feature=truststore -r requirements-dev.txt
.venv\Scripts\python -m pytest -q         # expect 432 passed
.venv\Scripts\ruff.exe check .            # expect "All checks passed!"
git fetch origin rt09-dropped-script sensor-witness-cpu
```

Then confirm the things that are **not in git** exist on this machine:

| Thing | Where | Notes |
|---|---|---|
| `.env` | repo root | From `.env.example`; Meta (`LLAMA_API_KEY`), Modal, GitHub App, HF |
| GitHub App private key | outside the repo; path in `GITHUB_PRIVATE_KEY_PATH` | |
| Chamber SSH key + `~/.ssh/config` | `Host chamber` → `3.223.99.234`, user `ubuntu` | `ssh chamber` must work |
| **SBOM signing private key** | **only in the first machine's session scratchpad** (`sbom_signing_key.pem`) | ⚠️ copy it somewhere durable; without it new SBOM records can't be signed under the committed `eval/sbom/public_key.pem` |
| Raw detonation results | on the Chamber in `/tmp/*.tgz` (§6) | needed for every re-score and branch validation |

Gotchas that bite immediately:
- **Norton re-signs TLS on these machines.** Run Modal only through
  `.venv\Scripts\python scripts\modal_cli.py …`. Local scripts that hit the network need
  `truststore.inject_into_ssl()`. For git over HTTPS: `git -c http.sslBackend=schannel …`.
- **PowerShell 5.1:** no `&&`. Write commit messages to a file and `git commit -F` (no BOM).
- **Piping a check into `tail`/`Select-Object` hides its exit code.** Check ruff/pytest
  exit status directly before committing (one commit slipped through this way on Nov 2).

---

## 2. What was done on Nov 2 (second session, no `.env`)

All on `main` unless marked as a branch. Commit hashes for `git show`.

| Commit | Change | Why | Status |
|---|---|---|---|
| `e2ddec1` | The pinned-cert test generated its own cert (the `.pem` fixture was swallowed by the `*.pem` gitignore rule, so every fresh clone failed). README: puppeteer is ⚠️ not ✅, E8 row, test counts, limits. `.env.example`: `https://` Chamber URL + `CHAMBER_CA_PEM`. Disclosure wording → "reported privately". | correctness of docs/tests | done |
| `294826c` | **Stale-check reconciler.** The webhook records each check run (Modal Dict `pr-detonator-pending-checks`); the job removes it on completion; `reconcile_checks` (every 5 min) fails closed any check still open 15 min after creation. A job whose PR got a newer head skips its comment/review. `GitHubClient.get_check_run`, `get_pr_head_sha`. | a hard Modal kill left checks `in_progress` forever; a slow old job could overwrite the newer head's report | **not deployed** |
| `c06b6a1` | **Model outage can't produce Clean.** If Muse is asked and fails, a rules-only result is capped at ⚠️ Needs review ("Reduced coverage"); new base-branch policy key `model_requirement: required` fails the check instead. `LlmOutcome.skipped` marks the eval's deliberate rules-only arms (numbers unchanged). **Differential** suppresses LOW findings only against a fully verified base (`unverified_reason`), and caches only verified bases. | 9 of 20 red-team attacks are Clean on rules alone, so a failed model call turned them green; base trust was `status == completed` only | **not deployed** |
| `30c9838` | **Evidence grounding.** Every telemetry event the model sees has an id (HMAC of the job id). `key_evidence` must cite ids and say `observed` or `source_inferred`. `brain/evidence.py` checks every claim (unknown / other-job / wrong-type ids rejected); report section "Evidence the AI cited, checked against the kernel record" renders cited events *from the kernel record*; hosts/IPs in the model's prose that aren't in the record or diff are flagged; eval gets an unsupported-claim rate. Verdicts unchanged. | Meta-tooling score; structured output guarantees shape, not truth; `key_evidence` was never shown anywhere | **not deployed; changes the Muse schema + prompt** |
| `13a7c31` | Release leak scan (`git archive` + content grep). Removed the disclosure recipient and vendor org from this file. Other hits intended (SBOM public key, per-run decoy creds in a fixture). | embargo | done |
| `540852f` | REVIEW_BRIEF / README / SUBMISSION describe the above; REVIEW_BRIEF tags each "[Test; not yet live-verified]". | | done |
| `b05c0d2`, `181f54f` | **`eval/repeat.py`**: re-score frozen telemetry N times; flip rate, worst-case unsafe passes, benign blocks, grounding over all trials → `eval/REPEAT.{md,json}`. | temperature 0 ≠ determinism | **not run** (~$20 for 142 cases × 5) |
| `d7f6b2a` | **SBOM version delta**: `behavior_delta` / `render_delta`, `python -m brain.sbom diff old.json new.json [public_key.pem]`. Comparability (install finished, untruncated, same package, environment, detector version, signatures), changed scripts by path, an "attention" list (never a verdict). Optional `environment` block on records; committed records byte-identical and still verify. | HANDOFF item 4 | done; **not wired into E8** |
| `d927f96` (was branch `rt09-dropped-script`) | `EXEC_DROPPED_BINARY` also fires for a dropped script run by an interpreter (`sh /tmp/stage.sh`, `node /home/…/x.js`); per-interpreter inline-code flags; relative paths resolved against kernel cwd with `posixpath` only (never touches the host fs). | `rt09` fired no rule; only Muse caught it | **validated and merged.** Re-scored rules-only against all 622 recorded detonations: the 122-case set and the 500-package sweep are identical in blocked count and in which cases fire the rule, while `rt09-dropped-binary` now fires (red-team rules-HIGH 10 → 11). One new true positive, zero new blocks. |
| `e8c328d` (was branch `sensor-witness-cpu`) | **⚠️ Contract v3** (`shared/contract.py`, optional `DetonateResult.sensor` + `resources`). Chamber wraps the install with `/bin/true pre-<nonce>` / `post-<nonce>` markers; the parser accepts a marker only from our wrapper and drops the wrapper and markers from telemetry. Missing marker → Could not verify. Cgroup CPU/memory sampler (systemd and cgroupfs layouts; `None` if neither). Rule `RES_CPU_HEAVY` (LOW, build tools exempt) **off** (`CPU_REVIEW_THRESHOLD_S = None`). | "exec events exist" ≠ "sensor watched this container"; `rt08` leaves only CPU time | **merged and live on both Chamber and Brain.** See the bug note below. |

> **The witness passed 20 unit tests and still failed in production** — worth remembering.
> `_is_wrapper` required the witness shell's parent to be *outside* the container, but the
> sandbox image declares an `ENTRYPOINT`, so the real tree is `docker-entrypoint.sh` → our
> shell → `/bin/true`. Every live run reported `pre_seen=False`, and because `brain/verdict.py`
> fails closed on a missing marker, deploying the Brain would have made **every pull request
> "Could not verify"**. Every test fixture had modelled the wrapper as a direct child of the
> runtime. Fixed in `e8c328d`: a wrapper is accepted when its parent is outside the container
> **or is itself a container root**, which keeps the anti-spoof property (a payload descends
> from the install command, so its shell can have neither an external nor a root parent).
> Validated live: `pre_seen`/`post_seen` true on a benign install and on `m01`, wrapper and
> markers excluded, cgroup sampling returning real numbers. Lesson: validate sensor changes on
> the VM *before* deploying the Brain that enforces them.
>
> Rollback of the Chamber code, if ever needed, is the backup the deploy made:
> `sudo cp -a /opt/pr-detonator/backup-<stamp>/{chamber,shared} /opt/pr-detonator/ && sudo systemctl restart chamber.service`
> (the newest stamp is in `/opt/pr-detonator/LAST_BACKUP`).

Also done outside git: the **disclosure email was sent** Nov 2 to the package's sole npm
maintainer (re-confirmed the issue in that day's latest version first). Docs say "reported
privately, no response or fix yet".

An external "expert" architecture/expansion spec was reviewed against the code (not
committed; it's the user's file). Verdict: its diagnosis was right on the model-outage gap
(worse than it said), the base-comparison trust, free-text evidence and the sensor witness —
all addressed above. Its 7-agent process, adaptive probes, in-toto/DSSE receipts and
automated remediation workflow were judged post-hackathon.

---

## 3. Where we go from here, in order

Each step has a pass condition. If a step fails, stop and fix or revert before the next.

### Step 1 — Live-check the new Muse schema (~5 min) ★ first
`30c9838` changed the response schema (`kind`, `refs`, `event_type: file`). Confirm the Meta
API accepts it: run one analysis against a recorded result, e.g. a tiny script that loads
`tests/fixtures/detonate_real_e4.json` and calls `llm_client_from_env().analyze(...)`, or
`scripts/probe_llama.py` adapted to `brain.llm.SCHEMA`.
**Pass:** a parsed `LlmVerdict` whose `key_evidence` items carry real ids, and
`brain.evidence.check(...)` supports most of them. **If the API rejects the schema:** fix
the schema (likely an unsupported keyword), never ship a Brain that can't parse responses —
with `c06b6a1` that would cap every PR at Needs review.

### Step 2 — Rotate the Modal token, then deploy the Brain from `main` (~15 min)
`modal token new` (the old one went out in a shared ZIP), then
`.venv\Scripts\python scripts\modal_cli.py deploy -m brain.app`. The deploy creates the new
Dict and the `reconcile_checks` schedule.
**Pass:** deploy succeeds; `reconcile_checks` appears as a scheduled function.

### Step 3 — Re-run E1–E8 on GitHub (~15 min)
Push an empty commit to each `e*` branch of `pr-detonator-demo/demo-target` (E7 last: it
holds the Chamber for 180 s). Clone with `git -c http.sslBackend=schannel clone …`.
**Pass:**
- E1/E2/E3 ✅, E4/E5/E6/E8 🛑, E7 🛑 Could not verify (same as Nov 1).
- E4/E5 reports show "Evidence the AI cited … (N of M supported)" with most supported.
- Modal Dict `pr-detonator-pending-checks` gains an entry per run and is empty afterwards.
- The bot's report comment is edited, not duplicated.

### Step 4 — Fetch raw results; validate and merge `rt09-dropped-script` (~30 min)
`scp chamber:/tmp/eval-results-6.tgz .` (+ `rt-out`, `gm-out`, `sweep500`; §6). Run the
branch's rules over every benign and sweep result (a short script calling
`brain.rules.evaluate` on each `DetonateResult`, counting new `EXEC_DROPPED_BINARY` hits vs
`main`). **Pass:** zero new hits on the 104 benign and the 500 sweep; `rt09` now fires. Then
rebase onto `main`, re-run tests, merge, deploy the Brain. **Fail:** narrow the rule (e.g. to
scripts written during the run) or leave it unmerged and keep `rt09` as a model-caught case.

### Step 5 — Chamber deploy of `sensor-witness-cpu` (~1 h) — the risky one
1. **Snapshot first:** create a fresh AMI of the working Chamber (an older one exists:
   `pr-detonator-chamber-2026-11-01`). This is the rollback.
2. Rebase the branch onto `main` (expect a small conflict in `brain/rules.py`: both
   branches touch it), run tests.
3. Copy the branch's `shared/` and `chamber/` to the VM and `sudo bash
   chamber/provision/setup.sh` (idempotent; keeps secret and TLS cert — `demo/RUNBOOK.md`).
4. On the VM, **probe before trusting** (CLAUDE.md rule): confirm the container cgroup path
   (`/sys/fs/cgroup/system.slice/docker-<id>.scope/cpu.stat` or `…/docker/<id>/…`) and
   that Tetragon reports the wrapper with a `containerd-shim` parent and the two
   `/usr/bin/true pre-/post-<nonce>` execs. Record a real line as a test fixture.
5. Deploy the Brain from the branch, re-run E1–E8.
**Pass:** every run reports `sensor witness ✓`, CPU seconds appear in the footer, E1–E8
unchanged. **Fail / anything odd:** redeploy `main`'s `chamber/` (the Brain treats a missing
witness as a v2 Chamber), or restore the AMI. Don't debug on the live VM past ~30 min.

### Step 6 — Re-run the benign set; calibrate `rt08`; merge the witness branch (~1–1.5 h VM)
Re-detonate the 104 benign + attacks on the v3 Chamber (`eval/run_chamber.py`, chained —
the Chamber is single-job). **Pass:** zero new "Could not verify" from the witness. Then
look at `cpu_s` for benign (with and without build tools) vs `rt08`/`gm08`; set
`CPU_REVIEW_THRESHOLD_S` only if there's clear separation, else leave it off and say so.
Merge the branch.

### Step 7 — Re-score, re-stamp, repeatability (~1 h, ~$25 API)
From a **clean tree**: `python -m eval.run_brain <dir> eval/results` (stamps the commit;
gains the grounding section), the red-team set likewise, then
`python -m eval.repeat <dir> --trials 5`. Update README / SUBMISSION / eval/README /
REVIEW_BRIEF numbers, and change every "[Test; not yet live-verified]" tag that now holds
to "[Live]". **Report the worst case** from `REPEAT.md`, not the mean.

### Step 8 (optional) — SBOM delta in the E8 demo (~45 min)
Detonate color-helper 1.0.0 and 1.0.1, build both records with `environment` (image
digest, node, npm, command) via `scripts/build_sbom.py`, sign with the SBOM private key,
commit, and show `python -m brain.sbom diff … eval/sbom/public_key.pem` (expect: new raw IP,
changed `install.js`). Skip if the key is lost.

### Step 9 — Nov 4: record, submit
- **Record the demo** (`demo/DEMO_SCRIPT.md`) + a backup recording. Biggest single score
  lever. Consider a beat on the grounding section and "the AI can't silently drop out".
- Paste the video URL into `docs/SUBMISSION.md` (still `_[link]_`); check it logged out.
- Confirm the official rules/weights in the participant portal.
- Release artifact: `git archive --format=zip -o release.zip HEAD`, then grep its contents
  for `.env`, keys and the embargoed identifiers (§7) before sharing.
- Submit by mid-afternoon; keep VM, Modal app and API quota up through judging.

**Cut order if time runs short:** 8 → 6's calibration (leave CPU rule off) → 5–6 entirely
(leave witness unmerged; describe it as built, not shipped) → 4. Never cut 1–3, 7, 9.

---

## 4. Disclosure (owner's)

Sent Nov 2 to the sole npm maintainer. If no reply in 1–2 weeks: ask the vendor's public
code host for a private security contact (no details in public), then security@npmjs.com.
Say "acknowledged"/"fixed" only if they actually reply or ship a fix. Keep the recipient and
package identifiers out of this repo (they're in the owner's sent mail).

## 5. Open items only the owner can do

1. Back up the **SBOM signing private key** from the first machine (§1).
2. **Rotate the Modal token** before deploying (§3 step 2).
3. **Record the demo**, paste the URL, confirm the rules (§3 step 9).

## 5b. Chamber code in `main` that is NOT on the box

### `persistence-files.yaml` — DEPLOYED and measured, Nov 3

`chamber/policies/persistence-files.yaml` is **live on the Chamber** and installed to
`/etc/tetragon/tetragon.tp.d/`, so it survives a restart. `FILE_PERSISTENCE` is at **HIGH**,
promoted on the measurement in [`eval/PERSISTENCE.md`](../eval/PERSISTENCE.md): **0 of 104**
benign controls open a persistence path, `truncated` stayed false on all 106 runs, and
`gm04-rcfile-persist` / `rt06-persist-rcfile` now **Block** where they previously fired no rule
at all.

It was loaded with `tetra tracingpolicy add` rather than a Tetragon restart — the existing
sensors were never interrupted. Rollback:

```bash
ssh chamber 'sudo tetra tracingpolicy delete persistence-files \
  && sudo rm -f /etc/tetragon/tetragon.tp.d/persistence-files.yaml'
```

**If you deploy a Tetragon policy again, do it in this order** (the earlier version of this
section had it backwards): detonate the two or three cases that *should* fire it first, confirm
the events arrive, and only then spend an hour on the benign denominator. And check validity
before believing a clean false-positive count — npm reads `~/.npmrc` on every install, so a
record with no `file_events` means tracing died, and a block of those would read as "zero false
positives" for entirely the wrong reason.

Two hardening changes to `chamber/detonate.py` are committed but **not deployed**. The running
Chamber still has the old `validate`. Both are strict tightenings that reject nothing the Brain
or the eval harness actually sends, so the divergence is harmless and there is **no need to
redeploy before filming** — a Chamber deploy carries real risk (see
[`CHAMBER_RECOVERY.md`](CHAMBER_RECOVERY.md), the IP-SAN trap), and these buy defence-in-depth
on a boundary only the HMAC-signing Brain can reach.

| Change | What it rejects | Verified against |
|---|---|---|
| `JOB_ID_RE` requires an alphanumeric first char | `job_id` starting `-` (was not exploitable) | uuid4 shape |
| Command tail allowlisted token by token | `--ignore-scripts`, `--prefix /etc`, `--registry=…`, non-package args | all 142 real `eval/cases.py` commands + `registry_sweep` specs |

Deploy them with the next Chamber deploy that happens for another reason. If you do deploy,
re-run one benign and one attack case afterwards — the command allowlist is on the hot path for
every detonation.

## 5c. Brain code in `main` that is NOT deployed

The deployed Brain is **v33 (Nov 2, 16:45 ET)**, which predates every Brain commit after
`a96c8a1`. Check with `python scripts\modal_cli.py app history pr-detonator` and compare against
`git log -- brain/`. Not deployed:

| Change | Effect if deployed | Effect of leaving it |
|---|---|---|
| `brain/evidence.py` — uncited-prose check (`e8e7098`) + its false-positive fix (`d8a3d81`) | A grounding line appears when the model's prose cites a path or port the record does not support | Nothing observable. See the note below |
| `brain/sampling.py`, `brain/pipeline.py` — best-of-N band (`4167bb0`, `d57728b`) | None: `MODEL_SAMPLES = 1`, so the code is inert either way (W2 ships off) | None |
| `brain/evidence_manifest.py` — signable provenance record (new) | None: not wired into `pipeline.py`. It is a standalone capability with a CLI verifier, gated behind coordinator review before any pipeline wiring, per the v5 plan's Ticket A | None — nothing calls it in production yet |
| `brain/runlog.py` — `detonation_s` escaped on the dashboard | None visible; closes a gap against the file's stated invariant | None — the value is a float, so nothing can inject through it |

**No action needed before submitting.** `docs/SUBMISSION.md` §grounding describes the
uncited-prose check, and that description is accurate: it is a claim about the repository and
about the eval numbers, and `eval/run_brain.py` imports `brain.pipeline.analyze` directly
(it uses the deployed app only for the separate `PromptGuard` class), so every eval figure comes
from this working tree, not from the deployed Brain. The only component running the older code
is the live GitHub App, where the prose check fires on nothing we have observed anyway — so
there is no visible difference to a judge opening a PR. Deploy it with the next Brain deploy
(after rotating the Modal token, W10 §5.2); do not deploy specially for this.

**Verdict numbers are unaffected by any of this.** `grounding` is computed *after* `combine()`
in `brain/pipeline.py` and flows only into the rendered report, so it can never move a verdict —
the eval tables stamped at `a96c8a1` still hold and need no re-score.

**Re-checked at `1a73403`.** `python scripts/release_ledger.py` lists every code file touched
since the eval stamp, which is the right prompt but not the answer — and that list has grown
from 7 files to 14, so the earlier version of this table (written at `8f2b657`) was stale.
**Do not hand-audit this any more:** `python -m eval.score_rules <telemetry> --verify` re-derives
the stamped `rules` column from the recorded telemetry and names any disagreement. It currently
reports **141 of 142 agreeing, with one recorded difference**, which is the answer this table
used to approximate.

| Changed since `a96c8a1` | Moves a verdict? |
|---|---|
| `brain/rules.py` — `EXEC_SCHEDULED_PERSISTENCE` | **Yes, one case.** `gm05-cron-inject` Clean → Blocked at the rules level. Measured 0 matches in 604 uncurated packages and 0 of 104 benign. Its `full` verdict was already Blocked, so no published figure changes. Recorded in `eval/score_rules.py::KNOWN_DRIFT` |
| `brain/rules.py` — `FILE_PERSISTENCE` | **No, on this telemetry.** The policy was not loaded on Nov 2, so no recorded record carries those `file_events`. It *does* move `gm04`/`rt06` on telemetry captured after the deploy — see `eval/PERSISTENCE.md` |
| `brain/intent.py` — W13 second key | **No.** A conjunct can only shrink what gets cleared, and all three hosts ever cleared are on the vendor list; pinned by `test_the_fix_changes_no_verdict_in_the_stamped_evaluation` |
| `brain/timeline.py`, `brain/report.py` | **No.** Built after `combine()` and passed only to `render()`; all five attack fixtures keep their verdicts |
| `brain/evidence.py` | **No.** Grounding is computed after `combine()` and feeds only the report |
| `brain/sampling.py`, `brain/pipeline.py` | **No.** `MODEL_SAMPLES = 1`, so the band is never entered |
| `brain/runlog.py`, `brain/sbom.py` | **No.** Dashboard escaping and the SBOM CLI's terminal rendering |
| `chamber/detonate.py`, `chamber/telemetry.py` | **No.** Strict input tightenings that reject nothing the harness sends; still not deployed |
| `chamber/policies/persistence-files.yaml`, `chamber/provision/setup.sh` | **No** retroactively — a new tracing policy cannot change telemetry already recorded |
| `eval/cases.py` | **No.** One comment about the rt08 CPU measurement |

So the stamped tables still hold, with the one recorded `gm05` exception. Re-run the full eval
only when a *behavioural* change lands that `score_rules --verify` flags as an unexplained
disagreement.

## 6. Raw detonation results

Scored outputs are committed (`eval/results.json`, `eval/REDTEAM.json`, `eval/SWEEP*.json`);
raw per-case `DetonateResult` JSONs are not. They're on the Chamber:

```powershell
scp chamber:/tmp/eval-results-6.tgz .   # the 122-case set
scp chamber:/tmp/rt-out.tgz .           # rt01-rt10
scp chamber:/tmp/gm-out.tgz .           # gm01-gm10 (independent red team)
scp chamber:/tmp/sweep500.tgz .         # 500-package sweep
scp chamber:/tmp/sweep-out.tgz .        # 100-package sweep (contains the finding)
tar -xzf eval-results-6.tgz
```

Re-score: `.venv\Scripts\python -m eval.run_brain <dir> eval/results` (needs
`LLAMA_API_KEY` and the deployed Modal app; score from a clean tree).

**Rules-only re-score, free and offline** — `eval/score_rules.py`. This is the one to reach for
while changing a rule, because it answers "does this hard-block anything benign" with no model,
no Modal and no cost, in about a second:

**Mind the nesting.** `v3-out.tgz` contains a `v3-out/` directory, so extracting it into a
folder of the same name gives `v3-out/v3-out/*.json`. `eval/score_rules.py` searches with
`rglob` and finds them either way; **`eval/repeat.py` joins the path directly and will silently
match zero cases**, printing a cheerful `0 cases × 5 trials` and spending nothing. Check the
case count in the output before believing a clean result.

```powershell
scp chamber:/tmp/v3-out.tgz .    # the 142-case set the current eval was scored from
tar -xzf v3-out.tgz              # -> ./v3-out/*.json  (142 files; verify with `ls v3-out`)
.venv\Scripts\python -m eval.score_rules v3-out --verify            # reproduces the stamp
.venv\Scripts\python -m eval.score_rules v3-out --baseline base.json
#   ... change a rule ...
.venv\Scripts\python -m eval.score_rules v3-out --compare base.json # what moved
```

`--verify` re-derives the stamped `rules` column from the telemetry and fails on any
disagreement not listed in `KNOWN_DRIFT` with a measurement behind it. Run it first: if the
harness cannot reproduce the committed numbers, its verdict on a *change* is worthless too.
Point it at `sweep-out`/`sweep500` as well for 604 uncurated packages of false-positive
denominator.

## 7. Gotchas

- **One Chamber job at a time** (409 when busy). Chain long runs with a wait loop.
- **`pgrep -f <manifest-name>` matches your own wait loop.** Match on `run_chamber.py`.
- **Never zip the working directory** (ships `.env`, `.git/`, `.venv/`). Use `git archive`.
- **The sweep finding's identifier is in public git history** (`07feaba`, and the vendor org
  in `e2ddec1`); the current tree is clean (release scan, `13a7c31`). Don't claim it's
  concealed; don't show `git log` on camera; don't rewrite history.
- **`eval/SWEEP.md` is the 100-package run** with the finding and must stay that way;
  the 500-package run is `eval/SWEEP500.md`.
- **Eval stamps:** `eval/results.*` is stamped `0aff394`, `eval/REDTEAM.*` `1aa9c45`. Every
  Nov 2 code commit touched `brain/`, so both must be re-stamped (step 7).
- **The Muse schema changed** (`30c9838`). Recorded responses from before still parse (new
  fields default), but their claims count as unsupported. That's correct, not a bug.
- **A test run once took 44 min** on the first machine; re-runs took ~40 s with no slow test.
  It was the machine stalling. If it happens again, run `pytest --durations=10`.

## 8. Claims to keep honest

- "0 blocked across 104 popular packages": true. **"104/104 clean" is not**: 95 clean,
  3 needs review, 6 could not verify — four native builds that exit 1 in this image
  (`better-sqlite3`, `argon2`, `cpu-features`, `node-pty`) and two that hit the install timeout
  (`biome`, `cypress`). Checked against `eval/results.json` at the stamped commit; an earlier
  version of this line and of `docs/SUBMISSION.md` said 97/3/4, which was stale.
- **19/20 red team is 95% of that cohort**, not a real-world detection rate (exact 95% CI
  roughly 75–100%).
- The **500-package sweep can't give a false-positive rate**: the packages aren't labelled.
- Dormant payloads blocked from diff content are **source-assisted**, not kernel-observed.
  (The grounding labels these `source_inferred` now.)
- **Hardened Docker in a dedicated VM, not a microVM**; public TCP egress is still allowed.
- Temperature 0 is not determinism; Prompt Guard misses indirect injection (measured).
- `rt08` (inline CPU loop) is an honest miss until step 6 says otherwise.
- **Nothing from Nov 2's second session is live** until steps 1–7 say so. Don't describe
  the grounding, reconciler, model-outage cap or witness as live-verified before then.
- A signed SBOM record proves the record wasn't edited, **not** that the package is safe.
