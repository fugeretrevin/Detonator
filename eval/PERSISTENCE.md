# Install-time persistence tracing: deployed and measured

**Nov 3, 2026.** `chamber/policies/persistence-files.yaml` traces opens of shell startup files,
cron spools and systemd units. This records the live deployment and the measurement that
promoted `FILE_PERSISTENCE` from LOW to HIGH, because a blocking rule with an unmeasured
false-positive rate is the thing `docs/WEAKPOINTS.md` exists to prevent.

## Why the rule was needed

Re-scoring the recorded corpus with the rules alone (`eval/score_rules.py`) showed ten attack
cases the deterministic rules do not Block. Four shared one cause: `file_events` reported only
the four planted *credential* paths, so a payload appending to `~/.bashrc` left **no trace at
all** — not a weak signal, nothing. `gm04-rcfile-persist` and `rt06-persist-rcfile` scored Clean
with zero rules fired.

## What was deployed, and how

Loaded **live** with `tetra tracingpolicy add`, not by restarting Tetragon: the existing
`credential-files` and `detonator-connect` sensors were never interrupted (their post counts
kept climbing throughout), and rollback is a single `tetra tracingpolicy delete`. It was then
installed to `/etc/tetragon/tetragon.tp.d/` so it survives a restart. `chamber/provision/setup.sh`
installs `chamber/policies/*.yaml` by glob, so a fresh provision picks it up.

The installed `credential-files.yaml` was diffed against the repo first: byte-identical, no
drift on the box.

It reuses `security_file_open` with the same single `file` argument as the credential policy, so
**no new Tetragon event shape** is involved — the Brain parses `args[0].file_arg.path` exactly as
before.

## Order of operations: mechanism first, denominator second

The two attack cases were detonated **before** the 104 benign, deliberately. If the policy had
not produced the expected events there was no point spending an hour on the false-positive
denominator. (The runbook in `docs/HANDOFF.md` §5b originally listed benign first; that was the
wrong order and has been corrected.)

| Case | File events captured | Rules | Verdict before | Verdict after |
|---|---|---|---|---|
| `gm04-rcfile-persist` | `~/.bashrc`, `~/.zshrc` | 2 × `FILE_PERSISTENCE` | Clean (no rule fired) | **Blocked** |
| `rt06-persist-rcfile` | `~/.bashrc` | 1 × `FILE_PERSISTENCE` | Clean (no rule fired) | **Blocked** |

## The false-positive measurement

All **104 benign controls** re-detonated live against the registry with the policy loaded.

| | Result |
|---|---|
| Benign cases opening any persistence path | **0 of 104** |
| Benign cases where `FILE_PERSISTENCE` fires | **0 of 104** |
| Runs with `truncated` telemetry | **0 of 106** |

**Validity was checked before the result**, because a clean number means nothing if the
collector was dead. npm reads `~/.npmrc` on every install, so a properly traced record always
carries at least one file event:

| Validity check | Result |
|---|---|
| Completed runs with zero exec events (blind collector) | 0 |
| Runs whose sensor witness failed | 0 |
| Runs with **no** `file_events` at all | 0 |

So "0 of 104" means *nothing opened these paths*, not *tracing was not running*. The policy's
post counter also rose during the run, confirming it stayed loaded.

## Two honest notes

**The policy is host-global.** Host shell startups reading `/etc/bash.bashrc` post events too —
7 observed, every one `/bin/bash` outside any container, all from SSH logins during this work.
The Chamber's parser filters to the job's container, so they can never reach a verdict, and the
volume is negligible against the 200 MB export budget. Recorded rather than left to be
rediscovered.

**Two benign verdicts differ from the stamped eval, and neither is caused by this rule.**
`biome` (Could not verify → Clean, installed in 5.8 s) and `cypress` (Could not verify → Needs
review, 40 s) had previously hit the 240 s install timeout. Neither fires `FILE_PERSISTENCE`.
That is real-world variance: this corpus installs live packages, so the "6 could not verify" in
W3 is a property of the Nov 2 run rather than a fixed rate — on Nov 3 it was 4. The stamped
`eval/results.json` is deliberately left untouched; this is a separate measurement, not a
re-score.

## What this does not close

Sibling-package tampering (`gm10-dep-tamper`, `rt07-self-propagate`) is still open. Those
rewrite a file inside a *different* `node_modules` package, which needs write tracing under
`/work/node_modules/` — a prefix npm writes constantly, so it would flood the event cap and,
because truncation fails closed, turn every verdict into "Could not verify". That needs a
write-only filter plus a volume benchmark and a `cwd`-based discriminator between a script
writing into its own package and a sibling's. See `docs/WEAKPOINTS.md` W5.
