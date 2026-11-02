# PR Detonator — submission write-up

Paste-ready sections for the submission form. Numbers are from the stamped evaluation in
[eval/README.md](../eval/README.md); re-run the eval at the final commit before submitting
and update the figures and the commit hash here (see "Before you submit" at the end).

---

## Tagline (one line)

**Static scanners read code. PR Detonator runs it — in a kernel-traced sandbox — and holds
what it did against what the pull request claimed.**

---

## The problem (120 words)

Supply-chain attacks have moved to **install time**. A package's `postinstall` script runs on
every laptop and CI runner that installs it, before anyone imports a line of its code. That
is how event-stream (2018), ua-parser-js (2021) and the Shai-Hulud npm worm (2025) spread —
and the pull request that lets them in is usually a one-line version bump that review and
auto-merge wave straight through.

Reviewing the diff doesn't help: the malicious code isn't in the diff, it's inside the
dependency. Static and LLM code review read code that attackers obfuscate, and an LLM
reviewer can be talked out of a finding by text the attacker also controls.

---

## What it is (100 words)

A GitHub App. On every pull request it clones the exact head commit into a disposable,
hardened sandbox, runs `npm install`, and records what the code actually does at the kernel
level with eBPF: every process executed, every TCP connection attempted, every DNS lookup,
and which directory each install script ran from.

Deterministic rules turn those kernel facts into a severity floor. Meta's Muse predicts what
the PR *should* do before it runs, explains what it actually did, and — for borderline cases
— investigates with tools. The verdict is a check run that blocks the merge, plus an inline
review comment on the exact line responsible.

---

## The core idea

> **The model predicts. The kernel verifies. Rules set the floor.**

1. **Ground truth from the kernel.** Tetragon's `tcp_connect` fires on the SYN, so even a
   connection to an unreachable host is recorded. The sandbox's only DNS resolver logs every
   lookup, so a connection is named by the answer the sandbox actually received — and
   "connected with no lookup at all" becomes the strongest signal we have.
2. **The Intent Contract.** Before any telemetry exists, Muse predicts the expected hosts and
   executables from the PR's title, description and file names **only — never the diff**, so
   payload code can't steer the prediction. Code, not the model, then compares that prediction
   to the kernel record. This is the measurable answer to "why do you need a model": it cut
   benign "needs review" results from 5 to 3 without clearing a single attack.
3. **Un-talk-out-able.** Model output can only ever *raise* severity. Deterministic rules set
   a floor no model can lower. Prompt injection in the PR becomes evidence rather than
   influence. Timeouts, crashes and integrity failures all fail closed — never "clean".
4. **The guilty line.** When a PR is blocked, code walks the flagged process back to the npm
   lifecycle script that launched it and comments on that exact diff line. If a *dependency's*
   script did it, the Chamber copies the file out of the sandbox and we point at the line
   inside it, with a sha256 — so the author of an innocent-looking version bump sees the real
   payload.

---

## How Meta's models are used (and what each one measurably adds)

| Model | Role | Measured contribution |
|---|---|---|
| `muse-spark-1.3` | **Intent Contract** — predicts expected install behavior from PR text alone, before the sandbox runs | Cut benign "needs review" 5 → 3 with zero attacks cleared. Runs in parallel with detonation, so it adds no latency |
| `muse-spark-1.3` | **Behavior analysis** — compares stated intent with the kernel record, explains it, decodes obfuscation onto the guilty line | Caught the one attack rules alone miss (exfiltration to an ordinary resolvable domain). **Decoded the payload correctly in 5/5 obfuscated attacks** and named the right dependency and file in **2/2** dependency-delivered attacks |
| `muse-spark-1.3` + tool calling | **Investigator agent** — for ⚠️ verdicts only, with three read-only tools (npm registry facts, our host classification, the captured install script) | Produces a triage note for the human: *"puppeteer, published 2013, maintainers unchanged, install.mjs only calls downloadBrowsers(); storage.googleapis.com is a known package CDN."* Can escalate to blocked, never clear |
| **Llama Prompt Guard 2 (86M)** | Screens the PR text for jailbreaks, on CPU | **Validated before it was allowed to affect anything**: catches explicit jailbreaks (0.97–1.00) but *missed* the indirect, document-embedded injections in our own scenarios (0.00–0.32). So it is scoped to "don't trust flagged text" and never decides a verdict |

Cost: **~$0.015 per pull request**. Model latency p50 12.5 s, p95 24.2 s — fully overlapped
with the sandbox run.

---

## Results

### What the tool teams already run says about the same pull requests

`npm audit`, run on our own attack payloads ([method and raw output](../eval/BASELINE.md)):

| Pull request | `npm audit` | PR Detonator |
|---|---|---|
| Shai-Hulud reconstruction (bump → steals `~/.npmrc`, runs TruffleHog, POSTs secrets) | **found 0 vulnerabilities** | 🛑 Blocked, payload line decoded |
| "Fix typo" with an `$(env)`-exfiltrating postinstall | **found 0 vulnerabilities** | 🛑 Blocked + canary token caught |
| base64 → `sh` | **found 0 vulnerabilities** | 🛑 Blocked, command decoded |
| Stolen `$GITHUB_TOKEN` in a request header | **found 0 vulnerabilities** | 🛑 Blocked (critical) |
| ua-parser-js 0.7.29 (the real 2021 hijack) | 1 high — GHSA-pjwm-rvh2-c87w | 🛑 Blocked |

`npm audit` isn't broken — it's **retrospective**. It catches ua-parser-js because the world
has known since October 2021. It cannot cover the window before an advisory exists, which is
the only window that matters, and it has no opinion at all about malicious code in the
project's *own* `package.json`. PR Detonator blocked all five from behavior alone.

### The evaluation

**122 real detonations** on real infrastructure, scored by the production pipeline with the
real models. Full per-case table and methodology: [eval/README.md](../eval/README.md).

| Set | Rules only | + Intent Contract | Full pipeline |
|---|---|---|---|
| **104 popular packages** (35 run install scripts) | **0 blocked**, 5 ⚠️ | **0 blocked**, 3 ⚠️ | **0 blocked**, 3 ⚠️ |
| **16 simulated install-time attacks** | 15 blocked | 15 blocked | **16 blocked** |
| **2 reconstructions of real incidents** | 2 blocked | 2 blocked | **2 blocked** |

- **Zero false blocks across 104 popular packages**, including the hard ones that download
  binaries at install: puppeteer, playwright, electron, prisma, cypress, chromedriver,
  esbuild, sharp, bcrypt, sqlite3, canvas, @sentry/cli, re2.
- **We rebuilt two real attacks** (defanged, delivered as Dependabot-style version bumps):
  **ua-parser-js 0.7.29** (geofenced miner download) and the **Shai-Hulud worm** (downloads
  the real TruffleHog, scans for secrets, posts them to webhook.site). Both are blocked and
  blamed on the bumped line.
- **Rebuilding Shai-Hulud found a genuine gap in our own detector.** Under the rules as they
  stood it was only a *mergeable* ⚠️: GitHub is allowlisted and webhook.site was just an
  unlisted domain. Two kernel-level rules closed it — running a binary dropped into a temp
  directory, and contacting a known exfiltration service. It is now blocked by rules alone.
- **Scaling the benign set to 104 found a false positive, and we fixed it.** `re2`'s install
  spawns a nested `npm run`, and npm reads `~/.npmrc` as its own config — which tripped our
  credential-bait rule. The rule now never flags an npm process; a real theft reads that file
  from the dependency's own code, which still fires.

Both of those are in the write-up on purpose: the evaluation's job was to find our mistakes,
and reporting what it found is the point.

---

## What's engineered carefully (not just a demo)

- **Nothing of value in the blast radius.** The sandbox gets no tokens and no host
  environment; public repos are cloned anonymously; the VM has no cloud IAM role. Private
  repos are cloned on the *host* with a token scoped to that one repository, read-only,
  over TLS to a certificate the Brain pins.
- **Only TCP may leave the sandbox.** Everything else — UDP, ICMP, DNS to any other resolver
  — is logged and rejected, and reported as a blocked egress attempt. (Before we closed this,
  a test UDP datagram really did get out.)
- **Canary credentials.** Each run plants freshly generated fake tokens in the environment,
  `~/.npmrc` and `~/.aws`, plus decoy `gh`/`aws`/`trufflehog` CLIs on `PATH`. If one of those
  values shows up in a command, a DNS name or the install's output, that's a critical finding.
  The values are redacted before anything reaches the model or GitHub.
- **Integrity in both directions.** Requests *and* responses between the Brain and the sandbox
  are HMAC-signed, the response bound to its job id — so a result can't be altered in transit
  or replayed from an older, clean run. Any failure fails the check closed.
- **Everything untrusted is escaped.** Process arguments, hostnames, model output and captured
  code are rendered as HTML entities in comments: no markdown, links, @mentions or fake bot
  markers.
- **Differential detonation.** For a dependency bump we detonate the base commit too (cached)
  and report only the behavior the PR *introduced*. Low findings the old version already
  produced are suppressed so routine bumps stay quiet; high and critical never are.
- **Per-repo policy**, read from the base branch only — never the PR's head, where the author
  could allowlist their own exfiltration host.

15 deterministic rules, **360 automated tests**, and every fixture is recorded real output
(Tetragon events, dnsmasq logs, kernel firewall lines, Muse responses, GitHub patches).

---

## Try it / see it

- **Repository:** https://github.com/fugeretrevin/Detonator (MIT)
- **Live demo PRs:** https://github.com/pr-detonator-demo/demo-target/pulls — nine scenarios
  from a clean README edit to a Dependabot-style bump whose new version opens a reverse shell.
- **Live dashboard:** https://fugeretrevin--pr-detonator-dashboard.us-east.modal.run/ —
  recent runs, verdict tally, and a **behavior atlas**: what each package did at install.
- **Demo video:** _[link]_

---

## Honest limitations

- **Install-time only.** Payloads that fire when a package is imported, at runtime, or only
  inside one specific application (event-stream, 2018) are out of scope. We say so rather
  than reconstructing that incident and claiming a catch.
- **A payload that waits** longer than the detonation timeout, or detects a sandbox and stays
  dormant, can still evade us. The canary credentials make the sandbox look worth robbing,
  which helps, but it isn't a solution.
- **Our attacks are our own.** 16 of the 18 are written by us, knowing the detectors. Treat
  "16 of 16" as "covers these techniques", not a real-world detection rate. A held-out set
  written by a different model is the obvious next step.
- **Three benign packages land on ⚠️** because they download from Google Cloud Storage, where
  anyone can host a bucket. That's a deliberate trade-off: we never auto-clear shared hosting.
- **One sandbox VM, one job at a time.** Queued pull requests wait, then fail closed. Fine for
  a demo; a real deployment needs a pool.
- **Model variance.** Temperature 0 but not bit-reproducible; the "full pipeline" column can
  move by about one case between runs.

---

## Where this goes

1. **Registry-scale watch.** Detonate every new version of the top npm packages minutes after
   publication and alert on behavior changes — "v4.2.1 adds a raw-IP connection". That catches
   an account-takeover release before installs spread, which is exactly how Shai-Hulud moved.
2. **Behavioral SBOM.** A signed, per-version record of what a package *does* at install.
   Lockfiles pin bytes; this pins behavior, and it's diffable. The dashboard's behavior atlas
   is the first version of it.
3. **More ecosystems.** pip `setup.py`, cargo build scripts, gem extensions, and GitHub
   Actions themselves.
4. **Containment**, not just detection: Tetragon can kill the process on `/dev/tcp` instead of
   only recording it.

---

## Stack

Modal (serverless Brain, CPU class for Prompt Guard 2, scheduled health check, dashboard) ·
EC2 + Docker + **Tetragon/eBPF** + dnsmasq + iptables (the sandbox) · Meta Model API
(`muse-spark-1.3`, incl. tool calling) · Llama Prompt Guard 2 86M from Hugging Face ·
GitHub App (checks, review comments, branch protection) · Python 3.11, FastAPI, pydantic.

---

## Before you submit (checklist — delete this section when pasting)

1. **Re-run the full eval at the final commit** and update every figure above plus the commit
   hash in `eval/README.md`. The numbers here are from commit `04b7c25`; the detection core
   is unchanged since, but the table should be stamped at whatever you submit.
2. Record the demo video (`demo/DEMO_SCRIPT.md`) and paste the link into "Try it / see it".
3. Rotate the Meta API key and the GitHub webhook secret, redeploy, re-run E1–E9.
4. Confirm the repo is public, the README links resolve, and the dashboard loads.
5. Decide on the held-out red-team row (limitations mentions it as "next step" — if you run
   it, move the result into Results instead).
6. Keep the VM, the Modal app and API quota alive through judging.
