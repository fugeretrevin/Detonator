# PR Detonator — submission write-up

Paste-ready sections for the submission form. Numbers are from the stamped evaluation in
[eval/README.md](../eval/README.md); re-run the eval at the final commit before submitting
and update the figures and the commit hash here (see "Before you submit" at the end).

---

## Tagline (one line)

**Static scanners read code. PR Detonator runs it — in a kernel-traced sandbox — and holds
what it did against what the pull request claimed.**

---

## Open with this (the one result to lead on)

We pointed it at **100 packages published to npm minutes earlier**, knowing nothing about any
of them. It cleared 73 of 73 that installed, and flagged one — which turned out to have a real
install-time code-execution exposure: a fallback that downloads the product binary from a
hardcoded bare IP with **TLS verification disabled**, then extracts and runs it. Not malware,
a deliberate fallback with an unsafe default. We **reported it privately to the maintainer on
Nov 2, 2026**; no response or fix yet, so the name is omitted here. No advisory existed and nobody
told us to look. The behavior alone gave it away.

We then scaled the sweep to **500** of the newest packages ([`eval/SWEEP500.md`](../eval/SWEEP500.md)):
413 of 421 that installed cleared, seven landed in *needs review*, and there was exactly **one**
block — a package that downloads and runs binaries at install. The tiering doing its job at
scale, not a wall of false alarms.

These 500 are **unlabelled**: nobody has established that any of them is benign or malicious, so
this measures alert volume on uncurated live traffic, not a false-positive rate. One block in 421
is the claim; "499 confirmed clean" is not.

---

## The problem (120 words)

Supply-chain attacks have moved to **install time**. A package's `postinstall` runs on every
laptop and CI runner that installs it, before anyone imports a line of its code — that is how
event-stream (2018), ua-parser-js (2021) and the Shai-Hulud worm (2025) spread. The pull
request that lets one in is usually a **one-line version bump**, so there is nothing in the
diff to review.

And increasingly nobody is: **AI coding agents now open the PRs and choose the dependencies**,
sometimes packages that don't exist, which attackers then register. Review became the
bottleneck exactly as machine-written dependency changes exploded.

Static and LLM code review read source that attackers obfuscate — and an LLM reviewer can be
talked out of a finding by text the attacker also controls.

---

## The window everything else is blind in

`npm audit` and every advisory-based tool can only know about an attack after someone
publishes an advisory. These are the real windows ([sources and caveats](../eval/DWELL_TIME.md)):

| Incident | Malicious version installable for | Caught by behavior in |
|---|---|---|
| ua-parser-js (2021) | **≈4 hours** before clean versions; ≈8 h to advisory | **12.4 s**, rules alone |
| Shai-Hulud (2025) | **≈1 day** before public reports | **9.8 s**, rules alone |
| event-stream (2018) | **over two months** | **Not covered** — it ran on `require`, not install. We say so rather than claiming it |

We check pull requests, so the honest claim is that we'd have caught the PR adopting a poisoned
version at the moment it opened — not that we'd have protected everyone during those windows.
Closing that is what the registry-scale watch is for: detonate each new release at publish
time and diff its behavior record against the previous version.

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
3. **Un-talk-out-able.** The post-run analysis is escalate-only: its output can raise severity
   and never lower it, so a **HIGH or CRITICAL rule hit cannot be cleared by any model
   output.** Precisely one narrower path exists, and it is worth stating rather than rounding
   off: the *pre-observation* prediction may clear a single **LOW** `NET_UNLISTED_DOMAIN` hit
   for a host it named **before** the install ran — and only if the PR added no install
   scripts, the host is not shared hosting anyone can publish under, and the destination was a
   resolved domain rather than a raw IP (those can never be explained). That is the mechanism
   that cut benign "needs review" from 5 to 3. Prompt injection in the PR becomes evidence
   rather than influence. Timeouts, crashes and integrity failures all fail closed — never "clean" —
   and so does the model itself: if the analysis fails, the result can't be "clean" either.
   Every piece of evidence the model cites is checked by code against the kernel record.
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

**A four-arm ablation separates the two model uses** — same 122 cases, same commit, scored by
the production pipeline ([full table](../eval/results.md)):

| Arm | Benign ⚠️ needs-review (of 104) | Attacks blocked (of 16) |
|---|---|---|
| rules only | 5 | 15 |
| rules + Intent Contract | **3** | 15 |
| rules + analysis, *no* Contract | 5 | **16** |
| full (both) | **3** | **16** |

They repair different failures and neither substitutes for the other. The **Contract** is what
removes benign review noise and clears no attack: it explains `binaries.prisma.sh` for a Prisma
bump and `download.cypress.io` for Cypress, because the PR's stated purpose predicts those
hosts. The **analysis** is what closes the one detection gap and changes no benign verdict:
`m12` exfiltrates to an ordinary *resolvable* domain, which the rules can only rate LOW — so
rules and Contract both leave it a **mergeable** ⚠️, and only reading the telemetry against the
diff makes it Blocked. That is the argument for using a model here at all, and it is why the
rules still set an independent floor underneath both.

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

To be clear about what that comparison is: `npm audit` is the **default tooling baseline** — what
a team already has without adopting anything — not the state of the art. It is an advisory
lookup, so "found 0 vulnerabilities" on a bespoke payload is the expected result rather than a
failure on its part, and it would be dishonest to present it as a defeated competitor. See the
related-work note under Honest limitations.

### What a blind sweep of the live registry turned up

We also pointed it at packages nobody curated: the **100 most recent publishes** from npm's
change feed, detonated minutes after they went live ([method](../eval/SWEEP.md)).

Of the 73 that install on linux-x64: **0 blocked, 0 needs-review.** That makes the
false-positive claim much harder to wave away than a benign set we hand-picked. 7 ran install
scripts; none reached a host outside the npm registry and GitHub.

**One package did get flagged, and it turned out to be a real security weakness — just not an
attack.** The raw-IP rule fired because its `postinstall` connected to a hardcoded IP address
on a non-standard port with no DNS lookup at all. Reading its published source explained why:
a fallback path downloads the product binary from that bare IP with
**`rejectUnauthorized: false`** — TLS certificate verification disabled — then extracts it and
links it as the executable. Anyone able to intercept that connection, or who later controls
that address, can have an arbitrary binary executed on every machine running `npm install`
(CWE-295 plus CWE-494).

It isn't malicious: the maintainer owns the package and this is clearly a deliberate fallback
with an unsafe default.

**Disclosure status, stated precisely:** a private report was **sent to the package's sole npm
maintainer on Nov 2, 2026**, after confirming the issue is still present in that day's latest
version. There is no response or fix yet, so the disclosure is not complete. We omit the name
here, and we will not pretend that amounts to concealment — the identifier was
committed earlier in this public repository's history and can be recovered from the git log.
We did not attempt to intercept the connection and make no claim about exploitability in
practice.

We think this is the most interesting result in the project, because nobody planned it. A
behavioral rule fired on live registry data with no prior knowledge, the follow-up correctly
concluded "not an attack", and there was still a genuine install-time code-execution exposure
underneath. It also validates the specific signal that caught it: we only saw this because the
connection **skipped DNS entirely**, which is the one thing a sandbox that logs every lookup
can notice and a source scanner cannot.

### The evaluation

**142 real detonations** on real infrastructure, scored by the production pipeline with the
real models. Full per-case table and methodology: [eval/README.md](../eval/README.md).

| Set | Rules only | + Intent Contract | Full pipeline |
|---|---|---|---|
| **104 popular packages** (35 run install scripts) | **0 blocked**, 4 ⚠️, 6 ⏱️ | **0 blocked**, 3 ⚠️, 6 ⏱️ | **0 blocked**, 3 ⚠️, 6 ⏱️ |
| **16 simulated install-time attacks** | 15 blocked | 15 blocked | **16 blocked in 3 of 5 trials, 15 in the worst** |
| **2 reconstructions of real incidents** | 2 blocked | 2 blocked | **2 blocked** |
| **10 red-team, written by us to target our blind spots** | 6 blocked | 6 blocked | **9 blocked** |
| **10 red-team, written by a model that never saw our rules** | 5 blocked, 1 ⏱️ | 5 blocked, 1 ⏱️ | **10 blocked** |

**Every one of those 142 runs carries a per-job sensor witness.** The sandbox execs a
nonce-marked marker before and after the install; a missing marker fails the check closed
instead of passing as a quiet install, because "no events" and "nothing happened" are not the
same thing. 139 runs recorded both markers, and the 3 that recorded only the first are exactly
the 3 that hit the timeout and were killed.

**And 452 of 452 cited claims the model made point at a real kernel event of the right type** —
none rejected, no invented hosts or IPs. Code checks that, not trust: every event carries an id
that is an HMAC of the job id (so a PR author can't forge one), an `observed` claim must cite an
event of its own type, and a claim drawn from the diff rather than from runtime is labelled
`source_inferred` so it is never presented as something the kernel watched happen.

To be precise about that figure, because it is easy to overstate: it covers every entry in the
model's `key_evidence`, plus any hostname, IP, file path or port appearing in its prose even
when nothing is cited for it. It cannot police prose claims that are not mechanically
checkable, so it measures **citation discipline and the absence of invented concrete facts**
rather than total factual accuracy.

The prose-level half of that has caught nothing real so far: across 420 recorded analyses it
flagged 33 claims, all of which turned out to be the checker's own bug rather than the model's
error (it looked for `:9000` and missed `/dev/tcp/10.0.0.1/9000`). Fixed, it now fires on
nothing we have seen. So treat it as a **regression guard**, not as evidence that the model
never embellishes — the full accounting is in [`docs/WEAKPOINTS.md`](WEAKPOINTS.md) W4.

**We re-ran the model five times per case on identical telemetry, because temperature 0 is not
determinism** ([`eval/REPEAT.md`](../eval/REPEAT.md)). Across 24 attack and boundary-benign
cases the flip rate is **1/24** and **no benign case was blocked in any trial**; across the 20
red-team cases it is **1/20**. Exactly one case is unstable — `m12`, which exfiltrates to an
ordinary *resolvable* domain that the rules can only rate LOW, so its verdict hangs on whether
Muse says `malicious` or `suspicious` on that call. That is why we quote **16/16 in 3 of 5
trials** rather than a flat 16/16, and **19/20 red team in 4 of 5 trials, 18/20 in the worst**.
A single scored run would have let us claim the better number and never know.

- **Zero false blocks across all 104 popular packages**, in every arm — including the hard ones
  that download binaries at install: puppeteer, playwright, electron, prisma, chromedriver,
  esbuild, sharp, bcrypt, sqlite3, canvas, @sentry/cli, re2. (Not every one of the 104 produced
  a *verdict*: six are "could not verify", itemised in the next point. "Zero blocked" is a
  statement about false positives, not a claim that all 104 were verified clean.)
- **6 of the 104 are ⏱️ "could not verify", not clean**, and we count them that way on purpose,
  for two different reasons. Four failed to compile (exit 1) because the sandbox image carries
  no C toolchain, so `node-gyp` cannot build: `better-sqlite3`, `argon2`, `cpu-features` and
  `node-pty`. Two more hit the install timeout: `biome` and `cypress`. In neither case did we
  watch a complete install, so we will not call them clean — but that is a **usability limit of
  our sandbox, not a judgement about those packages**. So the honest benign result is *95
  verified clean, 3 needing review, 6 unverifiable, 0 blocked* — never "104/104 clean". An
  earlier version of this tool reported the four compile failures as Clean; finding and fixing
  that is in the write-up because it is the single most important thing a security tool can get
  right. The full accounting, including why adding a compiler to the sandbox is a security
  trade-off rather than a free fix, is [`docs/WEAKPOINTS.md`](WEAKPOINTS.md) W3.
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

- **"Clean" means we actually watched.** A Clean verdict requires three separate things to
  hold: the install *finished* (exit 0), the telemetry was not truncated by the event cap, and
  the sensor recorded process events at all (a real `npm install` always execs, so zero events
  means the collector was blind, not that the install was quiet). If any one fails we return
  **Could not verify** as a check *failure* — GitHub treats `neutral` as passing, so a run we
  could not observe must never be neutral. It is an absence of evidence, not an accusation, and
  the report names which precondition failed. We found and fixed this: a failed install used to
  report Clean.
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

15 deterministic rules, **417 automated tests**, and every fixture is recorded real output
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
- **The denominators are small, and we did the arithmetic rather than hoping nobody would.**
  Exact 95% intervals ([`python -m eval.intervals`](../eval/intervals.py)): "16 of 16 attacks
  blocked" is consistent with a true rate as low as **79%**; "19 of 20 red-team" spans
  **75.1–99.9%**; "2 of 2 incidents" has a lower bound of 15.8% and so establishes very little
  on its own. The benign result is the firmest: 0 of 104 blocked puts the false-block rate under
  **3.5%**. All of these bound sampling error only — the cohorts are hand-picked, so they are a
  floor on uncertainty, not a generalisation guarantee.
- **Three benign packages land on ⚠️** because they download from Google Cloud Storage, where
  anyone can host a bucket. That's a deliberate trade-off: we never auto-clear shared hosting.
- **One sandbox VM, one job at a time.** Queued pull requests wait, then fail closed. Fine for
  a demo; a real deployment needs a pool.
- **Model variance.** Temperature 0 but not bit-reproducible; the "full pipeline" column can
  move by about one case between runs.
- **We are not the first to run packages and watch them.** Behavioral supply-chain analysis
  exists: **OpenSSF Package Analysis** sandboxes packages and records their file, network and
  process activity, and tracks behavior across releases; **Socket** reviews dependency changes
  directly in GitHub pull requests and flags install scripts and suspicious capabilities. Any
  claim here to be the first or only runtime package scanner would be false, and we make none.
  What we think is genuinely different is the *combination*: a prediction of expected behavior
  committed **before** the install runs, kernel telemetry as the ground truth it is checked
  against, attribution back to the exact diff line, every model claim verified against the event
  record by code, and a merge gate that fails closed. We have **not** run a head-to-head against
  those tools — that needs matched package populations, comparable access and a scoring rule
  agreed in advance, none of which we have — so treat this paragraph as positioning, not as a
  measured comparison.

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
   hash in `eval/README.md`. The numbers here are from commit `a96c8a1`. Re-stamp if you change
   *detection logic* — anything under `brain/`, `shared/`, `chamber/`, or `eval/cases.py`.
   Commits that only touch docs or the generated result files do not change the numbers and do
   not invalidate the stamp.
2. Record the demo video (`demo/DEMO_SCRIPT.md`) and paste the link into "Try it / see it".
3. Rotate the Meta API key and the GitHub webhook secret, redeploy, re-run E1–E9.
4. Confirm the repo is public, the README links resolve, and the dashboard loads.
5. Decide on the held-out red-team row (limitations mentions it as "next step" — if you run
   it, move the result into Results instead).
6. Keep the VM, the Modal app and API quota alive through judging.
