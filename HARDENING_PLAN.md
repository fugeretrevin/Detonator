# PR Detonator: Hardening & Scoring Plan (Nov 1 → code freeze Nov 2 evening)

> **For the coding agent.** Read this with BUILD_PLAN.md and the project brief. Work top to bottom.
> Each item has acceptance criteria: meet them, show evidence, commit, stop and summarize.
> Finish the open 15-issue list first. Where an item below overlaps one of those issues, do it once.

## Invariants (never break these)

- Model output (contract, analysis, any agent) can **raise** severity or **explain**. It never clears a high/critical finding. The only thing allowed to clear anything is the existing contract rule for low `NET_UNLISTED_DOMAIN`.
- Fail closed: any error, timeout or integrity failure → `failure` ("Could not verify").
- Nothing PR-controlled or sandbox-produced is trusted: fence it in prompts, entity-encode it in comments.
- **Every new rule** must be run against the full benign set before adoption. Zero benign blocks, and report any new "needs review".
- No real malware. Simulated payloads target TEST-NET (`203.0.113.x`) or sinkholed names only.
- Every eval table is stamped with commit hash, date, model ID and run count.

---

## P0: Hardening a security-savvy judge will probe (do first, ~5–6 h)

### P0.1 Sign Chamber responses (~1 h)
Today requests are HMAC-signed, but **responses are not**. Anyone on-path between Modal and the plain-HTTP Chamber could rewrite a malicious run's telemetry into a clean one. Malicious PR → ✅ is the worst possible failure.
- Chamber signs the response: `X-Detonator-Signature = HMAC(secret, f"{timestamp}.{job_id}.{raw_body}")` plus a timestamp header.
- Brain verifies the signature, timestamp freshness (≤300 s), and that `job_id` matches the request. Any failure → fail closed.
- **Acceptance:** tests for a tampered body, a wrong job_id (replayed old clean response) and a stale timestamp. All of them → "Could not verify".

### P0.2 Close non-TCP egress (~1.5 h)
- iptables: from the sandbox subnet, reject **all UDP except to the resolver on 53**, and all ICMP. (TCP stays observed-not-blocked.)
- Make attempts visible: either count rejected packets per run (iptables counter or NFLOG read before/after the run) or add a Tetragon kprobe on `udp_sendmsg`. Then add rule `NET_NON_TCP_EGRESS` (high) when a non-DNS UDP/ICMP send is attempted.
- Add a simulated attack: node `dgram` sends env to `203.0.113.10:53535`.
- **Acceptance:** the new attack is blocked by rules. Benign set: zero blocks. Update brief issue #1 to "fixed".

### P0.3 Rotate exposed secrets **now** (~20 min, human)
Meta API key and webhook secret (and anything else that appeared in chat). Redeploy, then re-run E1 and E4. Don't wait until Nov 3: the exposure exists today.

### P0.4 Fork-PR test (~30 min)
Open a PR from a fork of `demo-target` (second GitHub account or a fork owned by the user). Confirm the allowlist uses the base repo owner, the fork's clone URL is used, and the result is correct. Required before inviting judges (P2.4).

### P0.5 Single-point-of-failure insurance for judging week (~1.5 h)
- Create an **AMI snapshot** of the working Chamber.
- Test `setup.sh` (or AMI launch) on a **fresh** VM once and record the time to recover. Update `CHAMBER_URL` back afterwards.
- Add a **Modal scheduled health check** (every 10 min) that hits `/health` and records status. If you have time, alert (GitHub issue on the Detonator repo, or email).
- Document the recovery runbook in `demo/RUNBOOK.md` (5 steps max).

### P0.6 One comment per PR (~1 h) (brief issue #13)
Find the bot's previous comment by a hidden marker and edit it. Keep a short "previous runs" line (SHA → verdict). Matters for the demo: a re-push shouldn't stack comments.

---

## P1: Features that move the score (in this order)

### P1.1 Capture the dependency's executed script → Muse explains the real payload (~3 h) ★ highest value
In E8 / Shai-Hulud, the **diff is a one-line version bump**. Muse never sees the malicious code, only telemetry. Fix that:
- Chamber: after the run and before removing the container, copy out files that lifecycle scripts executed (paths from exec args under `/work`, e.g. `node_modules/color-helper/postinstall.js`, plus `preinstall.sh` and similar). Caps: 5 files, 20 KB each. Add an `executed_scripts: [{path, package, sha256, content, truncated}]` field to the contract (bump the contract version and update the tests).
- Brain: give these to Muse as **untrusted, fenced** input, and ask for the guilty line *inside the dependency* plus a plain-English, deobfuscated explanation.
- Report: "`color-helper@1.0.1` → `node_modules/color-helper/postinstall.js:12`: opens a TCP socket to 203.0.113.10:4444 and pipes a shell." Include the sha256 so it's reproducible.
- **Acceptance:** E8 and the Shai-Hulud reconstruction show the dependency file, line and decoded meaning. No regressions on E1–E7.

### P1.2 Canary credentials and decoy tools (~3 h)
Make the sandbox look like a real dev/CI box and catch credential theft **without needing file tracing** (addresses brief issues #2 and #4 in part):
- Inject unique per-run decoys: env `GITHUB_TOKEN=ghp_<random>`, `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`/`SECRET`, `GITHUB_ACTIONS=true`, `CI=true`, and a decoy `~/.npmrc` line **scoped to a non-default registry** (`//npm.pkg.github.com/:_authToken=<decoy>`) so npm never sends it to registry.npmjs.org or breaks installs.
- Decoy tools on PATH: tiny stub scripts named `gh`, `aws`, `claude`, `gemini`, `trufflehog` that exit 0. Their exec shows up in Tetragon with full args.
- Rules: `DECOY_CREDENTIAL_SEEN` (critical) if any decoy value appears in exec args, DNS queries or captured scripts' output. `DECOY_TOOL_INVOKED` (high) if a stub runs.
- **Acceptance:** a new simulated attack, "read env, curl it with the token in a header", fires critical. The Shai-Hulud reconstruction also fires the TruffleHog decoy or credential rule. Benign set: zero hits (re-run all 26). Document the decoy values as per-run random, so no real secret is ever involved.

### P1.3 Held-out red-team evaluation (~2 h, mostly human + a different model)
Four rules were added *because* the eval exposed gaps, so the 14 attacks are no longer held out. A careful judge will notice.
- Have a **different model** (e.g. GPT Pro), given only the threat model and the TEST-NET constraint and **not the rules**, write 10 new defanged install-time attacks.
- Run them **once** at a frozen commit and report the result as a separate "held-out" row, whatever it is. If you then fix gaps, report "after fixes" as another row; never overwrite.
- **Acceptance:** `eval/results.md` has a held-out row with its commit stamp.

### P1.4 Scale the benign set and add the numbers judges ask for (~2 h attended, runs unattended)
Run this **early**: it may reveal false positives you need to fix before freeze.
- Expand benign to ~100 popular packages, prioritizing ones with install scripts (the npm registry API shows `scripts`/`hasInstallScript`).
- Full setup ×3 runs; report mean and range (model variance is already acknowledged).
- Record per PR: detonation time, end-to-end check time (p50/p95), Muse tokens in/out and **$ cost per PR**.
- Produce one headline stat for the pitch, e.g. "X of the 100 most-downloaded packages run install scripts; Y reach hosts outside the npm registry."
- **Acceptance:** an updated table with ✅/⚠️/❌ per setup, latency and cost columns, all stamped.

### P1.5 Measure what Muse explains, not just what it blocks (~1 h)
Add ground truth to each attack case (`what_it_does`, `decoded_payload` if obfuscated, `guilty_file:line`). Score Muse's guilty-line explanation (keyword match plus manual review) and the attribution accuracy of the line/package. Report: "Muse correctly decoded N/M obfuscated payloads; guilty line correct in K/M."
This turns "explanation" from a claim into a metric and strengthens the "why Muse" story.

### P1.6 Run log and live dashboard (better tracking) (~3 h)
- Every run writes a summary record (Modal Dict or Volume): PR link, SHA, verdict, rules fired, contract result, model calls with latency/tokens/cost, detonation time, packages that ran install scripts.
- A read-only public page (`@modal.asgi_app`): recent runs, verdict counts, p50 latency, cost, and a **behavior atlas** (package@version → hosts contacted, binaries run) built from runs plus eval data. This is the seed of the "behavioral SBOM" vision, made visible.
- PR content on the page is entity-encoded, the same as in comments.
- **Acceptance:** the page shows E1–E8 and the eval runs. Link it from the README and the check-run summary.

---

## P2: If P0 and P1.1–P1.4 are done before Nov 2 afternoon

### P2.1 Differential detonation for dependency bumps (~4–5 h)
For PRs that change existing dependencies, also detonate the **base SHA** (cache by SHA). Normalize behaviors (package, host, binary, script). Report the **delta**: "1.0.1 added connect 203.0.113.10:4444, which 1.0.0 did not do."
Policy: low findings also present on base are suppressed (fewer false alarms on routine bumps). High/critical are **never** suppressed. This is the strongest production argument: most real PRs are bumps, and this keeps them quiet.

### P2.2 Investigator agent for "needs review" only (~3–4 h)
Muse with tool calling (≤6 calls, 60 s): `registry_info(pkg, version)` (publish age, maintainer changes vs previous version, has install script before?), `get_executed_script(path)`, `host_info(name)`. Output: a **triage note** for the human ("puppeteer downloads Chrome for Testing from Google's official bucket; maintainers unchanged; published 12 days ago"). It can escalate but **cannot** clear. Show the tool log collapsed in the report.

### P2.3 Per-repo policy file (~1.5 h)
`.github/detonator.yml`, read from the **base** branch only (never head, or the attacker edits the policy): extra allowed domains, `needs_review: pass|block`, timeout. Shows production thinking and addresses "needs review is mergeable".

### P2.4 "Try it" path for judges (~1 h, after P0.4)
A public repo `pr-detonator-demo/try-it` with instructions: fork, add any npm package, open a PR, watch the check. Add a per-author rate limit (e.g. 5 runs/hour), a global kill switch env var, and the AMI recovery from P0.5. Don't open the App to arbitrary installs.

### P2.5 New-package signal (~1 h)
Deterministic registry lookup: dependency first published < 7 days ago, or a name that doesn't exist on the registry at base → `DEP_NEW_PACKAGE` (low). Supports the "AI agents add hallucinated packages" impact story.

---

## Demo script changes (`demo/DEMO_SCRIPT.md`)

- **0:00–0:20 Hook:** Shai-Hulud spread through npm install scripts in 2025. It arrives as a one-line version bump that review and auto-merge wave through.
- **0:20–0:40 Architecture, one slide:** model predicts, kernel verifies, rules set the floor.
- **0:40–1:30 Star moment:** Dependabot-style bump of the Shai-Hulud reconstruction. Normal CI green → Detonator red → inline comment on the bumped line → **the dependency's own payload line, decoded** (P1.1) → canary credential caught (P1.2).
- **1:30–1:50** E5: obfuscated reverse shell decoded on the guilty line.
- **1:50–2:10** E6: injection in the PR text. Muse flags it; the rules floor doesn't care. One line on Prompt Guard ("catches direct jailbreaks; we measured it and scoped it").
- **2:10–2:40** Eval: benign blocks 0/100, held-out row, what each Meta model adds, cost and latency per PR, the headline stat. Flash the dashboard.
- **2:40–3:00** Vision: auto-merge gate, AI-agent PRs, registry-scale watch, behavioral SBOM. "Try it" link.
- Cut from the live demo (keep in the table): E1, E2, E3, E7.

## Submission checklist
- README top: one-sentence pitch, demo GIF/video, "try it" link, dashboard link.
- A "How Meta models are used" section with **numbers** (contract FP reduction, attacks only Muse caught, decode accuracy, Prompt Guard measured scope).
- A limitations section (keep the honest list, updated after P0).
- Re-run the full eval at the final commit, stamped.
- Backup demo video recorded before any last-day changes.
