# PR Detonator: Roadmap to a Winning Submission (and Beyond)

Written Nov 1, 2026. Submission Nov 4. Everything here was checked against the running
system before being scheduled; "Validated" notes say what was measured.

## The thesis

Supply-chain attacks now run **at install time** (event-stream, ua-parser-js, the 2025 npm
worm that compromised `chalk`/`debug`, XZ Utils). Static scanners and LLM code review read
code that attackers obfuscate, and both can be talked out of a finding. PR Detonator is
the first reviewer that **runs the change and holds the kernel's record against the
author's story**:

> *The model predicts. The kernel verifies. Rules set the floor.*

Three things judges should remember:
1. **Ground truth**: eBPF sees every exec and connect attempt, even to unreachable hosts.
2. **Intent Contract**: Muse predicts what the PR should do *before* it runs (from title,
   description and file names only, never the payload), and code checks the prediction
   against telemetry. That answers "why do you need the model?" with something you can measure.
3. **Un-talk-out-able**: model output can only escalate. Prompt injection becomes evidence.

## Validation log (what we measured before scheduling work)

| Check | Result | Consequence |
|---|---|---|
| E1–E7 end-to-end on real infra | 7/7 correct (esbuild clean, revshell critical, injection flagged, hang fails closed) | Core loop is demo-ready |
| Live intent predictions (6 PRs incl. injection) | All correct; injection ignored; puppeteer→`storage.googleapis.com`, prisma→`binaries.prisma.sh`; 3–8 s, runs in parallel with detonation | Intent Contract ships |
| `npm install puppeteer` on the Chamber | Failed at first: sandbox HOME not writable (**bug, fixed**). After the fix: Chrome download from `34.3.0.27` has no name in the Brain → `NET_RAW_IP` → **false ❌** | **DNS capture on the Chamber is P0.** Without it, CDN-heavy packages false-alarm and the eval numbers are bad. The contract cannot help, because raw IPs are never explainable (by design). |
| **P0 done (Nov 1):** dnsmasq on det0, port 53 elsewhere rejected | puppeteer: both Chrome IPs named `storage.googleapis.com` from the sandbox's own lookups. Rules only ⚠️, rules+contract ✅, full ✅. E1–E7 re-run on GitHub: E1/E2/E3 ✅, E4/E5/E6 🛑, E7 🛑 could not verify | Gate passed. Eval (P1) can start. |
| **Guilty line done (Nov 1)** | Real E4/E5/E6 on GitHub: inline review comments on `package.json:5` (all three) and `scripts/telemetry-optout.js:8` (E5's `cp.spawn`). Muse decoded the E5 base64 to the exact reverse-shell command; +0 extra model calls (same analysis request) | Demo beat for E5 |
| **Eval done (Nov 1)**: 26 benign + 14 attacks, real Chamber + real model | Benign blocked 0/26 in every setup; needs review 5 → 1 with contract (2 full). Attacks blocked: rules 11/14 → 13/14 after adding `NET_INTERNAL_TARGET` + `DNS_ENCODED_LABEL` (gaps the eval exposed; no benign change); full 14/14, the model uniquely catching domain exfil | README headline. Open: playwright-chromium stays ⚠️ (prediction misses some CDN hosts); cypress ⚠️ in full only; storage.googleapis.com is shared hosting but not denylisted |

## Plan (by Nov 4)

### P0: correctness that the numbers depend on (owner: lead, touches the VM)
- **DNS capture (B4)**: dnsmasq on `det0` (10.250.0.1) with query logging; sandboxes use it
  as their only resolver; iptables allows only :53 to the host; the Chamber fills `dns_queries`
  and `resolved_domain` from the run's log window. `NET_RAW_IP` then means "connected with
  no lookup", the strongest signal we have. Brain enrichment becomes the fallback.
- Re-run E1–E7 + puppeteer. **Gate:** puppeteer not ❌; E4/E5 still ❌.

### P1: the evidence judges score
- **Evaluation harness** (agent prepares code; lead runs on the VM): ~25 popular packages
  with install scripts (puppeteer, playwright, prisma, sharp, esbuild, electron, bcrypt,
  node-sass, cypress, sqlite3, canvas, husky, core-js, …) + ~12 simulated payloads (TEST-NET
  only: curl/wget exfil, `/dev/tcp`, base64→sh, node `net.connect`, DNS-less fetch, delayed
  payload, obfuscated JS, env/`.npmrc` read + exfil, injection variants). Output: a table
  for **rules-only vs rules+Intent Contract vs full**: detection rate, false-positive rate
  (❌ on benign), and review rate (⚠️ on benign). The README headline comes from this table.
- **Pinpoint the guilty line** (agent): map the offending process chain to the exact
  diff line (the `package.json` script line, or the script file the chain executed) and
  post a GitHub **review comment on that line**; the model decodes obfuscation into a
  one-line plain-English "what this line does". Deterministic mapping first; model explains.

### P1b: "The dependency did it" (dependency attribution)

**Why:** most real supply-chain attacks come through a dependency update (event-stream,
ua-parser-js, chalk/debug 2025), often a bot's version bump with an innocent author.

**Validated Nov 1** (`dep-probe` branch: local tarball dependency `color-helper@1.0.1` whose
postinstall opens a socket to TEST-NET):
- Detection already works: `NET_RAW_IP` fires, so the PR would be blocked.
- Attribution doesn't: npm ran `sh -c "node install.js"`, which isn't in the PR's
  package.json, so no guilty line is posted. npm prints no banner for dependency scripts, so
  neither the report nor the model can name the package.
- The kernel knows: Tetragon's `process.cwd` for that `sh -c` is
  `/work/dep-probe/node_modules/color-helper`. npm sets it *before* package code runs, so a
  payload can't forge it (unlike files in node_modules or the lockfile it writes).

**Design** (trusted sources only: kernel cwd for *who*, the PR diff for *where*):
1. **Contract (flagged change, backward compatible):** `ExecEvent.cwd: str | None = None`.
   Chamber parser fills it from `process.cwd`. Old Brains ignore it; old Chambers send None.
2. **Brain `pinpoint`:** when the walk reaches npm's `sh -c`, take the package from its cwd
   (last `node_modules/<name>` or `node_modules/@scope/<name>` segment). Map to a line:
   a. the changed `"<name>": ...` line in package.json (direct bump) → inline comment there;
   b. else a changed `"node_modules/.../<name>"` entry in package-lock.json (transitive) →
      comment on that lockfile line;
   c. else (lockfile diff missing or too big, or dep unchanged) → report-only attribution:
      "ran from dependency `<name>`, not changed directly in this PR".
   Never trust versions or dependency trees read from the post-install filesystem.
3. **Report:** a "Packages that ran install scripts" list for *every* run (benign too, e.g.
   esbuild, puppeteer): the seed of the behavioral SBOM. Flagged ones are marked.
4. **Model:** pass `cwd` in the compact telemetry and the package name in `guilty_lines`, so
   the explanation reads "color-helper 1.0.1's postinstall opens a raw socket to ...".
5. **Demo E8, "Bump color-helper from 1.0.0 to 1.0.1"** (Dependabot-style title and body):
   main gets the harmless 1.0.0 (local tarball, no scripts); the PR swaps in 1.0.1. Uses
   `file:` tarballs in the repo so nothing is published to npm (say so in the demo).

**Tests:** fixture from the real dep-probe run (raw Tetragon lines with cwd), plus unit tests:
scoped names, nested `node_modules/a/node_modules/b`, a payload that `chdir`s before
spawning (attribution still comes from npm's `sh -c`), the PR's own script (unchanged
behavior), a dependency not changed in the PR (report-only), and a lockfile patch missing.

**Gate:** E8 on real GitHub is Blocked, with an inline comment on the bumped line naming
`color-helper`. E1–E7 unchanged. Re-run the 40-case eval: no benign regressions.

**Estimate:** ~4–5 h. Chamber redeploy (parser only) + Brain deploy; one change to demo
repo main (adds the harmless 1.0.0 dependency).

### P2: Meta-stack depth
- **Prompt Guard 2** (agent, blocked on HF access to `meta-llama/Llama-Prompt-Guard-2-86M`):
  CPU Modal function scoring PR title/body/diff chunks (512-token windows). Alone it is
  LOW (needs review); with any rule hit it is cited as evidence. Validate on E6 text + 20
  benign PR bodies before it can affect verdicts.

### P3: submission
- README headline numbers, 3-minute demo (E4 → E5 guilty-line → E6 injection → puppeteer clean
  → eval table), recorded backup, architecture slide.

### Cut (low score per hour)
Investigator agent, suggested-fix blocks, prompt caching, dashboard.

## Beyond the hackathon: why this could matter

1. **Registry-scale watch**: detonate every new version of the top 10k npm packages within
   minutes of publish. Alerts on behavior changes such as "v4.2.1 adds a raw-IP connect". This
   catches account-takeover releases (chalk/debug 2025) before installs spread.
2. **Behavioral SBOM**: a signed, per-version record of what a package does at install
   (hosts, executables). Lockfiles pin bytes; this pins *behavior*. Diffable, auditable.
3. **Differential detonation**: base vs head; report only behaviors the PR introduced.
4. **Kill-on-detect**: Tetragon enforcement (`Sigkill` on `/dev/tcp`) for live containment.
5. **More ecosystems**: pip (`setup.py`), cargo build scripts, gem extensions, GitHub
   Actions themselves.
6. **Distribution**: one-click GitHub App + self-hosted Chamber Terraform; private repos
   via TLS + mTLS between Brain and Chamber.
