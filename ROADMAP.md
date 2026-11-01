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
