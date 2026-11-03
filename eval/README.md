# Evaluation

142 real detonations on the Chamber (Tetragon + DNS capture), scored by the production
pipeline with the real model (`muse-spark-1.3`). Full per-case table: [results.md](results.md).

- **Benign (104):** popular packages, 35 of which run install scripts (puppeteer,
  playwright, electron, prisma, cypress, chromedriver, esbuild, @swc/core, sharp, bcrypt,
  sqlite3, better-sqlite3, canvas, @napi-rs/canvas, ffmpeg-static, @sentry/cli, re2, ...),
  the rest common pure-JS deps (express, react, axios, zod, ...). Each an "Add <pkg>" PR.
- **Malicious (16):** install-time attacks written for this eval ([cases.py](cases.py)):
  curl/wget exfil, `wget | sh`, `/dev/tcp` reverse shell, base64 → sh, pure-JS sockets,
  HTTPS env exfil, char-code obfuscation, `.npmrc` theft, perl sockets, cloud metadata
  probe, DNS-label exfil, exfil to a resolvable domain, prompt injection, delayed payload,
  UDP exfil, and a stolen `$GITHUB_TOKEN` in a request header. They only reach TEST-NET-3,
  the (blocked) metadata address, a `.invalid` name, example.com, or sinkholed services.

## Results

**Scored 2026-11-02 22:39 UTC at commit `a96c8a1`** (clean tree) with `muse-spark-1.3` and
Llama Prompt Guard 2, on **all 142 cases freshly detonated on the contract-v3 Chamber**: TLS,
signed responses, DNS capture and sinkhole, non-TCP egress blocked, per-run canary credentials
and decoy tools, **and a per-job sensor witness**. `results.json` carries the same stamp.

**Every run in this table carries a verified sensor witness.** 139 of 142 recorded both the
start and end marker; the 3 that recorded only the start (`biome`, `cypress`, `gm08-cpu-miner`)
are exactly the 3 that hit the timeout and were killed, so their end marker never ran — which is
the witness reporting truncated observation, correctly. No run was missing its start marker.

Four arms, so the two model uses can be told apart: `analysis` is the model reasoning over the
telemetry with **no** Intent Contract.

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked | ⏱️ Could not verify |
|---|---|---|---|---|---|
| benign (104) | rules | 94 | 4 | **0** | 6 |
| benign (104) | rules + Intent Contract | 95 | 3 | **0** | 6 |
| benign (104) | rules + analysis (no contract) | 94 | 4 | **0** | 6 |
| benign (104) | full (contract + Prompt Guard + analysis) | 95 | 3 | **0** | 6 |
| simulated attacks (16) | rules | 0 | 1 | 15 | 0 |
| simulated attacks (16) | rules + Intent Contract | 0 | 1 | 15 | 0 |
| simulated attacks (16) | rules + analysis (no contract) | 0 | 0 | **16** | 0 |
| simulated attacks (16) | full | 0 | 0 | **16** | 0 |
| real-incident reconstructions (2) | all four arms | 0 | 0 | **2** | 0 |
| red team, author (10) | rules / contract | 4 | 0 | 6 | 0 |
| red team, author (10) | analysis / full | 1 | 0 | **9** | 0 |
| red team, independent (10) | rules / contract | 4 | 0 | 5 | 1 |
| red team, independent (10) | analysis / full | 0 | 0 | **10** | 0 |

The author red-team row is 6 blocked by rules, not 5, because the merged `EXEC_DROPPED_BINARY`
change now catches `rt09` on kernel facts alone. The independent row shows 1 ⏱️ under
rules/contract because `gm08-cpu-miner` hit the timeout this run; the model still blocked it.

> **One scored run is a sample, not a fact.** Temperature 0 is not determinism. The `full`
> attack row is 16/16 here and was 15/16 on the previous pass of the same telemetry, with no
> model errors either time — `m12` alternates between `malicious` and `suspicious`.
> `REPEAT.md` / `REPEAT_CORE.md` measure the spread over five trials. **Prefer the
> repeatability numbers for any claim**, and read this table as one draw from them.
- **6 benign are ⏱️, not ✅.** Four are native builds that exit 1 with no C toolchain in the
  image (`better-sqlite3`, `argon2`, `cpu-features`, `node-pty`); two (`biome`, `cypress`) hit
  the install timeout. None was blocked. This is a limit of our sandbox, not a judgement about
  those packages — and it is why "104/104 clean" is never the right phrasing.

- **Repeatability (5 trials per case on identical telemetry, `REPEAT.md` / `REPEAT_CORE.md`).**
  Red team, 20 cases: flip rate **1/20** (only `gm08-cpu-miner`), worst case **2/20 attacks
  mergeable** (`rt08-local-miner` Clean in all five — the known inline-CPU-loop miss — plus
  `gm08` once). Attacks and boundary benign, 24 cases: flip rate **1/24**, worst case **1/18
  attacks mergeable**, **0/6 benign blocked in any trial**. The single unstable case is
  **`m12-domain-exfil`** (Blocked ×3, Needs review ×2): it exfiltrates to an ordinary
  *resolvable* domain, which the rules can only rate LOW, so the outcome hangs on whether Muse
  returns `malicious` (HIGH) or `suspicious` (LOW) on that call. So the honest claims are
  **16/16 attacks in 3 of 5 trials, 15/16 in the worst**, and **19/20 red team in 4 of 5
  trials, 18/20 in the worst** — never a flat 16/16 or 19/20.
- **Evidence grounding holds across every trial:** 452/452 claims in the scored run, and
  251/251 and 380/380 summed over the two 5-trial sets — 0% unsupported, no case naming a host
  or IP absent from both the telemetry and the diff. Measured by `brain/evidence.py`, which
  rejects an event id that isn't in that job's index (ids are an HMAC of the job id, so a PR
  author can't forge one) and requires an `observed` claim to cite an event of its own type.
  **What that number does and does not cover.** It checks every entry in `key_evidence`, which
  must cite an event of the right type, plus a regex for hostnames and IPs anywhere in the
  prose. It does **not** check other factual assertions made in prose without a citation — a
  sentence like *"it appended to `~/.bashrc`"* when nothing did would pass. So read it as a
  measure of **citation discipline and the absence of invented hosts**, not as total factual
  accuracy. Widening it to file paths, package and process names and ports is planned
  (`docs/WEAKPOINTS.md`, W4).
- **We measured whether CPU time could close the `rt08` gap, and it can't.** With cgroup
  sampling on all 142 cases, `rt08-local-miner` used **8.16 s** of CPU while **eight benign
  packages used more** — playwright-chromium 26.0, prisma 25.1, puppeteer 21.3, parcel 13.3,
  electron 9.7, nx 9.6, cypress 9.1, @swc/cli 8.3. Any threshold low enough to catch rt08 flags
  the most popular install-script packages in the ecosystem, and the build-tool exemption
  doesn't rescue them because they download prebuilt binaries rather than invoking a compiler.
  A ~30 s threshold would catch `gm08-cpu-miner` (36.3 s) cleanly, but the model already catches
  gm08 for forking a detached worker, so the rule buys nothing there either. `RES_CPU_HEAVY`
  therefore stays **off** on evidence, not caution: closing this needs a second signal (process
  ancestry, lifetime, syscall profile), not a bigger number. `cpu_s` is recorded on every run so
  it can be re-tested cheaply.
- **0 of 104 popular packages blocked, in any arm or any trial.** The 3 left at ⚠️ (puppeteer,
  playwright-chromium, chromedriver) all download from `storage.googleapis.com`, which is never
  auto-cleared.
- **The ablation separates the two model uses, and each fixes something the other does not.**
  The Intent Contract takes benign ⚠️ from 4 to 3 and clears **no** attack: 15 → 15. That is one
  case — `prisma`, whose install fetches engines from `binaries.prisma.sh`. It also clears
  `download.cypress.io` for Cypress and `cdn.playwright.dev` for playwright-chromium, but
  neither verdict changes: Cypress's install timed out (so it is ⏱️ either way) and
  playwright-chromium also reaches `storage.googleapis.com`, which is never auto-cleared. The
  analysis
  arm blocks 16/16 while leaving benign verdicts exactly where the rules left them: its one
  addition is **m12**, which exfiltrates to an ordinary *resolvable* domain that the rules can
  only rate LOW — so rules and contract both leave m12 a **mergeable** ⚠️.
- **Scaling to 104 found one real false positive and we fixed it:** `re2`'s install runs a
  nested `npm run verify-build`, and that npm reads `~/.npmrc` as config, which first tripped
  `CRED_FILE_ACCESS`. The rule now never flags an npm/npx process reading it; a theft reads it
  from the dependency's own code (m08 still fires). Numbers above are after the fix.
- **What Muse explained (ground truth, P1.5):** decoded the payload in **5/5** obfuscated
  attacks (base64, char-code, DNS-hex, and both reconstructions) and attributed **2/2**
  dependency-delivered attacks to the right package and file.
- **Cost and latency (full pipeline):** **$0.0181 per PR** mean (muse-spark-1.3), 2516 in /
  3524 out tokens mean, $2.57 for all 142 cases; detonation p50 5.9 s / p95 67.1 s; model
  latency p50 36.5 s / p95 66.7 s. These are the figures in
  [`results.md`](results.md#cost-and-latency-full-pipeline); the smaller numbers this line used
  to carry were from an earlier, smaller run and were never refreshed.
- New rules exercised: **m15** (UDP exfil) → `NET_NON_TCP_EGRESS`; **m16** (token in a curl
  header) → `DECOY_CREDENTIAL_SEEN` (critical); **m08** + Shai-Hulud → `CRED_FILE_ACCESS`.
- **4 native packages are ⏱️ "could not verify", not ✅ Clean** (better-sqlite3, argon2,
  cpu-features, node-pty): they compile from source and the minimal sandbox image has no C
  toolchain, so they exit 1. We never watched a complete install, so we do not call them clean.
  They are equally **not** false blocks — nothing was blocked, and this is a usability limit of
  our sandbox, not a judgement about those packages. Earlier runs of this suite counted them as
  ✅ Clean, which inflated the clean total to 99/101; the verdict now requires a finished
  install, whole telemetry and a live sensor before it will say Clean.

**Real-incident reconstructions** (defanged, delivered as Dependabot-style dependency bumps,
see `INCIDENTS` in [cases.py](cases.py)):
- **ua-parser-js 0.7.29 (Oct 2021):** preinstall → OS check → `preinstall.sh` → geolocation
  lookup → curl/wget the `jsextension` miner from a raw IP. Blocked before and after today's
  rules (`EXEC_NET_TOOL`, `NET_RAW_IP`, now also `NET_EXFIL_SERVICE`).
- **Shai-Hulud (npm worm, Sept 2025):** postinstall → `node bundle.js` → downloads the real
  TruffleHog from GitHub releases → runs it from `/tmp` → POSTs results to webhook.site.
  **With the rules as they were before this reconstruction, it was only ⚠️ (one low
  finding):** GitHub is allowlisted and webhook.site was just an unlisted domain. Two rules
  came out of it, `EXEC_DROPPED_BINARY` (no benign install ran a binary from temp/home) and
  `NET_EXFIL_SERVICE` (no benign install contacted one); now it is blocked by rules alone.
- Both are blamed on the bumped `package.json` line, naming the dependency.
- Not reconstructed: **event-stream (2018)**. Its payload ran when the package was
  `require`d inside one specific app (the Copay wallet), not at install, so install-time
  detonation would not see it. That is a scope limit, stated rather than faked.

Sources for the incident behavior: [Sysdig](https://sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages),
[Truesec](https://truesec.com/hub/blog/500-npm-packages-compromised-in-ongoing-supply-chain-attack-shai-hulud),
[MITRE ATT&CK S9008](https://attack.mitre.org/software/S9008/),
[BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-npm-library-hijacked-to-install-password-stealers-miners/),
[CERT-EU 2021-057](https://cert.europa.eu/publications/security-advisories/2021-057/),
[ua-parser-js#536](https://github.com/faisalman/ua-parser-js/issues/536),
[Hayden Parker on event-stream](https://medium.com/@hkparker/analysis-of-a-supply-chain-attack-2bd8fa8286ac).
The ua-parser-js geolocation service is a stand-in: our sources don't name it.

What each layer contributes:
- **Rules** never blocked a benign package, and catch 15/16 attacks on kernel facts alone.
- **The Intent Contract** clears downloads the PR text predicted from vendor-owned hosts
  (prisma, cypress, playwright's CDNs) without clearing any attack. The 3 benign installs
  left at ⚠️ (puppeteer, chromedriver, playwright-chromium) all fetch from
  `storage.googleapis.com`, which is deliberately never cleared: anyone can host a bucket
  there, the same as S3.
- **The analysis model** catches the attack rules can't: exfil to a *resolvable domain*
  (only a low-severity unlisted-domain hit for rules). It also flagged the injection case.
  It varies on cypress: "suspicious" in two earlier runs, benign in this one, so the full
  row's ⚠️ count moves between 3 and 4.
- **Prompt Guard 2** scored every benign case ≤ 0.002, and the m13 injection 0.01: it targets
  explicit jailbreaks, not injections embedded in PR text (see brain/prompt_guard.py for
  its validation), so it never decides a verdict here.
- **Dependency attribution:** every report now lists which packages ran install scripts
  (e.g. prisma → `prisma`, `@prisma/engines`), from the kernel-recorded working directory.

History (same day): the first run (before `NET_INTERNAL_TARGET` and `DNS_ENCODED_LABEL`,
two rules this eval motivated) had rules at 11/14; benign results were unchanged by them.
Before `storage.googleapis.com` was treated as shared hosting, contract clearing left 1
benign at ⚠️ instead of 3.

## Caveats

- One run; the model is sampled at temperature 0 but not bit-for-bit deterministic, so
  contract and full columns can move by a case between runs.
- The attacks are ours, written knowing the detectors. Treat 15/15 as "covers these
  techniques", not as a real-world detection rate.
- Benign installs ran without a lockfile at today's package versions.
- Benign scripts were attributed from detonations of `npm install <pkg>` (no lockfile).

## How certain are these numbers?

Not very, and the denominators are the reason. Exact (Clopper-Pearson) two-sided 95% intervals,
from `python -m eval.intervals`:

| Claim | Point | 95% interval |
|---|---|---|
| Benign packages hard-blocked | 0/104 | 0.0% – **3.5%** |
| …counting only the 98 we could verify | 0/98 | 0.0% – **3.7%** |
| Designed attacks blocked | 16/16 | **79.4%** – 100% |
| Incident reconstructions blocked | 2/2 | **15.8%** – 100% |
| Author red-team blocked | 9/10 | **55.5%** – 99.7% |
| Model-suggested red-team blocked | 10/10 | **69.2%** – 100% |
| Red-team blocked, both sets | 19/20 | **75.1%** – 99.9% |
| Sweep blocks (unlabelled) | 1/421 | 0.0% – **1.3%** |

Read the attack rows carefully: "16 of 16" is consistent with a true block rate as low as
**79%**, and "2 of 2" says almost nothing — its lower bound is 15.8%. Normal-approximation
intervals are not used because they are invalid at exactly these proportions, where they give
zero width.

These bound **sampling error only**, and assume the cases were drawn independently from the
population being described. They were not: the benign set is hand-picked popular packages, the
attacks are author-written, and repeated trials of one case are not independent. So each
interval is a **floor on uncertainty, not a generalisation guarantee**. A genuinely blind,
externally labelled set would do more for confidence here than any amount of extra arithmetic
(see [`docs/WEAKPOINTS.md`](../docs/WEAKPOINTS.md) W12).

## Reproduce

```
python -m eval.materialize <demo-repo-checkout> manifest.json   # push payloads/ to a branch
# on the Chamber VM (signs with its own secret):
sudo /opt/pr-detonator/venv/bin/python run_chamber.py manifest.json <repo-url> <sha> out/
# locally:
python -m eval.run_brain out/ eval/results
```
