# Evaluation

122 real detonations on the Chamber (Tetragon + DNS capture), scored by the production
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

**Scored 2026-11-02 06:37 UTC at commit `0aff394`** (clean tree, the deployed Brain) with
`muse-spark-1.3` and Llama Prompt Guard 2, on 122 detonations on the current Chamber: TLS,
signed responses, DNS capture and sinkhole, non-TCP egress blocked, per-run canary
credentials and decoy tools. `results.json` carries the same stamp.

Four arms, so the two model uses can be told apart: `analysis` is the model reasoning over the
telemetry with **no** Intent Contract.

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked | ⏱️ Could not verify |
|---|---|---|---|---|---|
| benign (104) | rules | 95 | 5 | **0** | 4 |
| benign (104) | rules + Intent Contract | 97 | 3 | **0** | 4 |
| benign (104) | rules + analysis (no contract) | 95 | 5 | **0** | 4 |
| benign (104) | full (contract + Prompt Guard + analysis) | 97 | 3 | **0** | 4 |
| simulated attacks (16) | rules | 0 | 1 | 15 | 0 |
| simulated attacks (16) | rules + Intent Contract | 0 | 1 | 15 | 0 |
| simulated attacks (16) | rules + analysis (no contract) | 0 | 0 | **16** | 0 |
| simulated attacks (16) | full | 0 | 0 | **16** | 0 |
| real-incident reconstructions (2) | all four arms | 0 | 0 | **2** | 0 |

- **0 of 104 popular packages blocked, in any arm.** The 3 left at ⚠️ (puppeteer,
  playwright-chromium, chromedriver) all download from `storage.googleapis.com`, which is never
  auto-cleared.
- **The ablation separates the two model uses, and each fixes something the other does not.**
  The Intent Contract takes benign ⚠️ from 5 to 3 (it explains `binaries.prisma.sh` for a Prisma
  bump and `download.cypress.io` for Cypress) and clears **no** attack: 15 → 15. The analysis
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
- **Cost and latency (full pipeline):** **$0.0149 per PR** mean (muse-spark-1.3), ~2.2k in /
  2.9k out tokens; detonation p50 4.5 s / p95 13.8 s; model latency p50 12.5 s / p95 24.2 s.
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

## Reproduce

```
python -m eval.materialize <demo-repo-checkout> manifest.json   # push payloads/ to a branch
# on the Chamber VM (signs with its own secret):
sudo /opt/pr-detonator/venv/bin/python run_chamber.py manifest.json <repo-url> <sha> out/
# locally:
python -m eval.run_brain out/ eval/results
```
