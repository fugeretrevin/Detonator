# Evaluation

40 real detonations on the Chamber (Tetragon + DNS capture), scored by the production
pipeline with the real model (`muse-spark-1.3`). Full per-case table: [results.md](results.md).

- **Benign (26):** popular packages, most with install-time downloads or scripts (puppeteer,
  playwright-chromium, electron, prisma, cypress, chromedriver, esbuild, sharp, bcrypt,
  sqlite3, canvas, ffmpeg-static, @sentry/cli, ...), each as an "Add <pkg>" PR.
- **Malicious (14):** install-time attacks written for this eval ([cases.py](cases.py)):
  curl/wget exfil, `wget | sh`, `/dev/tcp` reverse shell, base64 → sh, pure-JS sockets,
  HTTPS env exfil, char-code obfuscation, `.npmrc` theft, perl sockets, cloud metadata
  probe, DNS-label exfil, exfil to a resolvable domain, prompt injection, delayed payload.
  They only reach TEST-NET-3, the (blocked) metadata address, a `.invalid` name, or
  example.com with a dummy body.

## Results

**Scored 2026-11-01 17:04 UTC at commit `b45e980`** (clean tree, the deployed Brain) with
`muse-spark-1.3` and Llama Prompt Guard 2, on 43 detonations re-run the same day on the
current Chamber: TLS, DNS capture and sinkhole, non-TCP egress blocked and logged, planted
credential bait. `results.json` carries the same stamp.

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked |
|---|---|---|---|---|
| benign (26) | rules | 21 | 5 | **0** |
| benign (26) | rules + Intent Contract | 23 | 3 | **0** |
| benign (26) | full (contract + Prompt Guard + analysis) | 23 | 3 | **0** |
| simulated attacks (15) | rules | 0 | 1 | 14 |
| simulated attacks (15) | rules + Intent Contract | 0 | 1 | 14 |
| simulated attacks (15) | full | 0 | 0 | **15** |
| real-incident reconstructions (2) | rules / contract / full | 0 | 0 | **2** |

New in this run: **m15** (env exfil over UDP, no TCP at all) is blocked by
`NET_NON_TCP_EGRESS`; **m08** (.npmrc theft) and the **Shai-Hulud** reconstruction also trip
`CRED_FILE_ACCESS`. Every benign install opened `~/.npmrc` too, but only from npm's own
process, never from an install script, so the bait rule fired on none of them.

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
- **Rules** never blocked a benign package, and catch 14/15 attacks on kernel facts alone.
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
