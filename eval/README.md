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

**Scored 2026-11-01 15:26 UTC at commit `f1fc090`** (clean tree) with `muse-spark-1.3` and
Llama Prompt Guard 2, on detonations re-run the same day. `results.json` carries the same
stamp.

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked |
|---|---|---|---|---|
| benign (26) | rules | 21 | 5 | **0** |
| benign (26) | rules + Intent Contract | 23 | 3 | **0** |
| benign (26) | full (contract + Prompt Guard + analysis) | 23 | 3 | **0** |
| malicious (14) | rules | 0 | 1 | 13 |
| malicious (14) | rules + Intent Contract | 0 | 1 | 13 |
| malicious (14) | full | 0 | 0 | **14** |

What each layer contributes:
- **Rules** never blocked a benign package, and catch 13/14 attacks on kernel facts alone.
- **The Intent Contract** clears downloads the PR text predicted from vendor-owned hosts
  (prisma, cypress, playwright's CDNs) without clearing any attack. The 3 benign installs
  left at ⚠️ (puppeteer, chromedriver, playwright-chromium) all fetch from
  `storage.googleapis.com`, which is deliberately never cleared: anyone can host a bucket
  there, the same as S3.
- **The analysis model** catches the attack rules can't: exfil to a *resolvable domain*
  (only a low-severity unlisted-domain hit for rules). It also flagged the injection case.
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
- The attacks are ours, written knowing the detectors. Treat 14/14 as "covers these
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
