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

## Results (Nov 1, 2026)

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked |
|---|---|---|---|---|
| benign (26) | rules | 21 | 5 | **0** |
| benign (26) | rules + Intent Contract | 25 | 1 | **0** |
| benign (26) | full (contract + analysis) | 24 | 2 | **0** |
| malicious (14) | rules | 0 | 1 | 13 |
| malicious (14) | rules + Intent Contract | 0 | 1 | 13 |
| malicious (14) | full | 0 | 0 | **14** |

What each layer contributes:
- **Rules** never blocked a benign package, and catch 13/14 attacks on kernel facts alone.
- **The Intent Contract** cuts benign "needs review" from 5 to 1 (puppeteer, prisma,
  chromedriver, cypress downloads predicted from the PR text), without clearing any attack.
- **The analysis model** catches the attack rules can't: exfil to a *resolvable domain*
  (only a low-severity unlisted-domain hit for rules). It also flagged the injection case.
  Cost: it marked one benign install (cypress) "needs review" that the contract had cleared.

Two rules were added because this eval exposed gaps: `NET_INTERNAL_TARGET` (metadata or
private-range connect attempts) and `DNS_ENCODED_LABEL` (data in DNS names). Before them,
rules caught 11/14, and the model alone caught the other three. Benign results were the
same before and after.

## Caveats

- One run; the model is sampled at temperature 0 but not bit-for-bit deterministic, so
  contract and full columns can move by a case between runs.
- The attacks are ours, written knowing the detectors. Treat 14/14 as "covers these
  techniques", not as a real-world detection rate.
- Benign installs ran without a lockfile at today's package versions.
- `storage.googleapis.com` is cleared when predicted (puppeteer, chromedriver), but any GCS
  bucket lives there. Like S3 (already denylisted), it could be treated as shared hosting
  at the cost of puppeteer staying "needs review".

## Reproduce

```
python -m eval.materialize <demo-repo-checkout> manifest.json   # push payloads/ to a branch
# on the Chamber VM (signs with its own secret):
sudo /opt/pr-detonator/venv/bin/python run_chamber.py manifest.json <repo-url> <sha> out/
# locally:
python -m eval.run_brain out/ eval/results
```
