# Handoff — picking this up on another machine

**Written 2026-11-02.** State at this commit: `main` = `a7e83dc`, pushed, clean tree,
**380 tests pass / 1 skipped** (the skipped one is a symlink test that only runs on Linux;
it was verified on the Chamber VM). Brain is **deployed and live** from `caac170`, Chamber is
healthy. Submission deadline is **Wed 2026-11-04, 9:00 pm ET**.

---

## 1. Read these first

- `BUILD_PLAN.md` and `HARDENING_PLAN.md` — the standing plan; `CLAUDE.md` — working rules.
- `docs/SUBMISSION.md` — the paste-ready submission. **Still has `_[link]_` for the video.**
- `eval/README.md` — evaluation methodology and the current numbers.

## 2. What is NOT in git and must exist locally

This is the part that will break first on a new machine. None of it is committed, correctly.

| Thing | Where it lives on the old machine | Notes |
|---|---|---|
| `.env` | repo root | Rebuild from `.env.example`; holds Meta/Modal/GitHub/HF values |
| Chamber SSH key | `C:\Users\stoof\keys\detonator.pem` | Needed for any `ssh chamber` work |
| `~/.ssh/config` entry | `Host chamber` → `3.223.99.234`, user `ubuntu` | Recreate or `ssh ubuntu@3.223.99.234 -i <key>` |
| GitHub App private key | `C:\Users\stoof\keys\...` (path in `GITHUB_PRIVATE_KEY_PATH`) | Deliberately outside the repo |
| **SBOM signing private key** | **session scratchpad only** — `sbom_signing_key.pem` | ⚠️ See warning below |

> ⚠️ **Back up the SBOM signing private key before that machine's temp folder is cleared.**
> `eval/sbom/public_key.pem` is committed so the 73 existing signed records stay verifiable,
> but the matching *private* key exists only in the old machine's scratchpad. Lose it and you
> can't sign new records under the same identity. Copy it somewhere durable now.

## 3. Setup

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install --use-feature=truststore -r requirements-dev.txt
.venv\Scripts\python -m pytest            # expect 380 passed, 1 skipped
.venv\Scripts\ruff.exe check .
```

**Always run Modal through the wrapper** — Norton re-signs TLS on these machines and plain
`modal` fails cert verification:

```powershell
.venv\Scripts\python scripts\modal_cli.py deploy -m brain.app
```

Local scripts that talk to the network need `import truststore; truststore.inject_into_ssl()`.

## 4. Raw detonation results (needed to re-score anything)

The scored outputs are committed (`eval/results.json`, `eval/REDTEAM.json`, `eval/SWEEP*.json`),
but the **raw per-case `DetonateResult` JSONs are not** — they live in the old machine's
scratchpad and on the Chamber. Re-fetch from the VM:

```powershell
scp chamber:/tmp/eval-results-6.tgz .   # the 122-case set
scp chamber:/tmp/rt-out.tgz .           # rt01-rt10
scp chamber:/tmp/gm-out.tgz .           # gm01-gm10 (independent red team)
scp chamber:/tmp/sweep500.tgz .         # 500-package sweep
scp chamber:/tmp/sweep-out.tgz .        # 100-package sweep (contains the finding)
tar -xzf eval-results-6.tgz
```

Then re-score with: `.venv\Scripts\python -m eval.run_brain <dir> eval/results`
(needs `LLAMA_API_KEY` and the deployed Modal app; it stamps the commit and whether the tree
was dirty — **score from a clean tree** or the stamp says so).

## 5. Agreed next work, in this order

All four were approved. 1 and 2 are low-risk; 3 is the one that could destabilise the demo.

1. **Model repeatability + evidence grounding** (Meta tooling, 25% weight — the top remaining
   criticism in both audits). Re-score frozen telemetry ≥5× per model arm; report per-case
   verdict flip rate and the *worst* case, not the mean. Then build a ground-truth ledger and
   mechanically check each model claim maps to a real event: hosts against `connect_events` /
   `dns_queries`, binaries against `exec_events`, guilty `path:line` against the diff hunks,
   attributed packages against `executed_scripts`. Classify each claim supported / unsupported
   / contradicted. Pure offline re-scoring, so no risk to the live demo.
2. **Close the two concrete gaps found here.** (a) `rt09`: `EXEC_DROPPED_BINARY` does not fire
   when a dropped file runs via `sh /tmp/x.sh` rather than being `execve`'d directly — the model
   had to backstop it. Use interpreter args + kernel cwd, resolve paths inside the sandbox only.
   (b) Stale-check reconciliation: a hard Modal timeout/kill can bypass the exception handler and
   leave a check `in_progress`; add a reconciler keyed by SHA/check-run-id that writes a failing
   *Could not verify*, and never lets an older head SHA's green result stand for a new SHA.
   **Validate both against the 104 benign + 500 sweep before merging** — zero new benign blocks.
3. **Per-job Tetragon sentinel.** Non-empty `exec_events` proves the collector saw *something*,
   not that it was armed for *this* container. Emit a harmless unique per-job marker after the
   collector is ready, require its event with matching container identity and a timestamp after
   arming, fail closed otherwise. Touches `shared/contract.py` (flag this — it's the
   Brain/Chamber interface), `chamber/telemetry.py`, `chamber/detonate.py`, `brain/verdict.py`,
   plus fixtures. **Needs a VM redeploy, so only do it with a tested rollback.**
4. **Behavioral SBOM version-delta.** `brain/sbom.py` already does canonical JSON, Ed25519
   signing, verification and diffs — extend, don't rebuild. Show version A vs B: newly contacted
   hosts, changed script hashes, new sensitive-file reads, new dropped executables, pinned to
   image digest + Node/npm versions. Wire into the E8 demo PR. Remember the signature attests
   **record integrity only**, never that the package is safe.

## 6. Outstanding items only you can do

1. ~~Send the disclosure.~~ **Sent Nov 2, 2026** to `liu0218dong@gmail.com` (sole npm
   maintainer; no repo/bugs URL published), after confirming the issue is still in that day's
   latest version. Docs now say *reported privately, no response yet*. If there's no reply in
   1–2 weeks: ask for a private contact on Gitee (`onescience-ai`, no details in public), then
   security@npmjs.com. Only say "acknowledged"/"fixed" if they actually reply or ship a fix.
2. **Record the demo video** — `demo/DEMO_SCRIPT.md`. Biggest single score lever by both audits'
   own arithmetic (demo scored 7.1/10 at 25% weight).
3. **Paste the video URL** into `docs/SUBMISSION.md` and check it from a logged-out browser.
4. **Rotate the Modal token** (`modal token new`). A live `.env` went out in a shared ZIP;
   `MODAL_TOKEN_SECRET` can read your other Modal secrets, so it's the one that matters. Then
   redeploy and confirm.
5. **Confirm the official rules** in the participant portal. The 30/25/20/25 weighting comes
   from a third-party guide, not Meta's own page.

## 7. Gotchas

- **The Chamber runs one job at a time** and returns `409` when busy. Long sweeps block
  everything; chain jobs with a wait loop rather than firing concurrently.
- **`pgrep -f <manifest-name>` matches your own wait-loop's command line** — a wrapper polling
  for `manifest_sweep500` will see itself and never exit. Match on `run_chamber.py` instead.
- **Never zip the working directory.** It ignores `.gitignore` and ships `.env`, `.git/` and
  `.venv/`. Use `git archive --format=zip -o release.zip HEAD` and verify the contents.
- **The sweep finding's identifier is in public git history** (`07feaba` added it, `f4ee6ec`
  redacted it; the repo is public). Don't claim it is concealed; don't show a `git log` tab on
  camera. Rewriting history would not fix this honestly — sending the disclosure resolves it.
- **`eval/SWEEP.md` is the 100-package run and must stay that way** — it is the one containing
  the finding, and the README/SUBMISSION/demo cold-open all cite it. The 500-package scale run
  lives separately in `eval/SWEEP500.md`. Don't merge or overwrite them.
- **PowerShell 5.1**: no `&&`/`||`, and embedded double quotes in a `git commit -m` here-string
  break native-arg quoting — write the message to a file and use `git commit -F`, with
  `UTF8Encoding $false` or you get a BOM in the subject line.
- **Eval stamps**: `eval/results.*` is stamped `0aff394`, `eval/REDTEAM.*` is `1aa9c45`. A
  docs-only commit does not invalidate those; changing `brain/`, `shared/`, `chamber/` or
  `eval/cases.py` does. Re-stamp before submitting.

## 8. Claims to keep honest

These are the lines both audits flagged. Keep them precise:

- "0 blocked across 104 popular packages" — true. **"104/104 clean" is not**: 97 verified
  clean, 3 needs review, **4 could not verify** (native builds that exit 1 in this image).
- **19/20 red team is 95% of that cohort**, not 95% real-world detection (exact 95% CI is
  roughly 75–100%).
- The **500-package sweep cannot produce a false-positive rate** — the packages were never
  labelled. They are alert counts.
- Dormant payloads blocked from diff content are **source-assisted analysis**, not evidence the
  eBPF sensor observed them executing.
- It is **hardened Docker in a dedicated VM, not a microVM**, and public TCP egress is still
  allowed (private ranges, metadata and non-TCP are blocked; selected exfil services sinkholed).
- Temperature 0 is **not** determinism; Prompt Guard misses indirect injection (measured).
- `rt08` (a bare inline CPU loop) is an honest miss. Keep it in the write-up.
