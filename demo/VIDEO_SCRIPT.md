# PR Detonator — Hackathon Video Script (v2) and Submission Answers

Every number here traces to a committed result; see [`docs/FRAMING.md`](../docs/FRAMING.md) and
[`eval/CLAIM_LEDGER.md`](../eval/CLAIM_LEDGER.md). Target length about 3:00 (~500 words). Lines
marked ✂️ are the first to cut if a take runs long.

---

## Video script

### 1. The Problem and the Product (0:00–0:28)

**PARTNER 1:**
A pull request bumps one dependency. It looks routine. But npm packages can run code the moment
they install, before your app ever starts. That's how the ua-parser-js hijack and the Shai-Hulud
worm spread. And AI agents now open these pull requests faster than anyone can review them.

**PARTNER 2:**
PR Detonator is a GitHub App that runs the install *before* you merge. It watches every process,
network connection and DNS lookup at the kernel level, then posts the evidence back to the pull
request, right down to the line responsible.

> *On screen:* a demo PR with the 🛑 Blocked check and the inline comment on the guilty line.

### 2. A Real Finding (0:28–0:48)

**PARTNER 1:**
We pointed it at a hundred npm packages published minutes earlier. All seventy-three that
installed came back clean. But one of the others connected straight to a bare IP address with no
DNS lookup, downloaded a binary with certificate checks turned off, and ran it. No advisory
existed. We confirmed it in the source and reported it privately to the maintainer.

> ⚠️ **Do not show the package name or IP on screen.** The disclosure is still open (W11).

### 3. Attack Examples and the Baseline (0:48–1:07)

**PARTNER 2:**
We tested credential theft, encoded reverse shells and poisoned dependency bumps. On five of those
attacks, npm audit reported no vulnerabilities in four. PR Detonator blocked all five. ✂️ *It
catches our rebuild of the real ua-parser-js hijack in twelve seconds, and that version was live
for hours.* Advisory tools tell you what's already known. We show what the code actually does.

### 4. Architecture and Safety (1:07–1:29)

**PARTNER 1:**
Here's how it works. The Brain runs on Modal: it receives the webhook, calls the models, applies
nineteen deterministic rules and posts the check. Untrusted code runs separately in the Chamber,
an isolated sandbox traced with eBPF, holding bait credentials and no real secrets. Every message
between the two is cryptographically signed. And it fails closed: a timeout, a crash or a blind
sensor is never a pass.

> *On screen:* simple two-box diagram, Brain (Modal) ⇄ signed ⇄ Chamber (EC2 + eBPF).

### 5. Meta Integration and Its Impact (1:29–2:38)

**PARTNER 2:**
But a network connection alone doesn't tell you whether a change makes sense. A browser download
fits a PDF feature. In a typo fix, it's a red flag. That's where Meta comes in.

**PARTNER 1:**
Before anything runs, Muse Spark, through Meta's Model API, predicts what the install should do.
It works from the pull request's title and description only, never the code, so a payload can't
steer the prediction. Our code then checks that prediction against the kernel's record. Llama
Prompt Guard 2 screens the text for manipulation attempts, and we still treat that text as
untrusted.

**PARTNER 2:**
After installation, Muse compares what actually happened with what the change claimed, and
explains it. It decoded all five obfuscated payloads in our tests, and all 452 of its cited claims
checked out against the kernel record. It can raise a verdict but never lower one, so an attacker
can't talk it out of a finding. For unclear cases, Muse investigates with read-only tools and
writes the reviewer a note.

**PARTNER 1:**
Here's where it mattered most. We tested ten attacks written by a model that had never seen our
rules. Rules alone caught six. With Muse, all ten were flagged: nine blocked, one sent for review.
✂️ *Three of those misses are now caught by new rules too.*

### 6. Results and Closing (2:38–2:56)

**PARTNER 2:**
Across 104 popular packages, including puppeteer, prisma and esbuild, none were blocked. Three
needed review, and six we honestly couldn't verify. Against attacks an independent agent labeled
before we ran anything, seven of seven were blocked. ✂️ *All for under two cents of model spend
per pull request.*

**PARTNER 1:**
That's PR Detonator. See what a dependency change does before you trust it.

### 7. End Card (2:56–3:00, no narration)

> **PR Detonator**
> github.com/fugeretrevin/Detonator
> Built with Meta Muse Spark 1.3 and Llama Prompt Guard 2 · Runs on Modal

### Notes on the numbers

- **Section 2:** no download count is quoted on purpose; a download figure could identify a
  package whose disclosure is still open. Optional extra line: "scaled to five hundred packages:
  one block in 421 installs."
- **Section 5:** "rules alone caught six" is the first run of the held-out set; "nine blocked, one
  sent for review" is the full pipeline (`eval/BLIND_RESULTS.md`).
- **Avoided on purpose:** a flat "16/16" (it held in 3 of 5 trials) and "100% clean" (6 of 104
  were unverifiable).

---

## Submission form answers

**Team Name:** *[your team name]*

**Team members:** *[names]*

**Track:** Build for Your World

**Problem Statement:**
Supply-chain attacks moved to install time. An npm package's install script runs on every laptop
and CI runner that installs it, before anyone imports its code, and the pull request that brings
it in is usually a one-line version bump with nothing to review. AI coding agents now open these
pull requests and choose the dependencies faster than humans can review them. Advisory tools like
`npm audit` only know about an attack after someone publishes an advisory, and source-reading
reviewers can be fooled by obfuscation or by prompt injection in the pull request text.

**Project description:**
PR Detonator is a GitHub App that runs a pull request's `npm install` in a disposable,
kernel-traced sandbox before the merge, then blocks the merge if what the code *did* doesn't match
what the pull request *claimed*. It records every process, TCP connection and DNS lookup with
eBPF. Nineteen deterministic rules set a severity floor. Meta's Muse Spark predicts the expected
behavior beforehand and explains the observed behavior afterward. The result is a merge-gating
check run plus an inline comment on the exact line responsible, with every piece of evidence
verified against the kernel record. It fails closed: anything it couldn't fully observe is "Could
not verify," never "Clean."

Measured results:
- 0 of 104 popular packages blocked
- 9 of 10 held-out attacks blocked and 1 sent for review
- 7 of 7 attacks blocked on an independently labeled set
- One real, previously unreported install-time vulnerability found in a sweep of newly published
  packages

**Public repo:** https://github.com/fugeretrevin/Detonator

**Demo video:** *[link after upload]*

**Describe your use of Meta products:**
We use Meta's models in four distinct roles:
1. **Intent Contract (Muse Spark 1.3, Meta Model API):** before the sandbox runs, Muse predicts
   the expected network hosts and executables from the pull request's title, description and file
   names only, never the diff, so payload code can't steer it. Our code then checks that
   prediction against the kernel record. This cut benign "needs review" results without clearing a
   single attack.
2. **Behavior analysis (Muse Spark 1.3, structured output):** after installation, Muse compares
   the kernel record with the change's stated purpose, explains the result, and decodes obfuscated
   payloads onto the guilty line. It decoded 5 of 5 obfuscated attacks. Every event it cites is
   verified by code, and 452 of 452 cited claims resolved to a real kernel event.
3. **Investigator agent (Muse Spark 1.3 + tool calling):** for borderline cases only, Muse uses
   three read-only tools (npm registry facts, our host classification, the captured install
   script) to write a triage note for the human reviewer. It can escalate a verdict but never
   clear one.
4. **Llama Prompt Guard 2 (86M):** runs on CPU on Modal and screens pull request text for
   jailbreak attempts. We validated it before letting it affect anything and scoped it to flagging
   text as untrusted, never deciding a verdict.

**Why are Meta's models important to your solution?**
Kernel telemetry tells you *what* happened, but not whether it makes sense for this particular
change. A browser download is normal for a PDF feature and alarming in a typo fix. Muse supplies
that judgment, and we built the system so it can't be weaponized against us: rules set a floor the
model can never lower, and every claim it makes is checked against the kernel. The biggest payoff
showed up on attacks we didn't write. On a held-out set written by a model that had never seen our
rules, the deterministic rules missed four of ten, and Muse caught all four by reading the install
scripts and reasoning about behavior no rule had a pattern for. The model adds the most exactly
where hand-written rules are weakest. The Intent Contract also pushes the model past
classification: it makes a falsifiable prediction *before* execution, and the kernel then confirms
or refutes it.

**Feedback on partner technologies (Fireworks, Modal, Baseten):**
We used **Modal** (not Fireworks or Baseten). Modal ran our whole control plane: the webhook
endpoint, model orchestration, secrets, a scheduled health check and reconciler, the public
dashboard, and a CPU function for Prompt Guard 2. Serverless deploys and built-in secrets let a
small team ship a production-shaped service quickly, and `modal.Dict` gave us simple shared state
for dedupe and run history. Two pieces of friction:
- The Modal CLI failed TLS certificate verification on a machine whose antivirus re-signs TLS
  traffic. We worked around it with a small wrapper that uses the OS trust store. Native
  OS-trust-store support would help.
- Building `modal.Dict`s at import time made one core function hard to unit-test. Easier local or
  mock patterns for Dict-backed functions would help.

**How likely to build with Meta Model API again:** Very likely

**Overall opinion of Meta Model API:** Very favorable

**How likely to recommend Meta API:** 5/5

**How likely to recommend Muse Code:** 5/5

**Biggest obstacle (choose "Other"):**
Other: building trustworthy kernel-level telemetry from an isolated sandbox, and making sure "no
evidence" can never be mistaken for "clean." Every timeout, crash, truncated trace or blind sensor
had to fail closed.

**How did Meta models perform compared to other models:**
(No formal head-to-head was run, so this avoids claiming one.)
Muse Spark exceeded what our design required. Its structured output was reliable enough for code
to verify every citation (452 of 452 held up), it decoded 5 of 5 obfuscated payloads, and on
attacks written without knowledge of our rules it caught all four that our deterministic rules
missed, at under two cents per pull request.

**What matters most in an AI model or coding tool:**
Quality, specifically reliable, verifiable structured output we can check with code rather than
take on trust.

**Difficulty switching to other AI models:**
Low. All model calls go through one client with a fixed schema, and a deterministic floor sits
underneath. Switching would mean re-validating behavior we've already measured for Muse, though.

**What would stop you from using Meta's models:**
Nothing today. The two improvements that would help us most:
- **Lower latency.** Model analysis is most of our wall-clock time, with a median of about 36
  seconds against about 6 seconds for detonation.
- **More run-to-run consistency at temperature 0.** One borderline case flipped verdicts across
  identical inputs.
