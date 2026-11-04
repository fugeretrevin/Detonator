# PR Detonator — the case, and every number behind it

**One line:** static scanners *read* code; PR Detonator *runs* it in a kernel-traced sandbox and
holds what it actually did against what the pull request claimed — then blocks the merge with an
attributed, evidence-grounded verdict on the exact diff line.

**How to read this document.** It is the best framing for the project and the strongest measured
results gathered across every test and write-up, pulled into one place. Every number traces to a
committed artifact named in-line; the honest scope and limit of each is in
[`eval/CLAIM_LEDGER.md`](../eval/CLAIM_LEDGER.md), and every weak point with its gate is in
[`docs/WEAKPOINTS.md`](WEAKPOINTS.md). The stamped evaluation is commit `a96c8a1`, 142 real
detonations scored 2026-11-02; where a result came later (held-out set, cold-agent validation,
live egress test) the date and commit are given. Nothing here is a projection — if a number is not
measured, it is not claimed.

---

## 1. The problem, and why it is getting worse

Supply-chain attacks moved to **install time**. A package's `postinstall` script runs on every
laptop and CI runner that installs it — *before* anyone imports a line of its code. That is how
event-stream (2018), ua-parser-js (2021) and the Shai-Hulud worm (2025) spread. The pull request
that lets one in is usually a **one-line version bump**, so there is nothing in the diff to review.

The surface is enormous. npm hosts on the order of **6 million packages** serving **billions of
downloads a week**, and roughly **half of that traffic flows through packages maintained by a
single person** — the exact account-takeover vector Shai-Hulud used. A typical project pulls in
hundreds of transitive dependencies, any one of which can execute code at install time.
(Ecosystem figures: ecosyste.ms, Oct 2026; npm supply-chain audit, Q2 2026.)

And increasingly nobody reviews it anyway: **AI coding agents now open the PRs and pick the
dependencies** — sometimes packages that do not exist yet, which attackers then register
(slopsquatting). Machine-written dependency changes exploded exactly as human review became the
bottleneck.

The tools teams already run are blind in the one window that matters. `npm audit` and every
advisory-based scanner can only know about an attack **after** someone publishes an advisory.
Static and LLM source review read code the attacker obfuscates — and an LLM reviewer can be
*talked out* of a finding by text the attacker also controls (prompt injection in the PR body).

| Incident | Malicious version installable for | PR Detonator catches it in |
|---|---|---|
| ua-parser-js (2021) | ≈4 h before clean versions; ≈8 h to advisory | **12.4 s**, rules alone |
| Shai-Hulud (2025) | ≈1 day before public reports | **9.8 s**, rules alone |
| event-stream (2018) | over two months | **Not covered** — it ran on `require`, not install. We say so. |

Source: [`eval/DWELL_TIME.md`](../eval/DWELL_TIME.md). We review pull requests, so the honest claim
is that we would have blocked the PR adopting a poisoned version the moment it opened — not that we
protect everyone during the dwell window. Closing that window is what a registry-scale watch is for.

---

## 2. The core idea

> **The model predicts. The kernel verifies. Rules set the floor.**

1. **Ground truth from the kernel, not from source.** The sandbox runs the real `npm install`
   under Tetragon/eBPF. `tcp_connect` fires on the SYN, so even a connection to an unreachable host
   is recorded. The sandbox's only DNS resolver logs every lookup — so a connection is *named* by
   the answer the sandbox actually gave it, and **"connected with no DNS lookup at all" becomes the
   strongest signal we have.** A source scanner cannot see that; a running kernel cannot miss it.

2. **The Intent Contract — a prediction reality can refute.** Before any telemetry exists, Meta's
   Muse predicts the expected hosts and executables from the PR's **title, description and file
   names only — never the diff**, so payload code cannot steer the prediction. Then *code*, not the
   model, compares that prediction to the kernel record. This is a model making a falsifiable
   commitment, not a model being asked "does this look bad."

3. **Un-talk-out-able.** The post-run analysis is **escalate-only**: `combine() = max(rule, model,
   extra)`, so model output can raise severity and **never lower a HIGH or CRITICAL rule hit**.
   Exactly one narrower path exists and is stated rather than rounded off: the pre-observation
   prediction may clear a single **LOW** `NET_UNLISTED_DOMAIN` hit, and only for a host on an
   allowlist **in the repository or its base branch** — a list the PR author cannot write to. So
   naming a domain you own in your own PR body clears nothing. Prompt injection becomes *evidence*,
   not influence.

4. **Fail closed, everywhere.** Timeouts, crashes, truncated telemetry, a missing sensor witness,
   an HMAC mismatch, or a failed model call all resolve to **Could not verify** (a check *failure*),
   never "Clean." Absence of evidence is never an acquittal.

5. **The guilty line.** When a PR is blocked, code walks the flagged process back to the npm
   lifecycle script that launched it and comments on that exact diff line. If a *dependency's*
   script did it, the Chamber copies the file out of the sandbox and points at the line inside it,
   with a sha256 — so the author of an innocent-looking version bump sees the real payload.

---

## 3. Architecture

Two trust zones, connected by a signed contract.

- **Brain (Modal, serverless).** Receives the GitHub webhook, runs the Intent Contract and the
  post-run analysis, applies the deterministic rules, composes the verdict, posts the check run and
  the inline comment, and serves a live dashboard. Holds the secrets; never runs untrusted code.
- **Chamber (EC2 + Docker + Tetragon/eBPF + dnsmasq + iptables).** Clones the exact head commit
  into a disposable hardened container, runs `npm install`, and records every process exec, every
  TCP connect (on the SYN), every DNS lookup, and the working directory of each install script.
  Strips `.git` after clone and before install, so the cloned repo's own git machinery never runs.
- **The interface is `shared/contract.py` + `shared/signing.py`.** Requests *and* responses are
  HMAC-signed and the response is bound to its job id, so a result cannot be altered in transit or
  replayed from an older clean run. The Brain pins the Chamber's TLS certificate (the IP is baked in
  as a SAN).

What is deliberately **not** in the blast radius: no GitHub token, no API key, no host environment,
no cloud IAM role reaches the sandbox. Public repos are cloned anonymously; a private repo is cloned
on the *host* with a read-only token scoped to that one repository, over the pinned TLS path — the
token never enters the container.

Integrity you can audit after the fact: **every detonation carries a per-job sensor witness** — the
sandbox execs a nonce-marked marker before and after the install, and a missing marker fails the
check closed, because "no events" and "nothing happened" are not the same thing. In the stamped
eval, 139 of 142 runs recorded both markers; the 3 that recorded only the first are exactly the 3
that hit the timeout and were killed.

---

## 4. Why this beats static and LLM-only review

- **Behavior cannot be obfuscated.** Minified, base64'd, string-reversed — it does not matter,
  because we watch the syscalls, not the source. The model **decoded the payload correctly in 5 of 5
  obfuscated attacks** ([`eval/README.md`](../eval/README.md)).
- **A signal only a running kernel has.** The most interesting result in the project (Section 5)
  was caught because a connection **skipped DNS entirely** and went to a bare IP — the one thing a
  sandbox that logs every lookup notices and a source scanner structurally cannot.
- **The attacker does not get a vote.** Because the floor is deterministic and the model is
  escalate-only, prompt injection in the PR cannot clear a finding. An LLM-only reviewer has no such
  floor.
- **Against the default tooling baseline**, `npm audit` on our own attack payloads
  ([`eval/BASELINE.md`](../eval/BASELINE.md)):

| Pull request | `npm audit` | PR Detonator |
|---|---|---|
| Shai-Hulud reconstruction (steals `~/.npmrc`, runs TruffleHog, POSTs secrets) | found 0 vulnerabilities | 🛑 Blocked, payload line decoded |
| "Fix typo" with an `$(env)`-exfiltrating postinstall | found 0 vulnerabilities | 🛑 Blocked + canary token caught |
| base64 → `sh` | found 0 vulnerabilities | 🛑 Blocked, command decoded |
| Stolen `$GITHUB_TOKEN` in a request header | found 0 vulnerabilities | 🛑 Blocked (critical) |
| ua-parser-js 0.7.29 (the real 2021 hijack) | 1 high (GHSA-pjwm-rvh2-c87w) | 🛑 Blocked |

`npm audit` is not broken — it is **retrospective**, an advisory lookup. "0 vulnerabilities" on a
bespoke payload is the expected result, not a defeated competitor. We say so plainly, and we make
no head-to-head claim against the behavioral prior art (OpenSSF Package Analysis, Socket): no
matched-population comparison has been run. What is genuinely different here is the *combination* —
a prediction committed **before** the install runs, kernel telemetry as the ground truth it is
checked against, attribution to the exact diff line, every model claim verified by code, and a
merge gate that fails closed.

---

## 5. The attack patterns we cover

**19 deterministic rules**, counted from source and guarded against drift
(`tests/test_docs_match_eval.py`), across five families. Each turns a kernel fact into a severity
floor the model cannot lower. Representative rules and the technique each defeats:

**Network egress**
- `NET_RAW_IP` (HIGH) — a connection to a bare IP with no DNS lookup. *The rule that caught a real
  live-registry exposure (Section 6).*
- `NET_EXFIL_SERVICE` (HIGH) — contact with a known paste/webhook/exfil service (the Shai-Hulud
  `webhook.site` leg).
- `NET_UNLISTED_DOMAIN` (LOW) — a download from a host outside the registry/vendor allowlist.
- `NET_NON_TCP_EGRESS` — UDP/ICMP egress (before we closed this, a test UDP datagram really did get
  out; now it is logged and rejected).
- `NET_INTERNAL_TARGET` — a pivot toward internal/metadata ranges.

**DNS**
- `DNS_ENCODED_LABEL` (HIGH) — a hostname hex/encoded into a subdomain label for DNS exfiltration
  (caught a held-out 24-char all-hex label after the W15 floor fix).

**Credentials**
- `CRED_FILE_ACCESS` — an install script reading `~/.npmrc`, `~/.aws`, or a canary token (the
  values are freshly planted decoys; a real theft fires, an npm process reading its own config does
  not).

**Persistence** (all three dormant at install time, which is exactly why a behavioral-only rule
would miss them — so they inspect the recorded args directly)
- `FILE_PERSISTENCE` (HIGH) — a write to a shell-rc / cron / systemd path (caught a held-out
  `~/.bashrc` PATH-hijack it was not written against).
- `EXEC_SCHEDULED_PERSISTENCE` (HIGH) — cron/systemd scheduling. *0 occurrences in 742 installs.*
- `EXEC_GIT_CONFIG_PERSIST` (HIGH) — poisoning `git config` (`http.proxy`, `core.hookspath`, a
  `!`-shell alias, `url.*.insteadOf`). *0 across 742 installs.*

**Execution**
- `EXEC_INTERACTIVE_SHELL` (CRITICAL) — `/dev/tcp` reverse shell or an interactive shell `-i`.
- `EXEC_DROPPED_BINARY` (HIGH) — running a binary dropped into a temp/home directory.
- `EXEC_DECODE_PIPE` (HIGH) — a decoded payload piped into a shell (`base64 … | sh`).
- `EXEC_NET_TOOL` (HIGH) — `curl`/`wget`/`nc` executed during install.

**Resource & integrity**
- `RES_CPU_HEAVY` — cryptominer-class CPU burn (with a build-tool exemption so compilers are not
  flagged).
- `TELEMETRY_TRUNCATED` — the event cap was hit, so the run is unverifiable and fails closed.

Every rule shipped on a measurement, not a guess: the two persistence rules above were each
validated at **0 false positives** across the recorded install corpus before promotion to HIGH.

---

## 6. The best measured results, in one table

| What | Result | Source / scope | The honest limit |
|---|---|---|---|
| Benign false blocks | **0 of 104** popular packages hard-blocked, every arm — incl. puppeteer, playwright, electron, prisma, esbuild, sharp, sqlite3 | stamped eval `a96c8a1` | 95% upper bound on the false-block rate ≈ **3.5%**; 6 of 104 were *unverifiable*, not called clean |
| Designed attacks | **16 of 16** blocked (full pipeline, 3 of 5 trials; 15 worst) | stamped eval | consistent with a true rate as low as **79%**; author-written |
| Real-incident reconstructions | **2 of 2** blocked (ua-parser-js, Shai-Hulud), blamed on the bumped line | stamped eval | two illustrative patterns; 95% lower bound 15.8% |
| Red-team (author-written) | rules **6/10** → full pipeline **9/10** | stamped eval | `rt08` (bare CPU loop) is an open, documented miss |
| Red-team (model-written, never saw our rules) | rules 5/10 → full pipeline **10/10** blocked | stamped eval | single draw |
| **Held-out blind corpus** | rules floor **9/10** (6/10 as first run, +3 after measured fixes); **full pipeline flags 10/10** (9 blocked, 1 needs-review) | [`BLIND_RESULTS.md`](../eval/BLIND_RESULTS.md), `f013bd0`, Nov 3 | 10 cases is a gap-finder, not a recall rate |
| **Cold-agent validation** | **7 of 7** attacks blocked, **0 dangerous misses**, **12/14** exact agreement with labels frozen before any run | [`VALIDATION_RESULT.md`](../eval/VALIDATION_RESULT.md), `5fee239`, Nov 4 | blinding was instructed, not enforced; 14 cases |
| Live registry sweep (100) | **73 installed, 73 clean**; 1 of the other 27 blocked — a **real install-time RCE exposure** (CWE-295 + CWE-494), privately disclosed Nov 2 | [`SWEEP.md`](../eval/SWEEP.md) | two denominators; not malware |
| Live registry sweep (500) | 413 of 421 installed clean, 7 needs-review, **1 block** | [`SWEEP500.md`](../eval/SWEEP500.md) | unlabelled corpus — an alert rate, not accuracy |
| Evidence grounding | **452 of 452** cited claims resolve to a real kernel event of the right type; 0 invented hosts/IPs | [`results.md`](../eval/results.md) | measures citation discipline, not semantic truth |
| Repeatability | 5 runs/case: flip rate **1/24** (attack+boundary), **1/20** (red-team); **no benign blocked in any trial** | [`REPEAT.md`](../eval/REPEAT.md) | exactly one case (`m12`) is unstable, and we quote the worst number |
| Cost | **$0.0181 per PR** mean ($2.57 to score all 142) | stamped eval | model API spend only; excludes host compute |
| Latency | detonation p50 **5.9 s**, model p50 **36.5 s** | [`results.md`](../eval/results.md) | model dominates wall-clock; Intent Contract overlaps the sandbox |
| Live egress allowlist | exfil to a non-allowlisted IP **refused & logged**; benign installs **0 regression** | [`WEAKPOINTS.md`](WEAKPOINTS.md) W8, Nov 4 replica | validated on a replica; stays off the judged Chamber |
| Engineering | **19 deterministic rules, 1,070 automated tests**; reproducible from a fresh clone (750 pass with the Modal SDK unimportable) | repo HEAD | every fixture is recorded real output |

**The single most interesting result** (SWEEP, Section) was unplanned: the `NET_RAW_IP` rule fired
on a package published minutes earlier, the model-led follow-up correctly concluded *"not an
attack,"* and reading the source revealed a genuine exposure underneath — a fallback that downloads
the product binary from a hardcoded bare IP with **TLS verification disabled** (`rejectUnauthorized:
false`), then extracts and runs it. A behavioral rule found a real-world weakness with zero prior
knowledge, and the signal that caught it — a connection that skipped DNS — is one only this
architecture can see.

That is one unplanned hit from a 100-package glance at a registry of ~6 million. It is not a
widespread 0-day — the package is niche and the exposure needs an on-path attacker or control of
that address — but it is the point in miniature: across a surface that large, with billions of
weekly installs running code before anyone reads it, behavioral detonation surfaces real
install-time exposure that advisory lookups and source review structurally miss.

---

## 7. How we use Meta's models — four distinct ways

The model is not a classifier bolted on top; it fills four specific roles, and the ablation
separates what each one adds.

| Use | Model | What it does | Measured contribution |
|---|---|---|---|
| **Intent Contract** | `muse-spark-1.3` | predicts expected install behavior from PR text alone, *before* the sandbox runs | cut benign needs-review **4 → 3** with **zero** attacks cleared; runs in parallel with detonation (no added latency) |
| **Behavior analysis** | `muse-spark-1.3` | compares stated intent to the kernel record, explains it, decodes obfuscation onto the guilty line | caught the one attack rules alone miss (`m12`, exfil to a resolvable domain); **5/5** payloads decoded, **2/2** dependency attacks attributed |
| **Investigator agent** | `muse-spark-1.3` + tool calling | for ⚠️ cases only, three **read-only** tools (npm registry facts, our host classification, the captured script) | produces a human triage note; can escalate to blocked, **never clear** |
| **Jailbreak screen** | **Llama Prompt Guard 2 (86M)**, on CPU | screens PR text for injection | validated first: catches explicit jailbreaks (0.97–1.00), *missed* indirect document-embedded ones (0.00–0.32) — so it is scoped to "don't trust flagged text," never decides a verdict |

**A four-arm ablation** (same 122 cases, same commit) shows the two model uses repair *different*
failures and neither substitutes for the other:

| Arm | Benign ⚠️ (of 104) | Attacks blocked (of 16) |
|---|---|---|
| rules only | 4 | 15 |
| rules + Intent Contract | **3** | 15 |
| rules + analysis (no Contract) | 4 | **16** |
| full | **3** | **16** |

The honest size of each effect on our own eval is **one case** — which reads thin, until you look
where the rules were *not* built against the attacks.

**Where the model earns its place: the held-out set.** On 10 attacks written by a model cold to our
detectors, the deterministic rules missed **4 of 10** (git-config persistence, a short DNS-exfil
label — techniques the rules were never shaped for). **The model caught all four**, reading the
install-script source and reasoning about behavior no rule had a pattern for. On an
author-independent set the model moved **four** verdicts, not one — its contribution is largest
exactly where the hand-written rules are weakest. That is the unexpected, and the useful, part. (We
then closed two of those four gaps with new measured rules, so the floor is stronger too.)

---

## 8. Why this architecture fits the problem space

- **The threat is behavioral, so the detector is behavioral.** Install-time attacks *act* —
  connect, read, write, spawn. Watching the kernel meets the attack on its own terms, where
  obfuscation of the source buys the attacker nothing.
- **A merge gate must not be fooled by its own input.** The deterministic floor plus escalate-only
  model keeps the attacker, who controls the PR text, from clearing a finding — the failure mode
  that makes a naive LLM reviewer unsafe as a gate.
- **A verdict a human will act on must be attributable.** Kernel event → npm lifecycle script →
  exact diff line, with every model claim checked against the event record by code, is what turns
  "this looks suspicious" into "this line did this, here is the proof."
- **It fails in the safe direction.** Every uncertainty — timeout, crash, truncation, missing
  witness, integrity failure, model error — resolves to *Could not verify*, never a green check.
  For a security gate, that is the only acceptable bias.
- **It is honest about its edges.** The limits are enumerated, interval-bounded, and tested, not
  hidden — which is what lets a reviewer trust the numbers that *are* claimed.

---

## 9. Honest limitations (the short version)

Install-time only (import-time/runtime payloads like event-stream are out of scope). A payload that
waits out the detonation window or fingerprints the sandbox can still evade. Our designed attacks
are mostly our own, so "16/16" means "covers these techniques," not a real-world rate; the
denominators are small and the 95% intervals are published. One sandbox VM, one job at a time
(queued PRs fail closed). The model is temperature-0 but not bit-reproducible, so the full-pipeline
column can move ~one case. It is a hardened Docker container on a shared host, **not** a microVM.
Full accounting with scope, interval and gate: [`eval/CLAIM_LEDGER.md`](../eval/CLAIM_LEDGER.md) and
[`docs/WEAKPOINTS.md`](WEAKPOINTS.md).

---

## 10. Theme fit

**Build for Your World** (primary) — every developer and CI runner `npm install`s code from
strangers, and the review that would catch a malicious install script is exactly the work nobody has
time for. PR Detonator takes it off the human's plate and hands back an attributed decision on the
pull request.

**Push the Frontier** (one specific way) — the Intent Contract gives the model a capability it is
not usually given: it must state, from the PR text alone and *before* any code runs, what the
install should do, and then plain code checks that falsifiable prediction against the kernel's
record. Using Meta's model as a **predictor the kernel verifies**, rather than a classifier you hope
is right, is the frontier bit.
