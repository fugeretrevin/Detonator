# Baseline: what `npm audit` says about the same pull requests

`npm audit` is the tool every JavaScript team already runs. It answers a different question
from ours — *"does any installed package match a known published advisory?"* — and it answers
it well. We ran it against our own attack payloads to show exactly where that question stops
being enough.

Method: for each payload, in the sandbox image, `npm install --package-lock-only
--ignore-scripts` then `npm audit`. Run 2026-11-02 against the eval payload branch. Raw
output recorded in [baseline_npm_audit.json](baseline_npm_audit.json).

| Pull request | `npm audit` | PR Detonator |
|---|---|---|
| **Shai-Hulud reconstruction** — a version bump whose new release reads `~/.npmrc`, downloads the real TruffleHog, scans for secrets, POSTs them to webhook.site | **found 0 vulnerabilities** | 🛑 **Blocked** — `CRED_FILE_ACCESS`, `EXEC_DROPPED_BINARY`, `NET_EXFIL_SERVICE`, and the payload line inside the dependency decoded |
| **"Fix typo in README"** that adds a `postinstall` POSTing `$(env)` to a raw IP | **found 0 vulnerabilities** | 🛑 **Blocked** — `EXEC_NET_TOOL`, `NET_RAW_IP`, `DECOY_CREDENTIAL_SEEN`, inline comment on the guilty line |
| **base64 → `sh`** in a `postinstall` | **found 0 vulnerabilities** | 🛑 **Blocked** — `EXEC_DECODE_PIPE`, and Muse decodes the payload to the real command |
| **Stolen `$GITHUB_TOKEN`** sent in a curl header | **found 0 vulnerabilities** | 🛑 **Blocked (critical)** — the planted canary token appeared in the request |
| **ua-parser-js 0.7.29** (the real October 2021 hijack) | **1 high severity** — GHSA-pjwm-rvh2-c87w, "Embedded malware in ua-parser-js", CVSS 8.8, `range: =0.7.29` | 🛑 **Blocked** — `EXEC_NET_TOOL`, `NET_RAW_IP`, `NET_EXFIL_SERVICE`, blamed on the bumped line |

## What this actually shows

**`npm audit` is not broken — it is retrospective.** It caught ua-parser-js precisely because
the world has known about that attack since October 2021 and someone wrote an advisory for it.
That is the system working.

The problem is the window before the advisory exists. In the real incidents the malicious
version was installable long before anyone published a GHSA — the event-stream payload sat
undetected for over two months, and ua-parser-js was being downloaded by users who then
reported it to the maintainer. During that window `npm audit` says "found 0 vulnerabilities",
and so does every other tool that works by matching known-bad names and versions.

Our four novel payloads are exactly that window. Three of them aren't even dependency
problems: the malicious code is in the *project's own* `package.json`, which an advisory
database has no opinion about at all.

**PR Detonator doesn't need the attack to have a name.** It blocked all five, including
ua-parser-js, from behavior alone — a process reading a credential file, a binary executed out
of `/tmp`, a connection to a request-catcher service. Those facts are true the first time the
attack runs, which is the only time that matters.

## Caveats, stated plainly

- This is not a head-to-head benchmark of security products. `npm audit` is a dependency
  advisory checker; comparing it to runtime detonation on *novel* payloads is comparing two
  different jobs. The point is that teams rely on the first and it cannot cover this case.
- We did not test commercial supply-chain scanners (Socket, Snyk and similar), some of which
  do behavioral or heuristic analysis of package code and would likely flag some of these.
  A fair comparison against those is future work, not a claim we make here.
- `npm audit` run on our ua-parser-js reconstruction benefits from us reusing the real package
  name and version. An attacker publishing the same code under a new name gets the
  "0 vulnerabilities" result, which is what the Shai-Hulud row demonstrates.
