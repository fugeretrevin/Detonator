# Dwell time: how long real attacks stayed installable

Every detection method has a window in which it is blind. For advisory databases — `npm audit`
and everything built on it — that window is the gap between a malicious version going live and
somebody publishing a GHSA. These are the real windows, from published post-incident reporting.

| Incident | Malicious version live | Publicly known | Window | Would PR Detonator have caught it? |
|---|---|---|---|---|
| **ua-parser-js** 0.7.29 / 0.8.0 / 1.0.0 | 2021-10-22, ~12:15 GMT | clean versions published ~16:16–16:26 GMT; GitHub advisory 20:38 GMT | **≈4 hours** (≈8 h to advisory) | **Yes** — our reconstruction is blocked in **12.4 s** on rules alone (`EXEC_NET_TOOL`, `NET_RAW_IP`, `NET_EXFIL_SERVICE`) |
| **Shai-Hulud** (npm worm) | first infected releases 2025-09-14, 18:35 UTC | first public reports 2025-09-15/16 (sources differ) | **≈1 day** | **Yes** — our reconstruction is blocked in **9.8 s** (`CRED_FILE_ACCESS`, `EXEC_DROPPED_BINARY`, `NET_EXFIL_SERVICE`) |
| **event-stream** / flatmap-stream | payload published 2018-10-05 | flagged on GitHub 2018-11-20 | **over two months** | **No** — out of scope, and we say so. The payload ran when one specific application *imported* the package, not at install, so install-time detonation never executes it |

## What this table does and does not claim

**It does claim:** these attacks are detectable from behavior the first time they run, in
seconds, without anyone having seen them before. The two we reconstructed are blocked by
deterministic rules — no model judgement required — because reading a credential file,
executing a binary dropped into `/tmp`, or opening a socket to a raw IP are facts, not
signatures.

**It does not claim** that we would have protected the world during those windows. We check
**pull requests**. We would have caught the PR that introduced or bumped the dependency, at the
moment it was opened — which is the realistic path by which a team adopts a poisoned version.
We would *not* have seen a developer running `npm install` outside a PR, or an existing CI job
pulling a newly poisoned version within a semver range. Closing that gap is what the
registry-scale watch in the roadmap is for: detonate each new release at publish time and
diff its [behavior record](sbom/README.md) against the previous version, so "this version
started reading `~/.npmrc`" is an alert within minutes of publication rather than a GHSA days
later.

**Timing caveat:** the detonation times are ours, measured on the reconstructions in
[eval/README.md](README.md). A full check (clone, detonate, model analysis, comment) completes
in well under a minute; the seconds quoted are the sandbox run itself.

## Sources

- ua-parser-js: [Expo post-incident write-up](https://blog.expo.dev/ua-parser-js-and-malicious-npm-packages-8c13ee4141a),
  [Progress](https://www.progress.com/amp/malware-found-in-ua-parser-js-npm-library/dWU5d09jQTFGZndVVnJod2xERzk5TENYb204PQ2),
  [GHSA-pjwm-rvh2-c87w](https://github.com/advisories/GHSA-pjwm-rvh2-c87w)
- Shai-Hulud: [Sysdig](https://sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages),
  [Truesec](https://truesec.com/hub/blog/500-npm-packages-compromised-in-ongoing-supply-chain-attack-shai-hulud),
  [MITRE ATT&CK S9008](https://attack.mitre.org/software/S9008/).
  Reported discovery dates differ by a day between sources, so the window is given as
  approximate.
- event-stream: [Hayden Parker's analysis](https://medium.com/@hkparker/analysis-of-a-supply-chain-attack-2bd8fa8286ac),
  [The Hacker News](https://thehackernews.com/2018/11/nodejs-event-stream-module.html)
