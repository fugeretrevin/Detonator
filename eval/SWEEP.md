# Registry sweep: packages published to npm minutes before we ran them

100 packages taken straight from npm's change feed and detonated, newest first. Nobody curated this list — it is whatever the registry published. Scored with the deterministic rules only (no model calls), so a sweep this size costs VM time alone.

**27 of the 100 never installed** on this platform and are excluded from the rates below: the feed is largely per-platform binary subpackages (`…-darwin-arm64`, `…-windows-amd64`) that npm refuses on linux-x64, plus one whose version had already been unpublished. Everything else is scored over the **73 packages that actually installed**.

| Result | Count |
|---|---|
| Clean | 73/73 |
| Needs review | 0/73 |
| Blocked | 0/73 |
| Could not verify | 0/73 |

- **7/73 ran install scripts.**
- **0/73 contacted a host outside the npm registry and GitHub.**

**Reading `SWEEP.json` directly will not reproduce this table, and that is expected.** Its
per-row `verdict` field tallies 97 Clean / 2 Could not verify / 1 Blocked, because this run
pre-dates the fail-closed scoring that `eval/results.json` and `SWEEP500.json` use: the 24
packages that exited non-zero carry `"Clean"` there rather than `"Could not verify"`. The rates
above deliberately exclude all 27 non-installing packages, so no published figure depends on
those 24 rows. Re-score with `eval/score_rules.py` for current semantics; the 500-package sweep
already shows them correctly (79 Could not verify, exactly its 79 non-installing packages).

## Findings (across all 100, including ones that did not finish)

| Package | Verdict | Rules | Off-registry hosts | Install |
|---|---|---|---|---|
| `<name withheld pending a fix>` | Blocked | NET_RAW_IP | <redacted IP> | timeout |

These are **observations, not accusations.** A package fetching its own vendor CDN at install is ordinary, and one automated run is not evidence of intent. Anything here would need human review before any claim is made about it.

**Follow-up on the one flagged package.** We read its published source (no execution). The
`postinstall` reaches a fallback that downloads the product binary from a hardcoded bare IP
with TLS certificate verification disabled (`rejectUnauthorized: false`), then extracts it and
links it as the executable — an install-time code-execution exposure if that connection is
intercepted or the address changes hands (CWE-295, CWE-494). It is **not malicious**: the
maintainer owns the package and this is a deliberate fallback with an unsafe default.

**Disclosure status: a private report was sent to the package's sole npm maintainer on
Nov 2, 2026**, after confirming the issue is still present in that day's latest version. No
response or fix yet, so disclosure is not complete. Two honest caveats about the redaction in
this file, too: the name and address are removed from the current text, but they were committed
earlier in this repository's history and this repository is public, so the identifier is
recoverable by anyone reading the git log. Treat the redaction as a courtesy in the prose, not
as effective concealment. We did not attempt interception and make no claim about
exploitability in practice.

## Behavior atlas (real packages, real install behavior)

| Package | Hosts contacted at install |
|---|---|
| `@astryxdesign/core` | registry.npmjs.org |
| `@embedded-postgres/linux-x64` | registry.npmjs.org |
| `<name withheld pending a fix>` | <redacted IP>, registry.npmjs.org |
| `esbuild` | registry.npmjs.org |
| `sharp` | registry.npmjs.org |
| `sprag-cli` | registry.npmjs.org |
