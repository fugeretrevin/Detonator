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

## Findings (across all 100, including ones that did not finish)

| Package | Verdict | Rules | Off-registry hosts | Install |
|---|---|---|---|---|
| `@onescience/onecode@1.19.3-202611021039` | Blocked | NET_RAW_IP | 218.90.133.98 | timeout |

These are **observations, not accusations.** A package fetching its own vendor CDN at install is ordinary, and one automated run is not evidence of intent. Anything here would need human review before any claim is made about it.

## Behavior atlas (real packages, real install behavior)

| Package | Hosts contacted at install |
|---|---|
| `@astryxdesign/core` | registry.npmjs.org |
| `@embedded-postgres/linux-x64` | registry.npmjs.org |
| `@onescience/onecode` | 218.90.133.98, registry.npmjs.org |
| `esbuild` | registry.npmjs.org |
| `sharp` | registry.npmjs.org |
| `sprag-cli` | registry.npmjs.org |
