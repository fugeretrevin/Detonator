# Registry sweep: packages published to npm minutes before we ran them

500 packages taken straight from npm's change feed and detonated, newest first. Nobody curated this list — it is whatever the registry published. Scored with the deterministic rules only (no model calls), so a sweep this size costs VM time alone.

**79 of the 500 never installed** on this platform and are excluded from the rates below: the feed is largely per-platform binary subpackages (`…-darwin-arm64`, `…-windows-amd64`) that npm refuses on linux-x64, plus one whose version had already been unpublished. Everything else is scored over the **421 packages that actually installed**.

Those excluded runs are recorded as **Could not verify**, never Clean: an install that exited nonzero, timed out, lost telemetry to the event cap, or produced no process events at all is an absence of evidence, not a clean bill of health. That is a usability limit of this sandbox, not a judgement about the package.

| Result | Count |
|---|---|
| Clean | 413/421 |
| Needs review | 7/421 |
| Blocked | 1/421 |
| Could not verify | 0/421 |

- **99/421 ran install scripts.**
- **5/421 contacted a host outside the npm registry and GitHub.**

## Findings (across all 500, including ones that did not finish)

| Package | Verdict | Rules | Off-registry hosts | Install |
|---|---|---|---|---|
| `baiduwangpan-cli@1.7.0` | Needs review | NET_UNLISTED_DOMAIN | ghfast.top | exit 0 |
| `@bike4mind/cli@4.0.0` | Needs review | NET_UNLISTED_DOMAIN | cdn.sheetjs.com | exit 0 |
| `@lsamien/yaovi@0.1.23` | Blocked | EXEC_DROPPED_BINARY EXEC_NET_TOOL NET_UNLISTED_DOMAIN | astral.sh, pypi.org | exit 0 |
| `@tarojs/cli-convertor@4.3.1` | Needs review | NET_INTERNAL_TARGET | - | exit 0 |
| `crawlmark-mcp@0.3.0` | Needs review | NET_UNLISTED_DOMAIN | storage.googleapis.com | exit 0 |
| `@tarojs/cli@4.3.1` | Needs review | NET_INTERNAL_TARGET | - | exit 0 |
| `@tarojs/create-app@4.3.1` | Needs review | NET_INTERNAL_TARGET | - | exit 0 |
| `@blacklake-tech-cn/castor-cli@0.1.0-beta.1` | Needs review | NET_UNLISTED_DOMAIN | bl-v3-cli.oss-cn-shanghai.aliyuncs.com | exit 0 |

These are **observations, not accusations.** A package fetching its own vendor CDN at install is ordinary, and one automated run is not evidence of intent. Anything here would need human review before any claim is made about it.

## Behavior atlas (real packages, real install behavior)

| Package | Hosts contacted at install |
|---|---|
| `@alicloud/openapi-core` | registry.npmjs.org |
| `@astryxdesign/core` | registry.npmjs.org |
| `@binoctal/open-agents-bridge` | api.github.com, github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `@blacklake-tech-cn/castor-cli` | bl-v3-cli.oss-cn-shanghai.aliyuncs.com, registry.npmjs.org |
| `@firedmosquito831/my-claude-code` | registry.npmjs.org |
| `@homebridge/node-pty-prebuilt-multiarch` | github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `@lsamien/yaovi` | astral.sh, nodejs.org, pypi.org, registry.npmjs.org |
| `@opencode/cli` | registry.npmjs.org |
| `@parcel/watcher` | registry.npmjs.org |
| `@scarf/scarf` | registry.npmjs.org |
| `@sentry/cli` | registry.npmjs.org |
| `@swc/core` | github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `@tarojs/binding` | registry.npmjs.org |
| `@threenative/core` | github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `@threenative/runtime-native` | github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `@znmin/claude-remote-cli` | registry.npmjs.org |
| `baiduwangpan-cli` | ghfast.top, registry.npmjs.org |
| `electron` | github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `esbuild` | codeload.github.com, github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `ffmpeg-static` | github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `koffi` | registry.npmjs.org |
| `puppeteer` | registry.npmjs.org, storage.googleapis.com |
| `rlm-harness` | registry.npmjs.org |
| `sharp` | github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `squirrelscan` | github.com, registry.npmjs.org, release-assets.githubusercontent.com |
| `ssh2` | astral.sh, nodejs.org, pypi.org, registry.npmjs.org |
