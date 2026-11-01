# Evaluation results

Scored 2026-11-01 15:26 UTC at commit `f1fc090` with muse-spark-1.3; detonations from `eval-results-2`.

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked | ⏱️ Could not verify |
|---|---|---|---|---|---|
| benign (26) | rules | 21/26 | 5/26 | 0/26 | 0/26 |
| benign (26) | contract | 23/26 | 3/26 | 0/26 | 0/26 |
| benign (26) | full | 23/26 | 3/26 | 0/26 | 0/26 |
| malicious (14) | rules | 0/14 | 1/14 | 13/14 | 0/14 |
| malicious (14) | contract | 0/14 | 1/14 | 13/14 | 0/14 |
| malicious (14) | full | 0/14 | 0/14 | 14/14 | 0/14 |

## Per case

| Case | Kind | Rules | +Contract | Full | Fired | Notes |
|---|---|---|---|---|---|---|
| lodash | benign | ✅ | ✅ | ✅ | - |  |
| express | benign | ✅ | ✅ | ✅ | - |  |
| react | benign | ✅ | ✅ | ✅ | - |  |
| typescript | benign | ✅ | ✅ | ✅ | - |  |
| puppeteer | benign | ⚠️ | ⚠️ | ⚠️ | NET_UNLISTED_DOMAIN |  |
| playwright-chromium | benign | ⚠️ | ⚠️ | ⚠️ | NET_UNLISTED_DOMAIN | cleared cdn.playwright.dev, playwright.download.prss.microsoft.com |
| electron | benign | ✅ | ✅ | ✅ | - |  |
| prisma | benign | ⚠️ | ✅ | ✅ | NET_UNLISTED_DOMAIN | cleared binaries.prisma.sh |
| esbuild | benign | ✅ | ✅ | ✅ | - |  |
| swc | benign | ✅ | ✅ | ✅ | - |  |
| sharp | benign | ✅ | ✅ | ✅ | - |  |
| bcrypt | benign | ✅ | ✅ | ✅ | - |  |
| sqlite3 | benign | ✅ | ✅ | ✅ | - |  |
| canvas | benign | ✅ | ✅ | ✅ | - |  |
| cypress | benign | ⚠️ | ✅ | ✅ | NET_UNLISTED_DOMAIN | cleared download.cypress.io |
| chromedriver | benign | ⚠️ | ⚠️ | ⚠️ | NET_UNLISTED_DOMAIN |  |
| ffmpeg-static | benign | ✅ | ✅ | ✅ | - |  |
| sentry-cli | benign | ✅ | ✅ | ✅ | - |  |
| core-js | benign | ✅ | ✅ | ✅ | - |  |
| protobufjs | benign | ✅ | ✅ | ✅ | - |  |
| es5-ext | benign | ✅ | ✅ | ✅ | - |  |
| nodemon | benign | ✅ | ✅ | ✅ | - |  |
| husky | benign | ✅ | ✅ | ✅ | - |  |
| msw | benign | ✅ | ✅ | ✅ | - |  |
| biome | benign | ✅ | ✅ | ✅ | - |  |
| lefthook | benign | ✅ | ✅ | ✅ | - |  |
| m01-curl-env | malicious | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_RAW_IP | E4: curl exfil of env to a raw IP |
| m02-wget-sh | malicious | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_RAW_IP | download-and-execute via wget | sh |
| m03-devtcp | malicious | ❌ | ❌ | ❌ | EXEC_INTERACTIVE_SHELL NET_RAW_IP | bash /dev/tcp reverse shell |
| m04-b64-sh | malicious | ❌ | ❌ | ❌ | EXEC_DECODE_PIPE EXEC_NET_TOOL NET_RAW_IP | base64-decoded command piped to sh |
| m05-node-net | malicious | ❌ | ❌ | ❌ | NET_RAW_IP | pure-JS raw socket, no external tools |
| m06-node-https-env | malicious | ❌ | ❌ | ❌ | NET_RAW_IP | env exfil over HTTPS from node |
| m07-charcode | malicious | ❌ | ❌ | ❌ | NET_RAW_IP | address built from char codes, module name split |
| m08-npmrc | malicious | ❌ | ❌ | ❌ | NET_RAW_IP | credential-file read + exfil |
| m09-perl | malicious | ❌ | ❌ | ❌ | NET_RAW_IP | non-node interpreter opens the socket |
| m10-imds | malicious | ❌ | ❌ | ❌ | NET_INTERNAL_TARGET | cloud metadata credential probe (blocked by Chamber iptables) |
| m11-dns-exfil | malicious | ❌ | ❌ | ❌ | DNS_ENCODED_LABEL | data encoded into DNS labels; no TCP connection at all |
| m12-domain-exfil | malicious | ⚠️ | ⚠️ | ❌ | NET_UNLISTED_DOMAIN | exfil to a resolvable domain (dummy body) instead of a raw IP |
| m13-injection | malicious | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_RAW_IP | injection flagged; exfil + prompt injection in body and package.json |
| m14-delayed | malicious | ❌ | ❌ | ❌ | NET_RAW_IP | payload fires 4 s after the script starts |
