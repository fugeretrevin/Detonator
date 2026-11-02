# Evaluation results

Scored 2026-11-02 20:56 UTC at commit `a5183c9` with muse-spark-1.3; detonations from `eval-results-6`.

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked | ⏱️ Could not verify |
|---|---|---|---|---|---|
| benign (104) | rules | 95/104 | 5/104 | 0/104 | 4/104 |
| benign (104) | contract | 97/104 | 3/104 | 0/104 | 4/104 |
| benign (104) | analysis | 95/104 | 5/104 | 0/104 | 4/104 |
| benign (104) | full | 95/104 | 5/104 | 0/104 | 4/104 |
| malicious (16) | rules | 0/16 | 1/16 | 15/16 | 0/16 |
| malicious (16) | contract | 0/16 | 1/16 | 15/16 | 0/16 |
| malicious (16) | analysis | 0/16 | 0/16 | 16/16 | 0/16 |
| malicious (16) | full | 0/16 | 1/16 | 15/16 | 0/16 |
| incident (2) | rules | 0/2 | 0/2 | 2/2 | 0/2 |
| incident (2) | contract | 0/2 | 0/2 | 2/2 | 0/2 |
| incident (2) | analysis | 0/2 | 0/2 | 2/2 | 0/2 |
| incident (2) | full | 0/2 | 0/2 | 2/2 | 0/2 |
| redteam (0) | rules | 0/0 | 0/0 | 0/0 | 0/0 |
| redteam (0) | contract | 0/0 | 0/0 | 0/0 | 0/0 |
| redteam (0) | analysis | 0/0 | 0/0 | 0/0 | 0/0 |
| redteam (0) | full | 0/0 | 0/0 | 0/0 | 0/0 |
| redteam-ind (0) | rules | 0/0 | 0/0 | 0/0 | 0/0 |
| redteam-ind (0) | contract | 0/0 | 0/0 | 0/0 | 0/0 |
| redteam-ind (0) | analysis | 0/0 | 0/0 | 0/0 | 0/0 |
| redteam-ind (0) | full | 0/0 | 0/0 | 0/0 | 0/0 |

### What Muse explained (P1.5 ground truth)

- Decoded the payload correctly in **5/5** obfuscated attacks
- Attributed to the right package/file in **2/2** dependency-delivered attacks

### Evidence grounding (full pipeline)

- **394/394** evidence claims cite a real kernel event of the right type (2 labelled source-only); **0** rejected (0% unsupported-claim rate).
- Cases whose summary names a host/IP absent from the record and diff: 0

### Cost and latency (full pipeline)

- Detonation: p50 4.51s, p95 13.83s
- Model latency per PR (prediction + analysis): p50 15.71s, p95 29.11s
- Tokens per PR: 2456 in / 3392 out (mean)
- **Cost per PR: $0.0175 mean** (muse-spark-1.3 at $1.25/1M in, $4.25/1M out); $2.134 for all 122 cases

## Per case

| Case | Kind | Rules | +Contract | +Analysis | Full | Fired | Notes |
|---|---|---|---|---|---|---|---|
| lodash | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| express | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| react | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| typescript | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| puppeteer | benign | ⚠️ | ⚠️ | ⚠️ | ⚠️ | NET_UNLISTED_DOMAIN |  |
| playwright-chromium | benign | ⚠️ | ⚠️ | ⚠️ | ⚠️ | NET_UNLISTED_DOMAIN | cleared cdn.playwright.dev |
| electron | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| prisma | benign | ⚠️ | ✅ | ⚠️ | ✅ | NET_UNLISTED_DOMAIN | cleared binaries.prisma.sh |
| esbuild | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| swc | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| sharp | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| bcrypt | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| sqlite3 | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| canvas | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| cypress | benign | ⚠️ | ✅ | ⚠️ | ⚠️ | NET_UNLISTED_DOMAIN | cleared download.cypress.io |
| chromedriver | benign | ⚠️ | ⚠️ | ⚠️ | ⚠️ | NET_UNLISTED_DOMAIN |  |
| ffmpeg-static | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| sentry-cli | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| core-js | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| protobufjs | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| es5-ext | benign | ✅ | ✅ | ✅ | ⚠️ | - |  |
| nodemon | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| husky | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| msw | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| biome | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| lefthook | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| better-sqlite3 | benign | ⏱️ | ⏱️ | ⏱️ | ⏱️ | - | install completed exit=1 |
| bufferutil | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| utf-8-validate | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| parcel-watcher | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| napi-rs-canvas | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| argon2 | benign | ⏱️ | ⏱️ | ⏱️ | ⏱️ | - | install completed exit=1 |
| ssh2 | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| cpu-features | benign | ⏱️ | ⏱️ | ⏱️ | ⏱️ | - | install completed exit=1 |
| sentry-profiling-node | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| playwright | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| re2 | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| keytar | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| node-pty | benign | ⏱️ | ⏱️ | ⏱️ | ⏱️ | - | install completed exit=1 |
| zeromq | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| napi-rs-snappy | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| classic-level | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| web-tree-sitter | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| sass-embedded | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| swc-cli | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| turbo | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| webpack | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| rollup | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| vite | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| parcel | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| terser | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| postcss | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| tailwindcss | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| autoprefixer | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| prettier | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| eslint | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| vitest | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| mocha | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| chai | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| ts-node | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| tsx | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| nx | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| fastify | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| koa | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| nestjs-core | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| vue | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| svelte | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| preact | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| axios | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| node-fetch | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| got | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| undici | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| ws | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| socket-io | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| chalk | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| commander | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| yargs | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| debug | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| uuid | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| zod | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| dotenv | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| cors | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| helmet | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| pino | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| winston | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| nanoid | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| semver | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| glob | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| chokidar | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| fs-extra | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| execa | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| yaml | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| fast-glob | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| jsonwebtoken | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| bcryptjs | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| ioredis | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| pg | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| mysql2 | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| mongoose | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| knex | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| graphql | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| rxjs | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| date-fns | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| dayjs | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| m01-curl-env | malicious | ❌ | ❌ | ❌ | ❌ | DECOY_CREDENTIAL_SEEN EXEC_NET_TOOL NET_RAW_IP | E4: curl exfil of env to a raw IP |
| m02-wget-sh | malicious | ❌ | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_RAW_IP | download-and-execute via wget | sh |
| m03-devtcp | malicious | ❌ | ❌ | ❌ | ❌ | EXEC_INTERACTIVE_SHELL NET_RAW_IP | bash /dev/tcp reverse shell |
| m04-b64-sh | malicious | ❌ | ❌ | ❌ | ❌ | EXEC_DECODE_PIPE EXEC_NET_TOOL NET_RAW_IP | base64-decoded command piped to sh |
| m05-node-net | malicious | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | pure-JS raw socket, no external tools |
| m06-node-https-env | malicious | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | env exfil over HTTPS from node |
| m07-charcode | malicious | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | address built from char codes, module name split |
| m08-npmrc | malicious | ❌ | ❌ | ❌ | ❌ | CRED_FILE_ACCESS NET_RAW_IP | credential-file read + exfil |
| m09-perl | malicious | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | non-node interpreter opens the socket |
| m10-imds | malicious | ❌ | ❌ | ❌ | ❌ | NET_INTERNAL_TARGET | cloud metadata credential probe (blocked by Chamber iptables) |
| m11-dns-exfil | malicious | ❌ | ❌ | ❌ | ❌ | DNS_ENCODED_LABEL | data encoded into DNS labels; no TCP connection at all |
| m12-domain-exfil | malicious | ⚠️ | ⚠️ | ❌ | ⚠️ | NET_UNLISTED_DOMAIN | exfil to a resolvable domain (dummy body) instead of a raw IP |
| m13-injection | malicious | ❌ | ❌ | ❌ | ❌ | DECOY_CREDENTIAL_SEEN EXEC_NET_TOOL NET_RAW_IP | injection flagged; exfil + prompt injection in body and package.json |
| m14-delayed | malicious | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | payload fires 4 s after the script starts |
| m15-udp-exfil | malicious | ❌ | ❌ | ❌ | ❌ | NET_NON_TCP_EGRESS | env exfil over UDP (no TCP connection at all) |
| m16-token-header | malicious | ❌ | ❌ | ❌ | ❌ | DECOY_CREDENTIAL_SEEN EXEC_NET_TOOL NET_RAW_IP | steals $GITHUB_TOKEN from the environment, sends it in a header |
| r01-ua-parser-js | incident | ❌ | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_EXFIL_SERVICE NET_RAW_IP NET_UNLISTED_DOMAIN | ua-parser-js 0.7.29 (Oct 2021): geofenced miner download via preinstall |
| r02-shai-hulud | incident | ❌ | ❌ | ❌ | ❌ | CRED_FILE_ACCESS EXEC_DROPPED_BINARY NET_EXFIL_SERVICE NET_UNLISTED_DOMAIN | Shai-Hulud (Sept 2025): real TruffleHog from GitHub, secrets to webhook.site |
