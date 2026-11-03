# Evaluation results

Scored 2026-11-02 22:39 UTC at commit `a96c8a1` with muse-spark-1.3; detonations from `v3-out`.

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked | ⏱️ Could not verify |
|---|---|---|---|---|---|
| benign (104) | rules | 94/104 | 4/104 | 0/104 | 6/104 |
| benign (104) | contract | 95/104 | 3/104 | 0/104 | 6/104 |
| benign (104) | analysis | 94/104 | 4/104 | 0/104 | 6/104 |
| benign (104) | full | 95/104 | 3/104 | 0/104 | 6/104 |
| malicious (16) | rules | 0/16 | 1/16 | 15/16 | 0/16 |
| malicious (16) | contract | 0/16 | 1/16 | 15/16 | 0/16 |
| malicious (16) | analysis | 0/16 | 0/16 | 16/16 | 0/16 |
| malicious (16) | full | 0/16 | 0/16 | 16/16 | 0/16 |
| incident (2) | rules | 0/2 | 0/2 | 2/2 | 0/2 |
| incident (2) | contract | 0/2 | 0/2 | 2/2 | 0/2 |
| incident (2) | analysis | 0/2 | 0/2 | 2/2 | 0/2 |
| incident (2) | full | 0/2 | 0/2 | 2/2 | 0/2 |
| redteam (10) | rules | 4/10 | 0/10 | 6/10 | 0/10 |
| redteam (10) | contract | 4/10 | 0/10 | 6/10 | 0/10 |
| redteam (10) | analysis | 1/10 | 0/10 | 9/10 | 0/10 |
| redteam (10) | full | 1/10 | 0/10 | 9/10 | 0/10 |
| redteam-ind (10) | rules | 4/10 | 0/10 | 5/10 | 1/10 |
| redteam-ind (10) | contract | 4/10 | 0/10 | 5/10 | 1/10 |
| redteam-ind (10) | analysis | 0/10 | 0/10 | 10/10 | 0/10 |
| redteam-ind (10) | full | 0/10 | 0/10 | 10/10 | 0/10 |

### What Muse explained (P1.5 ground truth)

- Decoded the payload correctly in **6/6** obfuscated attacks
- Attributed to the right package/file in **2/2** dependency-delivered attacks

### Evidence grounding (full pipeline)

- **452/452** evidence claims cite a real kernel event of the right type (13 labelled source-only); **0** rejected (0% unsupported-claim rate).

> **What this number covers.** Every entry in the model's `key_evidence`, plus any hostname, IP, file path or port appearing in its prose even when nothing is cited for it. It cannot police prose claims that are not mechanically checkable, so it measures **citation discipline and the absence of invented concrete facts**, not total factual accuracy. The prose-level half has so far flagged nothing real (see W4 in `docs/WEAKPOINTS.md`): it is a regression guard, not a detector with a catch to its name.
- Cases whose summary names a host/IP absent from the record and diff: 0

### Cost and latency (full pipeline)

- Detonation: p50 5.89s, p95 67.07s
- Model latency per PR (prediction + analysis): p50 36.55s, p95 66.72s
- Tokens per PR: 2516 in / 3524 out (mean)
- **Cost per PR: $0.0181 mean** (muse-spark-1.3 at $1.25/1M in, $4.25/1M out); $2.574 for all 142 cases

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
| cypress | benign | ⏱️ | ⏱️ | ⏱️ | ⏱️ | NET_UNLISTED_DOMAIN | cleared download.cypress.io; install timeout exit=None |
| chromedriver | benign | ⚠️ | ⚠️ | ⚠️ | ⚠️ | NET_UNLISTED_DOMAIN |  |
| ffmpeg-static | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| sentry-cli | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| core-js | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| protobufjs | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| es5-ext | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| nodemon | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| husky | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| msw | benign | ✅ | ✅ | ✅ | ✅ | - |  |
| biome | benign | ⏱️ | ⏱️ | ⏱️ | ⏱️ | - | install timeout exit=None |
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
| m12-domain-exfil | malicious | ⚠️ | ⚠️ | ❌ | ❌ | NET_UNLISTED_DOMAIN | exfil to a resolvable domain (dummy body) instead of a raw IP |
| m13-injection | malicious | ❌ | ❌ | ❌ | ❌ | DECOY_CREDENTIAL_SEEN EXEC_NET_TOOL NET_RAW_IP | injection flagged; exfil + prompt injection in body and package.json |
| m14-delayed | malicious | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | payload fires 4 s after the script starts |
| m15-udp-exfil | malicious | ❌ | ❌ | ❌ | ❌ | NET_NON_TCP_EGRESS | env exfil over UDP (no TCP connection at all) |
| m16-token-header | malicious | ❌ | ❌ | ❌ | ❌ | DECOY_CREDENTIAL_SEEN EXEC_NET_TOOL NET_RAW_IP | steals $GITHUB_TOKEN from the environment, sends it in a header |
| r01-ua-parser-js | incident | ❌ | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_EXFIL_SERVICE NET_RAW_IP NET_UNLISTED_DOMAIN | ua-parser-js 0.7.29 (Oct 2021): geofenced miner download via preinstall |
| r02-shai-hulud | incident | ❌ | ❌ | ❌ | ❌ | CRED_FILE_ACCESS EXEC_DROPPED_BINARY NET_EXFIL_SERVICE NET_UNLISTED_DOMAIN | Shai-Hulud (Sept 2025): real TruffleHog from GitHub, secrets to webhook.site |
| rt01-env-https | redteam | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | control: env exfil over HTTPS to a raw IP |
| rt02-ssh-key | redteam | ❌ | ❌ | ❌ | ❌ | CRED_FILE_ACCESS NET_RAW_IP | control: reads the bait SSH key and exfiltrates it |
| rt03-revshell | redteam | ❌ | ❌ | ❌ | ❌ | EXEC_INTERACTIVE_SHELL NET_RAW_IP | control: /dev/tcp reverse shell |
| rt04-fetch-exec | redteam | ❌ | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_RAW_IP | control: download-and-execute |
| rt05-charcode | redteam | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | control: char-code obfuscated raw IP |
| rt06-persist-rcfile | redteam | ✅ | ✅ | ❌ | ❌ | - | GAP: writes a persistence line to ~/.bashrc; no network at install |
| rt07-self-propagate | redteam | ✅ | ✅ | ❌ | ❌ | - | GAP: modifies a sibling node_modules package; no network at install |
| rt08-local-miner | redteam | ✅ | ✅ | ✅ | ✅ | - | GAP: local CPU miner, no egress and no dropped binary |
| rt09-dropped-binary | redteam | ❌ | ❌ | ❌ | ❌ | EXEC_DROPPED_BINARY | writes a stage to /tmp, chmods +x and runs it (expect EXEC_DROPPED_BINARY) |
| rt10-ci-dormant | redteam | ✅ | ✅ | ❌ | ❌ | - | GAP: sandbox-aware; dormant when CI is detected |
| gm01-env-exfil | redteam-ind | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | g1: environment-variable exfiltration via HTTP POST to a raw IP |
| gm02-cred-harvest | redteam-ind | ❌ | ❌ | ❌ | ❌ | CRED_FILE_ACCESS | g2: harvest ~/.ssh and ~/.aws credential files, upload them |
| gm03-obfuscated-exec | redteam-ind | ❌ | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_RAW_IP | g3: base64 payload decoded in-memory and run via child_process.exec |
| gm04-rcfile-persist | redteam-ind | ✅ | ✅ | ❌ | ❌ | - | g4: shell-profile modification (~/.bashrc, ~/.zshrc) for persistence |
| gm05-cron-inject | redteam-ind | ✅ | ✅ | ❌ | ❌ | - | g5: cron-job injection fetching a script from a .invalid host |
| gm06-binary-drop | redteam-ind | ❌ | ❌ | ❌ | ❌ | NET_RAW_IP | g6: download an external binary, chmod +x, run it detached |
| gm07-recon | redteam-ind | ❌ | ❌ | ❌ | ❌ | EXEC_NET_TOOL | g7: host fingerprinting (uname/whoami/ifconfig) written out and sent |
| gm08-cpu-miner | redteam-ind | ⏱️ | ⏱️ | ❌ | ❌ | - | install timeout exit=None; g8: detached background process doing heavy hashing (simulated cryptominer) |
| gm09-backdoor-listen | redteam-ind | ✅ | ✅ | ❌ | ❌ | - | g9: opens a listening TCP server (backdoor / bind shell) |
| gm10-dep-tamper | redteam-ind | ✅ | ✅ | ❌ | ❌ | - | g10: local supply-chain tampering — modifies a sibling node_modules package |
