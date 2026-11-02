# Evaluation results

Scored 2026-11-02 05:55 UTC at commit `1aa9c45` with muse-spark-1.3; detonations from `redteam-all`.

| Set | Setup | ✅ Clean | ⚠️ Needs review | ❌ Blocked | ⏱️ Could not verify |
|---|---|---|---|---|---|
| benign (0) | rules | 0/0 | 0/0 | 0/0 | 0/0 |
| benign (0) | contract | 0/0 | 0/0 | 0/0 | 0/0 |
| benign (0) | full | 0/0 | 0/0 | 0/0 | 0/0 |
| malicious (0) | rules | 0/0 | 0/0 | 0/0 | 0/0 |
| malicious (0) | contract | 0/0 | 0/0 | 0/0 | 0/0 |
| malicious (0) | full | 0/0 | 0/0 | 0/0 | 0/0 |
| incident (0) | rules | 0/0 | 0/0 | 0/0 | 0/0 |
| incident (0) | contract | 0/0 | 0/0 | 0/0 | 0/0 |
| incident (0) | full | 0/0 | 0/0 | 0/0 | 0/0 |
| redteam (10) | rules | 5/10 | 0/10 | 5/10 | 0/10 |
| redteam (10) | contract | 5/10 | 0/10 | 5/10 | 0/10 |
| redteam (10) | full | 1/10 | 0/10 | 9/10 | 0/10 |
| redteam-ind (10) | rules | 5/10 | 0/10 | 5/10 | 0/10 |
| redteam-ind (10) | contract | 5/10 | 0/10 | 5/10 | 0/10 |
| redteam-ind (10) | full | 0/10 | 0/10 | 10/10 | 0/10 |

### What Muse explained (P1.5 ground truth)

- Decoded the payload correctly in **1/1** obfuscated attacks

### Cost and latency (full pipeline)

- Detonation: p50 5.94s, p95 207.9s
- Model latency per PR (prediction + analysis): p50 22.56s, p95 31.35s
- Tokens per PR: 2252 in / 3515 out (mean)
- **Cost per PR: $0.0178 mean** (muse-spark-1.3 at $1.25/1M in, $4.25/1M out); $0.355 for all 20 cases

## Per case

| Case | Kind | Rules | +Contract | Full | Fired | Notes |
|---|---|---|---|---|---|---|
| rt01-env-https | redteam | ❌ | ❌ | ❌ | NET_RAW_IP | control: env exfil over HTTPS to a raw IP |
| rt02-ssh-key | redteam | ❌ | ❌ | ❌ | CRED_FILE_ACCESS NET_RAW_IP | control: reads the bait SSH key and exfiltrates it |
| rt03-revshell | redteam | ❌ | ❌ | ❌ | EXEC_INTERACTIVE_SHELL NET_RAW_IP | control: /dev/tcp reverse shell |
| rt04-fetch-exec | redteam | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_RAW_IP | control: download-and-execute |
| rt05-charcode | redteam | ❌ | ❌ | ❌ | NET_RAW_IP | control: char-code obfuscated raw IP |
| rt06-persist-rcfile | redteam | ✅ | ✅ | ❌ | - | GAP: writes a persistence line to ~/.bashrc; no network at install |
| rt07-self-propagate | redteam | ✅ | ✅ | ❌ | - | GAP: modifies a sibling node_modules package; no network at install |
| rt08-local-miner | redteam | ✅ | ✅ | ✅ | - | GAP: local CPU miner, no egress and no dropped binary |
| rt09-dropped-binary | redteam | ✅ | ✅ | ❌ | - | writes a stage to /tmp, chmods +x and runs it (expect EXEC_DROPPED_BINARY) |
| rt10-ci-dormant | redteam | ✅ | ✅ | ❌ | - | GAP: sandbox-aware; dormant when CI is detected |
| gm01-env-exfil | redteam-ind | ❌ | ❌ | ❌ | NET_RAW_IP | g1: environment-variable exfiltration via HTTP POST to a raw IP |
| gm02-cred-harvest | redteam-ind | ❌ | ❌ | ❌ | CRED_FILE_ACCESS | g2: harvest ~/.ssh and ~/.aws credential files, upload them |
| gm03-obfuscated-exec | redteam-ind | ❌ | ❌ | ❌ | EXEC_NET_TOOL NET_RAW_IP | g3: base64 payload decoded in-memory and run via child_process.exec |
| gm04-rcfile-persist | redteam-ind | ✅ | ✅ | ❌ | - | g4: shell-profile modification (~/.bashrc, ~/.zshrc) for persistence |
| gm05-cron-inject | redteam-ind | ✅ | ✅ | ❌ | - | g5: cron-job injection fetching a script from a .invalid host |
| gm06-binary-drop | redteam-ind | ❌ | ❌ | ❌ | NET_RAW_IP | g6: download an external binary, chmod +x, run it detached |
| gm07-recon | redteam-ind | ❌ | ❌ | ❌ | EXEC_NET_TOOL | g7: host fingerprinting (uname/whoami/ifconfig) written out and sent |
| gm08-cpu-miner | redteam-ind | ✅ | ✅ | ❌ | - | g8: detached background process doing heavy hashing (simulated cryptominer) |
| gm09-backdoor-listen | redteam-ind | ✅ | ✅ | ❌ | - | g9: opens a listening TCP server (backdoor / bind shell) |
| gm10-dep-tamper | redteam-ind | ✅ | ✅ | ❌ | - | g10: local supply-chain tampering — modifies a sibling node_modules package |
