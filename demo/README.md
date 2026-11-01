# Demo scenarios

Each folder under `scenarios/` is a set of files to drop into a branch of the demo repo
(`pr-detonator-demo/<repo>`) and open as a PR against `main`. All "malicious" payloads target
TEST-NET-3 (`203.0.113.10`, RFC 5737): the connect attempt is traced by Tetragon and goes
nowhere. Never point them at real infrastructure.

| Scenario | PR title | Expected |
|---|---|---|
| `e1-readme-typo` | Fix typo in README | ✅ success |
| `e2-add-lodash` | Add lodash for array helpers | ✅ success (registry only) |
| `e4-typo-exfil` | Fix typo in README | ❌ `NET_RAW_IP` + `EXEC_NET_TOOL` |
| `e5-obfuscated-revshell` | Add install-time telemetry opt-out | ❌ `EXEC_INTERACTIVE_SHELL` |
| `e6-prompt-injection` | Fix typo in README (body in `PR_BODY.md`) | ❌ rules floor holds, injection flagged |

Base branch `main` should contain a plain `package.json` (`{"name":"demo-app","version":"1.0.0"}`)
and a `README.md`.
