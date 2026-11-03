# Blind red-team corpus — audit sheet

`eval/blind_corpus.py` defines `BLIND_CORPUS`, a held-out set of defanged npm install-time
attack fixtures. It was written **blind to the detectors** (no `brain/rules.py`, `intent.py`,
`verdict.py`, `evidence.py`, `sbom.py`, no prompt files, no existing `eval/REDTEAM*/results*/
SWEEP*`). Its job is to measure what the tool misses, so a miss here is a useful finding.

Every destination below is reserved and non-routable, so nothing is ever exfiltrated:
TEST-NET-1 (`192.0.2.0/24`), TEST-NET-2 (`198.51.100.0/24`), TEST-NET-3 (`203.0.113.0/24`),
`.invalid` names (never resolve), and `example.com` (dummy body). File writes land only in the
throwaway install tree or the sandbox tmpfs.

| id | technique (one line) | defanged destination |
|----|----------------------|----------------------|
| `bc01-staged-hooks` | preinstall generates the egress script, postinstall runs it (payload absent from the diff) | `203.0.113.11` (TEST-NET-3) |
| `bc02-dead-drop` | harvests env + `~/.npmrc` to `node_modules/.cache/.telemetry.json`, no network | none (local file only) |
| `bc03-git-hook` | writes an executable `.git/hooks/post-checkout` that beacons on a later checkout | `198.51.100.20` (TEST-NET-2) |
| `bc04-git-alias` | hides the egress inside a `git` alias that fires on later git use | `192.0.2.30` (TEST-NET-1) |
| `bc05-delayed-beacon` | detached child connects out 6s after `npm install` has already returned | `203.0.113.40` (TEST-NET-3) |
| `bc06-platform-gate` | egress gated on `process.platform === "linux"` to skip developer laptops | `198.51.100.50` (TEST-NET-2) |
| `bc07-npm-token` | reads `_authToken` from `~/.npmrc`, base64-encodes it, stages it to `/tmp`, no network | none (local file only) |
| `bc08-dns-exfil` | host identity hex-encoded into a DNS label; no HTTP request | `collector.invalid` (never resolves) |
| `bc09-path-shadow` | drops a `git` shim that beacons, prepends `~/.local/bin` to PATH via `~/.bashrc` | `beacon.example.com` (dummy body) |
| `bc10-git-proxy` | sets global `git http.proxy` to a TEST-NET host (MITM of future git traffic) | `192.0.2.70` (TEST-NET-1) |

Full destination list (for grep-audit): `203.0.113.11`, `198.51.100.20`, `192.0.2.30`,
`203.0.113.40`, `198.51.100.50`, `192.0.2.70`, `collector.invalid`, `beacon.example.com`.
Two cases (`bc02`, `bc07`) reach no destination at all — they stage loot to disk.

## What this is and is not

It is a **held-out** set: written by a fresh agent with no detector knowledge, which is a real
step up from the `gm*` set (model-*suggested* but author-implemented) because these techniques
were not shaped around our rules. The destination envelope was independently re-audited from the
file bytes before the corpus was committed (`tests/test_blind_corpus.py` makes that audit
permanent), and verified against this sheet.

It is **not** "independent validation" in the sense W12 needs, and must not be cited as such.
The blinding was *instructed*, not technically enforced — nothing stopped the generating agent
from reading `brain/rules.py`, it was told not to — and the cases are still **scored by us** in
our own harness. Genuine external validation needs a third party who writes *and* scores against
a frozen build. The honest phrasing for any result from this set is: "a held-out set written
blind to the detectors, scored by us."

**Not yet detonated.** Scoring what the tool misses on this set requires detonating all 10 on the
Chamber (a live run, owner's call) and scoring the telemetry. Until then this is a ready,
audited corpus, not a result.
