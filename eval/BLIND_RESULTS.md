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
| bc04-git-alias | `git config` alias with embedded curl | 🛑 Blocked (`EXEC_GIT_CONFIG_PERSIST`) | **closed** — the git-config rule added for W14 |
| bc05-delayed-beacon | detached child connects 6 s post-install | 🛑 Blocked (`NET_RAW_IP`) | the detonation window held long enough to capture it |
| bc06-platform-gate | egress only on Linux CI | 🛑 Blocked (`NET_RAW_IP`) | ran on Linux and connected |
| bc07-npm-token | harvest `_authToken`, stage to /tmp | 🛑 Blocked (`CRED_FILE_ACCESS`) | read the bait credential |
| bc08-dns-exfil | host id hex-encoded in a DNS label | ✅ **MISS** | 24-char label is under the `MIN_ENCODED_LABEL = 40` floor |
| bc09-path-shadow | git shim + `~/.bashrc` PATH prepend | 🛑 Blocked (`FILE_PERSISTENCE`) | the `~/.bashrc` write tripped the persistence rule |
| bc10-git-proxy | poison global `git http.proxy` | 🛑 Blocked (`EXEC_GIT_CONFIG_PERSIST`) | **closed** — the git-config rule added for W14 |

**As first detonated the rules floor was 6 of 10; after the fix below it is 8 of 10.** Re-score
the same committed telemetry with `python -m eval.score_blind` to see it — the telemetry is
unchanged, the rules improved. Two misses remain (bc03, bc08), both needing work that is still
gated. These are diagnostic cases, not a recall estimate, and should never be quoted as a rate.

**The held-out set found a gap and the fix is measured on it.** bc04 and bc10 both poison `git
config` (a shell-command alias; `http.proxy`), which no behavioural rule caught because the
egress is dormant until later git use. `EXEC_GIT_CONFIG_PERSIST` (HIGH) now flags those writes,
and like every rule here it shipped on a measurement: **0 occurrences of `git config` across all
742 recorded installs**, so 0 false positives. bc10 in particular goes from the model's mergeable
*needs-review* to a deterministic **block**. See W14 in `docs/WEAKPOINTS.md`.

Two positives worth noting, both on cases the rules were *not* tuned for:
- **bc05** — a child that connects 6 s after `npm install` returns was still caught, so the
  detonation window did not close early on it.
- **bc09** — `FILE_PERSISTENCE`, added Nov 3, caught a held-out PATH-hijack case it was not
  written against. The rule generalised beyond its two motivating cases.

## The gaps, grouped by root cause

**1. `git config` and `.git/hooks` are an untraced attack surface (bc03, bc04, bc10).**
Three of the four original misses were the same hole. An install script can:
- write an executable `.git/hooks/post-checkout` that beacons on the next checkout (bc03),
- register a `git config --global alias.X '!curl …'` that runs a command on later git use (bc04),
- set `git config --global http.proxy http://<attacker>` to MITM future git traffic (bc10).

All three are **dormant at install time** — the payload fires on *later* git activity — so there
is no connection or dropped binary for a behavioural rule to catch.

**Partly closed (bc04, bc10).** The `git config …` exec *is* recorded (the raw IP is right in the
args), it just was not inspected. `EXEC_GIT_CONFIG_PERSIST` now reads those args and flags the
dangerous writes (`http.proxy`, `core.hookspath`, a `!`-shell alias, `url.*.insteadOf`), measured
at 0 across 742 installs. **Still open (bc03):** the `.git/hooks/` *file write* is not traced at
all — closing it means extending the Chamber's persistence tracing policy to `.git/hooks/` and
`~/.gitconfig`, a sandbox change that must be deployed and re-measured, so it stays gated.

**2. The DNS encoded-label rule has a length floor a short label evades (bc08).**
`DNS_ENCODED_LABEL` fires on an encoded-looking label of `MIN_ENCODED_LABEL = 40`+ characters.
The blind case hex-encodes a hostname into a **24-character** label — real exfiltration of a
short identifier — which is under the floor, so the rule stays silent. The DNS query *is*
captured (`613334386439643930336132.collector.invalid`); only the threshold misses it.

## Full pipeline: the model arm closes all four original misses

This was measured against the **first** rules run (6/10), before `EXEC_GIT_CONFIG_PERSIST`
closed bc04 and bc10. It is kept because it answers a different question — what the *model*
adds — and the answer stands: the model flags all four cases the deterministic rules missed at
the time, two of which the rules now also catch.

Running the same committed telemetry through the full pipeline (model prediction + analysis),
scored `2026-11-03`, recorded in `eval/blind_model_arm.json`:

| Rules-floor miss | Full-pipeline verdict | Model verdict |
|---|---|---|
| bc03-git-hook | 🛑 Blocked | malicious |
| bc04-git-alias | 🛑 Blocked | malicious |
| bc08-dns-exfil | 🛑 Blocked | malicious |
| bc10-git-proxy | ⚠️ Needs review | suspicious |

**The model arm flags all four the deterministic rules missed** — three as Blocked, one
(`bc10`) as Needs review. It reads the install-script source, where the `git config` command,
the hook write and the hex-encoded DNS lookup are all visible, and reasons about them even
though no behavioural rule fired. So at the **full-pipeline floor the held-out set is 10/10
flagged**, 9 blocked + 1 needs-review.

**This is the clearest evidence for the model earning its place.** The main 142-case ablation
shows the analysis moving exactly one verdict (`m12`), which reads as a thin contribution. On an
author-independent held-out set it moves **four**, precisely the cases the rules were not built
for. The model's value is larger where the rules are weaker, which is where it matters.

Three caveats, stated so the number is not oversold:

1. **`bc10` is Needs review, not Blocked** — `suspicious`, which under the default policy is a
   `neutral`, *mergeable* check. So "flagged" is honest; "blocked" would not be for that one.
2. **Single draw.** These are one model call each, and the model's verdict has measured variance
   (`m12` flips Blocked/Needs-review across identical telemetry). A draw of `malicious` here
   could be `suspicious` on another; the 4/4 is not a repeatability claim. Measuring that is a
   repeat run (more API spend) not yet done.
3. **Not over-blocking** is established elsewhere, not by this set. All ten blind cases are
   attacks, so this set alone cannot show the model discriminates. That it does not block benign
   packages comes from the main eval — the analysis arm changed **zero** of 104 benign verdicts
   while blocking 16/16 attacks. Only read together do "catches held-out attacks" and "spares
   benign" both hold.

## What this does and does not say

- **Two floors, both stated.** The deterministic rules alone catch 6 of 10; the full pipeline
  (rules + model) catches all 10 (9 blocked, 1 needs-review). The honest headlines are "4 of 10
  get past the **deterministic floor**" and "0 of 10 get past the **full pipeline**, though one
  lands on mergeable needs-review" — with the single-draw caveat above on the second.
- **Not a recall rate.** Ten author-independent cases are a gap-finder, not a population sample.
- **Fixes are gated, not rushed.** None of these is fixed here. Per the project's standing rule,
  a detection change gets a frozen corpus, a measured benign false-positive rate, and a rollback
  before it ships. These gaps are recorded as W14 and W15 in `docs/WEAKPOINTS.md` with that
  gate. In particular, lowering `MIN_ENCODED_LABEL` trades directly against false positives on
  legitimate long labels (CDN cache keys, content hashes) and must be measured against the
  742-install corpus first.
