# W12 blind validation: the tool vs a cold agent's frozen labels

**Detonated 2026-11-04** on the live Chamber against `fugeretrevin/Detonator@5fee239` (the
`validation-payloads` side branch), all 14 cases, `rc=0`, then scored through the **full
pipeline** (rules + model). The labels in `eval/validation_labels.json` were fixed by a fresh
agent, cold to the detectors, **before any case was run** — so this measures the tool against a
judgement it did not shape. Telemetry is in `eval/validation_telemetry/`; the scored comparison
is `eval/validation_result.json`.

## Result

| | Count |
|---|---|
| Cases | 14 (7 benign, 7 malicious) |
| **Exact agreement with the frozen labels** | **12 / 14** |
| **Attacks blocked** | **7 / 7** |
| **Dangerous misses** (attack the tool let through) | **0** |
| Sandbox-limit disagreements | 1 |
| Benign-calibration disagreements | 1 |

Per case:

| Case | Frozen label | Tool verdict | Outcome |
|---|---|---|---|
| v01-prebuilt-addon | Clean | Clean | ✅ match |
| v02-node-gyp-build | Clean | Could not verify | sandbox limit |
| v03-mirror-dns | Clean | Clean | ✅ match |
| v04-cpu-build | Clean | Clean | ✅ match |
| v05-cache-own-dir | Clean | Clean | ✅ match |
| v06-install-telemetry | Needs review | Clean | benign calibration |
| v07-browser-download | Clean | Clean | ✅ match |
| v08-env-exfil | Blocked | Blocked | ✅ match |
| v09-cred-harvest | Blocked | Blocked | ✅ match |
| v10-reverse-shell | Blocked | Blocked | ✅ match |
| v11-drop-and-run | Blocked | Blocked | ✅ match |
| v12-bashrc-persist | Blocked | Blocked | ✅ match |
| v13-dns-exfil | Blocked | Blocked | ✅ match |
| v14-token-steal | Blocked | Blocked | ✅ match |

## The two disagreements, and why neither is a failure

**v02 (sandbox limit, not a detection error).** The agent labelled a `node-gyp` native build
`Clean`. Our sandbox image has no C toolchain, so the build exits 1 and the tool returns
**Could not verify** — fail-closed, by design (W3). It is not that the tool judged the package
badly; it is that the tool could not watch a complete install and correctly declined to call it
clean. A reviewer sees "we could not verify this", which is the honest answer.

**v06 (benign calibration, and in the safe direction).** The agent's deliberate ambiguous case:
a package that `POST`s only non-sensitive `node`/`platform` telemetry at install, labelled
`Needs review` because the outbound POST is undisclosed. The tool returned `Clean`. This is the
tool being *more lenient* than the agent — but on a **benign** case, so it is not a security
miss; it is a judgement call about whether an undisclosed-but-harmless telemetry ping deserves a
reviewer's eyes. Both positions are defensible, and the disagreement is in the direction that
never blocks a real package.

## What this does and does not establish

- **No attack got through, and no benign package was hard-blocked.** On a set whose verdicts
  were fixed before the tool saw them, the tool blocked 7/7 attacks and cleared the benign ones
  (bar the one it honestly could not verify). That is the result that matters.
- **It is still not a human third-party audit.** The labels were frozen by a *cold agent*, which
  is a real step past the author-written and model-suggested sets (the agent genuinely had no
  detector knowledge and committed its calls before any run), but the blinding was instructed,
  not technically enforced, and the party is a model, not an external human. The honest phrasing
  stays: **"a cold agent's pre-registered labels, scored by us."** W12's ultimate ask — a human
  third party who writes and scores against a frozen build — is still open.
- **14 cases is small.** Exact agreement of 12/14 is a calibration signal, not a published
  accuracy rate; the confidence interval is wide and this is not quoted as one.
