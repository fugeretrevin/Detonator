# The sandbox has no C toolchain — a decision, not a gap (W3)

**Nov 3, 2026.** This memo characterizes the six benign "Could not verify" results in the
stamped eval (`eval/results.json`, scored Nov 2 at `a96c8a1`), quantifies the security cost of
adding a C toolchain to the sandbox, and records the decision. It is **report-only and offline**:
it changes no verdict, no stamped result, and does not touch the deployed
`chamber/sandbox/Dockerfile`. Coverage is **unchanged** — what changed is that the limitation is
now fully accounted for and the compiler tradeoff is measured rather than assumed.

The acceptance-gated rebuild in `docs/WEAKPOINTS.md` W3 ("add `build-essential`, re-run the 104")
remains an **after-judging** decision, for the reason given there: it changes the image every
eval number was measured on, and its own acceptance #4 could open a gap mid-submission.

## 1. What the six actually are

The stamped benign cohort is 104. Six read "Could not verify" in every arm. They split cleanly
into two causes, one reproducible and one a measurement artifact.

### The four native-build failures — reproducible, by design

| Package | status | exit | cpu_s | hosts contacted | Cause |
|---|---|---|---|---|---|
| `better-sqlite3` | completed | 1 | 5.07 | registry.npmjs.org, nodejs.org, github.com | node-gyp build, no compiler |
| `argon2` | completed | 1 | 3.85 | registry.npmjs.org, nodejs.org | node-gyp build, no compiler |
| `node-pty` | completed | 1 | 5.28 | registry.npmjs.org, nodejs.org | node-gyp build, no compiler |
| `cpu-features` | completed | 1 | 0.93 | registry.npmjs.org | node-gyp build, no compiler |

All four **ran to completion and exited 1** (`status: completed`, `exit_code: 1`) — a clean,
deterministic failure, not a crash or a hang. Three of the four fetched Node headers from
`nodejs.org`, which is exactly what `node-gyp` does before it tries to compile: it downloads the
headers for the running Node version, generates a Makefile, then invokes the C/C++ compiler. The
sandbox is `node:20-slim` + `ca-certificates curl wget netcat-openbsd git python3` — **python3 is
present (so node-gyp's configure step runs) but there is no `cc`/`g++`/`make`**, so the build step
fails. The four failed identically on both the Nov 2 and Nov 3 runs (`eval/PERSISTENCE.md`): this
is the real, reproducible half of W3.

**Committed evidence of the build path.** `eval/validation_telemetry/v02-node-gyp-build.json` is a
recorded node-gyp detonation. Its exec chain shows the signature —
`sh -c "node-gyp rebuild"` → `node-gyp.js rebuild` → `gyp_main.py …` — and its `stderr_tail`
carries the `gyp ERR! configure error` / `gyp ERR! not ok` tail. (That probe fails one step
earlier, at `binding.gyp not found`, because it is a defanged fixture with no real C source; the
four real packages fail one step later, at the missing compiler, down the *same* node-gyp path.)
The structured fields above are the committed per-package evidence; the literal `cc: not found`
line is not in the stamped corpus because `eval/results.json` does not store stderr.

### The two timeouts — a CDN-speed artifact, not a sandbox property

| Package | status | exit | Nov 2 | Nov 3 re-run |
|---|---|---|---|---|
| `biome` | timeout | — | >240 s (timed out) | **5.8 s** |
| `cypress` | timeout | — | >240 s (timed out) | **40 s** |

Both exceeded the 240 s install timeout on Nov 2 and both completed **well inside** it a day later
(`eval/PERSISTENCE.md`, confirmed while re-detonating all 104 benign controls with the persistence
policy loaded). `biome` ships no install script at all; `cypress` downloads its binary from
`download.cypress.io`. Neither involves the toolchain. So the Nov 2 "6" was "4" the next day, and
the two timeouts are a **registry/CDN speed artifact**, not something the sandbox causes. The
stamped `eval/results.json` is deliberately left at the Nov 2 figures.

**Net accounting of the six: 4 by-design unsupported-toolchain + 2 CDN-speed timeout + 0 genuine
failures.** `eval/toolchain.py` makes this split mechanical (see §4).

## 2. The security tradeoff of adding a C toolchain

Adding `build-essential` (gcc/g++/make/ld) to the sandbox would let the four native packages
compile — and would hand **every payload a compiler**. The cost is not image size; it is a real
reduction in detection surface, because several of our signals depend on a malicious binary
*arriving over the network* and being *executed from a drop location*. A local compile-from-source
produces a native artifact with **no fetch, no connection, and no dropped-binary exec** — it is
written into the package's own `build/` directory under `/work` and loaded by Node as a library,
not exec'd from `/tmp` or `$HOME`.

Concretely, these signals weaken (all defined in `brain/rules.py`; observed firing in
`eval/results.md`):

| Signal | Why a local compile evades it |
|---|---|
| **`EXEC_DROPPED_BINARY`** (HIGH) | The central one. It fires when a program is exec'd from a temp/home drop dir — i.e. a binary that was *fetched and dropped* at install time (`r02-shai-hulud` ran a fetched TruffleHog; `rt09-dropped-binary` dropped a stage to `/tmp`). A compiled `.node` addon lands in `/work/<pkg>/build/`, not a drop dir, and is `dlopen`'d by Node rather than exec'd — so this rule never sees it. The attacker trades "download a binary" for "build one locally" and the trace disappears. |
| **`EXEC_NET_TOOL`** (HIGH) | Fires on `curl`/`wget`/`nc` run during install — the usual way to *obtain* a payload. Building locally needs no network tool, so the exec is gone. |
| **`NET_RAW_IP`** (HIGH) | Fires on a TCP connection to a bare IP — how a staged binary is fetched from a drop host. No fetch, no connection, no hit. This is the single most common rule across the attack corpus. |
| **`NET_UNLISTED_DOMAIN`** (LOW) | Fires when a download reaches a host not on the allowlist. A local build contacts nothing, so there is no unlisted-domain download to flag. |
| **`NET_EXFIL_SERVICE`** (HIGH) | Fires on connections to known drop/staging services. A build that needs no staging host never trips it. |
| **DNS signals** (`DNS_ENCODED_LABEL` and the DNS witness generally) | A local build resolves nothing, so there is no staging-host lookup to observe. |
| **`RES_CPU_HEAVY` build-tool exemption** (`_cpu_hits`, currently off) | Secondary but real: the CPU-review exemption whitelists `cc/gcc/g++/make/node-gyp/cargo/rustc`. With a compiler actually present, an attacker can run `make` to *earn* that exemption and launder a CPU-bound miner as a build. Today the exemption is unreachable because those binaries do not exist in the image. |

The through-line: **our detection of install-time malware leans heavily on the payload touching
the network to arrive.** A compiler collapses "download and run" into "compile and load", which is
observable to almost none of the above. That is why this is a posture decision, not a packaging
convenience.

## 3. Recommendation

**Keep the no-compiler default.** Do not add `build-essential` before judging.

**Reclassify the four native-build cases as a by-design `unsupported-toolchain` outcome** — a
deliberately smaller blast radius — rather than a "failure to verify." The absence of a compiler
is a security property we are choosing, and the cost of that choice is bounded and named: four
mainstream native packages (`better-sqlite3`, `argon2`, `node-pty`, `cpu-features`) cannot be
built in the sandbox and therefore cannot be given a clean verdict. That is the correct trade: we
would rather not verify four benign packages than hand every payload a compiler and lose
`EXEC_DROPPED_BINARY` plus the network signals above.

The honest public statement therefore becomes, with all six fully accounted for:

> **98 of 104 benign packages verified.** 4 are native modules requiring a C toolchain we
> deliberately exclude from the sandbox for a smaller blast radius (a compiler would remove the
> network/dropped-binary signals our detection relies on); 2 were CDN-speed install timeouts that
> complete well inside the limit on re-run. 0 benign packages were blocked.

(98 = 104 − 6; the 98 is 94 clean + 4 needs-review in the stamped `full` arm. Coverage is
unchanged from the stamped numbers — this is the same result, honestly categorized.)

If the toolchain is ever added after judging, W3's acceptance #4 still binds: a red-team case that
**compiles** its payload locally must be added, and the eval must report honestly whether the
compiler-less signals above still catch it. That is the gap this memo exists to keep closed.

## 4. The mechanical classifier

`eval/toolchain.py` (report-only, no pipeline role) labels a finished detonation as
`unsupported-toolchain` / `cdn-timeout` / `genuine-failure` / `verified` from its `status`,
`exit_code`, `stderr_tail` and `exec_events`. It matches the node-gyp / missing-compiler signature
rather than a package list, so it generalizes, and it is pinned by `tests/test_toolchain.py`
against the committed `v02-node-gyp-build` telemetry and the W3 split. It exists so the accounting
in §1 and §3 is produced from data, not remembered — and it **cannot** change a verdict: it only
reads outcomes the telemetry already recorded.
