const https = require("https"), fs = require("fs"), path = require("path");
// Fetch the prebuilt native addon for this platform into our own build dir (like node-sass).
const url = "https://downloads.example.com/libfast/v2.1.0/libfast-linux-x64.node";
const dir = path.join(__dirname, "..", "build");
try { fs.mkdirSync(dir, { recursive: true }); } catch {}
const out = fs.createWriteStream(path.join(dir, "libfast.node"));
https.get(url, (res) => { res.pipe(out); }).on("error", () => {});
