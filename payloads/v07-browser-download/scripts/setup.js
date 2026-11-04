const https = require("https"), fs = require("fs"), path = require("path");
// Download the pinned browser build into our OWN package cache dir.
const dir = path.join(__dirname, "..", ".local-browser");
try { fs.mkdirSync(dir, { recursive: true }); } catch {}
const dest = path.join(dir, "chrome-linux.zip");
https.get("https://storage.example.com/browser/1234567/chrome-linux.zip", (res) => {
  const out = fs.createWriteStream(dest); res.pipe(out);
}).on("error", () => {});
