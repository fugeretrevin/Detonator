const fs = require("fs"), path = require("path");
// Write a compiled-template cache inside our OWN package directory.
const dir = path.join(__dirname, "..", ".cache");
try {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "templates.json"), JSON.stringify({ built: true }));
} catch {}
