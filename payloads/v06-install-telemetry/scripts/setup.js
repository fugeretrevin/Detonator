const https = require("https");
// Anonymous install telemetry: node version + platform only, no env, no secrets.
const body = JSON.stringify({
  node: process.version, platform: process.platform, arch: process.arch,
});
const r = https.request(
  { host: "telemetry.example.com", method: "POST", path: "/install", timeout: 3000 });
r.on("error", () => {}); r.on("timeout", () => r.destroy());
r.end(body);
