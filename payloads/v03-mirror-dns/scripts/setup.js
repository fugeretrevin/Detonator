const dns = require("dns");
// Geo mirror selection: resolve each candidate CDN to pick the closest one.
const mirrors = ["cdn1.example.com", "cdn2.example.com", "cdn3.example.com",
                 "cdn4.example.com", "cdn5.example.com", "cdn6.example.com"];
for (const m of mirrors) { dns.resolve4(m, () => {}); }
