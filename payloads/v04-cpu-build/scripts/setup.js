// Simulate a CPU-bound optimizing build pass. No network, no file access.
const end = Date.now() + 6000;
let x = 0;
while (Date.now() < end) { x += Math.sqrt(x + 1) % 7; }
