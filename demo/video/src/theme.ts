import { loadFont as loadInter } from "@remotion/google-fonts/Inter";
import { loadFont as loadMono } from "@remotion/google-fonts/JetBrainsMono";

export const FPS = 30;
export const W = 1920;
export const H = 1080;

const inter = loadInter("normal", {
  weights: ["400", "500", "600", "700", "800"],
  subsets: ["latin"],
});
const mono = loadMono("normal", { weights: ["400", "500", "700"], subsets: ["latin"] });

export const SANS = inter.fontFamily;
export const MONO = mono.fontFamily;

// Palette follows the logo: ink, charcoal, white, one red accent. Amber/green only for verdicts.
export const C = {
  bg: "#0B0C0F",
  bg2: "#111318",
  panel: "#15171C",
  panel2: "#1B1E24",
  border: "#2A2E37",
  text: "#F4F5F7",
  muted: "#9AA0AB",
  dim: "#5E6470",
  red: "#E5382D",
  redSoft: "rgba(229,56,45,0.16)",
  amber: "#F2A93B",
  amberSoft: "rgba(242,169,59,0.16)",
  green: "#3FB950",
  greenSoft: "rgba(63,185,80,0.16)",
  diffAdd: "rgba(46,160,67,0.22)",
  diffDel: "rgba(248,81,73,0.20)",
};

// Section boundaries in frames, straight from the script's timestamps.
export const T = {
  hook: { from: 0, dur: 24 * FPS },
  meet: { from: 24 * FPS, dur: 31 * FPS },
  discovery: { from: 55 * FPS, dur: 22 * FPS },
  system: { from: 77 * FPS, dur: 18 * FPS },
  meta: { from: 95 * FPS, dur: 44 * FPS },
  results: { from: 139 * FPS, dur: 27 * FPS },
  closing: { from: 166 * FPS, dur: 8 * FPS },
  end: { from: 174 * FPS, dur: 6 * FPS },
};
export const TOTAL = 180 * FPS;
