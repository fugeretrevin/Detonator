import { Easing, interpolate } from "remotion";

export const easeOut = Easing.bezier(0.16, 1, 0.3, 1);
export const easeInOut = Easing.bezier(0.65, 0, 0.35, 1);

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;

/** 0→1 progress between `start` and `start + dur`, eased. */
export const prog = (frame: number, start: number, dur = 18, easing = easeOut) =>
  interpolate(frame, [start, start + dur], [0, 1], { ...clamp, easing });

/** Fade + rise entrance. */
export const rise = (frame: number, start: number, dist = 28, dur = 20) => {
  const p = prog(frame, start, dur);
  return { opacity: p, transform: `translateY(${(1 - p) * dist}px)` };
};

/** Opacity for a block that fades in at `start` and out ending at `end`. */
export const window = (frame: number, start: number, end: number, fade = 12) =>
  Math.min(prog(frame, start, fade), 1 - prog(frame, end - fade, fade, easeInOut));

export const lerp = (p: number, a: number, b: number) => a + (b - a) * p;
