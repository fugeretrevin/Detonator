import React from "react";
import { AbsoluteFill, Img, Sequence, staticFile, useCurrentFrame } from "remotion";
import { C, MONO, SANS } from "../theme";
import { prog } from "../anim";

/** Re-times children so their useCurrentFrame() is 0 at `from` (and hidden before it). */
export const Sub: React.FC<{ from: number; children: React.ReactNode }> = ({ from, children }) => (
  <Sequence from={from} layout="none">
    {children}
  </Sequence>
);

/** Dark stage with a faint dot grid, shared by every graphic scene. */
export const Stage: React.FC<{ children: React.ReactNode; style?: React.CSSProperties }> = ({
  children,
  style,
}) => (
  <AbsoluteFill
    style={{
      background: C.bg,
      backgroundImage: `radial-gradient(${C.border} 1px, transparent 1px)`,
      backgroundSize: "36px 36px",
      fontFamily: SANS,
      color: C.text,
      ...style,
    }}
  >
    {children}
  </AbsoluteFill>
);

export const Panel: React.FC<{
  children: React.ReactNode;
  style?: React.CSSProperties;
  accent?: string;
}> = ({ children, style, accent }) => (
  <div
    style={{
      background: C.panel,
      border: `2px solid ${accent ?? C.border}`,
      borderRadius: 20,
      boxShadow: accent ? `0 0 0 6px ${accent}22` : "0 24px 60px rgba(0,0,0,0.45)",
      ...style,
    }}
  >
    {children}
  </div>
);

export const Kicker: React.FC<{ children: React.ReactNode; color?: string; style?: React.CSSProperties }> = ({
  children,
  color = C.red,
  style,
}) => (
  <div
    style={{
      fontFamily: MONO,
      fontSize: 22,
      fontWeight: 500,
      letterSpacing: 3,
      textTransform: "uppercase",
      color,
      ...style,
    }}
  >
    {children}
  </div>
);

export const Chip: React.FC<{
  children: React.ReactNode;
  color?: string;
  bg?: string;
  style?: React.CSSProperties;
}> = ({ children, color = C.text, bg = C.panel2, style }) => (
  <div
    style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 12,
      padding: "12px 22px",
      borderRadius: 999,
      background: bg,
      border: `2px solid ${color}55`,
      color,
      fontSize: 28,
      fontWeight: 600,
      whiteSpace: "nowrap",
      ...style,
    }}
  >
    {children}
  </div>
);

export const Dot: React.FC<{ color: string; size?: number }> = ({ color, size = 16 }) => (
  <span
    style={{ width: size, height: size, borderRadius: size, background: color, display: "inline-block" }}
  />
);

/**
 * The logo's ink outlines and shock lines vanish on a dark stage, so it always sits on a
 * white badge here (the same way it would on a light page).
 */
export const Logo: React.FC<{ size: number; style?: React.CSSProperties }> = ({ size, style }) => (
  <div
    style={{
      width: size,
      height: size,
      borderRadius: size * 0.24,
      background: "#FFFFFF",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      flexShrink: 0,
      ...style,
    }}
  >
    <Img src={staticFile("logo.svg")} style={{ width: size * 0.86, height: size * 0.86 }} />
  </div>
);

/** Small persistent brand mark for graphic scenes. */
export const Brand: React.FC = () => (
  <div
    style={{
      position: "absolute",
      left: 64,
      top: 52,
      display: "flex",
      alignItems: "center",
      gap: 14,
      fontSize: 26,
      fontWeight: 700,
      color: C.text,
      opacity: 0.9,
    }}
  >
    <Logo size={52} />
    PR Detonator
  </div>
);

/**
 * Show a rectangular region (in source pixels) of a large screenshot, scaled to `width`.
 * `zoom` > 1 pushes in on the region's centre for a slow camera move.
 */
export const Crop: React.FC<{
  src: string;
  srcW: number;
  region: [number, number, number, number];
  width: number;
  zoom?: number;
  style?: React.CSSProperties;
}> = ({ src, srcW, region, width, zoom = 1, style }) => {
  const [x, y, w, h] = region;
  const scale = (width / w) * zoom;
  const height = (width * h) / w;
  const offX = -x * scale - (w * scale - width) / 2;
  const offY = -y * scale - (h * scale - height) / 2;
  return (
    <div style={{ width, height, overflow: "hidden", position: "relative", ...style }}>
      <Img
        src={staticFile(src)}
        style={{ position: "absolute", left: offX, top: offY, width: srcW * scale, maxWidth: "none" }}
      />
    </div>
  );
};

/** Text that types out between `start` and `start + dur`. */
export const Typed: React.FC<{ text: string; start: number; dur: number; style?: React.CSSProperties }> = ({
  text,
  start,
  dur,
  style,
}) => {
  const frame = useCurrentFrame();
  const n = Math.round(prog(frame, start, dur, (t) => t) * text.length);
  return <span style={style}>{text.slice(0, n)}</span>;
};

/** An SVG path that draws itself. Pass the path length (approximate is fine). */
export const DrawPath: React.FC<{
  d: string;
  len: number;
  start: number;
  dur?: number;
  color?: string;
  width?: number;
  dashed?: boolean;
}> = ({ d, len, start, dur = 20, color = C.muted, width = 4 }) => {
  const frame = useCurrentFrame();
  const p = prog(frame, start, dur);
  return (
    <path
      d={d}
      fill="none"
      stroke={color}
      strokeWidth={width}
      strokeLinecap="round"
      strokeDasharray={len}
      strokeDashoffset={(1 - p) * len}
    />
  );
};
