import React from "react";
import { AbsoluteFill, Img, interpolate, OffthreadVideo, Sequence, staticFile, useCurrentFrame } from "remotion";
import { C, MONO, SANS, W } from "../theme";
import { easeInOut, prog, rise, window } from "../anim";
import { Brand, Kicker, Logo, Panel, Stage } from "../components/ui";

// 0:24–0:55 · Camera intro → swipe-matched whip → what it is → the live PR.

/**
 * In the footage both hands rise at ~5.0 s and sweep to the viewer's right, peaking around
 * 5.5–5.9 s. The whip starts just as the sweep accelerates, and moves the frame the same way.
 */
const WHIP_START = 160; // 5.33 s into the clip
const WHIP_DUR = 22;

const NameTag: React.FC<{ name: string; left: number; delay: number }> = ({ name, left, delay }) => {
  const frame = useCurrentFrame();
  const o = window(frame, 18 + delay, 150, 10);
  const slide = prog(frame, 18 + delay, 16);
  return (
    <div
      style={{
        position: "absolute",
        left,
        bottom: 96,
        opacity: o,
        display: "flex",
        alignItems: "stretch",
        transform: `translateX(${(1 - slide) * -24}px)`,
      }}
    >
      <div style={{ width: 8, background: C.red, borderRadius: 4 }} />
      <div
        style={{
          background: "rgba(11,12,15,0.82)",
          padding: "12px 26px 12px 20px",
          fontFamily: SANS,
          fontSize: 40,
          fontWeight: 700,
          color: C.text,
          letterSpacing: -0.5,
        }}
      >
        {name}
      </div>
    </div>
  );
};

const Camera: React.FC = () => {
  const frame = useCurrentFrame();
  const flash = interpolate(frame, [0, 14], [0.85, 0], { extrapolateRight: "clamp" });
  const settle = interpolate(frame, [0, 20], [1.08, 1], { extrapolateRight: "clamp", easing: easeInOut });
  return (
    <AbsoluteFill style={{ background: "#000" }}>
      <AbsoluteFill style={{ transform: `scale(${settle})` }}>
        <OffthreadVideo src={staticFile("media/intro.mp4")} muted style={{ width: "100%", height: "100%" }} />
      </AbsoluteFill>
      {/* Trevin sits on the left, Jaime on the right. */}
      <NameTag name="Trevin" left={300} delay={20} />
      <NameTag name="Jaime" left={1130} delay={0} />
      <AbsoluteFill style={{ background: "#fff", opacity: flash }} />
    </AbsoluteFill>
  );
};

// ---------------------------------------------------------------- what it is

const IconBox: React.FC<{ kind: "sandbox" | "trace" | "verdict" }> = ({ kind }) => (
  <svg width={92} height={92} viewBox="0 0 92 92" fill="none" stroke={C.text} strokeWidth={5} strokeLinecap="round" strokeLinejoin="round">
    {kind === "sandbox" && (
      <>
        <rect x={8} y={8} width={76} height={76} rx={14} strokeDasharray="10 8" stroke={C.muted} />
        <path d="M46 26 L64 36 L64 58 L46 68 L28 58 L28 36 Z" />
        <path d="M28 36 L46 46 L64 36 M46 46 L46 68" />
      </>
    )}
    {kind === "trace" && (
      <>
        <path d="M6 50 H26 L34 26 L46 72 L56 38 L62 50 H86" stroke={C.red} />
      </>
    )}
    {kind === "verdict" && (
      <>
        <path d="M12 16 H80 V64 H40 L24 80 V64 H12 Z" />
        <circle cx={46} cy={40} r={11} fill={C.red} stroke="none" />
      </>
    )}
  </svg>
);

const Step: React.FC<{ n: number; kind: "sandbox" | "trace" | "verdict"; title: string; body: string; at: number }> = ({
  n,
  kind,
  title,
  body,
  at,
}) => {
  const frame = useCurrentFrame();
  return (
    <div style={{ ...rise(frame, at, 50, 22) }}>
      <Panel
        style={{ width: 520, height: 440, padding: "44px 42px", display: "flex", flexDirection: "column", gap: 26 }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <IconBox kind={kind} />
          <span style={{ fontFamily: MONO, fontSize: 30, color: C.dim }}>0{n}</span>
        </div>
        <div style={{ fontSize: 42, fontWeight: 700, lineHeight: 1.15, letterSpacing: -0.5 }}>{title}</div>
        <div style={{ fontSize: 28, color: C.muted, lineHeight: 1.4 }}>{body}</div>
      </Panel>
    </div>
  );
};

const WhatItIs: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <Stage>
      <AbsoluteFill style={{ alignItems: "center", paddingTop: 130 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 30, ...rise(frame, 18) }}>
          <Logo size={128} />
          <div>
            <div style={{ fontSize: 84, fontWeight: 800, letterSpacing: -2 }}>PR Detonator</div>
            <Kicker color={C.muted} style={{ marginTop: 6 }}>
              A GitHub App
            </Kicker>
          </div>
        </div>
        <div style={{ display: "flex", gap: 44, marginTop: 90 }}>
          <Step n={1} kind="sandbox" at={60} title="Runs the install in isolation" body="Every PR is installed in a separate, throwaway environment." />
          <Step n={2} kind="trace" at={130} title="Traces it through the kernel" body="Processes and network activity, recorded as they happen." />
          <Step n={3} kind="verdict" at={205} title="Posts a verdict on the PR" body="Evidence-backed, right where the merge decision is made." />
        </div>
      </AbsoluteFill>
    </Stage>
  );
};

// ---------------------------------------------------------------- the live PR

type Shot = {
  src: string;
  region: [number, number, number, number]; // source px
  mark?: [number, number, number, number]; // source px
  caption: string;
  from: number;
  to: number;
};

const SRC_W = 2560;
const SHOTS: Shot[] = [
  { src: "media/pr-conversation.png", region: [48, 380, 1500, 260], caption: "A version bump, written like any Dependabot PR", from: 0, to: 64 },
  { src: "media/pr-files.png", region: [690, 790, 1806, 400], mark: [712, 1046, 1762, 80], caption: "One changed line: color-helper 1.0.0 → 1.0.1", from: 60, to: 128 },
  { src: "media/pr-conversation.png", region: [200, 1540, 1590, 340], mark: [212, 1690, 1566, 100], caption: "Stated intent vs. what the install actually did", from: 124, to: 192 },
  { src: "media/pr-conversation.png", region: [150, 3730, 1650, 400], mark: [212, 4040, 1410, 72], caption: "Raw-IP connection, no DNS lookup, traced in the kernel", from: 188, to: 256 },
  { src: "media/pr-checks.png", region: [62, 684, 2386, 470], mark: [540, 1088, 540, 72], caption: "The check fails, so the merge is blocked", from: 252, to: 320 },
  { src: "media/pr-files.png", region: [690, 790, 1580, 912], mark: [720, 1262, 1560, 96], caption: "Attributed inline to the dependency it came from", from: 316, to: 390 },
  { src: "media/pr-conversation.png", region: [180, 2976, 1632, 410], mark: [212, 3236, 744, 68], caption: "A full report on intent: predicted vs. observed", from: 386, to: 450 },
];

const MAX_W = 1560;
const MAX_H = 600;

const ShotView: React.FC<{ shot: Shot }> = ({ shot }) => {
  const frame = useCurrentFrame(); // local to the shot
  const len = shot.to - shot.from;
  const [x, y, w, h] = shot.region;
  const width = Math.min(MAX_W, (MAX_H * w) / h);
  const scale = width / w;
  const height = h * scale;
  const zoom = interpolate(frame, [0, len], [1, 1.05]);
  const markP = prog(frame, 14, 14);
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", opacity: window(frame, 0, len, 8) }}>
      <Panel style={{ overflow: "hidden", padding: 0, background: "#0d1117", marginTop: -40 }}>
        <div style={{ width, height, overflow: "hidden", position: "relative" }}>
          <div style={{ position: "absolute", inset: 0, transform: `scale(${zoom})`, transformOrigin: "50% 50%" }}>
            <Img
              src={staticFile(shot.src)}
              style={{ position: "absolute", left: -x * scale, top: -y * scale, width: SRC_W * scale, maxWidth: "none" }}
            />
            {shot.mark && (
              <div
                style={{
                  position: "absolute",
                  left: (shot.mark[0] - x) * scale - 8,
                  top: (shot.mark[1] - y) * scale - 6,
                  width: shot.mark[2] * scale + 16,
                  height: shot.mark[3] * scale + 12,
                  border: `4px solid ${C.red}`,
                  borderRadius: 10,
                  boxShadow: `0 0 0 9999px rgba(0,0,0,${0.35 * markP})`,
                  opacity: markP,
                }}
              />
            )}
          </div>
        </div>
      </Panel>
      <div style={{ position: "absolute", bottom: 110, fontSize: 40, fontWeight: 600, ...rise(frame, 6, 16) }}>
        {shot.caption}
      </div>
    </AbsoluteFill>
  );
};

const LivePR: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <Stage>
      <Brand />
      <div style={{ position: "absolute", right: 64, top: 64, opacity: prog(frame, 0, 12) }}>
        <Kicker color={C.muted}>Real PR · pr-detonator-demo/demo-target #12</Kicker>
      </div>
      {SHOTS.map((s, i) => (
        <Sequence key={i} from={s.from} durationInFrames={s.to - s.from} layout="none">
          <ShotView shot={s} />
        </Sequence>
      ))}
    </Stage>
  );
};

// ---------------------------------------------------------------- assembly

export const S2Meet: React.FC = () => {
  const frame = useCurrentFrame();
  const p = prog(frame, WHIP_START, WHIP_DUR, easeInOut);
  const blur = Math.sin(p * Math.PI) * 34;
  const shift = W * 1.08;
  const streaks = Math.sin(p * Math.PI);

  return (
    <AbsoluteFill style={{ background: C.bg }}>
      {/* Explainer runs from the whip until 0:40, then the PR walkthrough to 0:55. */}
      <Sequence from={WHIP_START} durationInFrames={480 - WHIP_START} layout="none">
        <AbsoluteFill style={{ transform: `translateX(${(p - 1) * shift}px)`, filter: `blur(${blur}px)` }}>
          <WhatItIs />
        </AbsoluteFill>
      </Sequence>
      <Sequence from={480} layout="none">
        <AbsoluteFill style={{ opacity: prog(frame, 480, 12) }}>
          <LivePR />
        </AbsoluteFill>
      </Sequence>
      {/* Camera clip, whipped out to the right with the hands. */}
      <Sequence durationInFrames={WHIP_START + WHIP_DUR} layout="none">
        <AbsoluteFill style={{ transform: `translateX(${p * shift}px)`, filter: `blur(${blur}px)` }}>
          <Camera />
        </AbsoluteFill>
      </Sequence>
      {/* Speed streaks sell the whip. */}
      {streaks > 0.01 && (
        <AbsoluteFill style={{ pointerEvents: "none" }}>
          {Array.from({ length: 14 }).map((_, i) => (
            <div
              key={i}
              style={{
                position: "absolute",
                top: 40 + i * 74 + ((i * 37) % 30),
                left: ((i * 211) % 900) - 200 + p * 900,
                width: 700 + ((i * 97) % 500),
                height: 3 + (i % 3),
                background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.55), transparent)",
                opacity: streaks * 0.8,
              }}
            />
          ))}
        </AbsoluteFill>
      )}
    </AbsoluteFill>
  );
};
