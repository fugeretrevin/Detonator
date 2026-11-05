import React from "react";
import { AbsoluteFill, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { C, MONO } from "../theme";
import { prog, rise } from "../anim";
import { Logo, Stage } from "../components/ui";

// 2:46–2:54 closing line, 2:54–3:00 end card.

export const S7Closing: React.FC = () => {
  const frame = useCurrentFrame();
  const out = 1 - prog(frame, 226, 14);
  return (
    <Stage>
      <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", padding: 160, opacity: out }}>
        <div style={{ fontSize: 40, color: C.muted, textAlign: "center", lineHeight: 1.4, ...rise(frame, 0) }}>
          AI agents are publishing more code than ever.
          <br />
          Traditional code scanning can't see true behavior.
        </div>
        <div style={{ fontSize: 92, fontWeight: 800, letterSpacing: -2.5, lineHeight: 1.1, textAlign: "center", marginTop: 60, ...rise(frame, 100, 36) }}>
          Detonator shows what the code
          <br />
          actually does
        </div>
        <div style={{ fontSize: 56, fontWeight: 700, color: C.red, marginTop: 28, ...rise(frame, 140) }}>
          before you decide to trust it.
        </div>
      </AbsoluteFill>
    </Stage>
  );
};

export const S8EndCard: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const s = spring({ frame, fps, config: { damping: 14, stiffness: 120 } });
  return (
    <Stage style={{ backgroundImage: "none" }}>
      <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
        <div style={{ transform: `scale(${0.6 + s * 0.4})`, opacity: Math.min(1, s * 1.4) }}>
          <Logo size={300} />
        </div>
        <div style={{ fontSize: 96, fontWeight: 800, letterSpacing: 10, marginTop: 30, ...rise(frame, 14, 24) }}>
          PR DETONATOR
        </div>
        <div style={{ fontSize: 40, color: C.muted, marginTop: 18, ...rise(frame, 26) }}>
          See what your dependencies do before you merge.
        </div>
        <div style={{ fontFamily: MONO, fontSize: 32, color: C.text, marginTop: 44, ...rise(frame, 40) }}>
          github.com/fugeretrevin/Detonator
        </div>
      </AbsoluteFill>
    </Stage>
  );
};
