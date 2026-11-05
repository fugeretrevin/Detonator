import React from "react";
import { AbsoluteFill, useCurrentFrame } from "remotion";
import { C, MONO } from "../theme";
import { prog, rise, window } from "../anim";
import { Brand, Chip, Kicker, Panel, Stage, Sub } from "../components/ui";

// 2:19–2:46 · Benign results, famous attacks, what's next. Figures exactly as the script gives them.

const Popular: React.FC = () => {
  const frame = useCurrentFrame();
  const n = Math.round(prog(frame, 6, 34) * 98);
  const bar = prog(frame, 50, 30);
  const segs = [
    { n: 95, label: "Clean", color: C.green },
    { n: 3, label: "Needs review", color: C.amber },
    { n: 0, label: "Blocked", color: C.red },
  ];
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={rise(frame, 0)}>
        <Kicker style={{ textAlign: "center" }}>Proven results</Kicker>
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 28, marginTop: 10 }}>
        <div style={{ fontSize: 220, fontWeight: 800, letterSpacing: -8, lineHeight: 1 }}>{n}</div>
        <div style={{ fontSize: 64, fontWeight: 700, ...rise(frame, 10) }}>popular packages</div>
      </div>
      <div style={{ width: 1400, height: 40, borderRadius: 20, background: C.panel2, overflow: "hidden", display: "flex", marginTop: 50 }}>
        {segs.map((s) => (
          <div key={s.label} style={{ width: `${(s.n / 98) * 100 * bar}%`, background: s.color }} />
        ))}
      </div>
      <div style={{ display: "flex", gap: 90, marginTop: 50 }}>
        {segs.map((s, i) => (
          <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 20, ...rise(frame, 80 + i * 16) }}>
            <span style={{ fontSize: 96, fontWeight: 800, color: s.color, letterSpacing: -3 }}>{s.n}</span>
            <span style={{ fontSize: 36, fontWeight: 600 }}>{s.label}</span>
          </div>
        ))}
      </div>
    </AbsoluteFill>
  );
};

const AttackCard: React.FC<{ name: string; meta: string; at: number }> = ({ name, meta, at }) => {
  const frame = useCurrentFrame();
  const stamp = prog(frame, at + 22, 10);
  return (
    <div style={rise(frame, at, 40)}>
      <Panel style={{ width: 720, padding: "40px 44px" }}>
        <Kicker color={C.muted}>{meta}</Kicker>
        <div style={{ fontSize: 58, fontWeight: 800, letterSpacing: -1.5, marginTop: 12 }}>{name}</div>
        <div style={{ marginTop: 28, opacity: stamp, transform: `scale(${1.3 - stamp * 0.3})`, transformOrigin: "left center" }}>
          <Chip color={C.red} bg={C.redSoft} style={{ fontSize: 32 }}>
            ● Blocked
          </Chip>
        </div>
      </Panel>
    </div>
  );
};

const Famous: React.FC = () => {
  const frame = useCurrentFrame();
  const overlays = [
    "5/5 selected attacks blocked",
    "ua-parser-js reconstruction: blocked in 12.4 seconds",
    "$0.0181 mean model API cost per PR, excluding infrastructure",
  ];
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={rise(frame, 0)}>
        <Kicker style={{ textAlign: "center" }}>Validated against famous attack patterns</Kicker>
      </div>
      <div style={{ display: "flex", gap: 50, marginTop: 50 }}>
        <AttackCard name="Shai-Hulud worm" meta="npm worm · 2025" at={10} />
        <AttackCard name="ua-parser-js hijack" meta="account takeover · 2021" at={30} />
      </div>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 18, marginTop: 60 }}>
        {overlays.map((t, i) => (
          <div key={t} style={{ fontFamily: MONO, fontSize: 28, color: C.muted, ...rise(frame, 80 + i * 24, 14) }}>
            {t}
          </div>
        ))}
      </div>
    </AbsoluteFill>
  );
};

const Next: React.FC = () => {
  const frame = useCurrentFrame();
  const TILE = 150;
  const GAP = 26;
  const speed = 5;
  const scanX = 960;
  const names = Array.from({ length: 13 });
  return (
    <AbsoluteFill style={{ alignItems: "center", paddingTop: 210 }}>
      <div style={rise(frame, 0)}>
        <Kicker style={{ textAlign: "center" }}>What's next</Kicker>
      </div>
      <div style={{ fontSize: 68, fontWeight: 800, letterSpacing: -1.5, marginTop: 14, textAlign: "center", ...rise(frame, 8) }}>
        Monitor new releases continuously
      </div>
      <div style={{ fontSize: 36, color: C.muted, marginTop: 18, ...rise(frame, 16) }}>
        and warn developers before risky packages spread.
      </div>
      <div style={{ position: "absolute", top: 640, left: 0, right: 0, height: 200, opacity: prog(frame, 20, 14) }}>
        {names.map((_, i) => {
          const x = 1100 + i * (TILE + GAP) - frame * speed;
          const passed = x + TILE / 2 < scanX;
          const risky = i === 3;
          return (
            <div
              key={i}
              style={{
                position: "absolute",
                left: x,
                top: 30,
                width: TILE,
                height: TILE,
                borderRadius: 20,
                background: passed && risky ? C.amberSoft : C.panel,
                border: `3px solid ${passed ? (risky ? C.amber : C.green) : C.border}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontFamily: MONO,
                fontSize: 22,
                color: passed ? (risky ? C.amber : C.green) : C.dim,
              }}
            >
              {passed ? (risky ? "⚠ warn" : "✓") : "npm"}
            </div>
          );
        })}
        <div style={{ position: "absolute", left: scanX - 3, top: 0, width: 6, height: 210, background: C.red, borderRadius: 3, boxShadow: `0 0 24px ${C.red}` }} />
      </div>
    </AbsoluteFill>
  );
};

export const S6Results: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <Stage>
      <Brand />
      <AbsoluteFill style={{ opacity: window(frame, 0, 336, 12) }}>
        <Popular />
      </AbsoluteFill>
      <AbsoluteFill style={{ opacity: window(frame, 330, 566, 12) }}>
        <Sub from={330}>
          <Famous />
        </Sub>
      </AbsoluteFill>
      <AbsoluteFill style={{ opacity: prog(frame, 560, 12) }}>
        <Sub from={560}>
          <Next />
        </Sub>
      </AbsoluteFill>
    </Stage>
  );
};
