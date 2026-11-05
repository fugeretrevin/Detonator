import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { C, MONO } from "../theme";
import { easeInOut, lerp, prog, rise, window } from "../anim";
import { Chip, DrawPath, Kicker, Panel, Stage, Sub, Typed } from "../components/ui";

// 0:00–0:24 · One-line bump → install runs code → unexpected connection → the question.

const DiffLine: React.FC<{ sign: " " | "-" | "+"; children: React.ReactNode; glow?: number }> = ({
  sign,
  children,
  glow = 0,
}) => {
  const bg = sign === "+" ? C.diffAdd : sign === "-" ? C.diffDel : "transparent";
  const col = sign === "+" ? C.green : sign === "-" ? "#F85149" : C.dim;
  return (
    <div
      style={{
        display: "flex",
        gap: 28,
        padding: "8px 32px",
        background: bg,
        boxShadow: glow ? `inset 6px 0 0 ${C.green}` : undefined,
      }}
    >
      <span style={{ color: col, width: 20 }}>{sign}</span>
      <span>{children}</span>
    </div>
  );
};

const DiffCard: React.FC = () => {
  const frame = useCurrentFrame();
  const glow = prog(frame, 40, 16);
  return (
    <Panel style={{ width: 980, overflow: "hidden" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          padding: "20px 32px",
          borderBottom: `2px solid ${C.border}`,
          fontFamily: MONO,
          fontSize: 26,
          color: C.muted,
        }}
      >
        <span style={{ color: C.text }}>package.json</span>
        <span>
          <span style={{ color: C.green }}>+1</span> <span style={{ color: "#F85149" }}>−1</span>
        </span>
      </div>
      <div style={{ fontFamily: MONO, fontSize: 36, padding: "18px 0", color: C.text }}>
        <DiffLine sign=" ">
          <span style={{ color: C.muted }}>"dependencies": {"{"}</span>
        </DiffLine>
        <DiffLine sign="-">
          {"  "}"color-helper": <span style={{ color: "#FFA198" }}>"1.0.0"</span>
        </DiffLine>
        <DiffLine sign="+" glow={glow}>
          {"  "}"color-helper": <span style={{ color: "#7EE787" }}>"1.0.1"</span>
        </DiffLine>
        <DiffLine sign=" ">
          <span style={{ color: C.muted }}>{"}"}</span>
        </DiffLine>
      </div>
    </Panel>
  );
};

const Terminal: React.FC = () => (
  <Panel style={{ width: 860, overflow: "hidden" }}>
    <div style={{ display: "flex", gap: 10, padding: "18px 24px", borderBottom: `2px solid ${C.border}` }}>
      {["#3A3D45", "#3A3D45", "#3A3D45"].map((c, i) => (
        <span key={i} style={{ width: 16, height: 16, borderRadius: 8, background: c }} />
      ))}
    </div>
    <div style={{ fontFamily: MONO, fontSize: 34, lineHeight: 1.75, padding: "22px 34px", minHeight: 260 }}>
      <div>
        <span style={{ color: C.green }}>$ </span>
        <Typed text="npm install" start={0} dur={16} />
      </div>
      <Line at={30} color={C.muted}>
        &gt; color-helper@1.0.1 <span style={{ color: C.amber }}>postinstall</span>
      </Line>
      <Line at={44} color={C.muted}>
        &gt; node install.js
      </Line>
      <Line at={70} color={C.red}>
        ● running before your app starts…
      </Line>
    </div>
  </Panel>
);

const Line: React.FC<{ at: number; color: string; children: React.ReactNode }> = ({ at, color, children }) => {
  const frame = useCurrentFrame();
  return <div style={{ color, opacity: prog(frame, at, 6) }}>{children}</div>;
};

const Node: React.FC<{ title: string; sub: string; accent?: string; style?: React.CSSProperties }> = ({
  title,
  sub,
  accent,
  style,
}) => (
  <Panel accent={accent} style={{ width: 440, padding: "30px 34px", ...style }}>
    <div style={{ fontFamily: MONO, fontSize: 34, fontWeight: 700, color: accent ?? C.text }}>{title}</div>
    <div style={{ fontSize: 26, color: C.muted, marginTop: 10 }}>{sub}</div>
  </Panel>
);

const Network: React.FC = () => {
  const frame = useCurrentFrame(); // local to the beat
  const packets = [0, 1, 2].map((i) => {
    const t = ((frame - 40 - i * 14) / 42) % 1;
    return frame > 40 + i * 14 ? t : -1;
  });
  const threats = ["Reaches the network", "Reads credentials", "Runs hidden payloads"];
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={{ position: "relative", width: 1500, height: 300 }}>
        <div style={{ position: "absolute", left: 0, top: 40, ...rise(frame, 0) }}>
          <Node title="npm install" sub="your CI runner or laptop" />
        </div>
        <svg width={1500} height={300} style={{ position: "absolute", left: 0, top: 0 }}>
          <DrawPath d="M 460 120 L 1040 120" len={580} start={14} dur={24} color={C.red} width={5} />
          {packets.map((t, i) =>
            t >= 0 ? <circle key={i} cx={lerp(t, 470, 1030)} cy={120} r={9} fill={C.red} /> : null,
          )}
        </svg>
        <div style={{ position: "absolute", right: 0, top: 40, ...rise(frame, 30) }}>
          <Node title="203.0.113.10:4444" sub="unexpected outbound connection" accent={C.red} />
        </div>
      </div>
      <div style={{ display: "flex", gap: 28, marginTop: 70 }}>
        {threats.map((t, i) => (
          <div key={t} style={rise(frame, 70 + i * 26)}>
            <Chip color={C.red} bg={C.redSoft}>
              {t}
            </Chip>
          </div>
        ))}
      </div>
    </AbsoluteFill>
  );
};

const Question: React.FC = () => {
  const frame = useCurrentFrame();
  const words = ["How", "do", "you", "know", "what", "you're", "actually", "merging?"];
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", padding: 160 }}>
      <div style={{ fontSize: 104, fontWeight: 800, lineHeight: 1.12, textAlign: "center", letterSpacing: -2 }}>
        {words.map((w, i) => (
          <span
            key={i}
            style={{
              display: "inline-block",
              marginRight: 28,
              color: i >= 6 ? C.red : C.text,
              ...rise(frame, i * 6, 40),
            }}
          >
            {w}
          </span>
        ))}
      </div>
    </AbsoluteFill>
  );
};

export const S1Hook: React.FC = () => {
  const frame = useCurrentFrame();

  // Beat A/B: diff card, then it slides left as the terminal arrives.
  const toLeft = prog(frame, 150, 26, easeInOut);
  const abOpacity = window(frame, 0, 340, 14);
  const termIn = rise(frame, 168, 40);

  // Exit: punch in, blur and flash into the camera footage.
  const exitP = prog(frame, 676, 44, (t) => t * t);
  const exitStyle: React.CSSProperties = {
    transform: `scale(${1 + exitP * 0.7})`,
    filter: `blur(${exitP * 26}px)`,
    opacity: 1 - prog(frame, 700, 20),
  };
  const flash = interpolate(frame, [690, 712, 720], [0, 0.85, 0.85], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <Stage>
      <AbsoluteFill style={exitStyle}>
        {/* A + B */}
        <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", opacity: abOpacity }}>
          <div style={{ position: "absolute", top: 150, ...rise(frame, 0) }}>
            <Kicker color={C.muted}>Pull request · 1 file changed</Kicker>
          </div>
          <div style={{ transform: `translateX(${toLeft * -470}px) scale(${1 - toLeft * 0.18})` }}>
            <div style={rise(frame, 6, 40)}>
              <DiffCard />
              <div style={{ marginTop: 34, display: "flex", justifyContent: "center", opacity: prog(frame, 70, 14) * (1 - toLeft) }}>
                <Chip color={C.green} bg={C.greenSoft}>
                  ✓ Looks harmless
                </Chip>
              </div>
            </div>
          </div>
          <div style={{ position: "absolute", right: 110, ...termIn }}>
            <Sub from={175}>
              <Terminal />
            </Sub>
          </div>
        </AbsoluteFill>

        {/* C */}
        <AbsoluteFill style={{ opacity: window(frame, 336, 520, 14) }}>
          <Sub from={336}>
            <Network />
          </Sub>
        </AbsoluteFill>

        {/* D */}
        <AbsoluteFill style={{ opacity: prog(frame, 516, 12) }}>
          <Sub from={516}>
            <Question />
          </Sub>
        </AbsoluteFill>
      </AbsoluteFill>
      <AbsoluteFill style={{ background: "#fff", opacity: flash }} />
    </Stage>
  );
};
