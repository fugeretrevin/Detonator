import React from "react";
import { AbsoluteFill, useCurrentFrame } from "remotion";
import { C, MONO } from "../theme";
import { lerp, prog, rise } from "../anim";
import { Brand, Chip, DrawPath, Kicker, Panel, Stage } from "../components/ui";

// 1:17–1:35 · GitHub → Modal brain → EC2 chamber (Docker + Tetragon + DNS) → evidence → verdict.

const Bullets: React.FC<{ items: string[]; at: number; step?: number }> = ({ items, at, step = 14 }) => {
  const frame = useCurrentFrame();
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 22 }}>
      {items.map((t, i) => (
        <div key={t} style={{ fontSize: 27, color: C.muted, display: "flex", gap: 14, ...rise(frame, at + i * step, 12, 12) }}>
          <span style={{ color: C.dim }}>—</span>
          {t}
        </div>
      ))}
    </div>
  );
};

const Packet: React.FC<{ x1: number; x2: number; y: number; start: number; color?: string }> = ({
  x1,
  x2,
  y,
  start,
  color = C.text,
}) => {
  const frame = useCurrentFrame();
  const t = (frame - start) / 26;
  if (t < 0 || t > 1) return null;
  return <circle cx={lerp(t, x1, x2)} cy={y} r={9} fill={color} />;
};

const Lane: React.FC<{ x1: number; x2: number; y: number; at: number; label: string; color?: string; above?: boolean }> = ({
  x1,
  x2,
  y,
  at,
  label,
  color = C.muted,
  above = true,
}) => {
  const frame = useCurrentFrame();
  const dir = x2 > x1 ? 1 : -1;
  const tip = x2;
  return (
    <g>
      <DrawPath d={`M ${x1} ${y} L ${x2} ${y}`} len={Math.abs(x2 - x1)} start={at} dur={14} color={color} width={4} />
      <path
        d={`M ${tip - dir * 16} ${y - 11} L ${tip} ${y} L ${tip - dir * 16} ${y + 11}`}
        fill="none"
        stroke={color}
        strokeWidth={4}
        strokeLinecap="round"
        opacity={prog(frame, at + 12, 6)}
      />
      <text
        x={(x1 + x2) / 2}
        y={above ? y - 20 : y + 40}
        textAnchor="middle"
        fill={color}
        style={{ fontFamily: MONO, fontSize: 22 }}
        opacity={prog(frame, at + 8, 10)}
      >
        {label}
      </text>
    </g>
  );
};

export const S4System: React.FC = () => {
  const frame = useCurrentFrame();
  const witness = prog(frame, 430, 14);
  return (
    <Stage>
      <Brand />
      <div style={{ position: "absolute", left: 100, top: 150, ...rise(frame, 0) }}>
        <Kicker>How it works</Kicker>
        <div style={{ fontSize: 60, fontWeight: 800, letterSpacing: -1.5, marginTop: 12 }}>
          The model predicts. The kernel verifies.
        </div>
      </div>

      {/* GitHub */}
      <div style={{ position: "absolute", left: 90, top: 470, ...rise(frame, 6) }}>
        <Panel style={{ width: 300, height: 250, padding: 30, display: "flex", flexDirection: "column", justifyContent: "center" }}>
          <div style={{ fontSize: 40, fontWeight: 800 }}>GitHub</div>
          <div style={{ fontSize: 26, color: C.muted, marginTop: 10 }}>pull request opened</div>
        </Panel>
      </div>

      {/* Modal brain */}
      <div style={{ position: "absolute", left: 560, top: 400, ...rise(frame, 24) }}>
        <Panel style={{ width: 460, height: 420, padding: "34px 36px" }}>
          <Kicker color={C.muted}>Modal</Kicker>
          <div style={{ fontSize: 46, fontWeight: 800, marginTop: 6 }}>The Brain</div>
          <Bullets at={40} items={["Webhooks", "Job coordination", "API calls", "Inference"]} />
          <div style={{ position: "absolute", left: 36, bottom: 30, ...rise(frame, 360, 16) }}>
            <Chip color={C.text} style={{ fontSize: 24, padding: "8px 18px" }}>
              Meta · reasons about intent
            </Chip>
          </div>
        </Panel>
      </div>

      {/* EC2 chamber */}
      <div style={{ position: "absolute", left: 1190, top: 330, ...rise(frame, 170) }}>
        <Panel style={{ width: 640, height: 560, padding: "34px 36px", position: "relative" }}>
          <Kicker color={C.muted}>AWS EC2</Kicker>
          <div style={{ fontSize: 46, fontWeight: 800, marginTop: 6 }}>The Chamber</div>
          <Bullets at={186} items={["Dedicated Linux VM", "Docker containers", "Tetragon tracing", "Logging"]} />
          <div style={{ display: "flex", gap: 16, marginTop: 30 }}>
            <div style={rise(frame, 250)}>
              <Chip color={C.red} bg={C.redSoft} style={{ fontSize: 24, padding: "10px 18px" }}>
                Tetragon · what the code does
              </Chip>
            </div>
            <div style={rise(frame, 262)}>
              <Chip style={{ fontSize: 24, padding: "10px 18px" }}>DNS capture</Chip>
            </div>
          </div>
        </Panel>
        <div style={{ display: "flex", gap: 16, marginTop: 22, opacity: witness, transform: `translateY(${(1 - witness) * 14}px)` }}>
          <Chip color={C.green} bg={C.greenSoft} style={{ fontSize: 26 }}>
            ✓ Sensor witness
          </Chip>
          <Chip color={C.green} bg={C.greenSoft} style={{ fontSize: 26 }}>
            ✓ Verified execution
          </Chip>
        </div>
      </div>

      <svg width={1920} height={1080} style={{ position: "absolute", left: 0, top: 0 }}>
        <Lane x1={392} x2={556} y={560} at={18} label="webhook" />
        <Lane x1={1022} x2={1186} y={560} at={160} label="job" />
        <Lane x1={1186} x2={1022} y={680} at={300} label="evidence" color={C.red} above={false} />
        <Lane x1={556} x2={392} y={680} at={330} label="verdict" color={C.red} above={false} />
        <Packet x1={392} x2={556} y={560} start={30} />
        <Packet x1={1022} x2={1186} y={560} start={172} />
        <Packet x1={1186} x2={1022} y={680} start={312} color={C.red} />
        <Packet x1={556} x2={392} y={680} start={342} color={C.red} />
        <Packet x1={1186} x2={1022} y={680} start={440} color={C.red} />
        <Packet x1={556} x2={392} y={680} start={470} color={C.red} />
      </svg>
    </Stage>
  );
};
