import React from "react";
import { AbsoluteFill, useCurrentFrame } from "remotion";
import { C, MONO } from "../theme";
import { prog, rise, window } from "../anim";
import { Brand, Chip, Kicker, Panel, Stage, Sub } from "../components/ui";

// 1:35–2:19 · Predict → Screen → Analyze → Investigate, the rules floor, then the blind-test result.

const STAGES = [
  { name: "Predict", model: "Muse Spark", body: "Before execution, predicts expected behavior from the PR." },
  { name: "Screen", model: "Llama Prompt Guard 2", body: "Screens untrusted PR text for prompt attacks." },
  { name: "Analyze", model: "Muse Spark", body: "Compares the prediction with the kernel trace and decodes payloads." },
  { name: "Investigate", model: "Muse Spark + tools", body: "Digs into borderline cases without touching anything." },
];

const Stages: React.FC = () => {
  const frame = useCurrentFrame();
  const active = frame < 380 ? -1 : Math.floor((frame - 380) / 45) % 4;
  return (
    <AbsoluteFill style={{ alignItems: "center", paddingTop: 170 }}>
      <div style={rise(frame, 0)}>
        <Kicker style={{ textAlign: "center" }}>Meta AI in the loop</Kicker>
      </div>
      <div style={{ fontSize: 72, fontWeight: 800, letterSpacing: -2, marginTop: 14, ...rise(frame, 8) }}>
        Meta's models change the result.
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 18, marginTop: 90 }}>
        {STAGES.map((s, i) => {
          const at = 60 + i * 80;
          const lit = active === i || (active === -1 && prog(frame, at, 10) > 0 && frame < at + 60);
          return (
            <React.Fragment key={s.name}>
              {i > 0 && (
                <div style={{ fontSize: 44, color: C.dim, opacity: prog(frame, at - 6, 10) }}>→</div>
              )}
              <div style={rise(frame, at, 40, 20)}>
                <Panel
                  accent={lit ? C.red : undefined}
                  style={{ width: 380, height: 380, padding: "38px 34px", display: "flex", flexDirection: "column" }}
                >
                  <span style={{ fontFamily: MONO, fontSize: 26, color: lit ? C.red : C.dim }}>0{i + 1}</span>
                  <div style={{ fontSize: 50, fontWeight: 800, marginTop: 14, letterSpacing: -1 }}>{s.name}</div>
                  <div style={{ fontFamily: MONO, fontSize: 22, color: C.muted, marginTop: 10 }}>{s.model}</div>
                  <div style={{ fontSize: 28, color: C.text, opacity: 0.85, lineHeight: 1.4, marginTop: "auto" }}>{s.body}</div>
                </Panel>
              </div>
            </React.Fragment>
          );
        })}
      </div>
    </AbsoluteFill>
  );
};

const Arrow: React.FC<{ dir: "up" | "down"; color: string; crossed?: boolean }> = ({ dir, color, crossed }) => (
  <svg width={70} height={110} viewBox="0 0 70 110">
    <path
      d={dir === "up" ? "M35 100 V14 M12 36 L35 12 L58 36" : "M35 10 V96 M12 74 L35 98 L58 74"}
      fill="none"
      stroke={color}
      strokeWidth={7}
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    {crossed && <path d="M10 34 L60 80 M60 34 L10 80" stroke={C.text} strokeWidth={7} strokeLinecap="round" />}
  </svg>
);

const EVENTS = [
  { id: "7f3a91", what: "connect 203.0.113.10:4444", ok: true },
  { id: "91c04e", what: "exec node install.js", ok: true },
  { id: "c44e02", what: "exec sh -c \"node install.js\"", ok: true },
  { id: "e0b7d5", what: "“nothing unusual happened”", ok: false },
];

const Floor: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill style={{ flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 110 }}>
      <div style={{ width: 760 }}>
        <div style={rise(frame, 0)}>
          <Kicker>Rules set the security floor</Kicker>
        </div>
        <div style={{ position: "relative", height: 470, marginTop: 30 }}>
          <div style={{ position: "absolute", left: 0, top: 30, display: "flex", alignItems: "center", gap: 22, ...rise(frame, 40) }}>
            <Arrow dir="up" color={C.text} />
            <div>
              <div style={{ fontSize: 42, fontWeight: 700 }}>Muse can escalate</div>
              <div style={{ fontSize: 28, color: C.muted, marginTop: 6 }}>Clean → Review → Blocked</div>
            </div>
          </div>
          <div
            style={{
              position: "absolute",
              left: 0,
              right: 0,
              top: 210,
              height: 16,
              borderRadius: 8,
              background: C.red,
              transformOrigin: "left",
              transform: `scaleX(${prog(frame, 14, 22)})`,
            }}
          />
          <div style={{ position: "absolute", left: 0, top: 236, fontFamily: MONO, fontSize: 24, color: C.red, opacity: prog(frame, 30, 10) }}>
            HIGH-SEVERITY RULE FINDING
          </div>
          <div style={{ position: "absolute", left: 0, top: 300, display: "flex", alignItems: "center", gap: 22, ...rise(frame, 80) }}>
            <Arrow dir="down" color={C.dim} crossed />
            <div>
              <div style={{ fontSize: 42, fontWeight: 700 }}>…but never erase one</div>
              <div style={{ fontSize: 28, color: C.muted, marginTop: 6 }}>A model can't argue a rule away</div>
            </div>
          </div>
        </div>
      </div>
      <div style={rise(frame, 140, 30)}>
        <Kicker color={C.muted} style={{ marginBottom: 18 }}>
          Every cited event, checked by code
        </Kicker>
        <Panel style={{ width: 760, padding: "26px 32px", fontFamily: MONO, fontSize: 27 }}>
          {EVENTS.map((e, i) => {
            const p = prog(frame, 160 + i * 22, 10);
            return (
              <div
                key={e.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 22,
                  padding: "16px 0",
                  borderBottom: i < EVENTS.length - 1 ? `2px solid ${C.border}` : undefined,
                  opacity: 0.25 + p * 0.75,
                }}
              >
                <span style={{ color: C.dim }}>{e.ok ? `evt ${e.id}` : "no event"}</span>
                <span style={{ flex: 1, color: e.ok ? C.text : C.muted }}>{e.what}</span>
                <span style={{ color: e.ok ? C.green : C.red, fontWeight: 700, opacity: p }}>
                  {e.ok ? "✓ in trace" : "✕ rejected"}
                </span>
              </div>
            );
          })}
        </Panel>
      </div>
    </AbsoluteFill>
  );
};

const Squares: React.FC<{ fills: string[]; at: number }> = ({ fills, at }) => {
  const frame = useCurrentFrame();
  return (
    <div style={{ display: "flex", gap: 14 }}>
      {fills.map((f, i) => {
        const p = prog(frame, at + i * 5, 12);
        const empty = f === "none";
        return (
          <div
            key={i}
            style={{
              width: 70,
              height: 70,
              borderRadius: 14,
              background: empty ? "transparent" : f,
              border: `3px ${empty ? "dashed" : "solid"} ${empty ? C.dim : f}`,
              opacity: p,
              transform: `scale(${0.5 + p * 0.5})`,
            }}
          />
        );
      })}
    </div>
  );
};

const ResultRow: React.FC<{ label: string; sub: string; big: string; detail: string; fills: string[]; at: number; hero?: boolean }> = ({
  label,
  sub,
  big,
  detail,
  fills,
  at,
  hero,
}) => {
  const frame = useCurrentFrame();
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 60, ...rise(frame, at - 10, 30) }}>
      <div style={{ width: 470 }}>
        <div style={{ fontSize: 42, fontWeight: 800, letterSpacing: -0.5, whiteSpace: "nowrap" }}>{label}</div>
        <div style={{ fontSize: 26, color: C.muted, marginTop: 6 }}>{sub}</div>
      </div>
      <Squares fills={fills} at={at} />
      <div style={{ width: 300, opacity: prog(frame, at + 60, 14) }}>
        <div style={{ fontSize: hero ? 84 : 72, fontWeight: 800, letterSpacing: -2, color: hero ? C.text : C.muted }}>{big}</div>
        <div style={{ fontSize: 28, color: hero ? C.text : C.muted, fontWeight: 600 }}>{detail}</div>
      </div>
    </div>
  );
};

const Results: React.FC = () => {
  const frame = useCurrentFrame();
  const rules = [...Array(6).fill(C.red), ...Array(4).fill("none")];
  const full = [...Array(9).fill(C.red), C.amber];
  return (
    <AbsoluteFill style={{ alignItems: "center", paddingTop: 170 }}>
      <div style={rise(frame, 0)}>
        <Kicker style={{ textAlign: "center" }}>Original blind test</Kicker>
      </div>
      <div style={{ fontSize: 64, fontWeight: 800, letterSpacing: -1.5, marginTop: 14, ...rise(frame, 8) }}>
        10 novel attacks, written blind to our rules
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 70, marginTop: 90 }}>
        <ResultRow label="Rules only" sub="deterministic engine" big="6/10" detail="blocked" fills={rules} at={40} />
        <ResultRow label="Meta-powered pipeline" sub="rules + Muse Spark" big="10/10" detail="flagged · 9 Blocked, 1 Review" fills={full} at={130} hero />
      </div>
      <div style={{ display: "flex", gap: 30, marginTop: 70, ...rise(frame, 240) }}>
        <Chip color={C.red} bg={C.redSoft} style={{ fontSize: 26 }}>
          <span style={{ width: 18, height: 18, background: C.red, borderRadius: 4 }} /> Blocked
        </Chip>
        <Chip color={C.amber} bg={C.amberSoft} style={{ fontSize: 26 }}>
          <span style={{ width: 18, height: 18, background: C.amber, borderRadius: 4 }} /> Needs review
        </Chip>
        <Chip color={C.muted} style={{ fontSize: 26 }}>
          <span style={{ width: 18, height: 18, border: `3px dashed ${C.dim}`, borderRadius: 4 }} /> Missed
        </Chip>
      </div>
      <div style={{ fontSize: 30, color: C.muted, marginTop: 40, ...rise(frame, 300) }}>
        Then the rules were hardened with Meta's findings.
      </div>
    </AbsoluteFill>
  );
};

export const S5Meta: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <Stage>
      <Brand />
      <AbsoluteFill style={{ opacity: window(frame, 0, 606, 12) }}>
        <Stages />
      </AbsoluteFill>
      <AbsoluteFill style={{ opacity: window(frame, 600, 936, 12) }}>
        <Sub from={600}>
          <Floor />
        </Sub>
      </AbsoluteFill>
      <AbsoluteFill style={{ opacity: prog(frame, 930, 12) }}>
        <Sub from={930}>
          <Results />
        </Sub>
      </AbsoluteFill>
    </Stage>
  );
};
