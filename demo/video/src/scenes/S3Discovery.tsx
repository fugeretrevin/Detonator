import React from "react";
import { AbsoluteFill, useCurrentFrame } from "remotion";
import { C, MONO } from "../theme";
import { prog, rise, window } from "../anim";
import { Brand, Chip, Kicker, Panel, Stage, Sub } from "../components/ui";

// 0:55–1:17 · An uncurated sweep of 100 new packages turns up one real, unsafe install path.
// Nothing here identifies the package: the disclosure is still private.

const FLAGGED = 63;

const Grid: React.FC = () => {
  const frame = useCurrentFrame();
  const red = prog(frame, 150, 10);
  const pulse = 0.5 + 0.5 * Math.sin(frame / 5);
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(10, 52px)", gap: 14 }}>
      {Array.from({ length: 100 }).map((_, i) => {
        const on = prog(frame, 24 + (i % 10) * 2 + Math.floor(i / 10) * 5, 10);
        const isFlag = i === FLAGGED;
        return (
          <div
            key={i}
            style={{
              width: 52,
              height: 52,
              borderRadius: 10,
              background: isFlag && red > 0 ? C.red : C.panel2,
              border: `2px solid ${isFlag && red > 0 ? C.red : C.border}`,
              opacity: 0.25 + on * 0.75,
              transform: `scale(${0.6 + on * 0.4})`,
              boxShadow: isFlag && red > 0 ? `0 0 ${18 + pulse * 22}px ${C.red}` : undefined,
            }}
          />
        );
      })}
    </div>
  );
};

const Sweep: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill style={{ flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 140 }}>
      <div style={{ width: 700 }}>
        <div style={rise(frame, 0)}>
          <Kicker>Uncurated registry sweep</Kicker>
        </div>
        <div style={{ fontSize: 120, fontWeight: 800, letterSpacing: -3, lineHeight: 1, marginTop: 24, ...rise(frame, 8) }}>
          100
        </div>
        <div style={{ fontSize: 54, fontWeight: 700, lineHeight: 1.15, marginTop: 10, ...rise(frame, 14) }}>
          newly published packages
        </div>
        <div style={{ fontSize: 32, color: C.muted, marginTop: 24, ...rise(frame, 22) }}>No handpicking. No hints.</div>
        <div style={{ marginTop: 44, ...rise(frame, 160) }}>
          <Chip color={C.red} bg={C.redSoft}>
            1 flagged at install time
          </Chip>
        </div>
      </div>
      <div style={rise(frame, 10, 40)}>
        <Grid />
      </div>
    </AbsoluteFill>
  );
};

/** A redaction bar sized to `n` characters. */
const R: React.FC<{ n: number }> = ({ n }) => (
  <span
    style={{
      display: "inline-block",
      width: `${n * 0.62}em`,
      height: "0.95em",
      background: "#3A3D45",
      borderRadius: 4,
      verticalAlign: "-0.12em",
    }}
  />
);

const EvLine: React.FC<{ at: number; tag: string; tagColor?: string; children: React.ReactNode }> = ({
  at,
  tag,
  tagColor = C.muted,
  children,
}) => {
  const frame = useCurrentFrame();
  return (
    <div style={{ display: "flex", gap: 22, ...rise(frame, at, 14, 12) }}>
      <span style={{ width: 120, color: tagColor }}>{tag}</span>
      <span style={{ flex: 1 }}>{children}</span>
    </div>
  );
};

const Evidence: React.FC = () => {
  const frame = useCurrentFrame();
  const hot = prog(frame, 120, 12);
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", gap: 36 }}>
      <div style={{ display: "flex", gap: 40 }}>
        <div style={rise(frame, 0, 30)}>
          <Kicker color={C.muted} style={{ marginBottom: 18 }}>
            Behavior evidence · anonymized
          </Kicker>
          <Panel style={{ width: 800, padding: "34px 38px", fontFamily: MONO, fontSize: 28, lineHeight: 2 }}>
            <EvLine at={14} tag="exec">
              node install.js <span style={{ color: C.dim }}>(postinstall)</span>
            </EvLine>
            <EvLine at={34} tag="connect" tagColor={C.red}>
              <R n={15} /> <span style={{ color: C.dim }}>(hardcoded bare IP)</span>
            </EvLine>
            <EvLine at={54} tag="tls" tagColor={C.red}>
              <span style={{ color: C.red }}>certificate verification disabled</span>
            </EvLine>
            <EvLine at={74} tag="download">
              <R n={10} /> → extracted
            </EvLine>
            <EvLine at={94} tag="exec" tagColor={C.red}>
              ./bin/<R n={9} /> <span style={{ color: C.dim }}>(downloaded binary)</span>
            </EvLine>
          </Panel>
        </div>
        <div style={rise(frame, 20, 30)}>
          <Kicker color={C.muted} style={{ marginBottom: 18 }}>
            Code path · redacted
          </Kicker>
          <Panel style={{ width: 800, padding: "34px 38px", fontFamily: MONO, fontSize: 28, lineHeight: 1.8 }}>
            <div style={{ color: C.dim }}>// install-time fallback</div>
            <div>
              <span style={{ color: C.muted }}>const</span> url = "https://<R n={15} />/<R n={7} />";
            </div>
            <div>
              https.get(url, {"{ "}
              <span
                style={{
                  background: `rgba(229,56,45,${0.35 * hot})`,
                  outline: hot > 0 ? `3px solid rgba(229,56,45,${hot})` : undefined,
                  borderRadius: 6,
                  padding: "0 6px",
                }}
              >
                rejectUnauthorized: false
              </span>
              {" }"}, (res) =&gt;
            </div>
            <div style={{ paddingLeft: 40 }}>extract(res, binDir);</div>
            <div style={{ paddingLeft: 40 }}>
              link(binDir, "<R n={7} />");
            </div>
            <div>{"});"}</div>
          </Panel>
        </div>
      </div>
      <div style={{ fontSize: 24, color: C.dim, ...rise(frame, 40) }}>
        Excerpt reconstructed from the published source · package, host and paths redacted
      </div>
    </AbsoluteFill>
  );
};

const Disclosed: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <svg width={120} height={120} viewBox="0 0 120 120" style={rise(frame, 0)}>
        <rect x={22} y={52} width={76} height={56} rx={12} fill="none" stroke={C.text} strokeWidth={7} />
        <path d="M38 52 V38 a22 22 0 0 1 44 0 V52" fill="none" stroke={C.text} strokeWidth={7} />
        <circle cx={60} cy={80} r={7} fill={C.red} />
      </svg>
      <div style={{ fontSize: 76, fontWeight: 800, letterSpacing: -1.5, marginTop: 34, ...rise(frame, 8) }}>
        Real-world finding
      </div>
      <div style={{ fontSize: 46, fontWeight: 600, color: C.muted, marginTop: 12, ...rise(frame, 16) }}>
        Privately disclosed
      </div>
      <div style={{ fontSize: 30, color: C.dim, marginTop: 40, ...rise(frame, 30) }}>
        Unsafe code path confirmed · reported to the maintainer
      </div>
    </AbsoluteFill>
  );
};

export const S3Discovery: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <Stage>
      <Brand />
      <AbsoluteFill style={{ opacity: window(frame, 0, 214, 12) }}>
        <Sweep />
      </AbsoluteFill>
      <AbsoluteFill style={{ opacity: window(frame, 204, 476, 12) }}>
        <Sub from={204}>
          <Evidence />
        </Sub>
      </AbsoluteFill>
      <AbsoluteFill style={{ opacity: prog(frame, 470, 12) }}>
        <Sub from={470}>
          <Disclosed />
        </Sub>
      </AbsoluteFill>
    </Stage>
  );
};
