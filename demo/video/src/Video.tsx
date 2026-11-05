import React from "react";
import { AbsoluteFill, Sequence, useCurrentFrame } from "remotion";
import { C, T } from "./theme";
import { prog } from "./anim";
import { S1Hook } from "./scenes/S1Hook";
import { S2Meet } from "./scenes/S2Meet";
import { S3Discovery } from "./scenes/S3Discovery";
import { S4System } from "./scenes/S4System";
import { S5Meta } from "./scenes/S5Meta";
import { S6Results } from "./scenes/S6Results";
import { S7Closing, S8EndCard } from "./scenes/S7S8Close";

/** Short fade from black at the head of a section. */
const FadeIn: React.FC<{ children: React.ReactNode; frames?: number }> = ({ children, frames = 10 }) => {
  const frame = useCurrentFrame();
  return <AbsoluteFill style={{ opacity: prog(frame, 0, frames) }}>{children}</AbsoluteFill>;
};

export const DemoVideo: React.FC = () => (
  <AbsoluteFill style={{ background: C.bg }}>
    <Sequence from={T.hook.from} durationInFrames={T.hook.dur} name="1 Hook">
      <S1Hook />
    </Sequence>
    {/* The hook ends on a white flash, and the camera clip opens on the same flash. */}
    <Sequence from={T.meet.from} durationInFrames={T.meet.dur} name="2 Meet PR Detonator">
      <S2Meet />
    </Sequence>
    <Sequence from={T.discovery.from} durationInFrames={T.discovery.dur} name="3 Discovery">
      <FadeIn>
        <S3Discovery />
      </FadeIn>
    </Sequence>
    <Sequence from={T.system.from} durationInFrames={T.system.dur} name="4 System">
      <FadeIn>
        <S4System />
      </FadeIn>
    </Sequence>
    <Sequence from={T.meta.from} durationInFrames={T.meta.dur} name="5 Meta">
      <FadeIn>
        <S5Meta />
      </FadeIn>
    </Sequence>
    <Sequence from={T.results.from} durationInFrames={T.results.dur} name="6 Results">
      <FadeIn>
        <S6Results />
      </FadeIn>
    </Sequence>
    <Sequence from={T.closing.from} durationInFrames={T.closing.dur} name="7 Closing">
      <FadeIn>
        <S7Closing />
      </FadeIn>
    </Sequence>
    <Sequence from={T.end.from} durationInFrames={T.end.dur} name="8 End card">
      <FadeIn frames={14}>
        <S8EndCard />
      </FadeIn>
    </Sequence>
  </AbsoluteFill>
);
