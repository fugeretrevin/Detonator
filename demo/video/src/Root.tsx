import React from "react";
import { Composition } from "remotion";
import { DemoVideo } from "./Video";
import { FPS, H, TOTAL, W } from "./theme";

export const Root: React.FC = () => (
  <Composition id="DemoVideo" component={DemoVideo} durationInFrames={TOTAL} fps={FPS} width={W} height={H} />
);
