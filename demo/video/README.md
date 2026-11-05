# Demo video (Remotion)

A 3:00, 1920×1080, 30 fps, silent cut of the demo script. Narration and music are added afterwards,
so every section starts exactly on the script's timestamps (`src/theme.ts`, `T`).

| Section | Time | File |
|---|---|---|
| 1 Hook | 0:00–0:24 | `src/scenes/S1Hook.tsx` |
| 2 Meet PR Detonator (camera clip → whip → explainer → real PR #12) | 0:24–0:55 | `src/scenes/S2Meet.tsx` |
| 3 Registry-sweep finding (anonymized) | 0:55–1:17 | `src/scenes/S3Discovery.tsx` |
| 4 How the system works | 1:17–1:35 | `src/scenes/S4System.tsx` |
| 5 Meta AI: stages, rules floor, blind-test result | 1:35–2:19 | `src/scenes/S5Meta.tsx` |
| 6 Results and what's next | 2:19–2:46 | `src/scenes/S6Results.tsx` |
| 7–8 Closing line and end card | 2:46–3:00 | `src/scenes/S7S8Close.tsx` |

## Media (not committed)

`public/media/` is gitignored. It holds the camera footage and the PR screenshots:

- `intro.mp4`: the iPhone clip, transcoded to 1080p H.264 with **audio and all metadata stripped**
  (the original `.MOV` carries GPS coordinates). Recreate it with:

  ```
  npx remotion ffmpeg -i IMG_2977.MOV -map 0:v:0 -an -vf scale=1920:-2 -c:v libx264 -crf 17 -pix_fmt yuv420p -map_metadata -1 -movflags +faststart public/media/intro.mp4
  ```

- `pr-conversation.png`, `pr-files.png`, `pr-checks.png`: logged-out headless-Chrome screenshots
  of https://github.com/pr-detonator-demo/demo-target/pull/12 (`/`, `/files`, `/checks`) at
  1280×2400, device scale 2. Crop regions in `S2Meet.tsx` are in those images' pixels.

The whip out of the camera clip is timed to the hand swipe (`WHIP_START` in `S2Meet.tsx`, 5.33 s
into the clip). If the clip is replaced, re-time that constant.

## Commands

```
npm install
npm run studio     # live preview / scrubbing
npm run render     # → out/pr-detonator-demo.mp4
```
