---
name: preview-gui
description: >-
  Render the hops Slint GUI to a PNG and LOOK AT IT yourself before showing
  the user or claiming a change works. Use this whenever you touch anything in
  hops-slint (ui/*.slint — app, widgets, theme — layout, colors, fonts,
  sizing), whenever asked to preview / see / screenshot / check how the GUI looks,
  and whenever the user reacts to the GUI's appearance. Slint draws its own pixels,
  so layout mistakes (stretched controls, an oval "pill", misaligned dots, blank
  fonts, dead space) are invisible in the code but obvious in a render. Never ship,
  commit, or describe a GUI change without rendering it and inspecting the image
  first — that mistake has burned this project before.
---

# preview-gui — look at your own GUI work

The single most important habit for GUI work: **you cannot review a UI by reading
its source.** Slint is a retained-mode renderer that draws its own pixels; a
`HorizontalLayout` that reads fine in code can stretch a chip into a giant box or
turn a rounded rect into an ellipse, and you'd never know. This skill renders the
actual `AppWindow` to a PNG headlessly (no display, no screen-recording
permission) so you can open the image, critique it, fix it, and repeat — the same
loop a designer uses with their eyes.

The harness already lives in the repo: [`crates/hops-slint/examples/render_png.rs`](../../../crates/hops-slint/examples/render_png.rs).

## The loop

1. **Edit** the `.slint` files (or `lib.rs` data).
2. **Render** to a PNG:
   ```bash
   cargo run -q -p hops-slint --example render_png -- <out.png> [width] [height]
   # e.g. write a 560x690 logical window (rendered at 2x -> 1120x1380 px):
   cargo run -q -p hops-slint --example render_png -- /tmp/preview.png 560 690
   ```
   Use the session scratchpad dir for `<out.png>`. Width/height default to
   `560 760`; pass a height close to the content so there's no dead band.
3. **Look** — `Read` the PNG. Actually study it.
4. **Critique** against the target (the user's reference image, or plain good
   taste). Be your own harshest reviewer — see the checklist below.
5. **Iterate** until it's genuinely right. *Then* show the user (copy the PNG
   somewhere they can open it, e.g. `~/hops/`, and/or relaunch the live app).

Do NOT hand the user a screenshot to QA for you. Render, review, fix, and only
surface it when you'd be proud of it.

## What to look for (this is where past bugs lived)

- **Vertical alignment.** In a `HorizontalLayout`, a `Text` auto-centers on the
  cross-axis but non-text items (`Dot`, `Chip`, `Toggle`, `PillButton`) do NOT —
  they top-align or stretch. Wrap each in `VerticalLayout { alignment: center; … }`
  to center them. (This was the "dot sits above the label" bug.)
- **Stretch.** A layout child with no fixed height is stretched to fill the
  row/cross-axis. That's what turned the connection pill into an ellipse and the
  chips/buttons into giant boxes. Pin control heights (see `Size` in theme.slint:
  `chip`, `control`, `row`) so they hug + center.
- **Fonts actually loading.** Space Grotesk / Space Mono have distinctive
  letterforms. If text looks like a generic system sans, the family name didn't
  match and it fell back — check the `import "../fonts/*.ttf"` and `Type.sans/mono`.
- **Tonal separation.** background vs surface vs surface-raised must be
  distinguishable, and the border visible, or cards read as a murky field.
- **Content fits.** The window `preferred-height` is omitted so it sizes to
  content — verify there's no dead band above/below and nothing clips.
- **De-boxing.** Nested filled surfaces (chip inside row inside card) look muddy;
  prefer plain colored text + ghost buttons for secondary controls.

## Changing what's rendered

Edit the mock data in `render_png.rs` to exercise the state you need to see:
`set_connected`, `set_capture/emulation/port`, `set_pairing_fp` (shows the pairing
card), and the `devices` / `trusted` `VecModel`s. Set `pairing_fp` to `""` to
review the common no-pairing layout. Keep at least one populated device + trusted
row so alignment/stretch bugs are visible.

## Slint 1.14 gotchas (baked into the harness — don't regress them)

The workspace pins **slint 1.14.1** (`Cargo.lock`). The harness depends on these,
all verified against the installed source:

- The slint dep needs feature **`software-renderer-systemfonts`** (see
  `crates/hops-slint/Cargo.toml`). It's additive — the real windowed app keeps its
  default backend. Without it, `AppWindow::new()` *panics* (the embedded TTFs try
  to register with a renderer that can't accept them) — it does not fail quietly.
- Install the headless `Platform` (returning a `MinimalSoftwareWindow`) **before**
  `AppWindow::new()`, or it falls back to the real backend.
- `MinimalSoftwareWindow` does **not** auto-size. Dispatch
  `WindowEvent::ScaleFactorChanged` **before** `set_size`, and `set_size` takes
  **physical** px (logical × scale).
- Call `ui.show()` (+ `update_timers_and_animations()`) before snapshotting, or the
  buffer is blank.
- `ui.window().take_snapshot()` returns RGBA8 but the software renderer leaves
  **alpha = 0** — force every `px[3] = 255` or the PNG saves fully transparent
  (reads as blank).
- If slint ever resolves to **1.17+**, the software renderer moved to a separate
  `i-slint-renderer-software` crate and the scale API changed — re-verify against
  source before trusting the harness.

## Why the software renderer (not a screenshot)

Screenshotting the real window needs the app to be an installed bundle the
screen-access resolver knows about (a raw `cargo run` binary isn't recognized
mid-session) and, via `screencapture`, a Screen-Recording grant. The software
renderer sidesteps all of it: pure computation, no window, no permission, fully
reproducible, and — because Slint renders identically across backends — a faithful
proxy for what the GPU-backed app shows the user.
