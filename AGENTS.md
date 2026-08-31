# hops — Agent Instructions

## Read this first

**hops** is a GPLv3 fork of [lan-mouse](https://github.com/feschber/lan-mouse): a software KVM
sharing one keyboard and mouse across machines. Renamed from lan-mouse on 2026-07-04 and
**deliberately severed** — this repo never fetches from or pushes to any lan-mouse remote.

> **Before forming a view on anything with history, read the decision record.**
> `~/Documents/GitHub/nisaba/projects/grabbr-hops/DECISIONS.md` — dated calls with rationale
> and reversibility. `JOURNAL.md` beside it is the session-by-session log.
>
> Grepping the journal for a keyword is **not** reading the record. This project has
> repeatedly lost hours re-deriving conclusions that were already written down, and has
> twice acted on a stale record that read as current. nisaba is private; this repo is public.

If `HandoffSessionCompact.md` exists in the repo root, **read it before anything else** —
it is the previous context window's state. See `.claude/skills/handoff/`.

## Method — the part that matters most here

- **Measure, don't reason.** Every conclusion in the 2026-08 scroll saga that came from
  *reading code* was wrong; every one from *instrumenting and measuring* was right. Same for
  the GUI: a window bug was misdiagnosed twice as sizing before anyone measured the live
  window and found it was a *paint* bug.
- **Prove a fix falsifiable.** Show the test fails without the change. Checking that your own
  new log line appeared proves your code ran, not that the bug is fixed. Mutation-test guards:
  reintroduce the defect and confirm the guard fires.
- **Never let a summary be the only record of research.** If a Workflow or subagent run
  produced output, the raw per-agent returns are the **primary source**: preserve them
  verbatim in nisaba `projects/grabbr-hops/research/<date>-<topic>-artifact.md`, with the
  workflow script as `-protocol.js`, *before* writing the synthesis — then check the
  synthesis against them. Standing rule: nisaba `positions/research-folder-discipline.md`.
  Transcripts survive at `~/.claude/projects/<slug>/<session>/subagents/workflows/wf_*/`.
- **Never `cd` into a path in scripts; run from the repo root.**
- **Dates are absolute.** Sessions here are days apart — say `2026-08-29`, never "today".
- **Verify machine state, never assume it.** Which build is running on which box has been
  wrong more than once. `ps` + `--version`.

## Architecture

**Pipeline:** `input-capture` → `hops-proto` over **QUIC** → `input-emulation`

- **Transport is QUIC** (`quinn`), ALPN `grabbr-hop/1`, default port 4242. It is *not* UDP
  events plus a TCP control channel — that was the pre-fork design.
- **`crates/`** holds all workspace members (moved there in `5345953`).
- **`input-capture`** reads OS events as a `Stream<CaptureEvent>`. Selection order:
  `InputCapturePortal (libei)` → `LayerShell (wlroots only)` → `X11` → `Windows`/`MacOs` →
  `Dummy`. **`x11.rs` capture is a stub** — `new()` returns `NotImplemented`.
- **`input-emulation`** replays via the `Emulation` trait. Falling back to `Backend::Dummy`
  is **refused** unless dummy was explicitly requested or `HOPS_ALLOW_DUMMY=1` — it accepts
  every event and discards it while the UI reports a healthy connection.
- **`hops-proto`** carries `Hello`, `Capability { flags }` (append-only bits, ours — upstream
  has no capability negotiation), and the input events.
- **`hops-ipc`** is the daemon↔frontend channel, **token-authenticated** (`0600`, beside
  `config.toml`). On Windows it is a localhost TCP socket, so the token is load-bearing.

### Frontends

| crate | status |
|---|---|
| `hops-slint` | the real GUI — macOS/Windows. Uses the unified `Device` projection. |
| `hops-tui` | Ratatui. The **only** frontend shipped on Linux, and the `default` feature. Also on the `Device` model. |

### The device model

One `Device` per physical peer, keyed by TLS leaf-cert fingerprint, projected over two config
tables (`[[clients]]` + `[authorized_fingerprints]`). Frontends render `AppModel::devices()`
filtered by `is_listable()`. **Never render the two tables separately** — that is the
double-entry bug the model exists to end.

Trust is destructive by design: delete revokes, a revoked fingerprint is a permanent tombstone,
and there is **no restore path**. Do not add one.

## Hard constraints

- **macOS signing:** `codesign --force --identifier com.grabbr.hops --sign "Developer ID
  Application: Hotash Studios LLC (9V42Q953X9)"`. **Omitting `--identifier` voids the
  Accessibility (TCC) grant** and hops silently falls back to a dummy backend. Re-sign after
  every rebuild that overwrites a binary launchd points at.
- **No raw input devices.** hops must not open `/dev/input` or `/dev/uinput`, and the
  installer must never tell users to join the `input` group — that grants system-wide
  keylogging for a capability hops does not have. Enforced by the `no /dev/input access` CI
  job. If a privileged backend is ever wanted, update the guard and the security model **in
  the same PR**.
- **Never contact any lan-mouse remote** (fetch or push). Reading a public PR via the GitHub
  API is fine; pulling code in is not.
- **GUI changes must be rendered and looked at** before shipping or describing. Use the
  `preview-gui` skill. Slint draws its own pixels; layout bugs are invisible in source.

## Commands

```sh
# what CI actually builds
cargo check --workspace --all-targets
RUSTFLAGS="-D warnings" cargo check --workspace --all-targets --no-default-features --features "tui slint"
cargo test --workspace --no-default-features --features "tui slint"
cargo fmt --all --check
HOPS_LOG_LEVEL=debug cargo run -- daemon
```

`hops-gtk` was retired on 2026-08-30 (2,585 LOC, never adopted the `Device` model, shipped by
no workflow, yet held `default` and first pick in `src/main.rs` dispatch — so a bare `cargo build`
produced the one frontend nobody ran). `tui` holds the `default` slot now.

**Linux backends are feature-gated; macOS/Windows backends are platform-gated** (`#[cfg(windows)]`,
`#[cfg(target_os = "macos")]`). That asymmetry once shipped a Linux release with no input
backends at all. `build.rs` also reads the **host** target, so cross-compiling Linux from a Mac
silently drops every Unix backend and reports success — build Linux natively (issue #44).

## CI

`check.yml` runs on every push to `main` and every PR: default features, the three release feature sets, workspace tests, rustfmt, and the
`no /dev/input access` guard. `release.yml` runs on `v*` tags and asserts the built Linux
binary actually contains real input backends.

## Workflow

1. Read `DECISIONS.md` for anything with history. Then the code. Then form a view.
2. Clarify OS-specific behaviour — capture/emulation differ substantially per platform.
3. Implement the minimal change; file follow-ups rather than absorbing them.
4. Add a test that fails without the fix. Mutation-test any guard.
5. `cargo fmt --all` and the `-D warnings` check above.
6. Record decisions in nisaba `DECISIONS.md`; record what happened in `JOURNAL.md`.
