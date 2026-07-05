# hops

**Share one keyboard and mouse across your Mac, Windows, and Linux machines** —
a software KVM. Move your cursor to the edge of the screen and it *hops* to the
next computer, keyboard and all. No hardware, no cloud; the machines talk
directly to each other over your LAN.

part of the **grabbr** suite · repo: **grabbr-hops** · a fork of
[lan-mouse](https://github.com/feschber/lan-mouse) · GPLv3

<p align="center">
  <img src="screenshots/hops-gui.png" width="520" alt="the hops control panel">
</p>

## Why hops

- **Truly cross-platform** — macOS, Windows, and Linux, one app, one binary
  (`hops`).
- **Encrypted, direct connections** — traffic runs over **QUIC + TLS 1.3**
  (quinn + rustls). Peers are pinned by public-key fingerprint, so only machines
  you've explicitly paired can connect (see [Security](#security)).
- **Explicit pairing** — a new machine shows up as a pairing request with its
  fingerprint; you name it and approve it once, and the trust persists.
- **Three ways to drive it** — a native **GUI**, a **terminal UI** for SSH /
  keyboard-driven use, and a **system-tray** icon; all attach to the same
  background daemon.
- **Runs headless** — install just the daemon on a server and control it over
  SSH (see [service/README.md](service/README.md)).
- **Themeable** — a built-in palette set plus your own themes dropped in as TOML.

## Interfaces

| | |
| --- | --- |
| **GUI** | `hops gui` — the windowed control panel (above). Native tray icon; starts hidden in the menu bar / notification area with `--hidden`. |
| **TUI** | `hops tui` — the same control panel in your terminal; ideal over SSH. |
| **Daemon** | `hops daemon` — the background receiver/sender the front-ends attach to. |
| **CLI** | `hops cli` — scripted, one-shot configuration. |

Running `hops` with no arguments picks up where you left off — on the first run
it asks how you'd like to drive it:

<p align="center">
  <img src="screenshots/hops-onboarding.png" width="620" alt="first-run interface picker">
</p>

## Install

### Build from source (all platforms)

You need a [Rust toolchain](https://rustup.rs) (stable).

```sh
git clone https://github.com/jtjones09/grabbr-hops
cd grabbr-hops
cargo build --release --no-default-features --features "tui slint"
```

The binary lands at `target/release/hops` (`hops.exe` on Windows). The
`slint` feature builds the cross-platform GUI; `tui` adds the terminal UI. For a
GUI-less server build, see [Headless](#headless).

### Platform notes

- **macOS** — grant **Accessibility** to the `hops` binary (System Settings →
  Privacy & Security → Accessibility) so it can inject input. For the grant to
  survive rebuilds, codesign with a stable identity. A menu-bar icon keeps hops
  reachable; `--hidden` starts it as tray-only.
- **Windows** — run `hops.exe`; allow it on your **private network** if Windows
  Firewall prompts. The tray icon lives in the notification area.
- **Linux** — the input capture/emulation backends are selected via cargo
  features (`layer_shell_capture`, `x11_capture`, `libei_*`, `wlroots_emulation`,
  …); see `Cargo.toml`. A legacy GTK front-end is also available via the default
  feature set. Desktop tray needs a StatusNotifierItem host (e.g. GNOME's
  AppIndicator extension).

### Headless

Run hops as a background daemon with no GUI — a KVM node you cross onto and
control over the network. Autostart units for **Linux (systemd)**, **macOS
(launchd)**, and **Windows (Scheduled Task)**, plus how to configure over SSH,
are in **[service/README.md](service/README.md)**.

## Usage

1. Start hops on both machines (`hops`, or install the autostart unit).
2. On one machine, add the other as a device (its address + which screen edge it
   sits on) — in the GUI's **+ add**, the TUI, or `config.toml`.
3. The first connection shows a **pairing request** with the peer's fingerprint.
   Name it and click **trust & name** (or approve it over the CLI/TUI on a
   headless box). Do this once per pair.
4. Move your cursor off the configured edge — it hops to the other machine.
   Keyboard, scroll, and modifiers follow.

## Security

- **Transport:** all traffic is **QUIC** (quinn) secured with **TLS 1.3**
  (rustls + ring). Nothing is sent in the clear.
- **Identity:** each machine holds a self-signed keypair; peers are verified by
  the **fingerprint of the public key**, not by a CA. rustls' certificate check
  is delegated to fingerprint pinning, so a machine is trusted only after you
  approve its fingerprint (trust on first use, with explicit consent).
- **No cloud, no accounts:** machines connect directly over your LAN. There is no
  relay and no telemetry.

Trust, config, and the keypair live in `~/.config/lan-mouse/` (Linux/macOS) or
`%LOCALAPPDATA%\lan-mouse\` (Windows).

> Note: this is a hobby-scale project, not an audited security product. Run it on
> networks you trust.

## Credits & license

hops is a fork of **[lan-mouse](https://github.com/feschber/lan-mouse)** by Felix
Eschberger (`feschber`) and its contributors — full attribution and the list of
what this fork changes are in [NOTICE.md](NOTICE.md). All original copyright is
preserved in the git history.

Licensed under the **GNU General Public License v3.0 or later** — see
[LICENSE](LICENSE).
