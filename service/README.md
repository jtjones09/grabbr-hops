# Running hops headless (no GUI)

hops is a background daemon plus one or more front-ends. On a server — or any box
you'd rather run without a window — you install just the daemon and configure it
remotely. This directory holds the autostart units for each OS.

| File | Platform | Use |
| ---- | -------- | --- |
| `hops.service` | Linux (desktop) | user service bound to your graphical session |
| `hops-headless.service` | Linux (server) | user service, **no display required** |
| `com.grabbr.hops.plist` | macOS | launchd daemon (LaunchAgent) |
| `windows/install-hops-daemon.ps1` | Windows | logon Scheduled Task (interactive session) |

## 1. Build without a GUI

The default build pulls in a desktop toolkit. For a server, build daemon-only —
optionally with the terminal UI so you can configure it over SSH:

```sh
# daemon only (smallest)
cargo build --release --no-default-features

# daemon + terminal UI (recommended for headless — lets you run `hops tui` over SSH)
cargo build --release --no-default-features --features tui
```

The binary is `target/release/hops` (`hops.exe` on Windows). Copy it somewhere on
PATH (e.g. `~/.local/bin/hops`, `/usr/local/bin/hops`, or
`%LOCALAPPDATA%\hops\hops.exe`) and point the autostart unit at it.

## 2. Autostart

### Linux (headless server)

```sh
mkdir -p ~/.config/systemd/user
cp hops-headless.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now hops-headless.service

# start at boot without an interactive login (the point of a server):
sudo loginctl enable-linger "$USER"

# let the daemon inject input via /dev/uinput without running as root:
sudo usermod -aG input "$USER"      # then re-login
```

### macOS

```sh
# edit the ExecStart path in the plist first, then:
cp com.grabbr.hops.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.grabbr.hops.plist
```

macOS input emulation needs a one-time **Accessibility** grant (System Settings →
Privacy & Security → Accessibility) that can only be given from a logged-in
session — it can't be pre-granted on a truly headless Mac. Grant it once for the
hops binary; it persists across reboots as long as the binary keeps a stable
codesign identity. After re-signing, `launchctl bootout` + `bootstrap` (not
`kickstart -k`) to avoid an `OS_REASON_CODESIGNING` spawn failure.

### Windows

```powershell
# from an elevated PowerShell (Run as administrator):
cd windows
.\install-hops-daemon.ps1 -HopsPath 'C:\path\to\hops.exe'
```

This registers a logon-triggered Scheduled Task rather than a Windows service on
purpose: a service runs in the isolated session 0 and cannot inject input into
your desktop. The task runs hops in your interactive session, which is what input
emulation requires.

## 3. Configure over SSH

The daemon writes a default config on first run and watches it for changes. Three
ways to configure a headless install, no GUI needed:

- **Terminal UI** (needs a `--features tui` build): `hops tui` over SSH — the full
  control panel in your terminal.
- **CLI**: `hops cli --help` for scripted one-shot changes.
- **Config file**, edited directly:
  - Linux / macOS: `~/.config/lan-mouse/config.toml`
  - Windows: `%LOCALAPPDATA%\lan-mouse\config.toml`

The on-disk state directory is `lan-mouse/` (config, the trusted-peer store, and
the TLS keypair) — kept under that name so it stays compatible with existing
installs; don't rename it.

## Pairing a headless node

hops trusts peers by public-key fingerprint. The first time another machine
connects, the headless daemon logs the pairing fingerprint; authorize it with the
CLI/TUI or by adding it to the config, and the two ends trust each other from then
on. There's no GUI prompt on a headless box — you approve from the controlling
machine or over SSH.
