# Running hops headless (no GUI)

hops is a background daemon plus one or more front-ends. On a server — or any box
you'd rather run without a window — you install just the daemon and configure it
remotely. This directory holds the autostart units for each OS.

| File | Platform | Use |
| ---- | -------- | --- |
| `hops.service` | Linux (desktop) | user service bound to your graphical session |
| `hops-headless.service` | Linux (server) | user service with no monitor or login; **still needs a display server** to inject input |
| `com.grabbr.hops.plist` | macOS | launchd daemon (LaunchAgent) |
| `windows/install-hops-daemon.ps1` | Windows | logon Scheduled Task (interactive session) |

## 1. Build without a GUI

The default build has the terminal UI and no desktop toolkit, which is what a
server wants: `hops tui` configures it over SSH. On Linux the input backends are
cargo features, and a build without a capture and an emulation backend does not
compile, since it could neither send nor receive input:

```sh
# Linux: the defaults (terminal UI + every backend)
cargo build --release

# macOS / Windows: the backends come with the platform
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

```

"Headless" here means no monitor and no login, not no display server. Every
Linux emulation backend injects through Wayland, X11 or the desktop portal, so
without one hops cannot inject input. See the header of `hops-headless.service`.

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
# from a normal PowerShell:
cd windows
.\install-hops-daemon.ps1 -HopsPath 'C:\path\to\hops.exe'
```

This registers a logon-triggered Scheduled Task rather than a Windows service on
purpose: a service runs in the isolated session 0 and cannot inject input into
your desktop. The task runs hops in your interactive session, which is what input
emulation requires.

#### Why hops is never elevated

hops runs as you and is never elevated: an administrator process started from a
folder you can write hands administrator to anything that can replace the file.
The cost is that hops cannot type or click into an elevated window. Started
elevated, hops refuses to run and says why, and so does the script above.

#### Upgrading from hops 0.12 or older

The old daemon listens where this version does not look for one, and this
version will not start beside it. hops 0.12 started at sign-in from a Run value
or from a scheduled task.

First, open a new, normal PowerShell and remove the Run values its
`install.ps1` set. They are in your own registry hive, so a shell started with
another account's password would look in that account's:

```powershell
$run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty $run -Name hops-daemon,hops-gui
```

##### Removing the task 0.12 ran elevated

The task runs the old daemon elevated, so removing it and stopping that daemon
needs PowerShell as administrator; without the task, a normal one does. These
commands only remove and stop:

```powershell
Unregister-ScheduledTask -TaskName hops-daemon -Confirm:$false
$old = Get-NetTCPConnection -LocalPort 5252 -State Listen
Stop-Process -Id $old.OwningProcess
```

A line that finds nothing to remove says so; that is expected. Quit the old
hops in the notification area too. Remove the task rather than reuse it: it
keeps its elevation.

##### Starting this version at sign-in

Then, from a new, normal PowerShell, set this version to start at sign-in:
register it with `install-hops-daemon.ps1` as above, from `service\windows` in
the source code zip on the release page; or, if 0.12 came from `install.ps1` in
a clone of the source, update the clone and run `install.ps1` again.

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

A headless machine pairs like any other (see "Connect two machines" in the
top-level README), with `hops tui` over SSH standing in for the window: press
`a` there to open add device, and open add device on the other machine too.
Both machines approve the request, then compare the number; neither can
approve for the other. Writing a fingerprint into `config.toml` is not how a
machine is paired: pairings live in a signed trust file, and `config.toml`'s
list is read only to rebuild that file when it is missing. How to remove a
machine or recover one is in [docs/SECURITY.md](../docs/SECURITY.md).
