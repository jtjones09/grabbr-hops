# Controlling a managed Mac

A managed Mac, such as a work laptop behind a VPN or security client,
often drops connections it did not open. hops handles this by having the
managed Mac open the connection to the machine that controls it. Nothing
then needs to reach the Mac from outside, and the Mac neither listens on a
port nor announces itself on the network. What each setting does on the
network is in [NETWORK.md](NETWORK.md).

Below, "the controlling machine" is the one whose keyboard and mouse you
use, and "the Mac" is the managed Mac.

## On the Mac

1. **Install the signed app.** Download `hops-macos-universal.dmg` from
   the [latest release](https://github.com/jtjones09/grabbr-hops/releases/latest),
   open it and drag **hops** to Applications, then open it from
   Applications. The dmg is signed and notarized; to check it first, see
   [Verifying a release](../SECURITY.md#verifying-a-release). The `.tar.gz`
   is not signed; do not use it here.
2. **Grant Accessibility.** System Settings → Privacy & Security →
   Accessibility: switch **hops** on. A Mac that is controlled needs it to
   move the pointer and type; without it the app says Accessibility is
   missing. Input Monitoring is needed only to read this Mac's own
   keyboard and mouse, which only a Mac that controls another machine
   does, so a Mac that is only controlled does not need it. If macOS asks
   whether hops may find devices on the local network, allow it.
3. **Stop listening and announcing.** Open
   `~/.config/lan-mouse/config.toml` and add these two lines at the top,
   above the first line that starts with `[`:

   ```toml
   listen = false
   discovery = false
   ```

   If either key is already in the file, change its value instead. hops
   reads them when it starts, so restart it: log out and back in, or run
   `launchctl kickstart -k gui/$(id -u)/com.grabbr.hops`. Afterwards
   `lsof -nP -iUDP:4722` shows no `*:4722`, which is a port being
   listened on.

## Pairing

1. On the controlling machine, open **add device**. A pairing request only
   appears there for two minutes after that.
2. On the Mac, open **add device** and add the controlling machine by its
   IP address or hostname, choosing the edge it sits on. With discovery
   off, it is not in the list; type it.
3. Both machines show a pairing request. On the Mac, answer **That machine
   controls this one**; on the controlling machine, **This machine
   controls that one**. Choose whether to share the clipboard, then
   approve on both.
4. The Mac shows a six-digit number; pick the same number on the
   controlling machine, then confirm on the Mac.

The Mac then dials the controlling machine and keeps that connection
open, dialling again when it drops. Until it does, the Mac's card on the
controlling machine reads "waiting for it to dial".

## On the controlling machine

It must listen (the default), and let UDP 4722 in from the Mac.

- **Windows.** Windows Defender Firewall asks the first time hops
  listens; allow it on the network type the machine is actually on. The
  rule it adds covers that `hops.exe`, at that path, on the network types
  ticked. A `hops.exe` in a different folder, such as a new version
  unpacked somewhere else, is a different program and needs its own rule.
  To add one yourself, from an administrator PowerShell:

  ```powershell
  New-NetFirewallRule -DisplayName "hops" -Direction Inbound -Action Allow `
    -Program "C:\path\to\hops.exe" -Protocol UDP -LocalPort 4722 -Profile Private
  ```

- **macOS.** If the macOS firewall is on, allow hops to accept incoming
  connections. A Mac that controls another machine needs Input
  Monitoring as well as Accessibility.

The Mac needs to reach UDP 4722 on the controlling machine, outbound. It
needs nothing inbound.

## Staying reachable

A Mac that is asleep cannot be controlled. While a device that may
control it is paired and switched on, hops keeps the Mac from sleeping
when idle, and lets the display turn off. [NETWORK.md](NETWORK.md#power-on-macos)
says how to change that.
