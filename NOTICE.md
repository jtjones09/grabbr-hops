# grabbr-hops

Share one keyboard and mouse across your Mac, Windows, and Linux machines — a
software KVM. Part of the **grabbr** suite of power-user utilities.

## Upstream & credit

grabbr-hops is a fork of **lan-mouse** by Felix Eschberger (`feschber`) and its
contributors:

  https://github.com/feschber/lan-mouse

It is distributed under the **GNU General Public License v3.0 or later** (see
`LICENSE`) — the same license as lan-mouse. All original lan-mouse copyright and
authorship is preserved in the git history.

### What grabbr-hops adds / changes

- A substantially reworked **macOS input backend**: modifier-coherence self-heal,
  an `IOHIDPostEvent` native-focus path (smoother, wakes the display), and
  VM-guest-aware injection (native → HID, Parallels/VM guest → CGEvent device
  bits, auto-detected).
- In progress: media/consumer-key support (HID consumer page), a **QUIC**
  transport with split reliable/unreliable channels + mutual-fingerprint pairing,
  and an HID-usage canonical input model.

Generally-useful fixes are contributed back upstream to lan-mouse where they fit.
