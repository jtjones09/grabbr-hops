# grabbr-hops

Share one keyboard and mouse across your Mac, Windows, and Linux machines — a
software KVM. Part of the **grabbr** suite of power-user utilities.

## Upstream & credit

grabbr-hops is a fork of **lan-mouse** by Felix Eschberger (`feschber`) and its
contributors:

  https://github.com/feschber/lan-mouse

All original lan-mouse copyright and authorship is preserved in the git
history. grabbr-hops is developed independently: it does not track lan-mouse,
and changes are not exchanged with it.

## License

grabbr-hops is distributed under the **GNU General Public License v3.0 or
later** (see `LICENSE`), the same license as lan-mouse.

The macOS and Windows builds include the graphical interface, built with
[Slint](https://slint.dev), which grabbr-hops uses under GPL-3.0-only. Those
binaries as a whole are therefore distributed under the GNU General Public
License version 3 only. The Linux build has no graphical interface and is not
affected.

Every release archive, and the app in the dmg, carries `LICENSE`,
`THIRD-PARTY-NOTICES.txt` with the licenses of the crates the binary is built
from, and an SBOM.

## What grabbr-hops adds / changes

- A **QUIC** transport (quinn, TLS 1.3) in place of lan-mouse's, with machines
  identified by the fingerprint of their own key.
- Pairing that both machines approve, choosing which way control goes and
  whether to share the clipboard, confirmed by comparing a six-digit number;
  the paired machines are kept in a signed trust store. See
  [docs/SECURITY.md](docs/SECURITY.md).
- One device per physical machine across every frontend: a Slint graphical
  interface for macOS and Windows, a terminal UI, and a command line.
- A token-authenticated channel between the service and its frontends.
- Discovery of other machines on the local network over mDNS.
- A substantially reworked **macOS input backend**: modifier-coherence
  self-heal, an `IOHIDPostEvent` native-focus path (smoother, wakes the
  display), VM-guest-aware injection, and media keys.
