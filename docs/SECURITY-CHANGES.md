# Security changes

Security fixes by release, in the terms a user sees. What pairing protects
against today is in [SECURITY.md](SECURITY.md).

## 0.13.0

Since 0.12.0. No advisory was published for these.

### Pairing and trust

- A pairing now needs approval on both machines and a six-digit number
  compared between them, bound to that connection's TLS session. Before,
  one approval on one machine trusted the other at once.
- A pairing request appears only within two minutes of add device being
  opened, or on the machine that added the other. Before, any machine
  that reached this one could put a request on screen at any time.
- Each request names the machine and address it came from. Before, a
  request could show the identity of a different machine.
- A pairing grants control only in the direction chosen. Every event from
  a machine not allowed to control this one is refused, including pointer
  motion and the crossing itself, and input is accepted only after the
  pointer has crossed onto this machine.
- A machine whose permission is withdrawn stops receiving input at once,
  over a link that was already open.
- Removing a machine takes effect at once, closes its links, tells it if
  it is connected, and refuses it during the TLS handshake. Before, a
  removed machine could be trusted again after a restart.
- Every pairing is listed and can be removed, including one this machine
  only controls.
- Renaming a device can no longer make it trusted.
- The list of paired machines is signed; a trust file edited by hand or
  copied from elsewhere stops hops instead of being trusted. A config
  file that does not parse no longer becomes an empty trust store.
- When one hostname answers as several machines, none is trusted.
- Every connection proves the other machine's key again: TLS session
  resumption is refused.
- A machine that holds no key can no longer make a machine that dials out
  report that its controller removed it.
- Approving a request, answering a number or turning a clipboard on is
  refused while another machine controls this one, including while it
  holds a key or button down.

### Clipboard

- The clipboard is shared only in the direction the pairing grants, is
  off unless chosen at pairing, and can be switched off per device.
- A copy a password manager marks as concealed or transient is neither
  read nor sent, and the clipboard is read only while some pairing may
  receive it.

### The local channel between the app and the service

- It can no longer run commands: the enter hook is set only in
  `config.toml`, is refused when hops runs elevated, and runs without a
  shell.
- The service says nothing until a connection proves it holds the token,
  and a connection without the token is capped in size and time.
- On Windows it was a TCP port on 127.0.0.1 that every signed-in user
  could reach. It is now a named pipe only this user can open, and each
  side proves the token to the other.
- The Windows logon task that starts hops no longer runs it with the
  highest privileges.

### Files, logs and input

- The configuration folder and the trust file are readable only by their
  owner, and hops never writes or changes permissions through a link in
  that folder.
- Keys pressed are never written to the general log. Keystroke logging
  is a separate, opt-in, time-limited mode.
- Malformed data from a paired machine can no longer crash the receiver,
  and a peer that stops reading no longer stalls the others.
- Keys and buttons held by a machine are released when its link ends or
  hops is stopped.
- The Linux installer no longer tells users to add themselves to a
  group that can read every keyboard on the machine, which would let any
  of their programs record every keystroke.

### Release

- Dependencies with published advisories were updated, among them rustls
  (RUSTSEC-2026-0285). A newly published vulnerability or unsoundness
  advisory against any dependency fails the build unless `deny.toml`
  ignores it with a reason; the release notes list every advisory let
  through, and why.
- Each release carries SHA-256 checksums, a build-provenance attestation,
  and an SBOM per target. The macOS signing keys are used only by a job
  that builds nothing.
