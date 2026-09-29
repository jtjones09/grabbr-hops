# What hops does on the network

Everything hops sends between machines, which way each connection goes,
and how to turn off the parts a managed network may not want. Setting up
a machine behind a VPN or security client is in
[MANAGED-MAC.md](MANAGED-MAC.md).

## Summary

| What | Protocol and port | Direction |
| --- | --- | --- |
| Input, clipboard and pairing between two machines | QUIC over UDP 4722, TLS 1.3 | see below for which machine opens it |
| Asking whether a machine still runs hops 0.12 | the start of a QUIC handshake to UDP 4242, the old port | outbound, only after a dial to 4722 got no answer |
| Finding other machines on the LAN | multicast DNS, UDP 5353, over IPv4 and IPv6 | multicast, both ways; off with `discovery = false` or `listen = false` |
| Looking up a device added by name | the system resolver | outbound DNS, as any program's lookup |
| The app talking to the hops service | a Unix socket, or a named pipe on Windows | this machine only; nothing on the network |

hops has no HTTP client, and sends no telemetry, crash reports or update
checks. There are no accounts, no cloud service and no relay: the two
machines connect to each other directly.

## Connections between machines

Every connection is QUIC over UDP, encrypted and authenticated with
TLS 1.3. Each machine proves the key it was paired with; a machine it
holds no pairing with is refused during the handshake. The port is 4722
unless `port` in `config.toml` says otherwise; a dial leaves from a
random local port. hops listens on every IPv4 interface and on no IPv6
one, so it cannot be reached over IPv6. A name can resolve to IPv6
addresses as well: a controlled machine dialling out, and the check for
an old hops below, send to every address the name gives, IPv6 ones
included, but only an IPv4 address can answer.

Input, the clipboard, the pairing number and the notice that a machine
was removed all travel over these connections; hops opens no other. An
open connection sends a QUIC keep-alive every 8 seconds and closes after
20 seconds without an answer.

To pair, the machine a device is added on dials it, offering the ALPN
`grabbr-hop/1`, until it answers; the pairing runs over that connection.
Once the two are paired, which machine opens the connection depends on
which way control goes:

- **The controlling machine dials**, offering `grabbr-hop/1`, when the
  pointer crosses to the device and no link is up. This is the usual
  case. The controlled machine needs UDP 4722 open inbound.
- **The controlled machine dials**, offering `grabbr-hop/1-driven`,
  whenever the other machine may control it, its device is switched on,
  and no connection the other machine opened is up. This holds whether
  or not this machine may also control the other, and whether or not it
  listens. It holds that connection open, and dials again 1 second after
  it drops, waiting up to 30 seconds between tries. The controlling
  machine needs UDP 4722 open inbound; the controlled machine needs only
  outbound UDP. This is how a machine behind a VPN or security client
  that drops unsolicited inbound connections is controlled.
- **Each controls the other**: each machine does both. For each
  direction, the first connection up carries it, and the other attempt
  stops.

When a dial to 4722 gets no answer, hops sends the start of a handshake to
UDP 4242 on the same addresses, the old port that hops 0.12 listens on,
and finishes no handshake there. If an older hops answers, the app says which
machine to update.

## Discovery

Unless it is turned off, hops announces itself by multicast DNS (UDP 5353,
on every interface, over IPv4 and IPv6) as `_hops._udp.local.` and listens
for other machines doing the same, so they appear in add device. The announcement carries:

- this machine's hostname;
- its IPv4 addresses, other than loopback, and the port hops listens on;
- the fingerprint of its public key, and the protocol version.

Nothing in it is trusted: it only suggests an address to dial.

## Turning parts off

In `config.toml` (`~/.config/lan-mouse/` on macOS and Linux,
`%LOCALAPPDATA%\lan-mouse\` on Windows). hops reads both settings when it
starts, so restart it after changing them.

- `discovery = false`: no announcement and no listening for others. Add
  devices by address or hostname instead.
- `listen = false`: hops listens on no port, announces nothing and looks
  for no other machine; each dial it makes still leaves from a random
  local port. It is controlled only over the connections it opens to the
  machines paired to control it.

## The local channel

The app, the terminal UI and the CLI reach the hops service through a
Unix socket (`~/Library/Caches/lan-mouse-socket.sock` on macOS,
`$XDG_RUNTIME_DIR/lan-mouse-socket.sock` on Linux) or, on Windows, a named
pipe that only the signed-in user can open. Each connection must prove it
holds the token in `ipc-token`, beside `config.toml`, which only that user
can read. Nothing on this channel leaves the machine.

## Power on macOS

A Mac that is asleep cannot be controlled. While a paired device that may
control this Mac is switched on, hops holds a `PreventUserIdleSystemSleep`
power assertion: the Mac does not go to sleep when idle, the display may
still turn off, and input from the controlling machine wakes it. With no
such device, hops holds no assertion. `pmset -g assertions` lists it.

The `GRABBR_KEEP_AWAKE` environment variable of the hops service changes
this: `display` keeps the display on as well
(`PreventUserIdleDisplaySleep`), and `off` holds no assertion, so the Mac
sleeps as usual and cannot be reached until it wakes. For the service
macOS starts at login, set it under `EnvironmentVariables` in
`~/Library/LaunchAgents/com.grabbr.hops.plist`.
