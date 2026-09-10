# Logging

Every hops process opens its own log, on every platform, whatever started it.
Nothing depends on a launcher redirecting output — a tray started by a wrapper
that redirects nothing used to throw its crash backtraces at a closed handle,
and a crash on "add device" was invisible for weeks because of it.

Four tiers, ordered by how deliberately you have to reach for them.

---

## Tier 1 — always on

One file per role, so a daemon and a tray attached to it do not interleave.
Capped at **8 MB**, keeping one previous generation as `<role>.log.1`.

| Platform | Files | OS-level |
| --- | --- | --- |
| macOS | `~/Library/Logs/hops/` | warnings and errors also go to the unified log |
| Windows | `%LOCALAPPDATA%\hops\logs\` | none — see below |
| Linux | `~/.local/state/hops/` (or `$XDG_STATE_HOME/hops/`) | see below |

Roles: `daemon.log`, `gui.log`, `tui.log`, `cli.log`.

On macOS, warnings and errors reach Console.app and survive the process:

```
log show --last 1h --predicate 'process == "hops"'
```

Only warnings and errors. macOS records a forwarded message as `Default`
whatever priority is passed, and `Default` is persisted to disk — so forwarding
every level would write hops' entire debug stream into storage it neither owns
nor rotates.

Windows has no OS-level sink. Writing to the Event Log needs a registered event
source, which is an elevated registry write at install time; the installer is
deliberately elevation-free, so that is an installer decision rather than a
logging one.

**Crashes.** The panic hook writes its backtrace through the logger, unbuffered,
with no `RUST_BACKTRACE` needed. The release profile sets `panic = "abort"`, so
that line is the last thing the process ever writes — which is why the file is
never buffered.

---

## Tier 2 — turning it up

```sh
HOPS_LOG_LEVEL=debug                  # hops' own crates only
HOPS_LOG_LEVEL=info,mdns_sd=debug     # name a dependency explicitly
HOPS_LOG_LEVEL=trace                  # per-wire-event; very loud
HOPS_LOG_FILE=/path/to/file           # override the path entirely
```

A bare level applies to hops' crates and holds dependencies at `warn`. It did
not always: a bare `debug` once meant *every* crate, and one dependency logging
each mDNS packet produced a multi-gigabyte file. A dependency now has to be
asked for by name.

`stderr` is written only when it is a terminal, or when no file could be opened.
A service launcher that redirects stderr into a file of its own would otherwise
receive a second, unrotated copy of everything.

---

## Tier 3 — diagnostic toggles

These change behaviour as well as output. All are off unless set.

| Variable | Effect |
| --- | --- |
| `HOPS_TRUELOOP_PROBE` | receiver-side cursor-divergence probe |
| `HOPS_COALESCE_MOTION` | batch motion, flushing at ~240 Hz |
| `HOPS_ADAPTIVE_EDGE=off` | disable adaptive edge crossing |
| `HOPS_EDGE_LEARN=off` | freeze edge thresholds |
| `HOPS_EDGE_THRESHOLD=<px>` | set a starting threshold, not persisted |
| `HOPS_ABSOLUTE_MOTION=0` | disable absolute motion |
| `HOPS_ALLOW_DUMMY=1` | run even when no real emulation backend is available |

`HOPS_COALESCE_MOTION` holds each movement for up to 4.2 ms before sending it.
That is measurable as cursor latency by anyone sensitive to it, so it belongs on
a command line for a comparison, never in a launcher.

`HOPS_ALLOW_DUMMY` overrides a refusal, not a warning. Without it, a daemon that
finds no usable emulation backend stops rather than accepting input and
discarding it — which it once did for hours while the interface still read
"connected".

**Queue metrics.** At `debug` in `hops::emulation`, the injection queue reports
once per *active* second:

```
[motion-metrics] 173 input/s | backlog now 0 | peak 4
```

Enough to tell a backed-up queue from a slow link without turning on anything
else:

```sh
HOPS_LOG_LEVEL=info,hops::emulation=debug
```

---

## Tier 4 — keystroke logging

Scancode mapping is not debuggable without key identity: the Linux↔Windows table
has had measurably wrong entries, and lock-key repeat and modifier coherence
both needed to see exactly which key arrived.

What it must never be is a side effect of turning up the log level. Before this
existed, `HOPS_LOG_LEVEL=debug` — set to look at a handshake or a config
reload — wrote every key pressed on the machine to the ordinary daemon log in
cleartext. One such file reached 4.4 GB and contained readable sentences.
Nobody choosing `debug` for a connection problem consented to that.

Three properties, all structural rather than advisory:

**Compiled out by default.** Without the `keylog` cargo feature — absent from
every release feature set — the recording code is not in the binary.

**Time-boxed, never unlimited.** `HOPS_LOG_KEYS` takes a duration, not a
boolean: `30s`, `10m`, `1h`, capped at one hour. `HOPS_LOG_KEYS=1` reads like
"on" and is rejected rather than quietly meaning one second.

**Its own file.** `~/hops/logs/keystrokes.log`, mode `0600` on unix. Keystrokes
never enter the general log, so a daemon log stays shareable — you could not
hand anyone a debug log without handing them your typing.

```sh
cargo build --release --features keylog
HOPS_LOG_KEYS=2m hops daemon
```

---

## Which log to read

**"It crashed."** The role's own file — `gui.log` for the tray, `daemon.log` for
the daemon. The backtrace is there even when the process was started by
something that redirects nothing.

**"Input isn't arriving."** `daemon.log` on the *receiving* machine. Check the
backend it chose: `using emulation backend: macos` is working, `dummy` is not.

**"The cursor feels slow."** `[motion-metrics]` on the receiving machine, and
check whether `HOPS_COALESCE_MOTION` is set on the sending one.

**"It won't pair."** `daemon.log` on both. A refused handshake names the reason,
and the two machines usually give different halves of it.
