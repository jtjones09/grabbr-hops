# What pairing protects, and how to recover

hops lets one machine type and move the pointer on another. A machine allowed
to control this one can do anything a person at this keyboard can do. This
page says what pairing stops, what it cannot stop, how to remove a machine,
and how to recover. How to report a vulnerability is in
[SECURITY.md](../SECURITY.md).

## What pairing protects against

- **Machines that were never paired.** Every connection is QUIC with TLS 1.3.
  Each machine is identified by the fingerprint of its own key, and a machine
  this one holds no pairing with is refused during the TLS handshake.
- **Requests nobody asked for.** A pairing request appears only on a machine
  where add device was opened in the last two minutes, or that is adding the
  other machine itself. Any other unknown machine is refused and logged.
- **A machine in the middle.** Approving a request grants nothing yet. Both
  machines approve, then compare a six-digit number: the machine that added
  shows it, the other picks it from three. The number is computed from the
  keys each machine sees on that connection, its TLS session, and a random
  value from each machine, each fixed before the other is revealed. A machine
  relaying between the two cannot choose it, and the two screens would show
  different numbers. A wrong pick ends the attempt, and nothing is trusted.
- **More than was granted.** A pairing lets control go only the way the
  person approving chose. Input from a machine not allowed to control this
  one is refused, and input is accepted only after the pointer has crossed
  onto this machine. The clipboard is shared only if chosen, only the way
  control goes, and can be switched off per device. Pairings made before
  hops asked about the clipboard keep sharing it the way control goes.
- **A trust file this machine did not write.** The list of paired machines
  is signed by a key kept beside it. A trust file edited by hand, copied
  from another installation, or restored on its own over a newer one stops
  hops from starting instead of being trusted. When the trust file is
  missing, the machines listed in `config.toml` are shown as needing to be
  paired again and are trusted with nothing, so a `config.toml` copied or
  edited while the trust file is gone grants nothing.
- **Reaching a machine that cannot be dialled.** A machine dials each
  machine allowed to control it, as well as waiting to be dialled, so one
  behind a VPN or security client that drops incoming connections is still
  controlled over the connection it opens. It dials only machines paired
  with it whose pairing lets them control it, checks that the machine that
  answers has that pairing's key before sending anything, opens no port to
  do so, and raises no pairing request on the machine it dials. A device
  switched off or removed is not dialled.

## What it cannot protect against

- **A machine allowed to control this one.** It has this keyboard. It can
  open a terminal and run anything this user can.
- **Programs running as the same user.** Such a program can read the token
  the app uses to reach the hops service, and then do what the app can:
  approve a pairing request that is waiting, answer its number, turn a paired
  machine's clipboard on, and open add device and add a machine itself, so it
  can pair a machine of its choosing. It can also read the keys and re-sign
  the trust file. hops refuses to approve, answer a number or turn a
  clipboard on while another machine is controlling this one or holds a key
  or button down on it, and for two seconds after its last input or after it
  leaves, counting a button let go as it leaves as its input, so that
  machine cannot click its own approval. That machine can still start such
  a program, which acts once it has left.
- **Adding the wrong machine.** The number proves that the two screens are
  connected to each other, not that the other machine is the one meant.
  Check the name and address on the request before approving.
- **Physical access.** Anyone at the keyboard can pair a machine. The keys
  are stored unencrypted; a copy of the configuration directory lets its
  holder pose as this machine to every machine that trusts it.
- **An administrator** of the machine, who can read every file and inject
  input without hops.
- **The network itself.** Traffic cannot be read or changed, but it can be
  blocked. Discovery announces that the machine runs hops, with its hostname,
  addresses and key fingerprint; set `discovery = false` in `config.toml` to
  turn it off and type addresses instead.

## Upgrading from hops 0.12

hops 0.12 kept one list of paired machines that did not say which machine
controls which. hops 0.13 does not guess: each machine on that list is
shown as paired with an older version, and trusted with nothing, in either
direction, until it is paired again. Use "add again" on its card, or `a` in
the terminal UI, with add device open on both machines, and choose which
machine controls which. A pairing that goes one way is the better choice
for a machine managed by someone else, such as a work laptop. Remove the
card for a machine no longer used.

hops 0.13 drops the old list from `config.toml` the next time it saves its
settings. A machine moved back to hops 0.12 after the upgrade has to be
paired again there too.

## Removing a machine

Remove it from its card in the app, or with `d` in the terminal UI
(`hops tui`, which also works over SSH). From a script, `hops cli list`
prints each card's id, and `hops cli remove-client <id>` removes the card
and the pairing with it. A machine with no card here, such as one that only
controls this one, is not listed; remove it in the app or the terminal UI.
Removal is allowed even while another machine is controlling this one.

- It takes effect at once: its links close and its clipboard stops.
- If a link between the two is up and the other machine runs hops 0.13 or
  later, it is told and removes this machine too. If not, its card reads
  "it removed this machine" the next time it tries to control this one;
  remove it there as well. A machine that never controls this one is not
  told, so remove this machine on it by hand.
- hops keeps no record of a removed machine and there is no undo. To use it
  again, pair the two machines again from the start.
- Each machine keeps its own pairings. Removing a machine here does not
  remove it from any other machine.

## Recovering

**A machine is lost or stolen.** It keeps its key, so it can still reach
every machine that trusts it. Remove it on each of them.

**Reinstalling hops.** The key and the pairings live in the configuration
directory, not in the app, so a reinstall keeps them:

| System | Configuration directory |
| --- | --- |
| macOS, Linux | `~/.config/lan-mouse/` (or `$XDG_CONFIG_HOME/lan-mouse/`) |
| Windows | `%LOCALAPPDATA%\lan-mouse\` |

On macOS and Linux only its owner can read it. A new operating system, a new
user account or a deleted directory gives the machine a new key. The other
machines then no longer recognise it: remove its old card on each and pair
again.

**A device no longer connects.** Its card says where it stands:

| The card says | What to do |
| --- | --- |
| it removed this machine | Remove it here, then pair again. |
| waiting for its approval | That machine has not approved the pairing or picked its number yet. Open add device on it and finish there. |
| not accepting input | hops runs there but cannot inject input. It may lack a permission, such as Accessibility on macOS. |
| paired with an older version: add it again | It was paired by hops 0.12 and is trusted with nothing. Add it again with add device open on both machines, and choose which machine controls which. |
| unreachable | Check that hops runs on both machines. One of the two must accept UDP on the port hops listens on (`port` in `config.toml`, or `o` in the terminal UI): a machine that cannot accept it is reached through the connection it opens to each machine allowed to control it. |

A notice can say more:

- "... does not let this machine control it": it was paired for the other
  direction only. Pair again, choosing the direction needed.
- "... answered for ... as ...": the device's address now reaches a
  different machine. Correct the address on its card; the pairing is kept.

**Starting over.** To end every pairing and keep this machine's key, remove
each device. To give the machine a new key as well, for example when a copy
of the configuration directory may exist elsewhere: quit hops and stop its
background service, move the whole configuration directory aside, then start
hops. Moving only the trust file aside ends every pairing too: the machines
`config.toml` still lists are shown as needing to be paired again, and are
trusted with nothing. Then remove this machine on every other machine.
