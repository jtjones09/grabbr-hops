# Upgrading from 0.12

## Update every machine

hops 0.13 listens on UDP 4722 instead of 4242, and a controlled machine
may dial the machine that controls it, which 0.12 does not understand. On
the default ports a 0.13 machine and a 0.12 machine cannot reach each
other, so update all of them. When a dial gets no answer on 4722, 0.13
checks the old port, and the app names the machine that still runs an
older hops.

## Pair each machine again

hops 0.12 kept one list of paired machines that did not say which machine
controls which, so 0.13 trusts none of them until they are paired again.
Each shows as "paired with an older version: add it again". The steps are
in [SECURITY.md](SECURITY.md#upgrading-from-hops-012).

## The port

hops 0.12 listens on 4242, the old port. A `port = 4242` line in
`config.toml`, at the top or in a device's `[[clients]]` entry, keeps it. Remove it on every machine to move to
4722, or keep 4242 on all of them. A firewall rule that lets UDP 4242 in
must be changed to 4722; on Windows, a `hops.exe` unpacked into a new
folder also needs a new rule (see
[MANAGED-MAC.md](MANAGED-MAC.md#on-the-controlling-machine)). Every port
hops uses is in [NETWORK.md](NETWORK.md).

## Stop the old service on Windows

The 0.12 background service keeps running beside 0.13 until it is
stopped. The steps are in [service/README.md](../service/README.md#windows).

hops 0.13 no longer writes `%USERPROFILE%\hops\logs`; its logs are in
`%LOCALAPPDATA%\hops\logs`, and the old folder can be removed. If hops was
installed with `install.ps1`, run it again first.

## macOS

Replace hops in Applications with the new version and open it. If the
background service is still running the older build, the app restarts
it.

hops 0.13 no longer creates or writes `~/hops/logs`; its logs are in
`~/Library/Logs/hops`, and the old folder can be removed. If hops was
installed with `install.sh`, run it again first.

## Linux

hops 0.13 names itself `com.grabbr.hops` to the desktop. The input
devices it creates carry that name instead of the upstream project's, and
the portal's consent prompt names hops instead of an unnamed application.

The prompt names hops with xdg-desktop-portal 1.20 or later, when
`com.grabbr.hops.desktop` is installed in `~/.local/share/applications`.
`install.sh` installs it. From the release archive, copy it there
yourself and change its `Exec=` line to the binary's absolute path, for
example `Exec="/opt/hops/hops"`. The portal looks a bare `hops` up on its
own `PATH`, the systemd user manager's rather than your shell's, and
ignores the entry without a message when it is not found there. Restart
hops after installing it.

The portal remembers "allow input control" per application, and 0.12 was
remembered as an unnamed one. The first start with the name in place
therefore asks once more. Allow it, and hops is remembered under its own
name.
