# Upgrading from 0.12

## Update every machine

hops 0.13 listens on UDP 4722 instead of 4242, and a controlled machine
may dial the machine that controls it, which 0.12 does not understand. On
the default ports a 0.13 machine and a 0.12 machine cannot reach each
other, so update all of them. When a dial gets no answer on 4722, 0.13
checks the old port, and the app names the machine that still runs an
older hops.

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

## macOS

Replace hops in Applications with the new version and open it. If the
background service is still running the older build, the app restarts
it.
