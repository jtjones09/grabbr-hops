# hops-ctl — the tray and the daemon are separate things

Restarting a crashed tray used to mean restarting both, because every launcher
did both and `taskkill /f /im hops.exe` (Windows) or a kill on the image name
could not tell them apart. So fixing a dead icon cost you your keyboard and
mouse — the daemon was working fine.

They are separate: the daemon is the service, the tray is a client that
attaches to it. `hops gui` is attach-only and never spawns or touches a daemon.

Same verbs on every platform:

    hops-ctl status
    hops-ctl restart-gui        # daemon keeps running; input never stops
    hops-ctl stop-gui | start-gui
    hops-ctl restart-daemon | stop-daemon | start-daemon

| Platform | Script | Mechanism |
| --- | --- | --- |
| macOS | `service/macos/hops-ctl` | `launchctl kickstart -k` on one agent |
| Linux | `service/linux/hops-ctl` | `systemctl --user` on one unit |
| Windows | `service/windows/hops-ctl.ps1` | by PID, role read from the command line |

Windows needs the extra work because both roles are `hops.exe`, so only the
command line distinguishes them. It stops **by PID, never by image name** —
which also means no elevated session, since stopping your own process by PID is
not a privileged operation. `-DryRun` prints what it would stop and does
nothing, which is how the targeting is checked without stopping a working KVM
to find out.

Linux needs `hops-gui.service` installed for the tray to be its own unit; it
`Wants` (not `Requires`) the daemon, so a tray failure can never take the
daemon down with it.

Run these from an interactive desktop session. A tray started from an SSH
session lands in a different session and its icon never appears.
