# macOS dev / daily launchers

The launch folder `~/grabbr-hop` holds a **daily** binary you run normally and a
**dev** build you switch onto to test a change and then switch back from.
`promote-to-daily.command` is the deliberate step that makes a validated dev
build your everyday one. These are the files that live there.

    cp -R service/macos/. ~/grabbr-hop/        # includes the dotfiles
    chmod +x ~/grabbr-hop/*.command ~/grabbr-hop/.switch-to ~/grabbr-hop/hops-ctl

Edit `HOPS_REPO` in `.hops-paths` if your checkout is not
`~/Documents/GitHub/grabbr-hops` (or export it).

- `grabbr-hop-dev.command` — updates the checkout, builds it, signs it with the
  Developer ID so the Accessibility grant survives rebuilds, and switches the
  daemon and tray onto it. It refuses to switch if the build does not match the
  source.
- `grabbr-hop-daily.command` — switches back to the promoted daily. Reports how
  far behind it is and never blocks.
- `promote-to-daily.command` — copies a validated dev build over the daily.
  Refuses a stale build unless given `force`.
- `stop-grabbr-hop.command` — stops the daemon and the tray.

## Updating the checkout

The dev launcher fast-forwards the checkout to its remote branch before it
builds, so what you test is what the branch holds. It builds what is there, and
says why, when the tree has uncommitted changes, the branch tracks no remote
branch, or the remote cannot be reached. It stops, having built nothing, when
the branch has diverged from its remote branch. `HOPS_NO_PULL=1` skips the
update. The Linux and Windows dev launchers do the same.
