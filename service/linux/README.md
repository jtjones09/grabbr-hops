# Linux dev / daily launchers

The same two-binary split the other platforms use: a **daily** binary you run
normally, and a **dev** build you switch onto to test a change and then switch
back from. `promote-to-daily` is the deliberate step that makes a validated dev
build your everyday one.

    cp -r service/linux/. ~/grabbr-hop/        # includes the dotfiles
    chmod +x ~/grabbr-hop/grabbr-hop-* ~/grabbr-hop/promote-to-daily ~/grabbr-hop/.switch-to

Edit `HOPS_REPO` in `.hops-paths` if your checkout is not `~/projects/grabbr-hops`
(or export it).

Every launcher runs `hops build-check` first, so a binary that does not match
its source is caught at launch rather than halfway through a test session:

- `grabbr-hop-dev` — builds, then **refuses to switch** if the build does not
  match the source. Nothing is switched before that check passes.
- `grabbr-hop-daily` — **reports and never blocks**. A promoted binary is
  deliberately behind the source; that is what promoting means. It only needs
  saying out loud.
- `promote-to-daily` — refuses a stale build by default. `promote-to-daily force`
  promotes anyway, for when you validated a build and the source has since moved
  on.

## Known gap

On Linux the `hops` front door can spawn a detached daemon outside systemd, so
`systemctl --user restart` succeeding does not prove the right binary is the one
serving input. `.switch-to` reports any hops daemon it finds running outside the
unit rather than killing it; if input goes to the wrong build, stop those first.
