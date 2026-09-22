#!/bin/bash
# grabbr-hop — DAILY DRIVER (run this for normal, everyday use).
# Points the daemon + tray at the STABLE promoted binary ~/grabbr-hop/hops,
# which dev rebuilds never touch, then opens the app. Also switches you BACK
# here after a dev test session (grabbr-hop-dev.command).
. "$HOME/grabbr-hop/.hops-paths" || { echo "missing .hops-paths"; exit 1; }
LAUNCH="$HOPS_LAUNCH"
BIN="$HOPS_DAILY"
if [ ! -x "$BIN" ]; then
  echo "No daily binary at $BIN."
  echo "Build + promote one: run grabbr-hop-dev.command, validate it, then promote-to-daily.command."
  exit 1
fi
# Say what this binary is, then start it regardless. A promoted daily is
# deliberately behind the source — that is what promoting means — so being
# behind is normal here and only needs saying out loud. It went unsaid for
# three weeks once, and the everyday binary ran old code the whole time.
hops_gate "$BIN" report

"$LAUNCH/.switch-to" "$BIN"
echo "grabbr-hop: now on the DAILY build ($BIN)."
sleep 1
exec "$BIN"    # open the app window (attaches to the running daemon)
