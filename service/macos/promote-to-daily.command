#!/bin/bash
# grabbr-hop — PROMOTE the current DEV build to be your DAILY driver.
# Copies the freshly-built + signed target/release/hops over ~/grabbr-hop/hops.
# Run this once a dev build is validated and you want it as your everyday binary,
# then run grabbr-hop-daily.command to switch onto it.
. "$HOME/grabbr-hop/.hops-paths" || { echo "missing .hops-paths"; exit 1; }
REPO="$HOPS_REPO"
LAUNCH="$HOPS_LAUNCH"
SRC="$HOPS_RAW"
[ -x "$SRC" ] || { echo "no dev build at $SRC — run grabbr-hop-dev.command first"; hops_hold; exit 1; }

# Refuse a stale build by default: promoting one is exactly how the everyday
# binary falls silently behind. But `force` has to exist — validating a build
# at one commit and promoting it after the source has moved on is the normal
# way this gets used, and refusing outright would make promotion impossible.
if [ "${1:-}" = force ]; then
  echo "  force: promoting WITHOUT a gate. What follows is a report, not a check:"
  hops_gate "$SRC" report
else
  hops_gate "$SRC" strict || {
    echo "  Your current daily is untouched."
    echo "  To promote this build anyway:  $0 force"
    hops_hold; exit 1
  }
fi
cp -f "$SRC" "$LAUNCH/hops"
codesign --force --identifier com.grabbr.hops \
  --sign "Developer ID Application: Hotash Studios LLC (9V42Q953X9)" "$LAUNCH/hops" 2>/dev/null \
  || echo "warn: Developer ID signing failed"
echo "promoted the current dev build -> DAILY (~/grabbr-hop/hops)."
echo "  -> run grabbr-hop-daily.command to switch onto it."

hops_hold
