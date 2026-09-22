#!/bin/bash
# grabbr-hop — DEV / TEST. Updates the checkout, rebuilds it, signs it with your
# Developer ID (so the Accessibility grant holds), switches the daemon + tray
# onto the DEV build for testing, and opens the TUI. Your DAILY binary
# (~/grabbr-hop/hops) is UNTOUCHED — run grabbr-hop-daily.command to switch back.
#
#   ./grabbr-hop-dev.command                 dev build, adaptive edge ON (default)
#   ./grabbr-hop-dev.command off             adaptive edge OFF (position barrier only)
#   ./grabbr-hop-dev.command learn-off       adaptive edge ON, self-tuning OFF
#   ./grabbr-hop-dev.command 40              starting edge threshold 40px
#   HOPS_COALESCE_MOTION=1 ./grabbr-hop-dev.command   also turn motion coalescing ON
#   HOPS_ABSOLUTE_MOTION=1 ./grabbr-hop-dev.command   advertise absolute motion (Stage 2);
#                                                     set on the RECEIVER so its peer emits it
. "$HOME/grabbr-hop/.hops-paths" || { echo "missing .hops-paths"; exit 1; }
REPO="$HOPS_REPO"
LAUNCH="$HOPS_LAUNCH"
RAW="$HOPS_RAW"
cd "$REPO" || { echo "no repo at $REPO"; hops_hold; exit 1; }
hops_update_checkout || { hops_hold; exit 1; }
echo "building dev..."
cargo build --release --no-default-features --features "tui slint" \
  || { echo; echo "  build failed — nothing was switched."; hops_hold; exit 1; }

# Does the binary cargo just linked match the source it was built from?
#
# Here, and not later, for two reasons. The bundle step below does `rm -rf` on
# hops-dev.app — the exact path launchd starts — so a gate placed after it
# would abort having already destroyed the working setup. And this checks the
# binary cargo linked, not the copy inside the bundle: that copy's mtime is its
# copy time, so "a file was saved during the build" can only ever be caught on
# this one.
hops_gate "$RAW" strict || { hops_hold; exit 1; }

# Run the dev build from an .app bundle, not the bare binary.
#
# macOS grants some permissions only to a bundle that DECLARES it wants them.
# Bonjour browsing is the one that bit: an undeclared browse is blocked with no
# prompt and no error, so discovery announced correctly, found nothing, and
# showed an empty list. It worked from a terminal — inheriting that grant — so
# it only failed in the way the daemon is actually run.
#
# The bundle is built by the SAME generator the release uses, so the build being
# tested declares exactly what the shipped app declares. A guard test fails if
# those two ever diverge again.
APP="$LAUNCH/hops-dev.app"
VERSION="$(grep -m1 '^version' "$REPO/Cargo.toml" | sed -E 's/.*"(.*)".*/\1/')"
ICNS=""
[ -f "$REPO/target/icon.icns" ] && ICNS="$REPO/target/icon.icns"
"$REPO/scripts/macos-app-bundle.sh" "$RAW" "$VERSION" "$APP" "$ICNS" --sign >/dev/null \
  || { echo "could not build the dev app bundle"; exit 1; }
BIN="$APP/Contents/MacOS/hops"

# Also sign the bare binary: it stays the thing `cargo run` and the tests use.
codesign --force --identifier com.grabbr.hops \
  --sign "Developer ID Application: Hotash Studios LLC (9V42Q953X9)" "$RAW" 2>/dev/null \
  || echo "warn: Developer ID signing failed — the Accessibility grant may drop"

# Build the daemon's extra env from the coalescing prefix + the adaptive-edge arg.
EXTRA=""
[ -n "$HOPS_COALESCE_MOTION" ] && EXTRA="${EXTRA}<key>HOPS_COALESCE_MOTION</key><string>${HOPS_COALESCE_MOTION}</string>"
[ -n "$HOPS_TRUELOOP_PROBE" ]   && EXTRA="${EXTRA}<key>HOPS_TRUELOOP_PROBE</key><string>${HOPS_TRUELOOP_PROBE}</string>"
[ -n "$HOPS_TRUELOOP_LAG" ]     && EXTRA="${EXTRA}<key>HOPS_TRUELOOP_LAG</key><string>${HOPS_TRUELOOP_LAG}</string>"
[ -n "$HOPS_ABSOLUTE_MOTION" ]  && EXTRA="${EXTRA}<key>HOPS_ABSOLUTE_MOTION</key><string>${HOPS_ABSOLUTE_MOTION}</string>"
case "${1:-}" in
  "")        ;;
  off)       EXTRA="${EXTRA}<key>HOPS_ADAPTIVE_EDGE</key><string>off</string>" ;;
  learn-off) EXTRA="${EXTRA}<key>HOPS_EDGE_LEARN</key><string>off</string>" ;;
  *[0-9]*)   EXTRA="${EXTRA}<key>HOPS_EDGE_THRESHOLD</key><string>$1</string>" ;;
  *)         echo "usage: [HOPS_COALESCE_MOTION=1] $0 [off|learn-off|<threshold-px>]"; exit 1 ;;
esac

"$LAUNCH/.switch-to" "$BIN" "$EXTRA"
echo "grabbr-hop: now on the DEV build ($BIN)."
echo "  -> first run from the bundle: macOS may ask for Accessibility, Input"
echo "     Monitoring and Local Network. Local Network is the new one — without"
echo "     it the daemon announces but never sees a peer."
echo "  -> run grabbr-hop-daily.command to switch back to your stable daily."
sleep 1
exec "$BIN" tui
