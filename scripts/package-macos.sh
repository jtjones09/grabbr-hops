#!/usr/bin/env bash
# Package a (universal) hops binary into a macOS .app bundle + a .dmg.
#
#   scripts/package-macos.sh <hops-binary> [out-dir] [version]
#
# NO Apple credentials needed — this only assembles the bundle. Code-signing and
# notarization are a separate step (scripts/sign-macos.sh) so the packaging can
# be built and tested without a Developer ID.
#
# Produces, in <out-dir> (default ./dist):
#   hops.app         — the app bundle (a menu-bar / LSUIElement app; the same
#                      binary also serves the CLI at Contents/MacOS/hops)
#   hops-macos.dmg   — a drag-to-Applications disk image
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:?usage: package-macos.sh <hops-binary> [out-dir] [version]}"
OUT="${2:-$REPO/dist}"
VERSION="${3:-$(grep -m1 '^version' "$REPO/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')}"
APP="$OUT/hops.app"

echo "==> Assembling $APP (version $VERSION)"
mkdir -p "$OUT"

# ONE generator, shared with the dev launcher. They used to differ — the release
# bundle carried the Info.plist and the dev build ran as a bare binary — so a
# permission declared here was simply absent from the build being tested. See
# scripts/macos-app-bundle.sh.
ICNS=""
if [ -f "$REPO/target/icon.icns" ]; then
    ICNS="$REPO/target/icon.icns"
    echo "    + icon.icns"
else
    echo "    (no target/icon.icns — run scripts/makeicns.sh to add a Finder icon)"
fi

# Signing and notarization stay in sign-macos.sh; this only assembles.
"$REPO/scripts/macos-app-bundle.sh" "$BIN" "$VERSION" "$APP" "$ICNS" >/dev/null

echo "==> Building $OUT/hops-macos.dmg"
STAGE="$(mktemp -d)"
cp -R "$APP" "$STAGE/hops.app"
ln -s /Applications "$STAGE/Applications"   # drag-to-install target
rm -f "$OUT/hops-macos.dmg"
hdiutil create -volname "hops" -srcfolder "$STAGE" -ov -format UDZO "$OUT/hops-macos.dmg" >/dev/null
rm -rf "$STAGE"

echo "==> Done:"
echo "    $APP"
echo "    $OUT/hops-macos.dmg"
