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
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/hops"
chmod +x "$APP/Contents/MacOS/hops"

# App icon is optional — build it with scripts/makeicns.sh (needs imagemagick +
# librsvg). Without it the bundle just gets the generic macOS app icon.
ICON_KEY=""
if [ -f "$REPO/target/icon.icns" ]; then
    cp "$REPO/target/icon.icns" "$APP/Contents/Resources/icon.icns"
    ICON_KEY='    <key>CFBundleIconFile</key><string>icon</string>'
    echo "    + icon.icns"
else
    echo "    (no target/icon.icns — run scripts/makeicns.sh to add a Finder icon)"
fi

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.grabbr.hops</string>
    <key>CFBundleExecutable</key><string>hops</string>
    <key>CFBundleName</key><string>hops</string>
    <key>CFBundleDisplayName</key><string>hops</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleVersion</key><string>${VERSION}</string>
${ICON_KEY}
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <!-- menu-bar app: no Dock icon / Cmd-Tab entry (matches set_accessory_policy) -->
    <key>LSUIElement</key><true/>
    <key>NSAppSleepDisabled</key><true/>
    <key>NSInputMonitoringUsageDescription</key>
    <string>hops needs Input Monitoring to capture your keyboard and mouse and forward it to the machines you've paired.</string>
</dict>
</plist>
PLIST

# Fail loudly if the plist is malformed rather than shipping a broken bundle.
plutil -lint "$APP/Contents/Info.plist" >/dev/null

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
