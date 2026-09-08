#!/usr/bin/env bash
# Build a minimal signed .app around a hops binary.
#
# ONE generator, used by both the release packaging and the dev launcher.
#
# It exists because those two had drifted: the release bundle carried the
# Info.plist and the dev build ran as a bare binary, so a permission declared
# for the shipped app was simply absent in the build actually being tested.
# Discovery is the case that made it visible — an undeclared Bonjour browse is
# blocked by macOS with no prompt and no error — but the same gap would hide
# any future entitlement the same way. Two ways to produce the same artifact is
# how the tested thing stops being the shipped thing.
#
# The release flow signs and notarizes separately (see sign-macos.sh), so this
# only signs when asked. The dev launcher asks, because a dev bundle that is not
# Developer-ID signed under the right identifier loses the Accessibility grant.
#
# usage: macos-app-bundle.sh <binary> <version> <output.app> [icon.icns] [--sign]
set -euo pipefail

BIN="${1:?binary}"
VERSION="${2:?version}"
APP="${3:?output .app path}"
ICNS="${4:-}"
SIGN="${5:-}"

[ -f "$BIN" ] || { echo "no such binary: $BIN" >&2; exit 1; }

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/hops"
chmod +x "$APP/Contents/MacOS/hops"

ICON_KEY=""
if [ -n "$ICNS" ] && [ -f "$ICNS" ]; then
  cp "$ICNS" "$APP/Contents/Resources/icon.icns"
  ICON_KEY="    <key>CFBundleIconFile</key><string>icon</string>"
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
    <!--
      Both discovery keys are required, and both were missing. macOS then
      allowed the outbound announcement and silently dropped every response, so
      hops advertised itself correctly, found nothing, and showed an empty list
      with no error anywhere.

      NSBonjourServices is the one that is easy to miss: recent macOS requires
      an app to DECLARE the service types it browses. Without it the browse is
      blocked whether or not Local Network is granted, and no prompt is ever
      shown, so there is nothing for a user to switch on.

      The service type must match hops::discovery::SERVICE_TYPE with the
      trailing mDNS domain removed. A guard test enforces that the two agree.
    -->
    <key>NSLocalNetworkUsageDescription</key>
    <string>hops finds the other machines you have paired on your local network, so you can add them without typing an address.</string>
    <key>NSBonjourServices</key>
    <array>
        <string>_hops._udp</string>
    </array>
</dict>
</plist>
PLIST

# Fail loudly rather than shipping (or running) a broken bundle.
plutil -lint "$APP/Contents/Info.plist" >/dev/null

# The identifier is NOT optional: TCC's designated requirement includes it, so a
# differently-identified bundle is a different app and the Accessibility and
# Input Monitoring grants do not apply. Matches the bare-binary signing exactly.
if [ "$SIGN" = "--sign" ]; then
  if security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application"; then
    codesign --force --deep --identifier com.grabbr.hops \
      --sign "Developer ID Application: Hotash Studios LLC (9V42Q953X9)" "$APP" >/dev/null
  else
    echo "warn: no Developer ID identity — bundle unsigned, macOS grants will not apply" >&2
  fi
fi

echo "$APP"
