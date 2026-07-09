#!/usr/bin/env bash
# Code-sign + notarize + staple hops.app, then produce a stapled .dmg for
# distribution. Run scripts/package-macos.sh FIRST to build dist/hops.app.
#
#   [env…] scripts/sign-macos.sh [out-dir]
#
# Requires (from your Apple Developer account — see docs/SIGNING.md):
#   DEVELOPER_ID   your signing identity, e.g.
#                  "Developer ID Application: Your Name (TEAMID)"
#                  list yours with:  security find-identity -v -p codesigning
#
# Notarization credentials — ONE of:
#   NOTARY_PROFILE                          a keychain profile you created once
#                                           with `xcrun notarytool store-credentials`
#   NOTARY_KEY + NOTARY_KEY_ID + NOTARY_ISSUER
#                                           App Store Connect API key: path to the
#                                           .p8, its Key ID, and the Issuer ID
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$REPO/dist}"
APP="$OUT/hops.app"
[ -d "$APP" ] || { echo "no $APP — run scripts/package-macos.sh first" >&2; exit 1; }
: "${DEVELOPER_ID:?set DEVELOPER_ID to your 'Developer ID Application: … (TEAMID)' identity}"

# Resolve notarytool auth from the environment.
if [ -n "${NOTARY_PROFILE:-}" ]; then
    NOTARY_AUTH=(--keychain-profile "$NOTARY_PROFILE")
elif [ -n "${NOTARY_KEY:-}" ] && [ -n "${NOTARY_KEY_ID:-}" ] && [ -n "${NOTARY_ISSUER:-}" ]; then
    NOTARY_AUTH=(--key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER")
else
    echo "notarization creds missing: set NOTARY_PROFILE, or NOTARY_KEY + NOTARY_KEY_ID + NOTARY_ISSUER" >&2
    exit 1
fi

echo "==> Signing with hardened runtime + secure timestamp"
# Sign the inner Mach-O first, then the bundle (inner → outer). No entitlements:
# the Slint build links only Apple frameworks (no library-validation issue) and
# uses no Apple Events / JIT, so the default hardened runtime is sufficient.
codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID" "$APP/Contents/MacOS/hops"
codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID" "$APP"
codesign --verify --strict --verbose=2 "$APP"

echo "==> Notarizing (submit + wait for Apple's verdict)"
ZIP="$OUT/hops-notarize.zip"
ditto -c -k --keepParent "$APP" "$ZIP"     # notarytool needs a zip/pkg/dmg
xcrun notarytool submit "$ZIP" "${NOTARY_AUTH[@]}" --wait
rm -f "$ZIP"

echo "==> Stapling the ticket to hops.app (offline verification)"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

echo "==> Rebuilding + stapling the .dmg from the stapled app"
STAGE="$(mktemp -d)"
cp -R "$APP" "$STAGE/hops.app"
ln -s /Applications "$STAGE/Applications"
rm -f "$OUT/hops-macos.dmg"
hdiutil create -volname "hops" -srcfolder "$STAGE" -ov -format UDZO "$OUT/hops-macos.dmg" >/dev/null
rm -rf "$STAGE"
xcrun stapler staple "$OUT/hops-macos.dmg"

echo "==> Gatekeeper assessment (expect: accepted / source=Notarized Developer ID)"
spctl --assess --type execute -vvv "$APP" 2>&1 || true

echo
echo "✅  Signed + notarized + stapled:"
echo "    $APP"
echo "    $OUT/hops-macos.dmg   ← distribute this"
