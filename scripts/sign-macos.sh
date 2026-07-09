#!/usr/bin/env bash
# Code-sign + notarize + staple hops.app, then produce a notarized+stapled .dmg
# for distribution. Run scripts/package-macos.sh FIRST to build <out-dir>/hops.app.
#
#   [env…] scripts/sign-macos.sh [out-dir]
#
# All code-signing happens in a private temp workspace, never in <out-dir>. That
# matters when the repo lives in an iCloud-synced folder (~/Documents): iCloud's
# file provider keeps re-adding com.apple.FinderInfo, and codesign then refuses
# with "resource fork, Finder information, or similar detritus not allowed". By
# signing in a non-synced workspace and only copying the finished artifacts out,
# this runs cleanly from anywhere.
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
APP_SRC="$OUT/hops.app"
[ -d "$APP_SRC" ] || { echo "no $APP_SRC — run scripts/package-macos.sh first" >&2; exit 1; }
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

# Sign in a non-synced workspace so codesign never trips over iCloud xattrs.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/hops-sign.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
APP="$WORK/hops.app"
ditto "$APP_SRC" "$APP"
xattr -cr "$APP"

echo "==> Signing hops.app (hardened runtime + secure timestamp)"
# Sign the inner Mach-O first, then the bundle (inner → outer). No entitlements:
# the Slint build links only Apple frameworks (no library-validation issue) and
# uses no Apple Events / JIT, so the default hardened runtime is sufficient.
codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID" "$APP/Contents/MacOS/hops"
codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID" "$APP"
codesign --verify --strict --verbose=2 "$APP"

echo "==> Notarizing hops.app + stapling the ticket (offline verification)"
ZIP="$WORK/hops-notarize.zip"
ditto -c -k --keepParent "$APP" "$ZIP"     # notarytool needs a zip/pkg/dmg
xcrun notarytool submit "$ZIP" "${NOTARY_AUTH[@]}" --wait
rm -f "$ZIP"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

echo "==> Building the .dmg from the stapled app, then signing + notarizing IT"
# The app's notarization does NOT cover the dmg — the dmg needs its own ticket,
# or `stapler staple <dmg>` fails with error 65. So sign + notarize the dmg too;
# the result is a stapled dmg that itself contains a stapled app.
DMG="$WORK/hops-macos.dmg"
STAGE="$(mktemp -d "$WORK/stage.XXXXXX")"
cp -R "$APP" "$STAGE/hops.app"
ln -s /Applications "$STAGE/Applications"   # drag-to-install target
hdiutil create -volname "hops" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"
codesign --force --timestamp --sign "$DEVELOPER_ID" "$DMG"
xcrun notarytool submit "$DMG" "${NOTARY_AUTH[@]}" --wait
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"

echo "==> Gatekeeper assessment (expect: accepted / source=Notarized Developer ID)"
spctl --assess --type execute -vv "$APP" 2>&1 || true
spctl --assess --type open --context context:primary-signature -vv "$DMG" 2>&1 || true

echo "==> Publishing signed artifacts to $OUT"
mkdir -p "$OUT"
rm -rf "$OUT/hops.app"
ditto "$APP" "$OUT/hops.app"
cp -f "$DMG" "$OUT/hops-macos.dmg"

echo
echo "✅  Signed + notarized + stapled:"
echo "    $OUT/hops.app"
echo "    $OUT/hops-macos.dmg   ← distribute this"
