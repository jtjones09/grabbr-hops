#!/usr/bin/env bash
# Verify a release dmg the way the Mac that opens it will: Gatekeeper accepts
# the image and the app inside it as notarized Developer ID code, both carry a
# stapled ticket, and the app is signed as com.grabbr.hops. Then check that it
# carries what every release artifact does: LICENSE, the third-party notices,
# an SBOM for each target of the universal binary, and a binary built with
# cargo auditable.
#
#   scripts/verify-macos-release.sh <dmg>
#
# Exits non-zero at the first check that does not pass. The release workflow
# runs this before it uploads the dmg, so a tag whose dmg fails it publishes
# nothing.
#
# Each check passes only on the evidence it names. `spctl --assess` answers
# "accepted" for anything once assessments are disabled, so its exit status
# alone is not proof; the notarized source line is required.
set -euo pipefail

DMG="${1:?usage: verify-macos-release.sh <dmg>}"
IDENTIFIER="com.grabbr.hops"

fail() {
    echo "::error::$*" >&2
    exit 1
}

gatekeeper() { # <what> <path> <spctl assess args...>
    local what="$1" path="$2" out
    shift 2
    out="$(spctl --assess -vv "$@" "$path" 2>&1)" || {
        echo "$out" >&2
        fail "Gatekeeper rejects $what."
    }
    echo "$out"
    grep -q '^source=Notarized Developer ID$' <<<"$out" ||
        fail "Gatekeeper did not assess $what as notarized Developer ID code."
}

stapled() { # <what> <path>
    xcrun stapler validate "$2" || fail "no notarization ticket is stapled to $1."
}

[ -s "$DMG" ] || fail "no dmg at $DMG, or it is empty."

gatekeeper "the dmg" "$DMG" --type open --context context:primary-signature
stapled "the dmg" "$DMG"

MNT="$(mktemp -d "${TMPDIR:-/tmp}/hops-verify.XXXXXX")"
trap 'hdiutil detach -quiet "$MNT" >/dev/null 2>&1 || true; rmdir "$MNT" 2>/dev/null || true' EXIT
hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$MNT" "$DMG" >/dev/null ||
    fail "cannot mount $DMG."
APP="$MNT/hops.app"
[ -d "$APP" ] || fail "$DMG holds no hops.app."

gatekeeper "hops.app" "$APP" --type execute
stapled "hops.app" "$APP"
codesign --verify --strict "$APP" || fail "hops.app's signature does not verify."

# The Accessibility and Input Monitoring grants are keyed to this identifier.
id="$(codesign -dv "$APP" 2>&1 | sed -n 's/^Identifier=//p')"
[ "$id" = "$IDENTIFIER" ] ||
    fail "hops.app is signed as '$id', not $IDENTIFIER; macOS would not apply its grants."

for f in LICENSE THIRD-PARTY-NOTICES.txt \
         hops-aarch64-apple-darwin.cdx.json hops-x86_64-apple-darwin.cdx.json; do
    [ -s "$APP/Contents/Resources/$f" ] || fail "hops.app carries no $f."
done
# The section cargo auditable embeds the dependency list in.
grep -qaF .dep-v0 "$APP/Contents/MacOS/hops" ||
    fail "hops.app's binary embeds no dependency list; it was not built with cargo auditable."

echo "OK: $DMG and the hops.app inside it are notarized, stapled and signed as $IDENTIFIER,"
echo "    and the app carries its licence, notices, SBOMs and dependency list."
