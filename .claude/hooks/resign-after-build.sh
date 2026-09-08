#!/usr/bin/env bash
# Re-sign the macOS dev binary after any cargo build, automatically.
#
# WHY THIS IS A HOOK AND NOT A NOTE
#
# The rule — "re-sign target/release/hops with --identifier com.grabbr.hops
# immediately after building" — was written down, in detail, including a record
# of the day it was skipped and what it cost. It was then skipped again.
#
# Skipping it is silent and expensive. codesign defaults the identifier to the
# filename, TCC's designated requirement includes the identifier, so a
# differently-identified binary is a DIFFERENT app to macOS. The Accessibility
# grant stops applying, input emulation falls back to `dummy`, and the daemon
# accepts input and discards it while every UI still reads "connected". The
# only visible symptom is the cursor sticking on the sender.
#
# Re-signing is idempotent and always correct, so there is nothing to decide:
# the hook just does it.
#
# Deliberately matches the launcher exactly. Do NOT add --options runtime or
# --timestamp.

set -uo pipefail
[ "$(uname -s)" = "Darwin" ] || exit 0

BIN="${CLAUDE_PROJECT_DIR:-.}/target/release/hops"
[ -f "$BIN" ] || exit 0

IDENTITY="Developer ID Application: Hotash Studios LLC (9V42Q953X9)"

# Already correct? Say nothing.
if codesign -dv --verbose=2 "$BIN" 2>&1 | grep -q "^Identifier=com.grabbr.hops$" \
   && codesign -dv --verbose=2 "$BIN" 2>&1 | grep -q "Developer ID Application"; then
  exit 0
fi

if codesign --force --identifier com.grabbr.hops --sign "$IDENTITY" "$BIN" 2>/dev/null; then
  echo "re-signed target/release/hops as com.grabbr.hops (TCC grant preserved)" >&2
else
  echo "COULD NOT RE-SIGN target/release/hops. It is adhoc-signed, so macOS treats" >&2
  echo "it as a different app, the Accessibility grant does not apply, and input" >&2
  echo "emulation will silently fall back to 'dummy' — accepting input and" >&2
  echo "discarding it. Run this before using the build:" >&2
  echo "  codesign --force --identifier com.grabbr.hops \\" >&2
  echo "    --sign \"$IDENTITY\" target/release/hops" >&2
fi
exit 0
