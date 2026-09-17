#!/bin/zsh
# Wrap a .app in a compressed, read-only disk image with an Applications link.
set -euo pipefail

APP="${1:-}"
DMG="${2:-}"
VOLNAME="${3:-续签助手}"

if [[ -z "$APP" || -z "$DMG" || ! -d "$APP" ]]; then
  print -u2 -- "usage: $0 /path/to/续签助手.app /path/to/out.dmg [volume name]"
  exit 1
fi

APP_BASENAME="${APP:t}"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/iparenewal-dmg.XXXXXX")"
MOUNT="$(mktemp -d "${TMPDIR:-/tmp}/iparenewal-dmg-mount.XXXXXX")"
mounted=0
cleanup() {
  if [[ "$mounted" -eq 1 ]]; then
    hdiutil detach "$MOUNT" >/dev/null 2>&1 || true
  fi
  rm -rf "$STAGE" "$MOUNT"
}
trap cleanup EXIT

COPYFILE_DISABLE=1 ditto --norsrc --noextattr --noqtn "$APP" "$STAGE/$APP_BASENAME"
ln -s /Applications "$STAGE/Applications"

mkdir -p "$(dirname "$DMG")"
rm -f "$DMG"
hdiutil create -volname "$VOLNAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null

hdiutil attach -nobrowse -readonly -mountpoint "$MOUNT" "$DMG" >/dev/null
mounted=1
if [[ ! -d "$MOUNT/$APP_BASENAME" ]]; then
  print -u2 -- "DMG is missing $APP_BASENAME"
  exit 1
fi
if [[ "$(readlink "$MOUNT/Applications")" != "/Applications" ]]; then
  print -u2 -- "DMG Applications link is invalid"
  exit 1
fi
hdiutil detach "$MOUNT" >/dev/null
mounted=0
print -- "$DMG"
