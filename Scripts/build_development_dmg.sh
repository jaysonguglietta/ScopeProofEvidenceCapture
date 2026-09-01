#!/bin/zsh
set -euo pipefail

project_root="${0:A:h:h}"
build_script="$project_root/Scripts/build_macos_capture.sh"
app="$project_root/DerivedData/Scopeproof Capture.app"
output_root="$project_root/DerivedData"
skip_build=false

if (( $# > 1 )) || { (( $# == 1 )) && [[ "$1" != "--skip-build" ]]; }; then
  echo "Usage: ./Scripts/build_development_dmg.sh [--skip-build]" >&2
  exit 2
fi
if (( $# == 1 )); then
  skip_build=true
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "The Scopeproof development DMG must be built on macOS." >&2
  exit 1
fi

if [[ "$skip_build" == false ]]; then
  "$build_script"
fi
if [[ ! -d "$app" ]]; then
  echo "Scopeproof Capture.app was not found at $app." >&2
  exit 1
fi

version="$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist")"
[[ "$version" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || { echo "The app version is invalid." >&2; exit 1; }

signature_details="$(codesign -dv --verbose=4 "$app" 2>&1)"
if [[ "$signature_details" != *"Signature=adhoc"* ]]; then
  echo "This script is only for the explicitly labeled ad-hoc development preview." >&2
  echo "Use Scripts/publish_release.sh for Developer ID signed and notarized releases." >&2
  exit 1
fi

staging_root="$(mktemp -d "${TMPDIR:-/tmp}/scopeproof-dmg.XXXXXX")"
mount_root="$(mktemp -d "${TMPDIR:-/tmp}/scopeproof-mount.XXXXXX")"
mounted=false
cleanup() {
  if [[ "$mounted" == true ]]; then hdiutil detach "$mount_root" >/dev/null 2>&1 || true; fi
  rm -rf "$staging_root" "$mount_root"
}
trap cleanup EXIT INT TERM

ditto "$app" "$staging_root/Scopeproof Capture.app"
ln -s /Applications "$staging_root/Applications"

dmg="$output_root/Scopeproof-Capture-${version}-development-preview.dmg"
checksum="$dmg.sha256"
hdiutil create -volname "Scopeproof Capture Preview" -srcfolder "$staging_root" -ov -format UDZO "$dmg"
(cd "$output_root" && shasum -a 256 "${dmg:t}" > "${checksum:t}")

hdiutil attach -nobrowse -readonly -mountpoint "$mount_root" "$dmg" >/dev/null
mounted=true
[[ -d "$mount_root/Scopeproof Capture.app" ]]
[[ -L "$mount_root/Applications" && "$(readlink "$mount_root/Applications")" == "/Applications" ]]
codesign --verify --deep --strict "$mount_root/Scopeproof Capture.app"
hdiutil verify "$dmg" >/dev/null
hdiutil detach "$mount_root" >/dev/null
mounted=false

echo "$dmg"
echo "$checksum"
