#!/bin/zsh
set -euo pipefail

project_root="${0:A:h:h}"
package_root="$project_root/macos/ScopeproofCapture"
output_root="$project_root/DerivedData"
app_name="Scopeproof Capture.app"
app_root="$output_root/$app_name"
module_cache="$package_root/.build/ModuleCache"
codesign_identity="${SCOPEPROOF_CODESIGN_IDENTITY:-}"
notary_profile="${SCOPEPROOF_NOTARY_PROFILE:-}"
entitlements="$package_root/Resources/ScopeproofCapture.entitlements"

mkdir -p "$module_cache" "$output_root"
staging_root="$(mktemp -d "$output_root/.scopeproof-build.XXXXXX")"
staged_app="$staging_root/$app_name"
previous_app="$output_root/.Scopeproof Capture.app.previous.$$"
cleanup() {
  /bin/rm -rf -- "$staging_root"
  if [[ -e "$previous_app" ]]; then
    if [[ ! -e "$app_root" ]]; then mv "$previous_app" "$app_root"
    else /bin/rm -rf -- "$previous_app"
    fi
  fi
}
trap cleanup EXIT INT TERM
export CLANG_MODULE_CACHE_PATH="$module_cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$module_cache"
cd "$package_root"
swift build -c release --disable-sandbox --scratch-path "$package_root/.build"

binary_candidates=(
  "$package_root"/.build/*-apple-macosx/release/ScopeproofCapture(N)
  "$package_root"/.build/release/ScopeproofCapture(N)
)
if (( ${#binary_candidates} == 0 )); then
  echo "ScopeproofCapture release binary was not produced." >&2
  exit 1
fi
binary_path="$binary_candidates[1]"
mkdir -p "$staged_app/Contents/MacOS" "$staged_app/Contents/Resources"
cp -p "$binary_path" "$staged_app/Contents/MacOS/ScopeproofCapture"
cp -p "$package_root/Resources/Info.plist" "$staged_app/Contents/Info.plist"

if [[ -n "$codesign_identity" ]]; then
  codesign --force --deep --options runtime --timestamp --entitlements "$entitlements" --sign "$codesign_identity" "$staged_app"
  codesign --verify --deep --strict "$staged_app"
  if [[ -n "$notary_profile" ]]; then
    archive_path="$output_root/Scopeproof-Capture-notarization.zip"
    ditto -c -k --keepParent "$staged_app" "$archive_path"
    xcrun notarytool submit "$archive_path" --keychain-profile "$notary_profile" --wait
    xcrun stapler staple "$staged_app"
    xcrun stapler validate "$staged_app"
  fi
else
  codesign --force --deep --sign - --requirements '=designated => identifier "com.scopeproof.capture"' "$staged_app"
fi
codesign --verify --deep --strict "$staged_app"
[[ "$(plutil -extract CFBundleIdentifier raw -o - "$staged_app/Contents/Info.plist")" == "com.scopeproof.capture" ]]
[[ "$(plutil -extract LSMinimumSystemVersion raw -o - "$staged_app/Contents/Info.plist")" == "14.0" ]]

# Publish only a complete, verified bundle. Renames stay on the same volume, and
# the exact prior build is restored if the final rename fails.
if [[ -e "$app_root" ]]; then mv "$app_root" "$previous_app"; fi
if ! mv "$staged_app" "$app_root"; then
  if [[ -e "$previous_app" ]]; then mv "$previous_app" "$app_root"; fi
  exit 1
fi
if [[ -e "$previous_app" ]]; then /bin/rm -rf -- "$previous_app"; fi
echo "$app_root"
