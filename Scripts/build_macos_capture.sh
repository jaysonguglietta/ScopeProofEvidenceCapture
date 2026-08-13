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

mkdir -p "$module_cache"
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
mkdir -p "$app_root/Contents/MacOS" "$app_root/Contents/Resources"
cp -p "$binary_path" "$app_root/Contents/MacOS/ScopeproofCapture"
cp -p "$package_root/Resources/Info.plist" "$app_root/Contents/Info.plist"

if [[ -n "$codesign_identity" ]]; then
  codesign --force --deep --options runtime --timestamp --entitlements "$entitlements" --sign "$codesign_identity" "$app_root"
  codesign --verify --deep --strict "$app_root"
  if [[ -n "$notary_profile" ]]; then
    archive_path="$output_root/Scopeproof-Capture-notarization.zip"
    ditto -c -k --keepParent "$app_root" "$archive_path"
    xcrun notarytool submit "$archive_path" --keychain-profile "$notary_profile" --wait
    xcrun stapler staple "$app_root"
    xcrun stapler validate "$app_root"
  fi
else
  codesign --force --deep --sign - --requirements '=designated => identifier "com.scopeproof.capture"' "$app_root"
fi
codesign --verify --deep --strict "$app_root"
[[ "$(plutil -extract CFBundleIdentifier raw -o - "$app_root/Contents/Info.plist")" == "com.scopeproof.capture" ]]
[[ "$(plutil -extract LSMinimumSystemVersion raw -o - "$app_root/Contents/Info.plist")" == "14.0" ]]
echo "$app_root"
