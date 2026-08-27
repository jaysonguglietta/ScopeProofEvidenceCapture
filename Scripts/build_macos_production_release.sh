#!/bin/zsh
set -euo pipefail
umask 077

if [[ -o xtrace ]]; then
  echo "Refusing to build a production release while shell tracing is enabled." >&2
  exit 1
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Production macOS releases must be built and notarized on macOS." >&2
  exit 1
fi

project_root="${0:A:h:h}"
package_root="$project_root/macos/ScopeproofCapture"
info_plist="$package_root/Resources/Info.plist"
entitlements="$package_root/Resources/ScopeproofCapture.entitlements"
output_root="${SCOPEPROOF_RELEASE_OUTPUT_DIR:-$project_root/DerivedData/Production}"
[[ "$output_root" = /* ]] || output_root="$project_root/$output_root"

: "${SCOPEPROOF_CODESIGN_IDENTITY:?Developer ID Application identity is required}"
: "${SCOPEPROOF_NOTARY_PROFILE:?Notarytool Keychain profile is required}"
: "${SCOPEPROOF_RELEASE_TEAM_ID:?Apple Developer team identifier is required}"
: "${SCOPEPROOF_RELEASE_VERSION:?Release version is required}"
: "${SCOPEPROOF_RELEASE_BUILD_NUMBER:?Monotonic bundle build number is required}"

[[ "$SCOPEPROOF_RELEASE_TEAM_ID" =~ '^[A-Z0-9]{10}$' ]] || {
  echo "Invalid Apple Developer team identifier." >&2
  exit 1
}
[[ "$SCOPEPROOF_RELEASE_VERSION" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || {
  echo "Release version must be a three-component semantic version." >&2
  exit 1
}
[[ "$SCOPEPROOF_RELEASE_BUILD_NUMBER" =~ '^[1-9][0-9]{0,8}$' ]] || {
  echo "Bundle build number must be a positive integer." >&2
  exit 1
}
[[ "$SCOPEPROOF_CODESIGN_IDENTITY" == "Developer ID Application: "* ]] || {
  echo "The signing identity must be a Developer ID Application identity." >&2
  exit 1
}
if [[ -n "${SCOPEPROOF_NOTARY_KEYCHAIN:-}" ]]; then
  [[ -f "$SCOPEPROOF_NOTARY_KEYCHAIN" && ! -L "$SCOPEPROOF_NOTARY_KEYCHAIN" ]] || {
    echo "The explicit notarization Keychain is missing or is a symlink." >&2
    exit 1
  }
  SCOPEPROOF_NOTARY_KEYCHAIN="${SCOPEPROOF_NOTARY_KEYCHAIN:A}"
fi

for required_command in swift codesign ditto hdiutil lipo node plutil shasum spctl xcrun; do
  command -v "$required_command" >/dev/null || {
    echo "Required release command is unavailable: $required_command" >&2
    exit 1
  }
done
xcrun --find notarytool >/dev/null
xcrun --find stapler >/dev/null
plutil -lint "$info_plist" >/dev/null
plutil -lint "$entitlements" >/dev/null

if [[ -n "$(git -C "$project_root" status --porcelain --untracked-files=normal)" ]]; then
  echo "Production releases require a clean, committed Git worktree." >&2
  exit 1
fi

bundle_identifier="$(plutil -extract CFBundleIdentifier raw -o - "$info_plist")"
bundle_version="$(plutil -extract CFBundleShortVersionString raw -o - "$info_plist")"
bundle_build="$(plutil -extract CFBundleVersion raw -o - "$info_plist")"
compiled_team="$(plutil -extract ScopeproofUpdateTeamIdentifier raw -o - "$info_plist")"
compiled_requirement="$(plutil -extract ScopeproofUpdateDesignatedRequirement raw -o - "$info_plist")"
compiled_download_origin="$(plutil -extract ScopeproofUpdateDownloadOrigin raw -o - "$info_plist")"
compiled_update_keys="$(plutil -extract ScopeproofUpdatePublicKeys json -o - "$info_plist" 2>/dev/null || true)"
[[ "$bundle_identifier" == "com.scopeproof.capture" ]] || { echo "Unexpected bundle identifier." >&2; exit 1; }
[[ "$bundle_version" == "$SCOPEPROOF_RELEASE_VERSION" ]] || { echo "Release version does not match Info.plist." >&2; exit 1; }
[[ "$bundle_build" == "$SCOPEPROOF_RELEASE_BUILD_NUMBER" ]] || { echo "Release build number does not match Info.plist." >&2; exit 1; }
[[ "$compiled_team" == "$SCOPEPROOF_RELEASE_TEAM_ID" ]] || { echo "Compiled update team does not match the signing team." >&2; exit 1; }
[[ "$compiled_download_origin" =~ '^https://[A-Za-z0-9.-]+$' && "$compiled_download_origin" != *".."* ]] || { echo "No exact HTTPS update download origin is compiled into Info.plist." >&2; exit 1; }
[[ -n "$compiled_update_keys" ]] || { echo "No update-signing public key is compiled into Info.plist." >&2; exit 1; }
printf '%s' "$compiled_update_keys" | node "$project_root/Scripts/validate_macos_update_keys.mjs" json
[[ "$compiled_requirement" == *"anchor apple generic"* \
  && "$compiled_requirement" == *'identifier "com.scopeproof.capture"'* \
  && "$compiled_requirement" == *"certificate leaf[subject.OU]"* \
  && "$compiled_requirement" == *"$SCOPEPROOF_RELEASE_TEAM_ID"* ]] || {
  echo "The compiled update requirement does not bind Apple trust, bundle identifier, and team." >&2
  exit 1
}

release_temp="$(mktemp -d "${TMPDIR:-/tmp}/scopeproof-production.XXXXXX")"
build_root="$release_temp/swift-build"
app_root="$release_temp/Scopeproof Capture.app"
staging_root="$release_temp/dmg-root"
mount_root="$release_temp/mount"
mounted=false
cleanup() {
  if [[ "$mounted" == true ]]; then hdiutil detach "$mount_root" >/dev/null 2>&1 || true; fi
  rm -rf "$release_temp"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$build_root/ModuleCache" "$app_root/Contents/MacOS" "$app_root/Contents/Resources" "$staging_root" "$mount_root" "$output_root"
export CLANG_MODULE_CACHE_PATH="$build_root/ModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$build_root/ModuleCache"
(
  cd "$package_root"
  swift build -c release --arch arm64 --scratch-path "$build_root"
)
binary_path="$build_root/arm64-apple-macosx/release/ScopeproofCapture"
if [[ ! -x "$binary_path" ]]; then binary_path="$build_root/release/ScopeproofCapture"; fi
[[ -x "$binary_path" && ! -L "$binary_path" ]] || { echo "The arm64 release binary was not produced." >&2; exit 1; }
[[ "$(lipo -archs "$binary_path")" == "arm64" ]] || { echo "The release binary is not arm64-only." >&2; exit 1; }
if [[ -n "$(git -C "$project_root" status --porcelain --untracked-files=normal)" ]]; then
  echo "The build modified the committed source tree; refusing to sign it." >&2
  exit 1
fi

ditto "$binary_path" "$app_root/Contents/MacOS/ScopeproofCapture"
ditto "$info_plist" "$app_root/Contents/Info.plist"
chmod 0755 "$app_root" "$app_root/Contents" "$app_root/Contents/MacOS" "$app_root/Contents/Resources"
chmod 0755 "$app_root/Contents/MacOS/ScopeproofCapture"
chmod 0644 "$app_root/Contents/Info.plist"

codesign --force \
  --entitlements "$entitlements" \
  --generate-entitlement-der \
  --options runtime \
  --sign "$SCOPEPROOF_CODESIGN_IDENTITY" \
  --timestamp \
  "$app_root"
codesign --verify --deep --strict --verbose=4 "$app_root"
codesign --verify --deep --strict --verbose=4 -R "$compiled_requirement" "$app_root"
signature_details="$(codesign -dv --verbose=4 "$app_root" 2>&1)"
[[ "$signature_details" == *"Identifier=$bundle_identifier"* ]] || { echo "Signed bundle identifier mismatch." >&2; exit 1; }
[[ "$signature_details" == *"TeamIdentifier=$SCOPEPROOF_RELEASE_TEAM_ID"* ]] || { echo "Signed team identifier mismatch." >&2; exit 1; }
[[ "$signature_details" == *"flags=0x10000(runtime)"* ]] || { echo "Hardened runtime is not enabled." >&2; exit 1; }
[[ "$signature_details" == *"Timestamp="* ]] || { echo "A trusted signing timestamp is missing." >&2; exit 1; }
signed_entitlements="$release_temp/signed-entitlements.plist"
codesign -d --entitlements :- "$app_root" >"$signed_entitlements" 2>/dev/null
plutil -lint "$signed_entitlements" >/dev/null
if plutil -extract com.apple.security.get-task-allow raw -o - "$signed_entitlements" 2>/dev/null | grep -q '^true$'; then
  echo "Production signing must not enable get-task-allow." >&2
  exit 1
fi

notary_arguments=(--keychain-profile "$SCOPEPROOF_NOTARY_PROFILE")
if [[ -n "${SCOPEPROOF_NOTARY_KEYCHAIN:-}" ]]; then
  notary_arguments+=(--keychain "$SCOPEPROOF_NOTARY_KEYCHAIN")
fi
notarize() {
  local artifact="$1"
  local label="$2"
  local result="$release_temp/notary-$label.json"
  if ! xcrun notarytool submit "$artifact" \
      "${notary_arguments[@]}" \
      --output-format json \
      --timeout 30m \
      --wait >"$result"; then
    local failed_status="$(plutil -extract status raw -o - "$result" 2>/dev/null || true)"
    local failed_id="$(plutil -extract id raw -o - "$result" 2>/dev/null || true)"
    echo "Apple notarization failed for $label (submission ${failed_id:-unknown}, status ${failed_status:-unknown})." >&2
    return 1
  fi
  local status="$(plutil -extract status raw -o - "$result" 2>/dev/null || true)"
  local submission_id="$(plutil -extract id raw -o - "$result" 2>/dev/null || true)"
  if [[ "$status" != "Accepted" ]]; then
    echo "Apple rejected notarization for $label (submission ${submission_id:-unknown}, status ${status:-unknown})." >&2
    exit 1
  fi
  [[ "$submission_id" =~ '^[A-Fa-f0-9]{8}(-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$' ]] || {
    echo "Apple returned a malformed notarization submission identifier for $label." >&2
    exit 1
  }
  if [[ "$label" == "application" ]]; then
    application_notary_result="$result"
  elif [[ "$label" == "disk-image" ]]; then
    disk_image_notary_result="$result"
  else
    echo "Unexpected notarization artifact label." >&2
    exit 1
  fi
  echo "Apple accepted notarization for $label (submission $submission_id)."
}

application_notary_result=""
disk_image_notary_result=""
notary_archive="$release_temp/Scopeproof-Capture-notary.zip"
ditto -c -k --keepParent --sequesterRsrc "$app_root" "$notary_archive"
notarize "$notary_archive" "application"
xcrun stapler staple "$app_root"
xcrun stapler validate "$app_root"
codesign --verify --deep --strict --verbose=4 "$app_root"
spctl --assess --type execute --verbose=4 "$app_root"

release_stem="Scopeproof-Capture-$SCOPEPROOF_RELEASE_VERSION"
final_zip="$output_root/$release_stem.zip"
final_dmg="$output_root/$release_stem.dmg"
zip_checksum="$final_zip.sha256"
dmg_checksum="$final_dmg.sha256"
notary_receipt="$output_root/$release_stem.notary-receipt.json"
release_sbom="$output_root/$release_stem.sbom.cdx.json"
release_provenance="$output_root/$release_stem.provenance.intoto.json"
for artifact in "$final_zip" "$final_dmg" "$zip_checksum" "$dmg_checksum" "$notary_receipt" "$release_sbom" "$release_provenance"; do
  [[ ! -e "$artifact" ]] || { echo "Refusing to overwrite existing release artifact: $artifact" >&2; exit 1; }
done

candidate_zip="$release_temp/$release_stem.zip"
candidate_dmg="$release_temp/$release_stem.dmg"
ditto -c -k --keepParent --sequesterRsrc "$app_root" "$candidate_zip"
ditto "$app_root" "$staging_root/Scopeproof Capture.app"
ln -s /Applications "$staging_root/Applications"
hdiutil create -volname "Scopeproof Capture" -srcfolder "$staging_root" -format UDZO "$candidate_dmg" >/dev/null
codesign --force --sign "$SCOPEPROOF_CODESIGN_IDENTITY" --timestamp "$candidate_dmg"
codesign --verify --verbose=4 "$candidate_dmg"
notarize "$candidate_dmg" "disk-image"
xcrun stapler staple "$candidate_dmg"
xcrun stapler validate "$candidate_dmg"
codesign --verify --verbose=4 "$candidate_dmg"
hdiutil verify "$candidate_dmg" >/dev/null
spctl --assess --type open --context context:primary-signature --verbose=4 "$candidate_dmg"

hdiutil attach -nobrowse -readonly -mountpoint "$mount_root" "$candidate_dmg" >/dev/null
mounted=true
[[ -d "$mount_root/Scopeproof Capture.app" ]]
[[ -L "$mount_root/Applications" && "$(readlink "$mount_root/Applications")" == "/Applications" ]]
codesign --verify --deep --strict --verbose=4 "$mount_root/Scopeproof Capture.app"
codesign --verify --deep --strict --verbose=4 -R "$compiled_requirement" "$mount_root/Scopeproof Capture.app"
xcrun stapler validate "$mount_root/Scopeproof Capture.app"
spctl --assess --type execute --verbose=4 "$mount_root/Scopeproof Capture.app"
hdiutil detach "$mount_root" >/dev/null
mounted=false

mv "$candidate_zip" "$final_zip"
mv "$candidate_dmg" "$final_dmg"
(
  cd "$output_root"
  shasum -a 256 "${final_zip:t}" >"${zip_checksum:t}"
  shasum -a 256 "${final_dmg:t}" >"${dmg_checksum:t}"
)
[[ -f "$application_notary_result" && -f "$disk_image_notary_result" ]] || {
  echo "Both accepted notarization results are required for release evidence." >&2
  exit 1
}
SCOPEPROOF_RELEASE_REQUIREMENT="$compiled_requirement" \
SCOPEPROOF_RELEASE_SOURCE_COMMIT="$(git -C "$project_root" rev-parse HEAD)" \
  node "$project_root/Scripts/macos_release_evidence.mjs" create \
    "$final_zip" "$final_dmg" "$application_notary_result" "$disk_image_notary_result" "$output_root"

echo "$final_zip"
echo "$zip_checksum"
echo "$final_dmg"
echo "$dmg_checksum"
echo "$notary_receipt"
echo "$release_sbom"
echo "$release_provenance"
