#!/bin/zsh
set -euo pipefail
umask 077

if [[ -o xtrace ]]; then
  echo "Refusing to prepare a production release while shell tracing is enabled." >&2
  exit 1
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Production macOS release candidates must be prepared on macOS." >&2
  exit 1
fi

project_root="${0:A:h:h}"
package_root="$project_root/macos/ScopeproofCapture"
info_plist="$package_root/Resources/Info.plist"
entitlements="$package_root/Resources/ScopeproofCapture.entitlements"
output_root="${SCOPEPROOF_RELEASE_PREPARED_OUTPUT_DIR:-$project_root/DerivedData/Prepared}"
[[ "$output_root" = /* ]] || output_root="$project_root/$output_root"

: "${SCOPEPROOF_RELEASE_VERSION:?Release version is required}"
: "${SCOPEPROOF_RELEASE_BUILD_NUMBER:?Monotonic bundle build number is required}"
: "${SCOPEPROOF_RELEASE_EXPECTED_COMMIT:?Approved 40-character source commit is required}"

[[ "$SCOPEPROOF_RELEASE_VERSION" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || {
  echo "Release version must be a three-component semantic version." >&2
  exit 1
}
[[ "$SCOPEPROOF_RELEASE_BUILD_NUMBER" =~ '^[1-9][0-9]{0,8}$' ]] || {
  echo "Bundle build number must be a positive integer." >&2
  exit 1
}
[[ "$SCOPEPROOF_RELEASE_EXPECTED_COMMIT" =~ '^[a-f0-9]{40}$' ]] || {
  echo "Approved source commit must be a full lowercase Git SHA." >&2
  exit 1
}
[[ "$(git -C "$project_root" rev-parse HEAD)" == "$SCOPEPROOF_RELEASE_EXPECTED_COMMIT" ]] || {
  echo "The checked-out source does not match the approved release commit." >&2
  exit 1
}
[[ -z "$(git -C "$project_root" status --porcelain --untracked-files=normal)" ]] || {
  echo "Release preparation requires a clean, committed Git worktree." >&2
  exit 1
}

for required_command in cmp ditto git lipo node plutil shasum swift zip; do
  command -v "$required_command" >/dev/null || {
    echo "Required release-preparation command is unavailable: $required_command" >&2
    exit 1
  }
done

plutil -lint "$info_plist" >/dev/null
plutil -lint "$entitlements" >/dev/null
bundle_identifier="$(plutil -extract CFBundleIdentifier raw -o - "$info_plist")"
bundle_version="$(plutil -extract CFBundleShortVersionString raw -o - "$info_plist")"
bundle_build="$(plutil -extract CFBundleVersion raw -o - "$info_plist")"
compiled_download_origin="$(plutil -extract ScopeproofUpdateDownloadOrigin raw -o - "$info_plist")"
compiled_hosted_origin="$(plutil -extract ScopeproofHostedAPIOrigins.0 raw -o - "$info_plist" 2>/dev/null || true)"
compiled_update_keys="$(plutil -extract ScopeproofUpdatePublicKeys json -o - "$info_plist" 2>/dev/null || true)"
[[ "$bundle_identifier" == "com.scopeproof.capture" ]] || { echo "Unexpected bundle identifier." >&2; exit 1; }
[[ "$bundle_version" == "$SCOPEPROOF_RELEASE_VERSION" ]] || { echo "Release version does not match Info.plist." >&2; exit 1; }
[[ "$bundle_build" == "$SCOPEPROOF_RELEASE_BUILD_NUMBER" ]] || { echo "Release build number does not match Info.plist." >&2; exit 1; }
[[ "$compiled_download_origin" =~ '^https://[A-Za-z0-9.-]+$' && "$compiled_download_origin" != *".."* ]] || { echo "No exact HTTPS update download origin is compiled into Info.plist." >&2; exit 1; }
[[ "$compiled_hosted_origin" =~ '^https://[A-Za-z0-9.-]+$' && "$compiled_hosted_origin" != *".."* ]] || { echo "No exact HTTPS hosted API origin is compiled into Info.plist." >&2; exit 1; }
if plutil -extract ScopeproofHostedAPIOrigins.1 raw -o - "$info_plist" >/dev/null 2>&1; then
  echo "Production releases must bind exactly one hosted API origin." >&2
  exit 1
fi
[[ -n "$compiled_update_keys" ]] || { echo "No update-signing public key is compiled into Info.plist." >&2; exit 1; }
printf '%s' "$compiled_update_keys" | node "$project_root/Scripts/validate_macos_update_keys.mjs" json
plutil -convert json -o - "$entitlements" \
  | node "$project_root/Scripts/validate_macos_release_entitlements.mjs"

release_temp="$(mktemp -d "${TMPDIR:-/tmp}/scopeproof-prepare.XXXXXX")"
build_root="$release_temp/swift-build"
payload_root="$release_temp/payload"
archive_temp="$release_temp/Scopeproof-Capture-prepared.zip"
cleanup() { rm -rf "$release_temp"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$build_root/ModuleCache" "$payload_root"
export CLANG_MODULE_CACHE_PATH="$build_root/ModuleCache"
export SWIFTPM_MODULECACHE_OVERRIDE="$build_root/ModuleCache"

(
  cd "$package_root"
  swift build -c release --arch arm64 --scratch-path "$build_root"
)
binary_path="$build_root/arm64-apple-macosx/release/ScopeproofCapture"
if [[ ! -x "$binary_path" ]]; then binary_path="$build_root/release/ScopeproofCapture"; fi
[[ -x "$binary_path" && ! -L "$binary_path" ]] || { echo "The arm64 release binary was not produced." >&2; exit 1; }
[[ "$(lipo -archs "$binary_path")" == "arm64" ]] || { echo "The prepared release binary is not arm64-only." >&2; exit 1; }
[[ -z "$(git -C "$project_root" status --porcelain --untracked-files=normal)" ]] || {
  echo "The release build modified the committed source tree." >&2
  exit 1
}

ditto "$binary_path" "$payload_root/ScopeproofCapture"
ditto "$info_plist" "$payload_root/Info.plist"
ditto "$entitlements" "$payload_root/ScopeproofCapture.entitlements"
printf '%s\n' "$SCOPEPROOF_RELEASE_EXPECTED_COMMIT" > "$payload_root/source-commit.txt"
chmod 0755 "$payload_root/ScopeproofCapture"
chmod 0644 "$payload_root/Info.plist" "$payload_root/ScopeproofCapture.entitlements" "$payload_root/source-commit.txt"

(
  cd "$payload_root"
  /usr/bin/zip -X -q "$archive_temp" \
    ScopeproofCapture \
    Info.plist \
    ScopeproofCapture.entitlements \
    source-commit.txt
)

mkdir -p "$output_root"
[[ -d "$output_root" && ! -L "$output_root" ]] || { echo "Prepared output directory must not be a symlink." >&2; exit 1; }
final_archive="$output_root/Scopeproof-Capture-prepared.zip"
final_checksum="$output_root/Scopeproof-Capture-prepared.zip.sha256"
[[ ! -e "$final_archive" && ! -e "$final_checksum" ]] || {
  echo "Refusing to overwrite an existing prepared release candidate." >&2
  exit 1
}
ditto "$archive_temp" "$final_archive"
(
  cd "$output_root"
  shasum -a 256 "${final_archive:t}" > "${final_checksum:t}"
)

echo "$final_archive"
echo "$final_checksum"
