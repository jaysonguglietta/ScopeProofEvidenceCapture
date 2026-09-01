#!/bin/zsh
set -euo pipefail
umask 077

if [[ -o xtrace ]]; then
  echo "Refusing to publish while shell tracing is enabled." >&2
  exit 1
fi

project_root="${0:A:h:h}"
: "${SCOPEPROOF_RELEASE_CANDIDATE_DIR:?Downloaded production candidate directory is required}"
: "${SCOPEPROOF_RELEASE_ATTESTATION_REPOSITORY:?GitHub owner/repository used for attestation is required}"
: "${SCOPEPROOF_RELEASE_EXPECTED_COMMIT:?Approved 40-character source commit is required}"
: "${SCOPEPROOF_UPDATE_PRIVATE_KEY:?P-256 update signing key path is required}"
: "${SCOPEPROOF_UPDATE_PUBLIC_KEY_X963_BASE64:?Compiled P-256 update public key is required}"
: "${SCOPEPROOF_UPDATE_KEY_ID:?Update signing key ID is required}"
: "${SCOPEPROOF_RELEASE_VERSION:?Release version is required}"
: "${SCOPEPROOF_RELEASE_SEQUENCE:?Monotonic release sequence is required}"
: "${SCOPEPROOF_RELEASE_URL:?Final HTTPS ZIP URL is required}"
: "${SCOPEPROOF_RELEASE_TEAM_ID:?Developer ID team identifier is required}"
: "${SCOPEPROOF_RELEASE_REQUIREMENT:?Designated requirement is required}"

[[ "$(uname -s)" == "Darwin" ]] || { echo "Production macOS publication verification requires macOS." >&2; exit 1; }
[[ "$SCOPEPROOF_RELEASE_VERSION" =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]] || { echo "Invalid release version." >&2; exit 1; }
[[ "$SCOPEPROOF_RELEASE_EXPECTED_COMMIT" =~ '^[a-f0-9]{40}$' ]] || { echo "Invalid approved commit." >&2; exit 1; }
[[ "$SCOPEPROOF_RELEASE_ATTESTATION_REPOSITORY" =~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' ]] || { echo "Invalid attestation repository." >&2; exit 1; }
[[ "$SCOPEPROOF_RELEASE_TEAM_ID" =~ '^[A-Z0-9]{10}$' ]] || { echo "Invalid Developer ID team." >&2; exit 1; }
[[ -d "$SCOPEPROOF_RELEASE_CANDIDATE_DIR" && ! -L "$SCOPEPROOF_RELEASE_CANDIDATE_DIR" ]] || { echo "Candidate directory must be a real directory, not a symlink." >&2; exit 1; }
source_candidate_dir="${SCOPEPROOF_RELEASE_CANDIDATE_DIR:A}"
[[ -f "$SCOPEPROOF_UPDATE_PRIVATE_KEY" && ! -L "$SCOPEPROOF_UPDATE_PRIVATE_KEY" ]] || { echo "Update private key must be a regular, non-symlink file." >&2; exit 1; }
private_key="${SCOPEPROOF_UPDATE_PRIVATE_KEY:A}"
if [[ "$private_key" == "$project_root"/* ]]; then
  echo "Refusing to read an update-signing private key from the repository." >&2
  exit 1
fi
private_key_mode="$(/usr/bin/stat -f '%Lp' "$private_key")"
[[ "$private_key_mode" == "400" || "$private_key_mode" == "600" ]] || {
  echo "The update-signing private key must have mode 0400 or 0600." >&2
  exit 1
}
[[ "$(/usr/bin/stat -f '%u' "$private_key")" == "$(/usr/bin/id -u)" ]] || {
  echo "The update-signing private key must be owned by the publishing user." >&2
  exit 1
}
[[ "$(/usr/bin/stat -f '%l' "$private_key")" == "1" ]] || {
  echo "The update-signing private key must not have additional hard links." >&2
  exit 1
}
key_acl_mode="$(/bin/ls -lde "$private_key" | /usr/bin/awk '{ print $1 }')"
[[ "$key_acl_mode" != *+* ]] || {
  echo "The update-signing private key must not have an extended ACL." >&2
  exit 1
}
key_directory="${private_key:h}"
while [[ "$key_directory" != "/" ]]; do
  key_directory_mode="$(/usr/bin/stat -f '%Lp' "$key_directory")"
  [[ "$key_directory_mode" =~ '^[0-7]{3,4}$' ]] || {
    echo "Could not validate update-signing key directory permissions: $key_directory" >&2
    exit 1
  }
  group_digit="${key_directory_mode[-2]}"
  world_digit="${key_directory_mode[-1]}"
  [[ "$group_digit" != [2367] && "$world_digit" != [2367] ]] || {
    echo "Update-signing key directories must not be group- or world-writable: $key_directory" >&2
    exit 1
  }
  key_directory="${key_directory:h}"
done

for required_command in codesign ditto gh hdiutil node plutil spctl unzip xcrun; do
  command -v "$required_command" >/dev/null || { echo "Required publication command is unavailable: $required_command" >&2; exit 1; }
done
xcrun --find stapler >/dev/null

stem="Scopeproof-Capture-$SCOPEPROOF_RELEASE_VERSION"
source_files=(
  "$source_candidate_dir/$stem.zip"
  "$source_candidate_dir/$stem.zip.sha256"
  "$source_candidate_dir/$stem.dmg"
  "$source_candidate_dir/$stem.dmg.sha256"
  "$source_candidate_dir/$stem.notary-receipt.json"
  "$source_candidate_dir/$stem.sbom.cdx.json"
  "$source_candidate_dir/$stem.provenance.intoto.json"
)
for artifact in "${source_files[@]}"; do
  [[ -f "$artifact" && ! -L "$artifact" ]] || { echo "Missing or unsafe candidate file: $artifact" >&2; exit 1; }
done

# Snapshot attacker-mutable downloads before any trust decision. Every subsequent
# attestation, digest, notarization, bundle, and manifest check uses only this copy.
verify_temp="$(mktemp -d "${TMPDIR:-/tmp}/scopeproof-publish.XXXXXX")"
chmod 0700 "$verify_temp"
candidate_dir="$verify_temp/candidate"
mount_root="$verify_temp/mount"
mounted=false
cleanup() {
  if [[ "$mounted" == true ]]; then hdiutil detach "$mount_root" >/dev/null 2>&1 || true; fi
  rm -rf "$verify_temp"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$candidate_dir" "$mount_root"
chmod 0700 "$candidate_dir" "$mount_root"
for artifact in "${source_files[@]}"; do
  /bin/cp -pP "$artifact" "$candidate_dir/${artifact:t}"
  [[ -f "$candidate_dir/${artifact:t}" && ! -L "$candidate_dir/${artifact:t}" ]] || { echo "Candidate changed type while it was snapshotted: $artifact" >&2; exit 1; }
done

archive="$candidate_dir/$stem.zip"
dmg="$candidate_dir/$stem.dmg"
receipt="$candidate_dir/$stem.notary-receipt.json"
sbom="$candidate_dir/$stem.sbom.cdx.json"
provenance="$candidate_dir/$stem.provenance.intoto.json"
candidate_files=("$archive" "$archive.sha256" "$dmg" "$dmg.sha256" "$receipt" "$sbom" "$provenance")

node "$project_root/Scripts/macos_release_evidence.mjs" verify \
  "$candidate_dir" "$SCOPEPROOF_RELEASE_VERSION" "$SCOPEPROOF_RELEASE_EXPECTED_COMMIT"
for artifact in "${candidate_files[@]}"; do
  gh attestation verify "$artifact" \
    --repo "$SCOPEPROOF_RELEASE_ATTESTATION_REPOSITORY" \
    --signer-workflow "$SCOPEPROOF_RELEASE_ATTESTATION_REPOSITORY/.github/workflows/macos-production-release.yml" \
    --source-digest "$SCOPEPROOF_RELEASE_EXPECTED_COMMIT" \
    --source-ref refs/heads/main \
    --deny-self-hosted-runners >/dev/null
done

while IFS= read -r entry; do
  [[ -n "$entry" && "$entry" != /* && "$entry" != *\\* && "/$entry" != *"/../"* && "$entry" != ".." ]] || {
    echo "Unsafe ZIP member path: $entry" >&2
    exit 1
  }
  [[ "$entry" == "Scopeproof Capture.app" || "$entry" == "Scopeproof Capture.app/"* || "$entry" == "__MACOSX" || "$entry" == "__MACOSX/" || "$entry" == "__MACOSX/Scopeproof Capture.app/"* ]] || {
    echo "Unexpected ZIP member: $entry" >&2
    exit 1
  }
done < <(unzip -Z1 "$archive")
ditto -x -k "$archive" "$verify_temp/unpacked"
app="$verify_temp/unpacked/Scopeproof Capture.app"
[[ -d "$app" && ! -L "$app" ]] || { echo "Candidate ZIP does not contain the expected application." >&2; exit 1; }
info_plist="$app/Contents/Info.plist"
plutil -lint "$info_plist" >/dev/null
bundle_identifier="$(plutil -extract CFBundleIdentifier raw -o - "$info_plist")"
bundle_version="$(plutil -extract CFBundleShortVersionString raw -o - "$info_plist")"
compiled_team="$(plutil -extract ScopeproofUpdateTeamIdentifier raw -o - "$info_plist")"
compiled_requirement="$(plutil -extract ScopeproofUpdateDesignatedRequirement raw -o - "$info_plist")"
compiled_download_origin="$(plutil -extract ScopeproofUpdateDownloadOrigin raw -o - "$info_plist")"
trusted_keys="$(plutil -extract ScopeproofUpdatePublicKeys json -o - "$info_plist")"
printf '%s' "$trusted_keys" | node "$project_root/Scripts/validate_macos_update_keys.mjs" json \
  "$SCOPEPROOF_UPDATE_KEY_ID" "$SCOPEPROOF_UPDATE_PUBLIC_KEY_X963_BASE64"
[[ "$bundle_identifier" == "com.scopeproof.capture" && "$bundle_version" == "$SCOPEPROOF_RELEASE_VERSION" ]] || { echo "Candidate bundle metadata does not match the publication." >&2; exit 1; }
[[ "$compiled_team" == "$SCOPEPROOF_RELEASE_TEAM_ID" && "$compiled_requirement" == "$SCOPEPROOF_RELEASE_REQUIREMENT" ]] || { echo "Candidate update identity does not match the approved release identity." >&2; exit 1; }
[[ "$compiled_download_origin" =~ '^https://[A-Za-z0-9.-]+$' && "$SCOPEPROOF_RELEASE_URL" == "$compiled_download_origin/macos/$SCOPEPROOF_RELEASE_VERSION/$stem.zip" ]] || { echo "Release URL is not the candidate's exact compiled immutable download path." >&2; exit 1; }

codesign --verify --deep --strict -R "$SCOPEPROOF_RELEASE_REQUIREMENT" "$app"
signing_details="$(codesign -dv --verbose=4 "$app" 2>&1)"
[[ "$signing_details" == *"TeamIdentifier=$SCOPEPROOF_RELEASE_TEAM_ID"* && "$signing_details" == *"flags=0x10000(runtime)"* && "$signing_details" == *"Timestamp="* ]] || { echo "Candidate signature lacks the approved team, hardened runtime, or timestamp." >&2; exit 1; }
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=4 "$app"

codesign --verify --verbose=4 "$dmg"
xcrun stapler validate "$dmg"
hdiutil verify "$dmg" >/dev/null
spctl --assess --type open --context context:primary-signature --verbose=4 "$dmg"
hdiutil attach -nobrowse -readonly -mountpoint "$mount_root" "$dmg" >/dev/null
mounted=true
[[ -d "$mount_root/Scopeproof Capture.app" ]]
codesign --verify --deep --strict -R "$SCOPEPROOF_RELEASE_REQUIREMENT" "$mount_root/Scopeproof Capture.app"
xcrun stapler validate "$mount_root/Scopeproof Capture.app"
spctl --assess --type execute --verbose=4 "$mount_root/Scopeproof Capture.app"
hdiutil detach "$mount_root" >/dev/null
mounted=false

publication_dir="${SCOPEPROOF_PUBLICATION_OUTPUT_DIR:-$project_root/DerivedData/Publication}"
[[ "$publication_dir" = /* ]] || publication_dir="$project_root/$publication_dir"
mkdir -p "$publication_dir"
[[ -d "$publication_dir" && ! -L "$publication_dir" ]] || { echo "Publication output directory must be a real directory, not a symlink." >&2; exit 1; }
[[ "$(/usr/bin/stat -f '%u' "$publication_dir")" == "$(/usr/bin/id -u)" ]] || { echo "Publication output directory must be owned by the publishing user." >&2; exit 1; }
publication_mode="$(/usr/bin/stat -f '%Lp' "$publication_dir")"
publication_group_digit="${publication_mode[-2]}"
publication_world_digit="${publication_mode[-1]}"
[[ "$publication_group_digit" != [2367] && "$publication_world_digit" != [2367] ]] || { echo "Publication output directory must not be group- or world-writable." >&2; exit 1; }
envelope="$publication_dir/$stem.release-envelope.json"
[[ ! -e "$envelope" ]] || { echo "Refusing to overwrite publication envelope: $envelope" >&2; exit 1; }
SCOPEPROOF_UPDATE_PRIVATE_KEY="$private_key" \
  SCOPEPROOF_RELEASE_DOWNLOAD_ORIGIN="$compiled_download_origin" \
  node "$project_root/Scripts/sign_update_manifest.mjs" "$archive" "$envelope"

echo "Verified the exact attested and notarized candidate without rebuilding: $archive"
echo "$envelope"
