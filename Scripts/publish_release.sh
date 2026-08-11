#!/bin/zsh
set -euo pipefail

project_root="${0:A:h:h}"
: "${SCOPEPROOF_CODESIGN_IDENTITY:?Developer ID Application identity is required}"
: "${SCOPEPROOF_NOTARY_PROFILE:?Notarytool Keychain profile is required}"
: "${SCOPEPROOF_UPDATE_PRIVATE_KEY:?P-256 update signing key path is required}"
: "${SCOPEPROOF_UPDATE_PUBLIC_KEY_X963_BASE64:?Compiled P-256 update public key is required}"
: "${SCOPEPROOF_UPDATE_KEY_ID:?Update signing key ID is required}"
: "${SCOPEPROOF_RELEASE_VERSION:?Release version is required}"
: "${SCOPEPROOF_RELEASE_SEQUENCE:?Monotonic release sequence is required}"
: "${SCOPEPROOF_RELEASE_URL:?Final HTTPS ZIP URL is required}"
: "${SCOPEPROOF_RELEASE_TEAM_ID:?Developer ID team identifier is required}"
: "${SCOPEPROOF_RELEASE_REQUIREMENT:?Designated requirement is required}"

trusted_keys="$(plutil -extract ScopeproofUpdatePublicKeys json -o - "$project_root/macos/ScopeproofCapture/Resources/Info.plist")"
[[ "$trusted_keys" == *"$SCOPEPROOF_UPDATE_KEY_ID"* && "$trusted_keys" == *"$SCOPEPROOF_UPDATE_PUBLIC_KEY_X963_BASE64"* ]] || { echo "Info.plist does not contain the matching release key and key ID." >&2; exit 1; }
compiled_team="$(plutil -extract ScopeproofUpdateTeamIdentifier raw -o - "$project_root/macos/ScopeproofCapture/Resources/Info.plist")"
compiled_requirement="$(plutil -extract ScopeproofUpdateDesignatedRequirement raw -o - "$project_root/macos/ScopeproofCapture/Resources/Info.plist")"
[[ "$compiled_team" == "$SCOPEPROOF_RELEASE_TEAM_ID" && "$compiled_requirement" == "$SCOPEPROOF_RELEASE_REQUIREMENT" ]] || { echo "Info.plist update identity does not match the release identity." >&2; exit 1; }

"$project_root/Scripts/build_macos_capture.sh"
app="$project_root/DerivedData/Scopeproof Capture.app"
archive="$project_root/DerivedData/Scopeproof-Capture-${SCOPEPROOF_RELEASE_VERSION}.zip"
codesign --verify --deep --strict -R "$SCOPEPROOF_RELEASE_REQUIREMENT" "$app"
signing_details="$(codesign -dv --verbose=4 "$app" 2>&1)"
[[ "$signing_details" == *"TeamIdentifier=$SCOPEPROOF_RELEASE_TEAM_ID"* ]]
spctl -a -t exec -vv "$app"
xcrun stapler validate "$app"
ditto -c -k --sequesterRsrc --keepParent "$app" "$archive"
node "$project_root/Scripts/sign_update_manifest.mjs" "$archive" "$project_root/DerivedData/macos-release-envelope.json"
