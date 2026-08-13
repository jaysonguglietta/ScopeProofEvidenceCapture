#!/bin/zsh
set -euo pipefail

project_root="${0:A:h:h}"
plist="$project_root/macos/ScopeproofCapture/Resources/Info.plist"
: "${SCOPEPROOF_UPDATE_PUBLIC_KEY_X963_BASE64:?P-256 X9.63 public key is required}"
: "${SCOPEPROOF_UPDATE_KEY_ID:?Update key ID is required}"
: "${SCOPEPROOF_UPDATE_KEY_NOT_BEFORE:?ISO-8601 not-before timestamp is required}"
: "${SCOPEPROOF_UPDATE_KEY_NOT_AFTER:?ISO-8601 not-after timestamp is required}"
: "${SCOPEPROOF_RELEASE_TEAM_ID:?Developer ID team identifier is required}"
: "${SCOPEPROOF_RELEASE_REQUIREMENT:?Designated requirement is required}"

[[ "$SCOPEPROOF_RELEASE_TEAM_ID" =~ '^[A-Z0-9]{10}$' ]] || { echo "Invalid Developer ID team identifier." >&2; exit 1; }
[[ "$SCOPEPROOF_UPDATE_KEY_ID" =~ '^[A-Za-z0-9._-]{1,64}$' ]] || { echo "Invalid update key ID." >&2; exit 1; }
[[ ${#SCOPEPROOF_RELEASE_REQUIREMENT} -ge 20 ]] || { echo "Designated requirement is too short." >&2; exit 1; }

entry="$(mktemp -t scopeproof-update-key).plist"
trap 'rm -f "$entry"' EXIT HUP INT TERM
plutil -create xml1 "$entry"
plutil -insert keyId -string "$SCOPEPROOF_UPDATE_KEY_ID" "$entry"
plutil -insert publicKeyX963Base64 -string "$SCOPEPROOF_UPDATE_PUBLIC_KEY_X963_BASE64" "$entry"
plutil -insert notBefore -string "$SCOPEPROOF_UPDATE_KEY_NOT_BEFORE" "$entry"
plutil -insert notAfter -string "$SCOPEPROOF_UPDATE_KEY_NOT_AFTER" "$entry"
plutil -replace ScopeproofUpdatePublicKeys -xml "<array>$(plutil -convert xml1 -o - "$entry" | sed -n '/<dict>/,/<\/dict>/p')</array>" "$plist"
plutil -replace ScopeproofUpdateTeamIdentifier -string "$SCOPEPROOF_RELEASE_TEAM_ID" "$plist"
plutil -replace ScopeproofUpdateDesignatedRequirement -string "$SCOPEPROOF_RELEASE_REQUIREMENT" "$plist"
plutil -lint "$plist"
echo "Configured macOS release identity in $plist. Review and commit the public metadata before publishing."
