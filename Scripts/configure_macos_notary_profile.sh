#!/bin/zsh
set -euo pipefail
umask 077

if [[ -o xtrace ]]; then
  echo "Refusing to configure notarization credentials while shell tracing is enabled." >&2
  exit 1
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Apple notarization credentials can only be configured on macOS." >&2
  exit 1
fi

project_root="${0:A:h:h}"
: "${SCOPEPROOF_NOTARY_PROFILE:?Notarytool Keychain profile name is required}"
: "${SCOPEPROOF_NOTARY_KEYCHAIN:?An explicit release Keychain path is required}"
: "${SCOPEPROOF_NOTARY_API_KEY_PATH:?App Store Connect API private-key path is required}"
: "${SCOPEPROOF_NOTARY_KEY_ID:?App Store Connect API key ID is required}"
: "${SCOPEPROOF_NOTARY_ISSUER_ID:?App Store Connect API issuer ID is required}"

[[ "$SCOPEPROOF_NOTARY_PROFILE" =~ '^[A-Za-z0-9._-]{1,64}$' ]] || {
  echo "Invalid notarytool profile name." >&2
  exit 1
}
[[ "$SCOPEPROOF_NOTARY_KEY_ID" =~ '^[A-Z0-9]{10}$' ]] || {
  echo "Invalid App Store Connect API key ID." >&2
  exit 1
}
[[ "$SCOPEPROOF_NOTARY_ISSUER_ID" =~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' ]] || {
  echo "Invalid App Store Connect API issuer ID." >&2
  exit 1
}

[[ -f "$SCOPEPROOF_NOTARY_API_KEY_PATH" && ! -L "$SCOPEPROOF_NOTARY_API_KEY_PATH" ]] || {
  echo "The notarization API key must be a regular, non-symlink file." >&2
  exit 1
}
[[ -f "$SCOPEPROOF_NOTARY_KEYCHAIN" && ! -L "$SCOPEPROOF_NOTARY_KEYCHAIN" ]] || {
  echo "The release Keychain must already exist as a regular, non-symlink file." >&2
  exit 1
}
api_key="${SCOPEPROOF_NOTARY_API_KEY_PATH:A}"
keychain="${SCOPEPROOF_NOTARY_KEYCHAIN:A}"
if [[ "$api_key" == "$project_root"/* ]]; then
  echo "Refusing to read an App Store Connect private key from the repository." >&2
  exit 1
fi
key_mode="$(stat -f '%Lp' "$api_key")"
[[ "$key_mode" == "400" || "$key_mode" == "600" ]] || {
  echo "The notarization API key must have mode 0400 or 0600." >&2
  exit 1
}

# Validation is intentionally enabled. The profile is stored only in the explicitly
# supplied Keychain; no Apple ID password or API private key is copied into the repo.
xcrun notarytool store-credentials "$SCOPEPROOF_NOTARY_PROFILE" \
  --key "$api_key" \
  --key-id "$SCOPEPROOF_NOTARY_KEY_ID" \
  --issuer "$SCOPEPROOF_NOTARY_ISSUER_ID" \
  --keychain "$keychain" >/dev/null

echo "Stored and validated the notarization profile in the explicit release Keychain."
