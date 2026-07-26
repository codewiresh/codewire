#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: verify-cw-release-signing-key.sh PUBLIC_KEY

Validates the required cw release-signing secrets against the checked-in
OpenPGP public key and proves the private key/passphrase can create a signature.
EOF
}

die() {
  printf 'verify-cw-release-signing-key: %s\n' "$*" >&2
  exit 1
}

if [ "$#" -ne 1 ] || [ "${1:-}" = '--help' ] || [ "${1:-}" = '-h' ]; then
  usage
  [ "$#" -eq 1 ] && exit 0
  exit 2
fi

public_key="$1"
[ -s "$public_key" ] || die "public key is missing or empty: $public_key"

for name in \
  CW_RELEASE_GPG_PRIVATE_KEY \
  CW_RELEASE_GPG_PASSPHRASE \
  CW_RELEASE_GPG_KEY_ID; do
  [ -n "${!name:-}" ] || die "$name is required"
done

expected_fingerprint="$(
  printf '%s' "$CW_RELEASE_GPG_KEY_ID" | tr '[:lower:]' '[:upper:]'
)"
[[ "$expected_fingerprint" =~ ^[0-9A-F]{40}$ ]] ||
  die 'CW_RELEASE_GPG_KEY_ID must be one exact 40-character fingerprint'

tmp="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

signing_home="$tmp/signing"
verify_home="$tmp/verify"
mkdir "$signing_home" "$verify_home"
chmod 700 "$signing_home" "$verify_home"

public_records="$tmp/public.records"
GNUPGHOME="$verify_home" gpg --batch --with-colons \
  --import-options show-only --import "$public_key" \
  >"$public_records" 2>/dev/null || die 'checked-in public key is not valid OpenPGP'

public_count="$(awk -F: '$1 == "pub" { count++ } END { print count + 0 }' "$public_records")"
[ "$public_count" -eq 1 ] ||
  die 'checked-in public key must contain exactly one primary key'
public_fingerprint="$(
  awk -F: '$1 == "pub" { primary = 1; next } primary && $1 == "fpr" { print $10; exit }' \
    "$public_records"
)"
[ "$public_fingerprint" = "$expected_fingerprint" ] ||
  die 'CW_RELEASE_GPG_KEY_ID does not match the checked-in public key'

printf '%s\n' "$CW_RELEASE_GPG_PRIVATE_KEY" |
  GNUPGHOME="$signing_home" gpg --batch --import >/dev/null 2>&1 ||
  die 'CW_RELEASE_GPG_PRIVATE_KEY is not a valid OpenPGP private key'

secret_records="$tmp/secret.records"
GNUPGHOME="$signing_home" gpg --batch --with-colons --list-secret-keys \
  >"$secret_records" 2>/dev/null ||
  die 'CW_RELEASE_GPG_PRIVATE_KEY contains no secret key'
secret_count="$(awk -F: '$1 == "sec" { count++ } END { print count + 0 }' "$secret_records")"
[ "$secret_count" -eq 1 ] ||
  die 'CW_RELEASE_GPG_PRIVATE_KEY must contain exactly one primary secret key'
secret_fingerprint="$(
  awk -F: '$1 == "sec" { primary = 1; next } primary && $1 == "fpr" { print $10; exit }' \
    "$secret_records"
)"
[ "$secret_fingerprint" = "$expected_fingerprint" ] ||
  die 'CW_RELEASE_GPG_PRIVATE_KEY does not match CW_RELEASE_GPG_KEY_ID'

probe="$tmp/release-signing-probe"
signature="$probe.asc"
printf 'codewire release signing preflight\n' >"$probe"
if ! printf '%s' "$CW_RELEASE_GPG_PASSPHRASE" |
  GNUPGHOME="$signing_home" gpg --batch --yes --pinentry-mode loopback \
    --passphrase-fd 0 --local-user "$expected_fingerprint" --armor \
    --detach-sign --output "$signature" "$probe" >/dev/null 2>&1; then
  die 'private key/passphrase signing probe failed'
fi

GNUPGHOME="$verify_home" gpg --batch --import "$public_key" >/dev/null 2>&1 ||
  die 'could not import the checked-in public key'
GNUPGHOME="$verify_home" gpg --batch --verify "$signature" "$probe" \
  >/dev/null 2>&1 || die 'checked-in public key rejected the signing probe'

printf 'release signing key preflight: OK (%s)\n' "$expected_fingerprint"
