#!/usr/bin/env bash
# shellcheck disable=SC2030,SC2031,SC2155 # Secret fixture exports are intentionally subshell-local.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VERIFY="$ROOT/scripts/ci/release/verify-cw-release-signing-key.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

generate_key() {
  local dir="$1"
  local uid="$2"
  local passphrase="$3"

  mkdir "$dir"
  chmod 700 "$dir"
  printf '%s' "$passphrase" >"$dir/passphrase"
  GNUPGHOME="$dir" gpg --batch --yes --pinentry-mode loopback \
    --passphrase-file "$dir/passphrase" \
    --quick-generate-key "$uid" ed25519 sign 0 >/dev/null 2>&1
  GNUPGHOME="$dir" gpg --batch --with-colons --list-secret-keys "$uid" |
    awk -F: '$1 == "fpr" { print $10; exit }' >"$dir/fingerprint"
  GNUPGHOME="$dir" gpg --batch --yes --armor --output "$dir/public.asc" \
    --export "$(<"$dir/fingerprint")"
  GNUPGHOME="$dir" gpg --batch --yes --pinentry-mode loopback \
    --passphrase-file "$dir/passphrase" --armor --output "$dir/private.asc" \
    --export-secret-keys "$(<"$dir/fingerprint")"
}

generate_key "$TMP/one" 'Release Fixture One <one@example.invalid>' \
  'fixture-one-passphrase'
generate_key "$TMP/two" 'Release Fixture Two <two@example.invalid>' \
  'fixture-two-passphrase'

run_one() {
  (
    export CW_RELEASE_GPG_PRIVATE_KEY="$(<"$TMP/one/private.asc")"
    export CW_RELEASE_GPG_PASSPHRASE="$(<"$TMP/one/passphrase")"
    export CW_RELEASE_GPG_KEY_ID="$(<"$TMP/one/fingerprint")"
    "$VERIFY" "$TMP/one/public.asc"
  )
}

run_one >"$TMP/success.out" 2>&1
grep -Fq 'release signing key preflight: OK' "$TMP/success.out"
if grep -Fq 'fixture-one-passphrase' "$TMP/success.out"; then
  echo 'release signing verifier printed the passphrase' >&2
  exit 1
fi

for missing in \
  CW_RELEASE_GPG_PRIVATE_KEY \
  CW_RELEASE_GPG_PASSPHRASE \
  CW_RELEASE_GPG_KEY_ID; do
  if (
    export CW_RELEASE_GPG_PRIVATE_KEY="$(<"$TMP/one/private.asc")"
    export CW_RELEASE_GPG_PASSPHRASE="$(<"$TMP/one/passphrase")"
    export CW_RELEASE_GPG_KEY_ID="$(<"$TMP/one/fingerprint")"
    unset "$missing"
    "$VERIFY" "$TMP/one/public.asc"
  ) >"$TMP/missing.out" 2>&1; then
    printf 'missing %s unexpectedly passed\n' "$missing" >&2
    exit 1
  fi
  grep -Fq "$missing is required" "$TMP/missing.out"
done

if (
  export CW_RELEASE_GPG_PRIVATE_KEY="$(<"$TMP/two/private.asc")"
  export CW_RELEASE_GPG_PASSPHRASE="$(<"$TMP/two/passphrase")"
  export CW_RELEASE_GPG_KEY_ID="$(<"$TMP/one/fingerprint")"
  "$VERIFY" "$TMP/one/public.asc"
) >"$TMP/private-mismatch.out" 2>&1; then
  echo 'mismatched private key unexpectedly passed' >&2
  exit 1
fi
grep -Fq 'does not match CW_RELEASE_GPG_KEY_ID' "$TMP/private-mismatch.out"

if (
  export CW_RELEASE_GPG_PRIVATE_KEY="$(<"$TMP/one/private.asc")"
  export CW_RELEASE_GPG_PASSPHRASE='wrong-passphrase'
  export CW_RELEASE_GPG_KEY_ID="$(<"$TMP/one/fingerprint")"
  "$VERIFY" "$TMP/one/public.asc"
) >"$TMP/passphrase-mismatch.out" 2>&1; then
  echo 'wrong passphrase unexpectedly passed' >&2
  exit 1
fi
grep -Fq 'private key/passphrase signing probe failed' \
  "$TMP/passphrase-mismatch.out"

if (
  export CW_RELEASE_GPG_PRIVATE_KEY="$(<"$TMP/one/private.asc")"
  export CW_RELEASE_GPG_PASSPHRASE="$(<"$TMP/one/passphrase")"
  export CW_RELEASE_GPG_KEY_ID="$(<"$TMP/two/fingerprint")"
  "$VERIFY" "$TMP/one/public.asc"
) >"$TMP/public-mismatch.out" 2>&1; then
  echo 'mismatched public fingerprint unexpectedly passed' >&2
  exit 1
fi
grep -Fq 'does not match the checked-in public key' "$TMP/public-mismatch.out"

printf 'release signing key preflight tests: OK\n'
