#!/usr/bin/env bash
# Sign the macOS cw pair with the Developer ID Application identity and have
# Apple notarize it (#2064): hardened runtime, the identifier sh.codewire.cw,
# a secure timestamp and no entitlements. Each signature is checked, and a
# notarization Apple does not accept fails the release before anything is
# published. The signed pair goes to a new directory with its own SHA256SUMS;
# a carried local runtime is copied unchanged (its Virtualization.framework
# helper keeps the ad hoc signature its runtime lock pins). This step compiles
# nothing.
set -euo pipefail
set +x
umask 077

usage() {
  cat <<'EOF'
usage: sign-macos-cw.sh <rcodesign> <key-directory> <unsigned-dir> <signed-dir> <vX.Y.Z>

  rcodesign      the pinned, checksum-verified rcodesign executable
  key-directory  fetch-openbao-macos-signing.sh output: developer-id.pem,
                 notary-key.p8, notary-key-id and notary-issuer-id
  unsigned-dir   the macOS pair as built: cw-<version>-<target> for both macOS
                 targets and, optionally, the local-runtime directory
  signed-dir     a new directory for the signed pair
EOF
}

die() {
  printf 'sign-macos-cw: %s\n' "$*" >&2
  exit 1
}

[ "$#" -eq 5 ] || { usage >&2; exit 2; }
rcodesign="$1" keys="$2" unsigned="$3" signed="$4" version="$5"
readonly identifier='sh.codewire.cw'
readonly team_id='PXQZM3GLP5'
readonly targets='aarch64-apple-darwin x86_64-apple-darwin'
# Apple usually answers within minutes; a release waits at most this long.
readonly notary_wait_seconds=1800

[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be vX.Y.Z, got: $version"
[ -x "$rcodesign" ] && [ -f "$rcodesign" ] || die 'rcodesign is not an executable file'
for name in developer-id.pem notary-key.p8 notary-key-id notary-issuer-id; do
  [ -f "$keys/$name" ] && [ ! -L "$keys/$name" ] || die "key directory lacks $name"
done
for target in $targets; do
  file="$unsigned/cw-$version-$target"
  [ -f "$file" ] && [ ! -L "$file" ] || die "missing unsigned $file"
done
[ ! -e "$signed" ] && [ ! -L "$signed" ] || die 'signed directory already exists'
# Signing holds no OpenPGP, mirror or R2 capability.
for name in CW_RELEASE_GPG_PRIVATE_KEY CW_RELEASE_GPG_PASSPHRASE AWS_ACCESS_KEY_ID \
  AWS_SECRET_ACCESS_KEY GH_MIRROR_TOKEN_FILE; do
  [ -z "${!name:-}" ] || die "$name must not reach macOS signing"
done
rcodesign="$(cd "$(dirname "$rcodesign")" && pwd)/$(basename "$rcodesign")"
keys="$(cd "$keys" && pwd)"
unsigned="$(cd "$unsigned" && pwd)"

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-macos-signing.XXXXXX")"
cleanup() {
  local result=$?
  trap - EXIT
  if ! { find "$work" -type f -exec shred -u {} + && rm -rf "$work"; }; then
    printf 'sign-macos-cw: private cleanup failed\n' >&2
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
mkdir -m 0700 "$work/home" "$work/pair"

# rcodesign reads no ambient configuration: no environment (the AWS SDK it
# uploads with honours AWS_* variables), no user or working-directory config.
run_rcodesign() {
  (cd "$work" && env -i PATH=/usr/bin:/bin HOME="$work/home" "$rcodesign" "$@")
}

for target in $targets; do
  run_rcodesign sign --config-file /dev/null --pem-file "$keys/developer-id.pem" \
    --binary-identifier "$identifier" --for-notarization --code-signature-flags runtime \
    "$unsigned/cw-$version-$target" "$work/pair/cw-$version-$target" >"$work/sign.log" 2>&1 || {
    cat "$work/sign.log" >&2
    die "signing the $target cw failed"
  }
done

# The signature each executable now carries: this identity's Developer ID
# certificate, hardened runtime, the product identifier and a timestamp.
for target in $targets; do
  file="$work/pair/cw-$version-$target"
  run_rcodesign verify --config-file /dev/null "$file" >/dev/null 2>&1 ||
    die "the $target signature does not verify"
  run_rcodesign print-signature-info --config-file /dev/null "$file" >"$work/info" 2>/dev/null ||
    die "the $target signature cannot be read"
  for line in "flags: CodeSignatureFlags(RUNTIME)" "identifier: $identifier" \
    "apple_certificate_profile: developer-id-application" "apple_team_id: $team_id" \
    "signature_verifies: true" "time_stamp_token:"; do
    sed 's/^[ -]*//' "$work/info" | grep -qxF -- "$line" || die "the $target signature lacks: $line"
  done
done

# Apple notarizes a zip, not a bare executable; it records each executable's
# code directory hash, which Gatekeeper looks up for a quarantined download.
(cd "$work/pair" && python3 -I -m zipfile -c "$work/cw-macos.zip" "cw-$version-aarch64-apple-darwin" \
  "cw-$version-x86_64-apple-darwin")
run_rcodesign encode-app-store-connect-api-key --config-file /dev/null --output-path "$work/notary-key.json" \
  "$(<"$keys/notary-issuer-id")" "$(<"$keys/notary-key-id")" "$keys/notary-key.p8" >/dev/null 2>&1 ||
  die 'the notary API key does not encode'
run_rcodesign notary-submit --config-file /dev/null --api-key-file "$work/notary-key.json" --wait \
  --max-wait-seconds "$notary_wait_seconds" "$work/cw-macos.zip" ||
  die 'Apple did not accept the notarization'

mkdir -m 0755 "$signed"
for target in $targets; do
  install -m 0755 "$work/pair/cw-$version-$target" "$signed/cw-$version-$target"
done
if [ -e "$unsigned/local-runtime" ]; then
  cp -R "$unsigned/local-runtime" "$signed/local-runtime"
fi
(cd "$signed" && sha256sum cw-* | sort -k2 >SHA256SUMS)
printf 'sign-macos-cw: signed and notarized identifier=%s team=%s\n' "$identifier" "$team_id"
