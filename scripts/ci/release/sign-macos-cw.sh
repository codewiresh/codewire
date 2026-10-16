#!/usr/bin/env bash
# Sign the macOS cw pair with the Developer ID Application identity and have
# Apple notarize it (#2064): hardened runtime, the identifier sh.codewire.cw,
# a secure timestamp and no entitlements. Each signature is checked, and a
# notarization Apple does not accept fails the release before anything is
# published. The signed pair goes to a new directory with its own SHA256SUMS;
# a carried local runtime is copied unchanged (its Virtualization.framework
# helper was signed before the runtime was packed: sign-macos-helper.sh). This
# step compiles nothing.
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

readonly signer=sign-macos-cw
die() {
  printf '%s: %s\n' "$signer" "$*" >&2
  exit 1
}

[ "$#" -eq 5 ] || { usage >&2; exit 2; }
rcodesign="$1" keys="$2" unsigned="$3" signed="$4" version="$5"
readonly identifier='sh.codewire.cw'
readonly targets='aarch64-apple-darwin x86_64-apple-darwin'
# shellcheck source=scripts/ci/release/macos-signing.sh
. "$(dirname "${BASH_SOURCE[0]}")/macos-signing.sh"

[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be vX.Y.Z, got: $version"
for target in $targets; do
  file="$unsigned/cw-$version-$target"
  [ -f "$file" ] && [ ! -L "$file" ] || die "missing unsigned $file"
done
[ ! -e "$signed" ] && [ ! -L "$signed" ] || die 'signed directory already exists'
unsigned="$(cd "$unsigned" && pwd)"
macos_signing_begin
mkdir -m 0700 "$work/pair"

for target in $targets; do
  run_rcodesign sign --config-file /dev/null --pem-file "$keys/developer-id.pem" \
    --binary-identifier "$identifier" --for-notarization --code-signature-flags runtime \
    "$unsigned/cw-$version-$target" "$work/pair/cw-$version-$target" >"$work/sign.log" 2>&1 || {
    cat "$work/sign.log" >&2
    die "signing the $target cw failed"
  }
done
for target in $targets; do
  macos_check_signature "$work/pair/cw-$version-$target" "$identifier" "$target"
done

(cd "$work/pair" && python3 -I -m zipfile -c "$work/cw-macos.zip" "cw-$version-aarch64-apple-darwin" \
  "cw-$version-x86_64-apple-darwin")
macos_notarize "$work/cw-macos.zip"

mkdir -m 0755 "$signed"
for target in $targets; do
  install -m 0755 "$work/pair/cw-$version-$target" "$signed/cw-$version-$target"
done
if [ -e "$unsigned/local-runtime" ]; then
  cp -R "$unsigned/local-runtime" "$signed/local-runtime"
fi
(cd "$signed" && sha256sum cw-* | sort -k2 >SHA256SUMS)
printf '%s: signed and notarized identifier=%s team=%s\n' "$signer" "$identifier" "$macos_team_id"
