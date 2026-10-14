#!/usr/bin/env bash
# Sign the macOS local VM runtime's Virtualization.framework helper with the
# Developer ID Application identity and have Apple notarize it (#1905):
# hardened runtime, the identifier sh.codewire.vz-runner, exactly the release
# source's developer-entitlements.plist and a secure timestamp. Every cw's
# runtime document pins the helper's digest, so it is signed before the
# runtime is packed, and only when the parts cache has no signed helper for
# its recipe (build-local-runtime.sh helper): its digest, and its
# notarization, then change only with its code. The signature and its
# entitlements are checked, and a notarization Apple does not accept fails the
# release before the runtime is packed. This step compiles nothing.
set -euo pipefail
set +x
umask 077

usage() {
  cat <<'EOF'
usage: sign-macos-helper.sh <rcodesign> <key-directory> <unsigned-helper> <entitlements> <signed-dir>

  rcodesign        the pinned, checksum-verified rcodesign executable
  key-directory    fetch-openbao-macos-signing.sh output: developer-id.pem,
                   notary-key.p8, notary-key-id and notary-issuer-id
  unsigned-helper  the codewire-vz-runner build-local-runtime.sh helper built
  entitlements     the release source's developer-entitlements.plist
  signed-dir       a new directory for the signed codewire-vz-runner and, when
                   the notarization log names it, notary-submission-id
EOF
}

readonly signer=sign-macos-helper
die() {
  printf '%s: %s\n' "$signer" "$*" >&2
  exit 1
}

[ "$#" -eq 5 ] || { usage >&2; exit 2; }
rcodesign="$1" keys="$2" unsigned="$3" entitlements="$4" signed="$5"
readonly identifier='sh.codewire.vz-runner'
# shellcheck source=scripts/ci/release/macos-signing.sh
. "$(dirname "${BASH_SOURCE[0]}")/macos-signing.sh"

[ -f "$unsigned" ] && [ ! -L "$unsigned" ] || die "missing unsigned helper $unsigned"
[ "$(basename "$unsigned")" = codewire-vz-runner ] || die 'the unsigned helper is not codewire-vz-runner'
[ -f "$entitlements" ] && [ ! -L "$entitlements" ] || die "missing entitlements $entitlements"
grep -q '<key>' "$entitlements" || die 'the entitlements grant nothing'
[ ! -e "$signed" ] && [ ! -L "$signed" ] || die 'signed directory already exists'
unsigned="$(cd "$(dirname "$unsigned")" && pwd)/codewire-vz-runner"
entitlements="$(cd "$(dirname "$entitlements")" && pwd)/$(basename "$entitlements")"
macos_signing_begin
mkdir -m 0700 "$work/helper"

run_rcodesign sign --config-file /dev/null --pem-file "$keys/developer-id.pem" \
  --binary-identifier "$identifier" --for-notarization --code-signature-flags runtime \
  --entitlements-xml-file "$entitlements" "$unsigned" "$work/helper/codewire-vz-runner" >"$work/sign.log" 2>&1 || {
  cat "$work/sign.log" >&2
  die 'signing the helper failed'
}
macos_check_signature "$work/helper/codewire-vz-runner" "$identifier" helper
# The signature carries exactly the given entitlements, in both its XML and
# its DER form: each key of the file, once in each, and nothing else.
expected="$(grep -o '<key>[^<]*</key>' "$entitlements" | sort | sed 'p')"
signed_keys="$(awk '/^ *entitlements(_der)?_plist:$/ { block = 1; next }
  block && /^ *- / { print; next } { block = 0 }' "$work/info" | grep -o '<key>[^<]*</key>' | sort || true)"
[ "$signed_keys" = "$expected" ] || die 'the helper signature does not carry exactly the given entitlements'

(cd "$work/helper" && python3 -I -m zipfile -c "$work/vz-runner-macos.zip" codewire-vz-runner)
macos_notarize "$work/vz-runner-macos.zip"

mkdir -m 0755 "$signed"
install -m 0755 "$work/helper/codewire-vz-runner" "$signed/codewire-vz-runner"
[ -z "$notary_submission_id" ] || printf '%s\n' "$notary_submission_id" >"$signed/notary-submission-id"
printf '%s: signed and notarized identifier=%s team=%s sha256=%s\n' "$signer" "$identifier" "$macos_team_id" \
  "$(sha256sum "$signed/codewire-vz-runner" | cut -c1-64)"
