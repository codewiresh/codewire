#!/usr/bin/env bash
# Synthetic proof for the VZ helper's Developer ID signing and notarization
# step (#1905), with the recording rcodesign stand-in
# (fixtures/rcodesign-stand-in.sh): exact signing settings and entitlements,
# every signature check, notarization of exactly the signed helper, its
# submission id, no ambient configuration, and nothing written when any of it
# fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SIGNER="$ROOT/scripts/ci/release/sign-macos-helper.sh"
readonly ENTITLEMENTS="$ROOT/crates/codewire-local-vmm/macos-vz-runner/developer-entitlements.plist"
CASES=0

fail() {
  printf '[test-sign-macos-helper] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/sign-macos-helper.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/unsigned" "$work/runner" "$work/caller" "$work/stand-in"
"$ROOT/scripts/ci/tests/fixtures/rcodesign-stand-in.sh" --install "$work/stand-in"
readonly STAND="$work/stand-in"
printf 'synthetic helper\n' >"$work/unsigned/codewire-vz-runner"
# A configuration file where the caller stands must not reach rcodesign.
printf '[default]\n' >"$work/caller/rcodesign.toml"
export RUNNER_TEMP="$work/runner"
unset CW_RELEASE_GPG_PRIVATE_KEY CW_RELEASE_GPG_PASSPHRASE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY GH_MIRROR_TOKEN_FILE

sign() {
  local signed="$1"
  shift
  (cd "$work/caller" && env "$@" AWS_ENDPOINT_URL=https://attacker.invalid RCODESIGN_PROFILE=hostile \
    "$SIGNER" "$STAND/bin/rcodesign" "$STAND/keys" "$work/unsigned/codewire-vz-runner" "$ENTITLEMENTS" "$signed")
}

# The helper is signed with exactly the entitlements, checked, notarized alone
# and handed over with its submission id.
: >"$STAND/calls"
: >"$STAND/env"
sign "$work/signed" >"$work/success.out" 2>&1 || fail "$(cat "$work/success.out")"
[ "$(tail -1 "$work/signed/codewire-vz-runner")" = developer-id-signature ] || fail 'the helper is not the signed bytes'
grep -qx 'stand-in-entitlement com.apple.security.virtualization' "$work/signed/codewire-vz-runner" ||
  fail 'the helper was not signed with the entitlements'
[ "$(ls "$work/signed")" = "$(printf 'codewire-vz-runner\nnotary-submission-id')" ] || fail 'unexpected signed files'
[ "$(cat "$work/signed/notary-submission-id")" = 0b7e5f2a-1c3d-4e5f-8a9b-0c1d2e3f4a5b ] ||
  fail 'the notary submission id was not kept'
[ "$(cat "$STAND/state/zip")" = codewire-vz-runner ] || fail 'notarization did not submit exactly the signed helper'
[ "$(cut -d' ' -f1 "$STAND/calls" | tr '\n' ' ')" = \
  'sign verify print-signature-info encode-app-store-connect-api-key notary-submit ' ] ||
  fail "unexpected rcodesign calls: $(cut -d' ' -f1 "$STAND/calls" | tr '\n' ' ')"
grep -q -- "--entitlements-xml-file $ENTITLEMENTS " "$STAND/calls" || fail 'the release entitlements were not used'
grep -v '^env:HOME PATH PWD SHLVL _ $' "$STAND/env" | grep -v '^cwd:' >/dev/null &&
  fail "rcodesign saw an ambient environment: $(grep '^env:' "$STAND/env" | sort -u)"
grep '^cwd:' "$STAND/env" | grep -qv "^cwd:$RUNNER_TEMP/codewire-macos-signing\." &&
  fail 'rcodesign ran outside its private directory'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'signing work survived cleanup'
grep -q '^sign-macos-helper: notary submission 0b7e5f2a-1c3d-4e5f-8a9b-0c1d2e3f4a5b accepted$' "$work/success.out" ||
  fail 'the submission id was not logged'
grep -q "^sign-macos-helper: signed and notarized identifier=sh.codewire.vz-runner team=PXQZM3GLP5 sha256=$(
  sha256sum "$work/signed/codewire-vz-runner" | cut -c1-64)$" "$work/success.out" || fail 'no completion line'
pass

# A log without the submission id still hands over the accepted helper.
touch "$STAND/state/no-submission-id"
sign "$work/signed-no-id" >"$work/no-id.out" 2>&1 || fail "$(cat "$work/no-id.out")"
[ ! -e "$work/signed-no-id/notary-submission-id" ] || fail 'an empty submission id was kept'
grep -q '^::warning::sign-macos-helper: notarization accepted, but its log names no submission id$' \
  "$work/no-id.out" || fail 'the missing id was not reported'
rm "$STAND/state/no-submission-id"
pass

refused() {
  local name="$1"
  shift
  if "$@" >"$work/$name.out" 2>&1; then
    fail "$name was accepted"
  fi
  [ ! -e "$work/refused" ] || fail "$name wrote a signed helper"
  [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail "$name left signing work"
  pass
}

# Every property of the signature is required.
for line in "          flags: CodeSignatureFlags(RUNTIME)" "          identifier: sh.codewire.vz-runner" \
    "            apple_certificate_profile: developer-id-application" "            apple_team_id: PXQZM3GLP5" \
    "          - signature_verifies: true" "            time_stamp_token:"; do
  printf '%s' "$line" >"$STAND/state/drop"
  refused "drop-${line//[^a-z]/}" sign "$work/refused"
  grep -q 'signature lacks' "$work/drop-${line//[^a-z]/}.out" || fail "missing ${line# *} was not refused by its check"
done
rm "$STAND/state/drop"

# Its entitlements are exactly the release source's, in both forms.
touch "$STAND/state/extra-entitlement"
refused extra-entitlement sign "$work/refused"
grep -q 'does not carry exactly the given entitlements' "$work/extra-entitlement.out" ||
  fail 'an extra entitlement was not refused by its check'
rm "$STAND/state/extra-entitlement"
printf '<plist><dict></dict></plist>\n' >"$work/empty.plist"
refused no-entitlements env "$SIGNER" "$STAND/bin/rcodesign" "$STAND/keys" "$work/unsigned/codewire-vz-runner" \
  "$work/empty.plist" "$work/refused"

touch "$STAND/state/verify-fails"
refused verify-fails sign "$work/refused"
rm "$STAND/state/verify-fails"

# A notarization Apple does not accept fails before anything is handed over.
touch "$STAND/state/reject"
refused notary-rejected sign "$work/refused"
grep -q 'Apple did not accept the notarization' "$work/notary-rejected.out" || fail 'rejection was not reported'
rm "$STAND/state/reject"

# Release OpenPGP, mirror and R2 capabilities never reach macOS signing.
for ambient in CW_RELEASE_GPG_PRIVATE_KEY=ambient AWS_SECRET_ACCESS_KEY=ambient GH_MIRROR_TOKEN_FILE=/x; do
  : >"$STAND/calls"
  refused "ambient-${ambient%%=*}" sign "$work/refused" "$ambient"
  [ ! -s "$STAND/calls" ] || fail "ambient ${ambient%%=*} reached rcodesign"
done

# Inputs are exact: the helper by its name, every key file and a new output.
cp "$work/unsigned/codewire-vz-runner" "$work/other-name"
refused wrong-name env "$SIGNER" "$STAND/bin/rcodesign" "$STAND/keys" "$work/other-name" "$ENTITLEMENTS" "$work/refused"
mv "$STAND/keys/notary-key.p8" "$work/notary-key.p8"
refused missing-key sign "$work/refused"
mv "$work/notary-key.p8" "$STAND/keys/notary-key.p8"
mv "$work/unsigned/codewire-vz-runner" "$work/helper"
refused missing-helper sign "$work/refused"
mv "$work/helper" "$work/unsigned/codewire-vz-runner"
if sign "$work/signed" >"$work/existing.out" 2>&1; then
  fail 'an existing signed directory was overwritten'
fi
pass

printf 'test-sign-macos-helper: PASS cases=%s\n' "$CASES"
