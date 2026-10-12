#!/usr/bin/env bash
# Synthetic proof for the macOS Developer ID signing and notarization step,
# with the recording rcodesign stand-in (fixtures/rcodesign-stand-in.sh):
# exact signing settings, every signature check, notarization of exactly the
# signed pair, no ambient configuration, and nothing written when any of it
# fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SIGNER="$ROOT/scripts/ci/release/sign-macos-cw.sh"
readonly VERSION=v0.3.389
CASES=0

fail() {
  printf '[test-sign-macos-cw] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/sign-macos-cw.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/unsigned/local-runtime/blobs" "$work/runner" "$work/caller" "$work/stand-in"
"$ROOT/scripts/ci/tests/fixtures/rcodesign-stand-in.sh" --install "$work/stand-in"
readonly STAND="$work/stand-in"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  printf 'synthetic %s cw\n' "$target" >"$work/unsigned/cw-$VERSION-$target"
done
printf 'synthetic runtime document\n' >"$work/unsigned/local-runtime/local-runtime.json"
printf 'synthetic blob\n' >"$work/unsigned/local-runtime/blobs/one"
# A configuration file where the caller stands must not reach rcodesign.
printf '[default]\n' >"$work/caller/rcodesign.toml"
export RUNNER_TEMP="$work/runner"
unset CW_RELEASE_GPG_PRIVATE_KEY CW_RELEASE_GPG_PASSPHRASE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY GH_MIRROR_TOKEN_FILE

sign() {
  local signed="$1"
  shift
  (cd "$work/caller" && env "$@" AWS_ENDPOINT_URL=https://attacker.invalid RCODESIGN_PROFILE=hostile \
    "$SIGNER" "$STAND/bin/rcodesign" "$STAND/keys" "$work/unsigned" "$signed" "$VERSION")
}

# The pair is signed, checked, notarized as one zip and handed over with its sums.
: >"$STAND/calls"
: >"$STAND/env"
sign "$work/signed" >"$work/success.out" 2>&1 || fail "$(cat "$work/success.out")"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  [ "$(tail -1 "$work/signed/cw-$VERSION-$target")" = developer-id-signature ] || fail "$target is not the signed bytes"
done
[ "$(cat "$STAND/state/zip")" = "cw-$VERSION-aarch64-apple-darwin cw-$VERSION-x86_64-apple-darwin" ] ||
  fail 'notarization did not submit exactly the signed pair'
(cd "$work/signed" && sha256sum --check --quiet SHA256SUMS) || fail 'signed SHA256SUMS does not verify'
[ "$(cut -d' ' -f3 "$work/signed/SHA256SUMS" | tr '\n' ' ')" = \
  "cw-$VERSION-aarch64-apple-darwin cw-$VERSION-x86_64-apple-darwin " ] || fail 'SHA256SUMS lists other files'
diff -r "$work/unsigned/local-runtime" "$work/signed/local-runtime" >/dev/null || fail 'the local runtime changed'
[ "$(cut -d' ' -f1 "$STAND/calls" | tr '\n' ' ')" = \
  'sign sign verify print-signature-info verify print-signature-info encode-app-store-connect-api-key notary-submit ' ] ||
  fail "unexpected rcodesign calls: $(cut -d' ' -f1 "$STAND/calls" | tr '\n' ' ')"
grep -v '^env:HOME PATH PWD SHLVL _ $' "$STAND/env" | grep -v '^cwd:' >/dev/null &&
  fail "rcodesign saw an ambient environment: $(grep '^env:' "$STAND/env" | sort -u)"
grep '^cwd:' "$STAND/env" | grep -qv "^cwd:$RUNNER_TEMP/codewire-macos-signing\." &&
  fail 'rcodesign ran outside its private directory'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'signing work survived cleanup'
grep -q '^sign-macos-cw: signed and notarized identifier=sh.codewire.cw team=PXQZM3GLP5$' "$work/success.out" ||
  fail 'no completion line'
pass

refused() {
  local name="$1"
  shift
  if "$@" >"$work/$name.out" 2>&1; then
    fail "$name was accepted"
  fi
  [ ! -e "$work/refused" ] || fail "$name wrote a signed pair"
  [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail "$name left signing work"
  pass
}

# Every property of each signature is required.
for line in "          flags: CodeSignatureFlags(RUNTIME)" "          identifier: sh.codewire.cw" \
    "            apple_certificate_profile: developer-id-application" "            apple_team_id: PXQZM3GLP5" \
    "          - signature_verifies: true" "            time_stamp_token:"; do
  printf '%s' "$line" >"$STAND/state/drop"
  refused "drop-${line//[^a-z]/}" sign "$work/refused"
  grep -q 'signature lacks' "$work/drop-${line//[^a-z]/}.out" || fail "missing ${line# *} was not refused by its check"
done
rm "$STAND/state/drop"

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

# Inputs are exact: a version, both executables, every key file and a new output.
refused bad-version env "$SIGNER" "$STAND/bin/rcodesign" "$STAND/keys" "$work/unsigned" "$work/refused" 0.3.389
mv "$STAND/keys/notary-key.p8" "$work/notary-key.p8"
refused missing-key sign "$work/refused"
mv "$work/notary-key.p8" "$STAND/keys/notary-key.p8"
mv "$work/unsigned/cw-$VERSION-x86_64-apple-darwin" "$work/x86"
refused missing-target sign "$work/refused"
mv "$work/x86" "$work/unsigned/cw-$VERSION-x86_64-apple-darwin"
if sign "$work/signed" >"$work/existing.out" 2>&1; then
  fail 'an existing signed directory was overwritten'
fi
pass

printf 'test-sign-macos-cw: PASS cases=%s\n' "$CASES"
