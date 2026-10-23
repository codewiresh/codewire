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
readonly SUBMISSION=0b7e5f2a-1c3d-4e5f-8a9b-0c1d2e3f4a5b
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
# Retries wait in the signer, not in rcodesign; this sleep records each wait
# and returns at once.
mkdir -p "$work/fakebin"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >>"%s/sleeps"\n' "$work" >"$work/fakebin/sleep"
chmod +x "$work/fakebin/sleep"
export PATH="$work/fakebin:$PATH"
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

# A notarization Apple does not accept fails before anything is handed over,
# with Apple's reason, and is never retried.
touch "$STAND/state/reject"
: >"$STAND/calls"
refused notary-rejected sign "$work/refused"
grep -q "Apple did not accept the notarization (submission $SUBMISSION): notarization package is invalid" \
  "$work/notary-rejected.out" || fail 'rejection was not reported with its reason'
[ "$(grep -c '^notary-' "$STAND/calls")" = 1 ] || fail 'a rejection was retried'
rm "$STAND/state/reject"

notary_calls() { grep -o '^notary-[a-z]*' "$STAND/calls" | tr '\n' ' '; }

# An upload that created no submission is retried, 30 s apart.
printf 2 >"$STAND/state/upload-fails"
: >"$STAND/calls"; : >"$work/sleeps"
sign "$work/signed-upload-retry" >"$work/upload-retry.out" 2>&1 || fail "$(cat "$work/upload-retry.out")"
[ "$(notary_calls)" = 'notary-submit notary-submit notary-submit ' ] || fail "upload retry calls: $(notary_calls)"
[ "$(grep -c 'the notary upload failed and created no submission' "$work/upload-retry.out")" = 2 ] ||
  fail 'upload failures were not warned'
[ "$(tr '\n' ' ' <"$work/sleeps")" = '30 30 ' ] || fail "upload retry waits: $(tr '\n' ' ' <"$work/sleeps")"
grep -q "notary submission $SUBMISSION accepted" "$work/upload-retry.out" || fail 'retried upload was not accepted'
pass

# An upload that never succeeds fails after four attempts and says so.
printf 9 >"$STAND/state/upload-fails"
refused upload-never sign "$work/refused"
grep -q 'the notary upload failed 4 times and created no submission' "$work/upload-never.out" ||
  fail 'a lost upload was not reported as one'
rm "$STAND/state/upload-fails"

# A submission whose answer was lost is waited on again by its id, not
# resubmitted, and its verdict is the last poll state.
touch "$STAND/state/lost-poll"
printf 2 >"$STAND/state/wait-lost"
: >"$STAND/calls"; : >"$work/sleeps"
sign "$work/signed-lost-poll" >"$work/lost-poll.out" 2>&1 || fail "$(cat "$work/lost-poll.out")"
[ "$(notary_calls)" = 'notary-submit notary-wait notary-wait notary-wait ' ] || fail "lost poll calls: $(notary_calls)"
[ "$(grep -c "lost contact with Apple while it processed submission $SUBMISSION" "$work/lost-poll.out")" = 3 ] ||
  fail 'lost contact was not warned for each attempt'
grep -q "notary submission $SUBMISSION accepted" "$work/lost-poll.out" || fail 'the waited submission was not accepted'
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  [ "$(tail -1 "$work/signed-lost-poll/cw-$VERSION-$target")" = developer-id-signature ] ||
    fail "$target is not handed over after a lost poll"
done
pass

# A waited submission that Apple did not accept fails with its verdict.
printf Invalid >"$STAND/state/wait-verdict"
refused wait-invalid sign "$work/refused"
grep -q "Apple did not accept the notarization: submission $SUBMISSION is Invalid" "$work/wait-invalid.out" ||
  fail 'a waited rejection was not reported'
rm "$STAND/state/wait-verdict"

# A submission that never answers again fails as lost contact, never as a
# rejection, and names the submission to check.
printf 99 >"$STAND/state/wait-lost"
refused wait-lost sign "$work/refused"
grep -q "lost contact with Apple's notary service: submission $SUBMISSION has no verdict" "$work/wait-lost.out" ||
  fail 'lost contact was not reported as such'
grep -q 'Apple did not accept' "$work/wait-lost.out" && fail 'lost contact was reported as a rejection'
rm "$STAND/state/lost-poll" "$STAND/state/wait-lost"

# Apple taking longer than the wait limit is its own failure.
touch "$STAND/state/wait-limit"
refused wait-limit sign "$work/refused"
grep -q "Apple did not finish notarization submission $SUBMISSION within 1800s" "$work/wait-limit.out" ||
  fail 'the wait limit was not reported'
rm "$STAND/state/wait-limit"

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
