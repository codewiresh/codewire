#!/usr/bin/env bash
# Synthetic proof for the macOS Developer ID signing and notarization step,
# with a recording stand-in for rcodesign: exact signing settings, every
# signature check, notarization of exactly the signed pair, no ambient
# configuration, and nothing written when any of it fails.
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
mkdir -p "$work/bin" "$work/keys" "$work/unsigned/local-runtime/blobs" "$work/runner" "$work/caller"

cat >"$work/bin/rcodesign" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
log="${0%/bin/rcodesign}/calls"
printf '%s\n' "$*" >>"$log"
# The signer clears the environment and works in its private directory.
{ printf 'env:'; env | cut -d= -f1 | sort | tr '\n' ' '; printf '\ncwd:%s\n' "$PWD"; } >>"${0%/bin/rcodesign}/env"
state="${0%/bin/rcodesign}/state"
command="$1"
shift
[ "$1" = --config-file ] && [ "$2" = /dev/null ] || exit 90
shift 2
case "$command" in
  sign)
    [ "$#" -eq 9 ] && [ "${*:1:7}" = "--pem-file ${0%/bin/rcodesign}/keys/developer-id.pem \
--binary-identifier sh.codewire.cw --for-notarization --code-signature-flags runtime" ] || exit 91
    { cat "$8"; printf 'developer-id-signature\n'; } >"$9"
    ;;
  verify)
    [ ! -e "$state/verify-fails" ]
    grep -q developer-id-signature "$1"
    ;;
  print-signature-info)
    grep -q developer-id-signature "$1"
    while IFS= read -r line; do
      [ -e "$state/drop" ] && [ "$line" = "$(cat "$state/drop")" ] && continue
      printf '%s\n' "$line"
    done <<'INFO'
- path: synthetic
  entity:
    mach_o:
      signature:
        code_directory:
          version: '0x20500'
          flags: CodeSignatureFlags(RUNTIME)
          identifier: sh.codewire.cw
        cms:
          certificates:
          - subject: 'CN=Developer ID Application: Synthetic (PXQZM3GLP5)'
            apple_certificate_profile: developer-id-application
            apple_team_id: PXQZM3GLP5
          signers:
          - signature_verifies: true
            time_stamp_token:
              certificates:
              - apple_team_id: Apple Certification Authority
INFO
    ;;
  encode-app-store-connect-api-key)
    [ "$1" = --output-path ] && [ "$3" = 01234567-89ab-cdef-0123-456789abcdef ] && [ "$4" = SYNTHET1C0 ] || exit 92
    grep -q synthetic-notary-key "$5"
    printf '{"issuer_id":"%s","key_id":"%s"}\n' "$3" "$4" >"$2"
    ;;
  notary-submit)
    [ "$1" = --api-key-file ] && [ -f "$2" ] && [ "$3" = --wait ] && [ "$4" = --max-wait-seconds ] || exit 93
    python3 -I -c 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); print(" ".join(sorted(z.namelist())))
for name in z.namelist(): assert b"developer-id-signature" in z.read(name), name' "$6" >"$state/zip" || exit 94
    [ ! -e "$state/reject" ] || { echo 'notary status: Invalid' >&2; exit 1; }
    ;;
  *) exit 95 ;;
esac
STUB
chmod +x "$work/bin/rcodesign"
mkdir "$work/state"

printf 'synthetic-developer-id\n' >"$work/keys/developer-id.pem"
printf 'synthetic-notary-key\n' >"$work/keys/notary-key.p8"
printf 'SYNTHET1C0' >"$work/keys/notary-key-id"
printf '01234567-89ab-cdef-0123-456789abcdef' >"$work/keys/notary-issuer-id"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  printf 'synthetic %s cw\n' "$target" >"$work/unsigned/cw-$VERSION-$target"
done
printf 'synthetic runtime document\n' >"$work/unsigned/local-runtime/local-runtime.json"
printf 'synthetic blob\n' >"$work/unsigned/local-runtime/blobs/one"
# A configuration file where the caller stands must not reach rcodesign.
printf '[default]\n' >"$work/caller/rcodesign.toml"
export KEYS="$work/keys"
export RUNNER_TEMP="$work/runner"
unset CW_RELEASE_GPG_PRIVATE_KEY CW_RELEASE_GPG_PASSPHRASE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY GH_MIRROR_TOKEN_FILE

sign() {
  local signed="$1"
  shift
  (cd "$work/caller" && env "$@" AWS_ENDPOINT_URL=https://attacker.invalid RCODESIGN_PROFILE=hostile \
    "$SIGNER" "$work/bin/rcodesign" "$work/keys" "$work/unsigned" "$signed" "$VERSION")
}

# The pair is signed, checked, notarized as one zip and handed over with its sums.
: >"$work/calls"
: >"$work/env"
sign "$work/signed" >"$work/success.out" 2>&1 || fail "$(cat "$work/success.out")"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  [ "$(tail -1 "$work/signed/cw-$VERSION-$target")" = developer-id-signature ] || fail "$target is not the signed bytes"
done
[ "$(cat "$work/state/zip")" = "cw-$VERSION-aarch64-apple-darwin cw-$VERSION-x86_64-apple-darwin" ] ||
  fail 'notarization did not submit exactly the signed pair'
(cd "$work/signed" && sha256sum --check --quiet SHA256SUMS) || fail 'signed SHA256SUMS does not verify'
[ "$(cut -d' ' -f3 "$work/signed/SHA256SUMS" | tr '\n' ' ')" = \
  "cw-$VERSION-aarch64-apple-darwin cw-$VERSION-x86_64-apple-darwin " ] || fail 'SHA256SUMS lists other files'
diff -r "$work/unsigned/local-runtime" "$work/signed/local-runtime" >/dev/null || fail 'the local runtime changed'
[ "$(cut -d' ' -f1 "$work/calls" | tr '\n' ' ')" = \
  'sign sign verify print-signature-info verify print-signature-info encode-app-store-connect-api-key notary-submit ' ] ||
  fail "unexpected rcodesign calls: $(cut -d' ' -f1 "$work/calls" | tr '\n' ' ')"
grep -v '^env:HOME PATH PWD SHLVL _ $' "$work/env" | grep -v '^cwd:' >/dev/null &&
  fail "rcodesign saw an ambient environment: $(grep '^env:' "$work/env" | sort -u)"
grep '^cwd:' "$work/env" | grep -qv "^cwd:$RUNNER_TEMP/codewire-macos-signing\." &&
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
  printf '%s' "$line" >"$work/state/drop"
  refused "drop-${line//[^a-z]/}" sign "$work/refused"
  grep -q 'signature lacks' "$work/drop-${line//[^a-z]/}.out" || fail "missing ${line# *} was not refused by its check"
done
rm "$work/state/drop"

touch "$work/state/verify-fails"
refused verify-fails sign "$work/refused"
rm "$work/state/verify-fails"

# A notarization Apple does not accept fails before anything is handed over.
touch "$work/state/reject"
refused notary-rejected sign "$work/refused"
grep -q 'Apple did not accept the notarization' "$work/notary-rejected.out" || fail 'rejection was not reported'
rm "$work/state/reject"

# Release OpenPGP, mirror and R2 capabilities never reach macOS signing.
for ambient in CW_RELEASE_GPG_PRIVATE_KEY=ambient AWS_SECRET_ACCESS_KEY=ambient GH_MIRROR_TOKEN_FILE=/x; do
  : >"$work/calls"
  refused "ambient-${ambient%%=*}" sign "$work/refused" "$ambient"
  [ ! -s "$work/calls" ] || fail "ambient ${ambient%%=*} reached rcodesign"
done

# Inputs are exact: a version, both executables, every key file and a new output.
refused bad-version env "$SIGNER" "$work/bin/rcodesign" "$work/keys" "$work/unsigned" "$work/refused" 0.3.389
mv "$work/keys/notary-key.p8" "$work/notary-key.p8"
refused missing-key sign "$work/refused"
mv "$work/notary-key.p8" "$work/keys/notary-key.p8"
mv "$work/unsigned/cw-$VERSION-x86_64-apple-darwin" "$work/x86"
refused missing-target sign "$work/refused"
mv "$work/x86" "$work/unsigned/cw-$VERSION-x86_64-apple-darwin"
if sign "$work/signed" >"$work/existing.out" 2>&1; then
  fail 'an existing signed directory was overwritten'
fi
pass

printf 'test-sign-macos-cw: PASS cases=%s\n' "$CASES"
