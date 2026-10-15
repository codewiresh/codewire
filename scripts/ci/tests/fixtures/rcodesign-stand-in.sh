#!/usr/bin/env bash
# A recording stand-in for rcodesign. It signs and notarizes nothing, holds no
# identity and opens no connection. The signers' tests (test-sign-macos-cw.sh,
# test-sign-macos-helper.sh) and the release dry run use it to exercise
# sign-macos-cw.sh, sign-macos-helper.sh and the jobs around them; the release
# itself installs the pinned rcodesign.
#
#   rcodesign-stand-in.sh --install DIR
#
# lays out DIR/bin/rcodesign, synthetic DIR/keys and an empty DIR/state.
# DIR/bin/rcodesign then answers the rcodesign commands the signer uses,
# records each call in DIR/calls and the environment it saw in DIR/env, and
# appends a marker to every executable it "signs", after the identifier and
# entitlements it was given. A file in DIR/state makes it misbehave: `drop`
# (omit that exact signature-info line), `extra-entitlement` (report one more
# entitlement than it was given), `verify-fails`, `reject` (the notarization)
# or `no-submission-id` (a notarization log without the id).
set -euo pipefail

if [ "${1:-}" = --install ]; then
  [ "$#" -eq 2 ] && [ -d "$2" ] || { echo 'usage: rcodesign-stand-in.sh --install DIR' >&2; exit 2; }
  root="$2"
  mkdir -m 0700 "$root/bin" "$root/keys" "$root/state"
  install -m 0700 "${BASH_SOURCE[0]}" "$root/bin/rcodesign"
  printf 'synthetic-developer-id\n' >"$root/keys/developer-id.pem"
  printf 'synthetic-notary-key\n' >"$root/keys/notary-key.p8"
  printf 'SYNTHET1C0' >"$root/keys/notary-key-id"
  printf '01234567-89ab-cdef-0123-456789abcdef' >"$root/keys/notary-issuer-id"
  chmod 0600 "$root/keys"/*
  : >"$root/calls"
  : >"$root/env"
  exit 0
fi

root="${0%/bin/rcodesign}"
[ "$root" != "$0" ] || { echo 'the stand-in runs only as DIR/bin/rcodesign' >&2; exit 96; }
printf '%s\n' "$*" >>"$root/calls"
{ printf 'env:'; env | cut -d= -f1 | sort | tr '\n' ' '; printf '\ncwd:%s\n' "$PWD"; } >>"$root/env"
state="$root/state"
command="$1"
shift
[ "${1:-}" = --config-file ] && [ "${2:-}" = /dev/null ] || exit 90
shift 2
case "$command" in
  sign)
    if [ "$#" -eq 9 ] && [ "${*:1:7}" = "--pem-file $root/keys/developer-id.pem \
--binary-identifier sh.codewire.cw --for-notarization --code-signature-flags runtime" ]; then
      { cat "$8"; printf 'developer-id-signature\n'; } >"$9"
    elif [ "$#" -eq 11 ] && [ "${*:1:7}" = "--pem-file $root/keys/developer-id.pem \
--binary-identifier sh.codewire.vz-runner --for-notarization --code-signature-flags runtime" ] &&
      [ "$8" = --entitlements-xml-file ] && [ -f "$9" ]; then
      { cat "${10}"; printf 'stand-in-identifier sh.codewire.vz-runner\n'
        sed -n 's/.*<key>\([^<]*\)<\/key>.*/stand-in-entitlement \1/p' "$9"
        printf 'developer-id-signature\n'; } >"${11}"
    else
      exit 91
    fi
    ;;
  verify)
    [ ! -e "$state/verify-fails" ]
    grep -q developer-id-signature "$1"
    ;;
  print-signature-info)
    grep -q developer-id-signature "$1"
    identifier="$(sed -n 's/^stand-in-identifier //p' "$1")"
    entitlements="$(sed -n "s/^stand-in-entitlement \(.*\)/        - '  <key>\1<\/key>'/p" "$1")"
    [ ! -e "$state/extra-entitlement" ] ||
      entitlements+=$'\n'"        - '  <key>com.apple.security.cs.disable-library-validation</key>'"
    while IFS= read -r line; do
      [ -e "$state/drop" ] && [ "$line" = "$(cat "$state/drop")" ] && continue
      printf '%s\n' "$line"
    done <<INFO
- path: synthetic
  entity:
    mach_o:
      signature:
        code_directory:
          version: '0x20500'
          flags: CodeSignatureFlags(RUNTIME)
          identifier: ${identifier:-sh.codewire.cw}
$( [ -z "$entitlements" ] || printf '        entitlements_plist:\n%s\n        entitlements_der_plist:\n%s\n' \
  "$entitlements" "$entitlements")
        cms:
          certificates:
          - subject: 'CN=Developer ID Application: Synthetic (PXQZM3GLP5)'
            apple_certificate_profile: developer-id-application
            apple_team_id: PXQZM3GLP5
          signers:
          - signature_verifies: true
            cdhash_plist:
            - '    <key>cdhashes</key>'
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
    [ -e "$state/no-submission-id" ] ||
      echo 'created submission ID: 0b7e5f2a-1c3d-4e5f-8a9b-0c1d2e3f4a5b' >&2
    [ ! -e "$state/reject" ] || { echo 'notary status: Invalid' >&2; exit 1; }
    ;;
  *) exit 95 ;;
esac
