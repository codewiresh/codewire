# shellcheck shell=bash
# shellcheck disable=SC2154 # signer, die, rcodesign and keys are the caller's.
# What every macOS signing run shares (#2064, #1905), sourced by
# sign-macos-cw.sh and sign-macos-helper.sh after they define `signer` and
# `die` and set `rcodesign` and `keys`. Each signature is this identity's
# Developer ID certificate, the hardened runtime, the caller's identifier and
# a secure timestamp, and a notarization Apple does not accept fails the run.

readonly macos_team_id='PXQZM3GLP5'
# Apple usually answers within minutes; a release waits at most this long.
readonly macos_notary_wait_seconds=1800

# Check the signer and its keys, refuse every other release capability, and
# make the private work directory $work, shredded on exit.
macos_signing_begin() {
  local name
  [ -x "$rcodesign" ] && [ -f "$rcodesign" ] || die 'rcodesign is not an executable file'
  for name in developer-id.pem notary-key.p8 notary-key-id notary-issuer-id; do
    [ -f "$keys/$name" ] && [ ! -L "$keys/$name" ] || die "key directory lacks $name"
  done
  # Signing holds no OpenPGP, mirror or R2 capability.
  for name in CW_RELEASE_GPG_PRIVATE_KEY CW_RELEASE_GPG_PASSPHRASE AWS_ACCESS_KEY_ID \
    AWS_SECRET_ACCESS_KEY GH_MIRROR_TOKEN_FILE; do
    [ -z "${!name:-}" ] || die "$name must not reach macOS signing"
  done
  rcodesign="$(cd "$(dirname "$rcodesign")" && pwd)/$(basename "$rcodesign")"
  keys="$(cd "$keys" && pwd)"
  work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-macos-signing.XXXXXX")"
  trap macos_signing_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  mkdir -m 0700 "$work/home"
}

macos_signing_cleanup() {
  local result=$?
  trap - EXIT
  if ! { find "$work" -type f -exec shred -u {} + && rm -rf "$work"; }; then
    printf '%s: private cleanup failed\n' "$signer" >&2
    result=1
  fi
  exit "$result"
}

# rcodesign reads no ambient configuration: no environment (the AWS SDK it
# uploads with honours AWS_* variables), no user or working-directory config.
run_rcodesign() {
  (cd "$work" && env -i PATH=/usr/bin:/bin HOME="$work/home" "$rcodesign" "$@")
}

# The signature FILE now carries: this identity's Developer ID certificate,
# hardened runtime, IDENTIFIER and a timestamp. Its full description stays in
# $work/info for the caller's own checks.
macos_check_signature() {
  local file="$1" named="$2" label="$3" line
  run_rcodesign verify --config-file /dev/null "$file" >/dev/null 2>&1 ||
    die "the $label signature does not verify"
  run_rcodesign print-signature-info --config-file /dev/null "$file" >"$work/info" 2>/dev/null ||
    die "the $label signature cannot be read"
  for line in "flags: CodeSignatureFlags(RUNTIME)" "identifier: $named" \
    "apple_certificate_profile: developer-id-application" "apple_team_id: $macos_team_id" \
    "signature_verifies: true" "time_stamp_token:"; do
    sed 's/^[ -]*//' "$work/info" | grep -qxF -- "$line" || die "the $label signature lacks: $line"
  done
}

# Have Apple notarize ZIP: Apple notarizes a zip, not a bare executable, and
# records each executable's code directory hash, which Gatekeeper looks up for
# a quarantined download. Sets notary_submission_id from the log; acceptance
# is rcodesign's exit status, so a log without the id only warns.
macos_notarize() {
  local zip="$1" status=0
  run_rcodesign encode-app-store-connect-api-key --config-file /dev/null --output-path "$work/notary-key.json" \
    "$(<"$keys/notary-issuer-id")" "$(<"$keys/notary-key-id")" "$keys/notary-key.p8" >/dev/null 2>&1 ||
    die 'the notary API key does not encode'
  run_rcodesign notary-submit --config-file /dev/null --api-key-file "$work/notary-key.json" --wait \
    --max-wait-seconds "$macos_notary_wait_seconds" "$zip" 2>&1 | tee "$work/notary.log" || status=$?
  [ "$status" = 0 ] || die 'Apple did not accept the notarization'
  notary_submission_id="$(sed -n 's/.*created submission ID: \([0-9a-f-]\{36\}\).*/\1/p' "$work/notary.log" | head -1)"
  if [ -n "$notary_submission_id" ]; then
    printf '%s: notary submission %s accepted\n' "$signer" "$notary_submission_id"
  else
    printf '::warning::%s: notarization accepted, but its log names no submission id\n' "$signer"
  fi
}
