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
# A failed upload, or a connection lost while Apple processes a submission, is
# retried this many times this far apart. rcodesign itself retries neither.
readonly macos_notary_attempts=4
readonly macos_notary_retry_seconds=30

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
# a quarantined download. Sets notary_submission_id from the log.
#
# Apple's verdict decides the run; a lost connection does not. rcodesign 0.29.0
# polls without retrying a transport error, so one dropped response used to read
# as a rejection. A verdict other than Accepted fails at once. An upload that
# created no submission is retried. A submission whose answer was lost is waited
# on again, by its id, within the same overall limit, and `notary-wait` reports
# the verdict only as its last `poll state` line.
macos_notarize() {
  local zip="$1" attempt status started reason verdict remaining
  run_rcodesign encode-app-store-connect-api-key --config-file /dev/null --output-path "$work/notary-key.json" \
    "$(<"$keys/notary-issuer-id")" "$(<"$keys/notary-key-id")" "$keys/notary-key.p8" >/dev/null 2>&1 ||
    die 'the notary API key does not encode'
  started=$SECONDS
  notary_submission_id=''
  for ((attempt = 1; attempt <= macos_notary_attempts; attempt++)); do
    status=0
    run_rcodesign notary-submit --config-file /dev/null --api-key-file "$work/notary-key.json" --wait \
      --max-wait-seconds "$macos_notary_wait_seconds" "$zip" 2>&1 | tee "$work/notary.log" || status=$?
    notary_submission_id="$(macos_notary_submission_id "$work/notary.log")"
    if [ "$status" = 0 ]; then
      macos_notary_accepted
      return
    fi
    macos_notary_refuse_verdict "$work/notary.log"
    grep -q 'reached time limit waiting for notarization' "$work/notary.log" &&
      die "Apple did not finish notarization submission ${notary_submission_id:-(no id)} within ${macos_notary_wait_seconds}s"
    [ -z "$notary_submission_id" ] || break
    reason="$(macos_notary_reason "$work/notary.log")"
    [ "$attempt" -lt "$macos_notary_attempts" ] ||
      die "the notary upload failed $macos_notary_attempts times and created no submission: $reason"
    printf '::warning::%s: the notary upload failed and created no submission (attempt %s of %s): %s\n' \
      "$signer" "$attempt" "$macos_notary_attempts" "$reason"
    sleep "$macos_notary_retry_seconds"
  done

  # The submission exists; only its answer was lost.
  for ((attempt = 1; attempt <= macos_notary_attempts; attempt++)); do
    reason="$(macos_notary_reason "$work/notary.log")"
    printf '::warning::%s: lost contact with Apple while it processed submission %s (attempt %s of %s): %s\n' \
      "$signer" "$notary_submission_id" "$attempt" "$macos_notary_attempts" "$reason"
    sleep "$macos_notary_retry_seconds"
    remaining=$((macos_notary_wait_seconds - (SECONDS - started)))
    [ "$remaining" -gt 0 ] || break
    status=0
    run_rcodesign notary-wait --config-file /dev/null --api-key-file "$work/notary-key.json" \
      --max-wait-seconds "$remaining" "$notary_submission_id" 2>&1 | tee "$work/notary.log" || status=$?
    [ "$status" = 0 ] || continue
    verdict="$(sed -n 's/.*poll state after [0-9]*s: \([A-Za-z]*\).*/\1/p' "$work/notary.log" | tail -1)"
    case "$verdict" in
      Accepted) macos_notary_accepted; return ;;
      '') die "notary-wait for submission $notary_submission_id ended without a verdict" ;;
      *) die "Apple did not accept the notarization: submission $notary_submission_id is $verdict" ;;
    esac
  done
  die "lost contact with Apple's notary service: submission $notary_submission_id has no verdict after $((SECONDS - started))s; Apple may still accept it, so check that submission before rerunning"
}

macos_notary_submission_id() {
  sed -n 's/.*created submission ID: \([0-9a-f-]\{36\}\).*/\1/p' "$1" | head -1
}

# The last error line of a notary log, for a warning or a final failure.
macos_notary_reason() {
  grep -iE 'error|failed|HTTP' "$1" | tail -1 | cut -c1-300 || true
}

# rcodesign's verdict errors (`notary-submit --wait`): a rejection, an invalid
# package or an incomplete status is Apple's answer, never retried.
macos_notary_refuse_verdict() {
  local verdict
  verdict="$(grep -E 'notarization rejected:|notarization package is invalid|notarization is incomplete' "$1" | tail -1 || true)"
  [ -z "$verdict" ] || die "Apple did not accept the notarization${notary_submission_id:+ (submission $notary_submission_id)}: ${verdict##*: }"
}

macos_notary_accepted() {
  if [ -n "$notary_submission_id" ]; then
    printf '%s: notary submission %s accepted\n' "$signer" "$notary_submission_id"
  else
    printf '::warning::%s: notarization accepted, but its log names no submission id\n' "$signer"
  fi
}
