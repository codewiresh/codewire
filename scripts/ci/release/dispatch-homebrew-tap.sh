#!/usr/bin/env bash
# Ask the Homebrew tap to move its formula to TAG, then wait for its answer
# (docs/dev/CLI-HOMEBREW-INSTALL.md, "How a release moves the tap"). The tap's
# own update-formula.yml verifies the signed release, checks the formula with
# Homebrew and commits it; this script only dispatches that run with the tap
# App's installation token, which can start and read the tap's runs and
# nothing else, and reports how the run ended. A run that ends any other way
# than success fails this script, saying the tap is behind.
set -euo pipefail

fail() {
  printf '::error::[dispatch-homebrew-tap] %s\n' "$*" >&2
  exit 1
}
[[ $# -eq 1 ]] || {
  printf 'usage: HOMEBREW_TAP_TOKEN_FILE=FILE dispatch-homebrew-tap.sh TAG\n' >&2
  exit 2
}
readonly tag="$1"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "$tag is not vMAJOR.MINOR.PATCH"
readonly token_file="${HOMEBREW_TAP_TOKEN_FILE:?HOMEBREW_TAP_TOKEN_FILE names the tap App token}"
[[ -f "$token_file" && ! -L "$token_file" && -s "$token_file" ]] ||
  fail 'the tap App token must be one nonempty regular file'
case "$(stat -c '%a' -- "$token_file")" in
  400|600) ;;
  *) fail 'the tap App token must have mode 0400 or 0600' ;;
esac
# The host is fixed: the token is only ever sent to GitHub's API.
readonly api="https://api.github.com/repos/codewiresh/homebrew-codewire/actions"
# The tap's run takes about ten minutes: Homebrew's checks on Linux and macOS.
readonly wait_seconds="${HOMEBREW_TAP_WAIT_SECONDS:-2400}"
readonly poll_seconds="${HOMEBREW_TAP_POLL_SECONDS:-20}"

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/homebrew-tap.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
behind() {
  fail "the Homebrew tap is behind: $1. The release is published; dispatch the tap's update-formula.yml for $tag to move it."
}

{
  printf 'header = "Authorization: Bearer '
  tr -d '\n' <"$token_file"
  printf '"\nheader = "Accept: application/vnd.github+json"\n'
  printf 'header = "X-GitHub-Api-Version: 2022-11-28"\n'
  printf 'silent\nshow-error\nfail\n'
} >"$work/github.curl"

# Without return_run_details GitHub accepts the dispatch with an empty answer
# that names no run to wait for.
jq -n --arg version "$tag" '{ref: "main", inputs: {version: $version}, return_run_details: true}' >"$work/dispatch.json"
curl --config "$work/github.curl" --connect-timeout 10 --max-time 30 \
  --request POST --header 'Content-Type: application/json' --data-binary @"$work/dispatch.json" \
  --output "$work/dispatched.json" "$api/workflows/update-formula.yml/dispatches" ||
  behind 'dispatching its update-formula.yml failed'
run_id="$(jq -er '.workflow_run_id | numbers | tostring' "$work/dispatched.json")" ||
  behind 'GitHub named no run for the dispatch'
run_url="$(jq -r '.html_url // empty' "$work/dispatched.json")"
printf '[dispatch-homebrew-tap] the tap is moving to %s in run %s %s\n' "$tag" "$run_id" "$run_url"

deadline=$((SECONDS + wait_seconds))
while :; do
  if curl --config "$work/github.curl" --connect-timeout 10 --max-time 30 \
      --output "$work/run.json" "$api/runs/$run_id"; then
    status="$(jq -r '.status // empty' "$work/run.json")"
    if [[ "$status" == completed ]]; then
      conclusion="$(jq -r '.conclusion // empty' "$work/run.json")"
      [[ "$conclusion" == success ]] || behind "its run $run_id for $tag ended ${conclusion:-without a conclusion} $run_url"
      printf '[dispatch-homebrew-tap] the tap moved its formula to %s in run %s\n' "$tag" "$run_id"
      exit 0
    fi
  fi
  ((SECONDS < deadline)) || behind "its run $run_id for $tag had not finished after ${wait_seconds}s $run_url"
  sleep "$poll_seconds"
done
