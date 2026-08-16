#!/usr/bin/env bash
# Wait for one exact Forgejo workflow-dispatch run using renewable, short-lived
# Authorized Integration JWTs. This is intentionally a light runner wait; it
# must never hold Docker/Kind capacity while the deploy workflow executes.
set -euo pipefail

fail() {
  printf '[wait-for-deploy-run] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || {
  printf 'usage: wait-for-deploy-run.sh RUN_ID WORKFLOW TOKEN_FETCHER\n' >&2
  exit 2
}
readonly run_id="$1"
readonly workflow="$2"
readonly token_fetcher="$3"
[[ "$run_id" =~ ^[1-9][0-9]*$ ]] || fail 'run ID must be a positive integer'
case "$workflow" in
  promote-dev.yaml | promote-prod.yaml) ;;
  *) fail 'workflow is not an allowlisted deploy entrypoint' ;;
esac
[[ -x "$token_fetcher" ]] || fail 'token fetcher is unavailable'

readonly poll_seconds="${DEPLOY_RUN_POLL_SECONDS:-15}"
readonly timeout_seconds="${DEPLOY_RUN_TIMEOUT_SECONDS:-7200}"
[[ "$poll_seconds" =~ ^[0-9]+$ && "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] ||
  fail 'poll and timeout values must be nonnegative integers'

curl_bin="${CURL_BIN:-curl}"
if [[ "$curl_bin" == */* ]]; then
  [[ -x "$curl_bin" ]] || fail 'curl is required for deploy run observation'
elif ! command -v "$curl_bin" >/dev/null 2>&1; then
  fail 'curl is required for deploy run observation'
fi

readonly run_url="https://forgejo.example.invalid/api/v1/repos/codewire/deploy/actions/runs/$run_id"
umask 077
work="$(mktemp -d)"
auth_header="$work/auth-header"
token_file="$work/token"
response_body="$work/run.json"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

token_minted_at=0
refresh_auth() {
  rm -f "$token_file" "$auth_header"
  "$token_fetcher" "$token_file" >/dev/null ||
    fail 'unable to renew the deploy integration token'
  {
    printf 'Authorization: Bearer '
    tr -d '\n' <"$token_file"
    printf '\n'
  } >"$auth_header"
  chmod 0600 "$auth_header"
  shred -u "$token_file" 2>/dev/null || rm -f "$token_file"
  token_minted_at="$(date +%s)"
}

started_at="$(date +%s)"
readonly started_at
while :; do
  now="$(date +%s)"
  (( now - started_at <= timeout_seconds )) ||
    fail "deploy run $run_id did not become terminal within ${timeout_seconds}s"
  if (( now - token_minted_at >= 3000 )); then
    refresh_auth
  fi
  if ! http_status="$(
    "$curl_bin" --silent --show-error \
      --proto '=https' --tlsv1.2 \
      --connect-timeout 15 --max-time 60 \
      --output "$response_body" --write-out '%{http_code}' \
      --request GET "$run_url" \
      --header "@$auth_header" \
      --header 'Accept: application/json'
  )"; then
    fail "unable to inspect deploy run $run_id"
  fi
  [[ "$http_status" == 200 ]] ||
    fail "Forgejo rejected deploy run observation (HTTP $http_status)"

  jq -e --argjson id "$run_id" --arg workflow "$workflow" '
    .id == $id and
    .repository.full_name == "codewire/deploy" and
    .workflow_id == $workflow and
    .prettyref == "main" and
    (.commit_sha | test("^[0-9a-f]{40}$")) and
    .trigger_event == "workflow_dispatch" and
    .trigger_user.login == "noel" and
    (.html_url | startswith("https://forgejo.example.invalid/codewire/deploy/actions/runs/"))
  ' "$response_body" >/dev/null ||
    fail "deploy run $run_id identity does not match the dispatched contract"

  status="$(jq -er '.status | strings' "$response_body")" ||
    fail "deploy run $run_id omitted its status"
  case "$status" in
    success)
      printf '[wait-for-deploy-run] exact deploy run %s succeeded: head=%s url=%s\n' \
        "$run_id" \
        "$(jq -r '.commit_sha' "$response_body")" \
        "$(jq -r '.html_url' "$response_body")"
      exit 0
      ;;
    waiting | running | blocked)
      sleep "$poll_seconds"
      ;;
    failure | cancelled | skipped)
      fail "exact deploy run $run_id finished with status $status ($(jq -r '.html_url' "$response_body"))"
      ;;
    *) fail "deploy run $run_id returned unknown status $status" ;;
  esac
done
