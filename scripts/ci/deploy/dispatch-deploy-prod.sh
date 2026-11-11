#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '[dispatch-deploy-prod] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: dispatch-deploy-prod.sh SOURCE_TAG\n' >&2
  exit 2
}
readonly SOURCE_TAG="$1"
[[ "$SOURCE_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  fail "source tag must be one exact stable SemVer tag"

curl_bin="${CURL_BIN:-curl}"
if [[ "$curl_bin" == */* ]]; then
  [[ -x "$curl_bin" ]] || fail "curl is required for deploy workflow dispatch"
elif ! command -v "$curl_bin" >/dev/null 2>&1; then
  fail "curl is required for deploy workflow dispatch"
fi

readonly server_url="${GITHUB_SERVER_URL:?set to the Forgejo base URL}"
readonly deploy_api="${server_url%/}/api/v1/repos/codewire/deploy/actions"
readonly dispatch_url="$deploy_api/workflows/promote-prod.yaml/dispatches"
# promote-prod usually finishes within four minutes of being dispatched. The
# integration token lasts an hour; the wait renews it well before that.
readonly wait_seconds="${DEPLOY_PROD_WAIT_SECONDS:-1800}"
readonly poll_seconds="${DEPLOY_PROD_POLL_SECONDS:-20}"
readonly renew_seconds=600
[[ "$wait_seconds" =~ ^[1-9][0-9]*$ ]] ||
  fail 'the deploy run wait must be a whole number of seconds'
[[ "$poll_seconds" =~ ^[0-9]+$ ]] ||
  fail 'the deploy run poll interval must be a whole number of seconds'
umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-dispatch-deploy-prod.XXXXXX")"
auth_header="$work/auth-header"
token_file="$work/token"
request_body="$work/request.json"
response_body="$work/response.json"
run_body="$work/run.json"
# shellcheck disable=SC2329 # Invoked by the EXIT trap.
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# authorize: a fresh short-lived integration token in the private header file.
authorize() {
  # The fetcher writes only a new path; a file a failed fetch left behind
  # would refuse every renewal.
  [[ ! -e "$token_file" ]] || shred -u "$token_file" || rm -f "$token_file"
  "$(dirname "$0")/../setup/fetch-forgejo-deploy-prod-token.sh" "$token_file" || return 1
  {
    printf 'Authorization: Bearer '
    tr -d '\n' <"$token_file"
    printf '\n'
  } >"$auth_header"
  shred -u "$token_file"
}
authorize || fail 'unable to obtain the production deploy integration token'
authorized_at=$SECONDS
printf '{"ref":"main","inputs":{"source_tag":"%s"}}\n' \
  "$SOURCE_TAG" | jq '. + {return_run_info:true}' >"$request_body"

# The exact line promote-prod.sh (codewire/deploy) prints when deploy main moved
# under its run; deploy's tests pin the same value (#4115). Production is
# prepared only on the main its verify-dev checked live, so such a run fails;
# a fresh run checks the new main and may succeed. Only that failure is retried,
# at most this many times; every other failure stays final.
readonly MAIN_MOVED_MARKER='codewire-promote-prod-outcome: deploy-main-moved'
readonly MAX_MAIN_MOVED_RETRIES=3

# dispatch: start one promote-prod run for this tag; sets run_id and run_number.
dispatch() {
  if ! status="$(
    "$curl_bin" --silent --show-error \
      --proto '=https' --tlsv1.2 \
      --connect-timeout 15 --max-time 60 \
      --output "$response_body" --write-out '%{http_code}' \
      --request POST "$dispatch_url" \
      --header "@$auth_header" \
      --header 'Accept: application/json' \
      --header 'Content-Type: application/json' \
      --data-binary "@$request_body"
  )"; then
    fail "unable to dispatch the deploy workflow"
  fi
  [[ "$status" == '201' ]] ||
    fail "Forgejo rejected the deploy workflow dispatch (HTTP $status)"
  run_id="$(jq -er '.id | numbers | select(. > 0)' "$response_body")" ||
    fail 'Forgejo dispatch response omitted the exact run ID'
  run_number="$(jq -er '.run_number | numbers | select(. > 0)' "$response_body")" ||
    fail 'Forgejo dispatch response omitted the repository run number'

  printf '[dispatch-deploy-prod] accepted signed source tag %s as deploy run %s / #%s\n' \
    "$SOURCE_TAG" "$run_id" "$run_number"
}

# renew: a fresh token, or the failure named and the renewal retried at the
# next poll.
renew() {
  if authorize; then
    authorized_at=$SECONDS
    return 0
  fi
  problem='the deploy token could not be renewed'
  printf '[dispatch-deploy-prod] %s; retrying\n' "$problem" >&2
  authorized_at=$((SECONDS - renew_seconds))
  return 1
}

# get URL OUTPUT: one authorized API read; prints the HTTP status.
get() {
  "$curl_bin" --silent --show-error \
    --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 60 \
    --output "$2" --write-out '%{http_code}' \
    "$1" \
    --header "@$auth_header" \
    --header 'Accept: application/json'
}

# Wait for that exact run's verdict. Production accepts a release only in
# promote-prod, which verifies the source, the bundle, Dev acceptance and the
# Production boundary, so this release run succeeds only when Production
# accepted the release; cli-release publishes a CLI only after that (#2892).
# A few minutes of a protected runner buy that guarantee. A failed lookup or
# token renewal is retried until the deadline; only promote-prod's own verdict
# ends the wait. A refused token is renewed in the same poll, so a wait that
# ends on a token that cannot be renewed names the renewal. If promote-prod finishes after the deadline, or is re-run
# after this run failed, rerun deploy-prod: promote-prod accepts an existing
# deploy tag for the same release, and this run then goes green.
# await: wait for run_id's verdict; sets state to success, failure, cancelled
# or skipped, or fails at the deadline.
await() {
  local run_url="$deploy_api/runs/$run_id"
  local deadline=$((SECONDS + wait_seconds))
  state='unknown'
  problem=''
  while ((SECONDS < deadline)); do
    sleep "$poll_seconds"
    if ((SECONDS - authorized_at >= renew_seconds)); then
      renew || continue
    fi
    if ! status="$(get "$run_url" "$run_body")" || [[ "$status" != '200' ]]; then
      problem="the deploy run lookup failed (HTTP ${status:-none})"
      printf '[dispatch-deploy-prod] deploy run %s lookup failed (HTTP %s); retrying\n' \
        "$run_id" "${status:-none}" >&2
      # A refused token is renewed now; the next poll presents the new one.
      [[ "${status:-}" != 401 ]] || renew || true
      continue
    fi
    problem=''
    jq -e --argjson id "$run_id" '.id == $id' "$run_body" >/dev/null 2>&1 ||
      fail "the deploy run lookup returned a run other than $run_id"
    state="$(jq -r '.status // "unknown"' "$run_body")"
    case "$state" in
      success|failure|cancelled|skipped) return 0 ;;
    esac
  done
  fail "deploy run $run_id has no verdict after ${wait_seconds}s (last status $state${problem:+; $problem})"
}

# main_moved: whether a failed job of run_id printed exactly the moved-main
# marker as one whole log line (after Forgejo's timestamp). Any lookup failure
# answers no, so an unknown failure is never retried.
main_moved() {
  local jobs_body="$work/jobs.json" log_body="$work/job.log" job_id
  [[ "$(get "$deploy_api/runs/$run_id/jobs" "$jobs_body" 2>/dev/null)" == 200 ]] || return 1
  while read -r job_id; do
    [[ "$job_id" =~ ^[1-9][0-9]*$ ]] || continue
    [[ "$(get "$deploy_api/jobs/$job_id/logs" "$log_body" 2>/dev/null)" == 200 ]] || continue
    awk -v marker="$MAIN_MOVED_MARKER" '
      { line = $0; sub(/\r$/, "", line)
        sub(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z /, "", line)
        if (line == marker) found = 1 }
      END { exit !found }' "$log_body" && return 0
  done < <(jq -r '(if type == "object" then .jobs else . end) | .[]?
    | select(.status == "failure") | .id' "$jobs_body" 2>/dev/null)
  return 1
}

retries=0
while :; do
  dispatch
  await
  case "$state" in
    success)
      printf '[dispatch-deploy-prod] deploy run %s succeeded: Production accepted %s\n' \
        "$run_id" "$SOURCE_TAG"
      exit 0
      ;;
    failure)
      # Retries left first, so an exhausted run reads no logs.
      if ((retries < MAX_MAIN_MOVED_RETRIES)) && main_moved; then
        retries=$((retries + 1))
        printf '[dispatch-deploy-prod] deploy run %s found deploy main moved under it; dispatching a fresh run (retry %s of %s)\n' \
          "$run_id" "$retries" "$MAX_MAIN_MOVED_RETRIES"
        continue
      fi
      ;;
  esac
  fail "deploy run $run_id ended $state: Production did not accept $SOURCE_TAG"
done
