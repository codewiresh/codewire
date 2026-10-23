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

# Wait for that exact run's verdict. Production accepts a release only in
# promote-prod, which verifies the source, the bundle, Dev acceptance and the
# Production boundary, so this release run succeeds only when Production
# accepted the release; cli-release publishes a CLI only after that (#2892).
# A few minutes of a protected runner buy that guarantee. A failed lookup or
# token renewal is retried until the deadline; only promote-prod's own verdict
# ends the wait. If promote-prod finishes after the deadline, or is re-run
# after this run failed, rerun deploy-prod: promote-prod accepts an existing
# deploy tag for the same release, and this run then goes green.
readonly run_url="$deploy_api/runs/$run_id"
deadline=$((SECONDS + wait_seconds))
state='unknown'
problem=''
while ((SECONDS < deadline)); do
  sleep "$poll_seconds"
  if ((SECONDS - authorized_at >= renew_seconds)); then
    if ! authorize; then
      problem='the deploy token could not be renewed'
      printf '[dispatch-deploy-prod] %s; retrying\n' "$problem" >&2
      continue
    fi
    authorized_at=$SECONDS
  fi
  if ! status="$(
    "$curl_bin" --silent --show-error \
      --proto '=https' --tlsv1.2 \
      --connect-timeout 15 --max-time 60 \
      --output "$run_body" --write-out '%{http_code}' \
      "$run_url" \
      --header "@$auth_header" \
      --header 'Accept: application/json'
  )" || [[ "$status" != '200' ]]; then
    problem="the deploy run lookup failed (HTTP ${status:-none})"
    printf '[dispatch-deploy-prod] deploy run %s lookup failed (HTTP %s); retrying\n' \
      "$run_id" "${status:-none}" >&2
    # A refused token is renewed at the next poll.
    [[ "${status:-}" != 401 ]] || authorized_at=$((SECONDS - renew_seconds))
    continue
  fi
  problem=''
  jq -e --argjson id "$run_id" '.id == $id' "$run_body" >/dev/null 2>&1 ||
    fail "the deploy run lookup returned a run other than $run_id"
  state="$(jq -r '.status // "unknown"' "$run_body")"
  case "$state" in
    success)
      printf '[dispatch-deploy-prod] deploy run %s succeeded: Production accepted %s\n' \
        "$run_id" "$SOURCE_TAG"
      exit 0
      ;;
    failure|cancelled|skipped)
      fail "deploy run $run_id ended $state: Production did not accept $SOURCE_TAG"
      ;;
  esac
done
fail "deploy run $run_id has no verdict after ${wait_seconds}s (last status $state${problem:+; $problem})"
