#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly DISPATCH="$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh"
readonly SOURCE_TAG='v0.3.367'
readonly TEST_REQUEST_TOKEN='test-only-oidc-request-token'
readonly TEST_JWT='synthetic.header.signature'
readonly EXPECTED_AUDIENCE='u:36:743b0975-b91c-4323-be37-a55707687c78'

fail() {
  printf '[test-dispatch-deploy-prod] ERROR: %s\n' "$*" >&2
  exit 1
}

# mkdir, not install -d: install would reset the mode of an existing shared
# directory that checks running beside this one hold open.
mkdir -p "$HOME/.cache"
work="$(mktemp -d "$HOME/.cache/codewire-prod-dispatch-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/capture" "$work/runner"

cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
output=''
url=''
previous=''
for argument in "$@"; do
  case "$previous" in
    --output) output="$argument" ;;
    --data-binary) cp "${argument#@}" "$MOCK_CAPTURE_DIR/request.json" ;;
    --header)
      [[ "$argument" == @* ]] && cp "${argument#@}" "$MOCK_CAPTURE_DIR/auth-header"
      ;;
  esac
  previous="$argument"
  [[ "$argument" == https://* ]] && url="$argument"
done
case "$url" in
  https://git.example.invalid/api/actions/oidc*audience=*)
    [[ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}" ]] || exit 91
    printf '%s\n' "$url" >"$MOCK_CAPTURE_DIR/oidc-url"
    printf 'fetch\n' >>"$MOCK_CAPTURE_DIR/token-fetches"
    fetches="$(wc -l <"$MOCK_CAPTURE_DIR/token-fetches")"
    # MOCK_FAILED_FETCHES: these fetches (1-based) are refused;
    # MOCK_FAILED_FETCHES_FROM: this fetch and every later one is.
    [[ ",${MOCK_FAILED_FETCHES:-}," != *",$fetches,"* ]] || exit 94
    [[ -z "${MOCK_FAILED_FETCHES_FROM:-}" || "$fetches" -lt "$MOCK_FAILED_FETCHES_FROM" ]] || exit 94
    if [[ "$fetches" -eq 1 ]]; then jwt="${MOCK_JWT:?}"; else jwt="${MOCK_JWT%%.*}.renewed-$fetches.${MOCK_JWT##*.}"; fi
    printf '%s' "$jwt" >"$MOCK_CAPTURE_DIR/latest-jwt"
    jq -n --arg value "$jwt" '{value:$value}' >"$output"
    ;;
  https://git.example.invalid/api/v1/repos/codewire/deploy/actions/runs/704)
    [[ "$(cat "$MOCK_CAPTURE_DIR/auth-header")" == "Authorization: Bearer $(cat "$MOCK_CAPTURE_DIR/latest-jwt")" ]] || exit 93
    polls="$(($(cat "$MOCK_CAPTURE_DIR/polls" 2>/dev/null || echo 0) + 1))"
    printf '%s' "$polls" >"$MOCK_CAPTURE_DIR/polls"
    IFS=, read -r -a states <<<"${MOCK_RUN_STATES:?}"
    state="${states[$((polls - 1))]:-${states[-1]}}"
    if [[ "$state" == http-* ]]; then
      printf '%s' "${state#http-}"
      exit 0
    fi
    jq -n --arg state "$state" --argjson id "${MOCK_RUN_ID:-704}" '{id:$id,status:$state}' >"$output"
    printf 200
    ;;
  https://git.example.invalid/api/v1/repos/codewire/deploy/actions/workflows/promote-prod.yaml/dispatches)
    jq -n '{id:704,run_number:20,jobs:["prepare"]}' >"$output"
    printf '%s' "${MOCK_DISPATCH_HTTP_STATUS:-201}"
    ;;
  *) exit 92 ;;
esac
MOCK
chmod +x "$work/bin/curl"

export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export GITHUB_SERVER_URL='https://git.example.invalid'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN="$TEST_REQUEST_TOKEN"
export CURL_BIN="$work/bin/curl"
export MOCK_CAPTURE_DIR="$work/capture"
export MOCK_JWT="$TEST_JWT"
export RUNNER_TEMP="$work/runner"
export DEPLOY_PROD_POLL_SECONDS=0 DEPLOY_PROD_WAIT_SECONDS=30
# reset_wait: a fresh poll and token-fetch count for the next case.
reset_wait() {
  rm -f "$work/capture/polls" "$work/capture/token-fetches"
}

# The dispatch waits for its exact promote-prod run, fetching a new token for
# each poll, and succeeds only on that run's success.
reset_wait
export MOCK_RUN_STATES=waiting,running,running,success
output="$work/success.out"
"$DISPATCH" "$SOURCE_TAG" >"$output" 2>&1 || fail "valid dispatch was rejected: $(cat "$output")"
grep -Fq "accepted signed source tag $SOURCE_TAG as deploy run 704 / #20" "$output" ||
  fail 'successful dispatch did not identify the exact accepted downstream run'
grep -Fq "deploy run 704 succeeded: Production accepted $SOURCE_TAG" "$output" ||
  fail 'the dispatch did not wait for the deploy run to succeed'
[[ "$(cat "$work/capture/polls")" == 4 ]] || fail 'the dispatch did not poll until the verdict'
[[ "$(wc -l <"$work/capture/token-fetches")" -eq 1 ]] ||
  fail 'the dispatch renewed a token that was still fresh'

# A refused token is renewed before the next lookup, which presents the new
# one; a renewal that fails is retried, and its failure is reported.
reset_wait
MOCK_RUN_STATES=http-401,running,success MOCK_FAILED_FETCHES=2 \
  "$DISPATCH" "$SOURCE_TAG" >"$work/renew.out" 2>&1 ||
  fail "a refused token ended the wait: $(cat "$work/renew.out")"
grep -Fq 'the deploy token could not be renewed; retrying' "$work/renew.out" ||
  fail 'a failed token renewal was not reported'
[[ "$(wc -l <"$work/capture/token-fetches")" -eq 3 ]] ||
  fail 'a refused token was not renewed until a renewal succeeded'
# A token that is refused and can never be renewed is named however the
# deadline falls: the refusal's renewal runs in the same poll, so it is always
# the wait's last event.
reset_wait
if DEPLOY_PROD_WAIT_SECONDS=2 DEPLOY_PROD_POLL_SECONDS=1 MOCK_RUN_STATES=http-401 MOCK_FAILED_FETCHES_FROM=2 \
    "$DISPATCH" "$SOURCE_TAG" >"$work/renew-never.out" 2>&1; then
  fail 'a wait whose token could never be renewed was accepted'
fi
grep -Fq 'has no verdict after 2s (last status unknown; the deploy token could not be renewed)' \
  "$work/renew-never.out" || fail "a lasting renewal failure was not named: $(cat "$work/renew-never.out")"

# A failed lookup is retried; only the run's own verdict ends the wait.
reset_wait
MOCK_RUN_STATES=http-500,running,success "$DISPATCH" "$SOURCE_TAG" >"$work/retry.out" 2>&1 ||
  fail "a transient lookup failure ended the wait: $(cat "$work/retry.out")"
grep -Fq 'deploy run 704 lookup failed (HTTP 500); retrying' "$work/retry.out" ||
  fail 'a failed lookup was not reported'

# Every other verdict fails the release run, naming it.
for state in failure cancelled skipped; do
  reset_wait
  if MOCK_RUN_STATES="running,$state" "$DISPATCH" "$SOURCE_TAG" >"$work/$state.out" 2>&1; then
    fail "a deploy run that ended $state was accepted"
  fi
  grep -Fq "deploy run 704 ended $state: Production did not accept $SOURCE_TAG" "$work/$state.out" ||
    fail "a deploy run that ended $state was not reported"
done

# No verdict within the wait fails too.
reset_wait
if DEPLOY_PROD_WAIT_SECONDS=1 DEPLOY_PROD_POLL_SECONDS=1 MOCK_RUN_STATES=running \
    "$DISPATCH" "$SOURCE_TAG" >"$work/timeout.out" 2>&1; then
  fail 'a deploy run without a verdict was accepted'
fi
grep -Fq 'deploy run 704 has no verdict after 1s (last status running)' "$work/timeout.out" ||
  fail 'a deploy run without a verdict was not reported'

# A lookup that answers for another run is refused.
reset_wait
if MOCK_RUN_STATES=success MOCK_RUN_ID=705 "$DISPATCH" "$SOURCE_TAG" >"$work/other-run.out" 2>&1; then
  fail 'a lookup answering for another run was accepted'
fi
grep -Fq 'the deploy run lookup returned a run other than 704' "$work/other-run.out" ||
  fail 'a lookup answering for another run was not reported'
if grep -Fq "$TEST_REQUEST_TOKEN" "$output"; then
  fail 'successful dispatch printed the OIDC request token'
fi
jq -e --arg source_tag "$SOURCE_TAG" \
  '. == {ref: "main", inputs: {source_tag: $source_tag}, return_run_info: true}' \
  "$work/capture/request.json" >/dev/null ||
  fail 'dispatch body omits exact run-info return or carries extra inputs'
grep -Fxq "Authorization: Bearer $TEST_JWT" "$work/capture/auth-header" ||
  fail 'dispatch did not use the short-lived Bearer JWT'
grep -Fxq "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${EXPECTED_AUDIENCE}" \
  "$work/capture/oidc-url" ||
  fail 'OIDC request used the wrong production integration audience'
failure_output="$work/failure.out"
export MOCK_DISPATCH_HTTP_STATUS=403
if "$DISPATCH" "$SOURCE_TAG" >"$failure_output" 2>&1; then
  fail 'HTTP rejection was accepted'
fi
grep -Fq 'HTTP 403' "$failure_output" ||
  fail 'HTTP rejection did not report its non-secret status'
if grep -Fq "$TEST_JWT" "$failure_output"; then
  fail 'HTTP rejection printed the JWT'
fi
unset MOCK_DISPATCH_HTTP_STATUS

marker="$work/invoked"
cat >"$work/curl-never" <<MOCK
#!/usr/bin/env bash
touch '$marker'
exit 99
MOCK
chmod +x "$work/curl-never"
for invalid_tag in \
  0.3.367 v0.3 v0.3.367-rc.1 v0.3.367+build v00.3.367 v0.03.367 latest; do
  if CURL_BIN="$work/curl-never" "$DISPATCH" "$invalid_tag" \
      >"$work/invalid-source.out" 2>&1; then
    fail "malformed source tag was accepted: $invalid_tag"
  fi
  [[ ! -e "$marker" ]] || fail "malformed source tag reached curl: $invalid_tag"
done

for bad in 0 1.5 -1 30s; do
  if DEPLOY_PROD_WAIT_SECONDS="$bad" CURL_BIN="$work/curl-never" "$DISPATCH" "$SOURCE_TAG" \
      >"$work/bad-wait.out" 2>&1; then
    fail "wait interval '$bad' was accepted"
  fi
  grep -Fq 'the deploy run wait must be a whole number of seconds' "$work/bad-wait.out" ||
    fail "wait interval '$bad' was not refused as such"
done
for bad in 1.5 -1 20s; do
  if DEPLOY_PROD_POLL_SECONDS="$bad" CURL_BIN="$work/curl-never" "$DISPATCH" "$SOURCE_TAG" \
      >"$work/bad-poll.out" 2>&1; then
    fail "poll interval '$bad' was accepted"
  fi
  grep -Fq 'the deploy run poll interval must be a whole number of seconds' "$work/bad-poll.out" ||
    fail "poll interval '$bad' was not refused as such"
done
reset_wait
[[ ! -e "$marker" ]] || fail 'a refused wait or poll interval reached curl'

if env -u GITHUB_SERVER_URL CURL_BIN="$work/curl-never" "$DISPATCH" "$SOURCE_TAG" \
    >"$work/no-server.out" 2>&1; then
  fail 'dispatch without GITHUB_SERVER_URL was accepted'
fi
grep -Fq 'GITHUB_SERVER_URL' "$work/no-server.out" ||
  fail 'missing GITHUB_SERVER_URL was not named'
[[ ! -e "$marker" ]] || fail 'dispatch without GITHUB_SERVER_URL reached curl'

printf '[test-dispatch-deploy-prod] OIDC stable-tag workflow dispatch contract passed\n'
