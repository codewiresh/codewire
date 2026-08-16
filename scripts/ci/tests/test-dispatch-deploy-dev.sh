#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly DISPATCH="$ROOT/scripts/ci/deploy/dispatch-deploy-dev.sh"
readonly SOURCE_SHA='1111111111111111111111111111111111111111'
readonly TEST_REQUEST_TOKEN='test-only-oidc-request-token'
readonly TEST_JWT='synthetic.header.signature'

fail() {
  printf '[test-dispatch-deploy-dev] ERROR: %s\n' "$*" >&2
  exit 1
}

install -d "$HOME/.cache"
work="$(mktemp -d "$HOME/.cache/codewire-dispatch-test.XXXXXX")"
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
  https://forgejo.example.invalid/api/actions/oidc*audience=*)
    jq -n --arg value "${MOCK_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://forgejo.example.invalid/api/v1/repos/codewire/deploy/actions/workflows/promote-dev.yaml/dispatches)
    jq -n '{id:703,run_number:19,jobs:["promote","reconcile","smoke"]}' >"$output"
    printf '%s' "${MOCK_DISPATCH_HTTP_STATUS:-201}"
    ;;
  https://forgejo.example.invalid/api/v1/repos/codewire/deploy/actions/runs/703)
    count_file="$MOCK_CAPTURE_DIR/poll-count"
    count=0
    [[ ! -f "$count_file" ]] || count="$(<"$count_file")"
    count=$((count + 1))
    printf '%s\n' "$count" >"$count_file"
    run_status="${MOCK_RUN_STATUS:-success}"
    if [[ "$run_status" == sequence && "$count" -eq 1 ]]; then
      run_status=running
    elif [[ "$run_status" == sequence ]]; then
      run_status=success
    fi
    jq -n --arg status "$run_status" '{
      id:703,
      repository:{full_name:"codewire/deploy"},
      workflow_id:"promote-dev.yaml",
      prettyref:"main",
      commit_sha:"2222222222222222222222222222222222222222",
      event:"",
      trigger_event:"workflow_dispatch",
      trigger_user:{login:"noel"},
      html_url:"https://forgejo.example.invalid/codewire/deploy/actions/runs/19",
      status:$status
    }' >"$output"
    printf '200'
    ;;
  *) exit 92 ;;
esac
MOCK
chmod +x "$work/bin/curl"

export ACTIONS_ID_TOKEN_REQUEST_URL='https://forgejo.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN="$TEST_REQUEST_TOKEN"
export CURL_BIN="$work/bin/curl"
export MOCK_CAPTURE_DIR="$work/capture"
export MOCK_JWT="$TEST_JWT"
export RUNNER_TEMP="$work/runner"
export DEPLOY_RUN_POLL_SECONDS=0
export DEPLOY_RUN_TIMEOUT_SECONDS=10
export MOCK_RUN_STATUS=sequence

output="$work/success.out"
"$DISPATCH" "$SOURCE_SHA" >"$output" 2>&1 || fail 'valid dispatch was rejected'
grep -Fq "accepted canonical source $SOURCE_SHA" "$output" ||
  fail 'successful dispatch did not identify the accepted source'
grep -Fq 'exact deploy run 703 succeeded' "$output" ||
  fail 'successful dispatch did not wait for the exact downstream run'
if grep -Fq "$TEST_REQUEST_TOKEN" "$output"; then
  fail 'successful dispatch printed the OIDC request token'
fi
jq -e --arg source "$SOURCE_SHA" \
  '. == {ref: "main", inputs: {source_sha: $source}, return_run_info: true}' \
  "$work/capture/request.json" >/dev/null ||
  fail 'dispatch body omits exact run-info return or carries extra inputs'
grep -Fxq "Authorization: Bearer $TEST_JWT" "$work/capture/auth-header" ||
  fail 'dispatch did not use the short-lived Bearer JWT'
[[ "$(<"$work/capture/poll-count")" == 2 ]] ||
  fail 'dispatch did not observe the running-to-success transition'

failure_output="$work/failure.out"
export MOCK_DISPATCH_HTTP_STATUS=403
if "$DISPATCH" "$SOURCE_SHA" >"$failure_output" 2>&1; then
  fail 'HTTP rejection was accepted'
fi
grep -Fq 'HTTP 403' "$failure_output" ||
  fail 'HTTP rejection did not report its non-secret status'
if grep -Fq "$TEST_JWT" "$failure_output"; then
  fail 'HTTP rejection printed the JWT'
fi
unset MOCK_DISPATCH_HTTP_STATUS

rm -f "$work/capture/poll-count"
export MOCK_RUN_STATUS=failure
if "$DISPATCH" "$SOURCE_SHA" >"$work/downstream-failure.out" 2>&1; then
  fail 'failed downstream deploy run was accepted'
fi
grep -Fq 'exact deploy run 703 finished with status failure' \
  "$work/downstream-failure.out" ||
  fail 'downstream failure did not identify the exact failed run'
unset MOCK_RUN_STATUS

marker="$work/invoked"
cat >"$work/curl-never" <<MOCK
#!/usr/bin/env bash
touch '$marker'
exit 99
MOCK
chmod +x "$work/curl-never"
if CURL_BIN="$work/curl-never" "$DISPATCH" uppercase-sha \
    >"$work/invalid-source.out" 2>&1; then
  fail 'malformed source SHA was accepted'
fi
[[ ! -e "$marker" ]] || fail 'malformed source reached curl'

printf '[test-dispatch-deploy-dev] OIDC SHA-only workflow dispatch contract passed\n'
