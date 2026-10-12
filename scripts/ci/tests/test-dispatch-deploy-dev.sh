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

# mkdir, not install -d: install would reset the mode of an existing shared
# directory that checks running beside this one hold open.
mkdir -p "$HOME/.cache"
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
  https://git.example.invalid/api/actions/oidc*audience=*)
    jq -n --arg value "${MOCK_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://git.example.invalid/api/v1/repos/codewire/deploy/actions/workflows/promote-dev.yaml/dispatches)
    jq -n '{id:703,run_number:19,jobs:["promote","reconcile","smoke"]}' >"$output"
    printf '%s' "${MOCK_DISPATCH_HTTP_STATUS:-201}"
    ;;
  *) exit 92 ;;
esac
MOCK
chmod +x "$work/bin/curl"

export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN="$TEST_REQUEST_TOKEN"
export CURL_BIN="$work/bin/curl"
export MOCK_CAPTURE_DIR="$work/capture"
export MOCK_JWT="$TEST_JWT"
export RUNNER_TEMP="$work/runner"
output="$work/success.out"
"$DISPATCH" "$SOURCE_SHA" >"$output" 2>&1 || fail 'valid dispatch was rejected'
grep -Fq "accepted canonical source $SOURCE_SHA as deploy run 703 / #19" "$output" ||
  fail 'successful dispatch did not identify the exact accepted downstream run'
if grep -Fq "$TEST_REQUEST_TOKEN" "$output"; then
  fail 'successful dispatch printed the OIDC request token'
fi
jq -e --arg source "$SOURCE_SHA" \
  '. == {ref: "main", inputs: {source_sha: $source}, return_run_info: true}' \
  "$work/capture/request.json" >/dev/null ||
  fail 'dispatch body omits exact run-info return or carries extra inputs'
grep -Fxq "Authorization: Bearer $TEST_JWT" "$work/capture/auth-header" ||
  fail 'dispatch did not use the short-lived Bearer JWT'
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
