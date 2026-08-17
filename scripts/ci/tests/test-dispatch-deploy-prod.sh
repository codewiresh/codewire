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

install -d "$HOME/.cache"
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
  https://forgejo.example.invalid/api/actions/oidc*audience=*)
    [[ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}" ]] || exit 91
    printf '%s\n' "$url" >"$MOCK_CAPTURE_DIR/oidc-url"
    jq -n --arg value "${MOCK_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://forgejo.example.invalid/api/v1/repos/codewire/deploy/actions/workflows/promote-prod.yaml/dispatches)
    jq -n '{id:704,run_number:20,jobs:["prepare"]}' >"$output"
    printf '%s' "${MOCK_DISPATCH_HTTP_STATUS:-201}"
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
output="$work/success.out"
"$DISPATCH" "$SOURCE_TAG" >"$output" 2>&1 || fail 'valid dispatch was rejected'
grep -Fq "accepted signed source tag $SOURCE_TAG as deploy run 704 / #20" "$output" ||
  fail 'successful dispatch did not identify the exact accepted downstream run'
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

printf '[test-dispatch-deploy-prod] OIDC stable-tag workflow dispatch contract passed\n'
