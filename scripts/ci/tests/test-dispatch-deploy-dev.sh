#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly DISPATCH="$ROOT/scripts/ci/deploy/dispatch-deploy-dev.sh"
readonly SOURCE_SHA='1111111111111111111111111111111111111111'
readonly TEST_TOKEN='test-only-dispatch-token-1234567890'

fail() {
  printf '[test-dispatch-deploy-dev] ERROR: %s\n' "$*" >&2
  exit 1
}

install -d "$HOME/.cache"
work="$(mktemp -d "$HOME/.cache/codewire-dispatch-test.XXXXXX")"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/bin"
mock_curl="$work/bin/curl"
capture_dir="$work/capture"
mkdir -p "$capture_dir"
cat >"$mock_curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${CODEWIRE_DEPLOY_PROMOTION_TOKEN+x}" ]] || exit 91
printf '%s\n' "$@" >"$MOCK_CAPTURE_DIR/args"
previous=''
for argument in "$@"; do
  case "$previous" in
    --data-binary)
      cp "${argument#@}" "$MOCK_CAPTURE_DIR/request.json"
      ;;
    --header)
      if [[ "$argument" == @* ]]; then
        cp "${argument#@}" "$MOCK_CAPTURE_DIR/auth-header"
      fi
      ;;
  esac
  previous="$argument"
done
printf '%s' "${MOCK_HTTP_STATUS:-204}"
MOCK
chmod +x "$mock_curl"

output="$work/success.out"
if ! env CODEWIRE_DEPLOY_PROMOTION_TOKEN="$TEST_TOKEN" \
  CURL_BIN="$mock_curl" MOCK_CAPTURE_DIR="$capture_dir" \
  "$DISPATCH" "$SOURCE_SHA" >"$output" 2>&1; then
  sed 's/test-only-dispatch-token-[A-Za-z0-9._~-]*/<redacted>/' "$output" >&2
  fail "valid dispatch was rejected"
fi
grep -Fq "accepted canonical source $SOURCE_SHA" "$output" ||
  fail "successful dispatch did not identify the accepted source"
if grep -Fq "$TEST_TOKEN" "$output"; then
  fail "successful dispatch printed the credential"
fi
jq -e --arg source "$SOURCE_SHA" \
  '. == {ref: "main", inputs: {source_sha: $source}}' \
  "$capture_dir/request.json" >/dev/null ||
  fail "dispatch body contains anything except main and the source SHA"
grep -Fxq "Authorization: token $TEST_TOKEN" "$capture_dir/auth-header" ||
  fail "dispatch did not use the private header file"
grep -Fxq 'https://git.example.invalid/api/v1/repos/codewire/deploy/actions/workflows/promote-dev.yaml/dispatches' \
  "$capture_dir/args" || fail "dispatch endpoint is not the reviewed deploy workflow"
if grep -Fq "$TEST_TOKEN" "$capture_dir/args"; then
  fail "credential was exposed on the curl command line"
fi

failure_output="$work/failure.out"
if env CODEWIRE_DEPLOY_PROMOTION_TOKEN="$TEST_TOKEN" \
  CURL_BIN="$mock_curl" \
  MOCK_CAPTURE_DIR="$capture_dir" MOCK_HTTP_STATUS=403 \
  "$DISPATCH" "$SOURCE_SHA" >"$failure_output" 2>&1; then
  fail "HTTP rejection was accepted"
fi
grep -Fq 'HTTP 403' "$failure_output" ||
  fail "HTTP rejection did not report its non-secret status"
if grep -Fq "$TEST_TOKEN" "$failure_output"; then
  fail "HTTP rejection printed the credential"
fi

marker="$work/invoked"
cat >"$work/curl-never" <<MOCK
#!/usr/bin/env bash
touch '$marker'
exit 99
MOCK
chmod +x "$work/curl-never"
if env CODEWIRE_DEPLOY_PROMOTION_TOKEN="$TEST_TOKEN" CURL_BIN="$work/curl-never" \
  "$DISPATCH" uppercase-sha >"$work/invalid-source.out" 2>&1; then
  fail "malformed source SHA was accepted"
fi
[[ ! -e "$marker" ]] || fail "malformed source reached curl"

if env CODEWIRE_DEPLOY_PROMOTION_TOKEN='short token' CURL_BIN="$work/curl-never" \
  "$DISPATCH" "$SOURCE_SHA" >"$work/invalid-token.out" 2>&1; then
  fail "malformed token was accepted"
fi
[[ ! -e "$marker" ]] || fail "malformed token reached curl"

printf '[test-dispatch-deploy-dev] SHA-only workflow dispatch contract passed\n'
