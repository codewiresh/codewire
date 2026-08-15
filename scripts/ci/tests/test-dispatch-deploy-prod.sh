#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly DISPATCH="$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh"
readonly SOURCE_TAG='v0.3.367'
readonly TEST_TOKEN='test-only-dispatch-token-1234567890'

fail() {
  printf '[test-dispatch-deploy-prod] ERROR: %s\n' "$*" >&2
  exit 1
}

install -d "$HOME/.cache"
work="$(mktemp -d "$HOME/.cache/codewire-prod-dispatch-test.XXXXXX")"
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
  "$DISPATCH" "$SOURCE_TAG" >"$output" 2>&1; then
  sed 's/test-only-dispatch-token-[A-Za-z0-9._~-]*/<redacted>/' "$output" >&2
  fail "valid dispatch was rejected"
fi
grep -Fq "accepted signed source tag $SOURCE_TAG" "$output" ||
  fail "successful dispatch did not identify the accepted source tag"
if grep -Fq "$TEST_TOKEN" "$output"; then
  fail "successful dispatch printed the credential"
fi
jq -e --arg source_tag "$SOURCE_TAG" \
  '. == {ref: "main", inputs: {source_tag: $source_tag}}' \
  "$capture_dir/request.json" >/dev/null ||
  fail "dispatch body contains anything except main and the source tag"
grep -Fxq "Authorization: token $TEST_TOKEN" "$capture_dir/auth-header" ||
  fail "dispatch did not use the private header file"
grep -Fxq 'https://forgejo.example.invalid/api/v1/repos/codewire/deploy/actions/workflows/promote-prod.yaml/dispatches' \
  "$capture_dir/args" || fail "dispatch endpoint is not the reviewed deploy workflow"
if grep -Fq "$TEST_TOKEN" "$capture_dir/args"; then
  fail "credential was exposed on the curl command line"
fi

failure_output="$work/failure.out"
if env CODEWIRE_DEPLOY_PROMOTION_TOKEN="$TEST_TOKEN" \
  CURL_BIN="$mock_curl" \
  MOCK_CAPTURE_DIR="$capture_dir" MOCK_HTTP_STATUS=403 \
  "$DISPATCH" "$SOURCE_TAG" >"$failure_output" 2>&1; then
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
for invalid_tag in \
  0.3.367 v0.3 v0.3.367-rc.1 v0.3.367+build v00.3.367 v0.03.367 latest; do
  if env CODEWIRE_DEPLOY_PROMOTION_TOKEN="$TEST_TOKEN" CURL_BIN="$work/curl-never" \
    "$DISPATCH" "$invalid_tag" >"$work/invalid-source.out" 2>&1; then
    fail "malformed source tag was accepted: $invalid_tag"
  fi
  [[ ! -e "$marker" ]] || fail "malformed source tag reached curl: $invalid_tag"
done

if env CODEWIRE_DEPLOY_PROMOTION_TOKEN='short token' CURL_BIN="$work/curl-never" \
  "$DISPATCH" "$SOURCE_TAG" >"$work/invalid-token.out" 2>&1; then
  fail "malformed token was accepted"
fi
[[ ! -e "$marker" ]] || fail "malformed token reached curl"

printf '[test-dispatch-deploy-prod] stable-tag-only workflow dispatch contract passed\n'
