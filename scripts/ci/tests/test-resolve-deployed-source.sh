#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly RESOLVER="$ROOT/scripts/ci/deploy/resolve-deployed-source.sh"
readonly SOURCE_SHA='1111111111111111111111111111111111111111'
readonly HEAD_SHA='2222222222222222222222222222222222222222'
readonly TEST_TOKEN='test-only-resolver-token-1234567890'

fail() {
  printf '[test-resolve-deployed-source] ERROR: %s\n' "$*" >&2
  exit 1
}

install -d "$HOME/.cache"
work="$(mktemp -d "$HOME/.cache/codewire-resolver-test.XXXXXX")"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$work/bin" "$work/capture"

python3 - "$work/valid.json" "$SOURCE_SHA" <<'PY'
import base64
import json
from pathlib import Path
import sys

release = {
    "source": {
        "repository": "codewire/codewire",
        "sha": sys.argv[2],
    },
    "images": {"gateway": "sha256:" + "1" * 64},
}
encoded = base64.b64encode(json.dumps(release).encode()).decode()
Path(sys.argv[1]).write_text(
    json.dumps({"encoding": "base64", "content": encoded}),
    encoding="utf-8",
)
PY

mock_curl="$work/bin/curl"
cat >"$mock_curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${CODEWIRE_DEPLOY_PROMOTION_TOKEN+x}" ]] || exit 91
printf '%s\n' "$@" >"$MOCK_CAPTURE_DIR/args"
output=''
previous=''
for argument in "$@"; do
  case "$previous" in
    --output) output="$argument" ;;
    --header)
      if [[ "$argument" == @* ]]; then
        cp "${argument#@}" "$MOCK_CAPTURE_DIR/auth-header"
      fi
      ;;
  esac
  previous="$argument"
done
cp "$MOCK_RESPONSE" "$output"
printf '%s' "${MOCK_HTTP_STATUS:-200}"
MOCK
chmod +x "$mock_curl"

candidate="$work/candidate.json"
success_output="$work/success.out"
if ! env CODEWIRE_DEPLOY_PROMOTION_TOKEN="$TEST_TOKEN" \
  CURL_BIN="$mock_curl" MOCK_CAPTURE_DIR="$work/capture" \
  MOCK_RESPONSE="$work/valid.json" \
  "$RESOLVER" "$candidate" "$HEAD_SHA" >"$success_output" 2>&1; then
  fail "valid release manifest was rejected"
fi
jq -e --arg source "$SOURCE_SHA" --arg head "$HEAD_SHA" '
  .schema == "codewire.ci-deployed-source-candidate/v1" and
  .retrieval == {valid: true, reasons: []} and
  .target == {repository: "codewire/codewire", head_sha: $head} and
  .release == {
    repository: "codewire/deploy",
    path: "environments/dev/release.json",
    ref: "main"
  } and
  .source == {repository: "codewire/codewire", sha: $source}
' "$candidate" >/dev/null || fail "valid untrusted candidate has the wrong contract"
[[ "$(stat -c '%a' "$candidate")" == 600 ]] || fail "candidate permissions are not private"
grep -Fq "resolved Dev source $SOURCE_SHA for head $HEAD_SHA" "$success_output" ||
  fail "successful resolution did not identify the non-sensitive source and head"
if grep -Fq "$TEST_TOKEN" "$success_output" "$work/capture/args" "$candidate"; then
  fail "resolver exposed its credential"
fi
grep -Fxq "Authorization: token $TEST_TOKEN" "$work/capture/auth-header" ||
  fail "resolver did not use a private authorization-header file"
grep -Fxq 'https://git.example.invalid/api/v1/repos/codewire/deploy/contents/environments/dev/release.json?ref=main' \
  "$work/capture/args" || fail "resolver used an unexpected private API path"

for case_name in forbidden malformed oversized; do
  case "$case_name" in
    forbidden)
      response="$work/valid.json"
      status=403
      expected=api_http_403
      ;;
    malformed)
      printf '{"encoding":"base64","content":"bm90LWpzb24="}\n' >"$work/malformed.json"
      response="$work/malformed.json"
      status=200
      expected=manifest_invalid
      ;;
    oversized)
      dd if=/dev/zero of="$work/oversized.json" bs=1048577 count=1 status=none
      response="$work/oversized.json"
      status=200
      expected=manifest_oversized
      ;;
  esac
  case_output="$work/$case_name.out"
  case_candidate="$work/$case_name-candidate.json"
  env CODEWIRE_DEPLOY_PROMOTION_TOKEN="$TEST_TOKEN" \
    CURL_BIN="$mock_curl" MOCK_CAPTURE_DIR="$work/capture" \
    MOCK_RESPONSE="$response" MOCK_HTTP_STATUS="$status" \
    "$RESOLVER" "$case_candidate" "$HEAD_SHA" >"$case_output" 2>&1
  jq -e --arg reason "$expected" --arg head "$HEAD_SHA" '
    .schema == "codewire.ci-deployed-source-candidate/v1" and
    .retrieval == {valid: false, reasons: [$reason]} and
    .target.head_sha == $head and .source == {}
  ' "$case_candidate" >/dev/null || fail "$case_name response returned the wrong fail-safe candidate"
  if grep -Fq "$TEST_TOKEN" "$case_output" "$case_candidate"; then
    fail "$case_name response exposed its credential"
  fi
done

marker="$work/curl-invoked"
cat >"$work/curl-never" <<MOCK
#!/usr/bin/env bash
touch '$marker'
exit 99
MOCK
chmod +x "$work/curl-never"
missing_candidate="$work/missing-candidate.json"
CURL_BIN="$work/curl-never" \
  "$RESOLVER" "$missing_candidate" "$HEAD_SHA" >"$work/missing.out" 2>&1
jq -e '.retrieval == {valid: false, reasons: ["token_unavailable"]}' \
  "$missing_candidate" >/dev/null || fail "missing credential did not produce a token-unavailable candidate"
[[ ! -e "$marker" ]] || fail "missing credential reached curl"

if CURL_BIN="$work/curl-never" \
  "$RESOLVER" "$work/invalid-head.json" invalid >"$work/invalid-head.out" 2>&1; then
  fail "invalid exact-head binding was accepted"
fi
[[ ! -e "$marker" ]] || fail "invalid exact-head binding reached curl"

printf '[test-resolve-deployed-source] untrusted candidate and credential-isolation cases passed\n'
