#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly RESOLVER="$ROOT/scripts/ci/deploy/resolve-deployed-source.sh"
readonly SOURCE_SHA='1111111111111111111111111111111111111111'
readonly HEAD_SHA='2222222222222222222222222222222222222222'
readonly TEST_REQUEST_TOKEN='test-only-oidc-request-token'
readonly TEST_JWT='synthetic.header.signature'

fail() {
  printf '[test-resolve-deployed-source] ERROR: %s\n' "$*" >&2
  exit 1
}

install -d "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/codewire-resolver-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/capture" "$work/runner"

python3 - "$work/valid.json" "$SOURCE_SHA" <<'PY'
import base64
import json
from pathlib import Path
import sys

release = {
    "source": {"repository": "codewire/codewire", "sha": sys.argv[2]},
    "images": {"gateway": "sha256:" + "1" * 64},
}
encoded = base64.b64encode(json.dumps(release).encode()).decode()
Path(sys.argv[1]).write_text(
    json.dumps({"encoding": "base64", "content": encoded}), encoding="utf-8"
)
PY

cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}" ]] || exit 91
output=''
url=''
previous=''
for argument in "$@"; do
  case "$previous" in
    --output) output="$argument" ;;
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
  https://git.example.invalid/api/v1/repos/codewire/deploy/contents/environments/dev/release.json?ref=main)
    cp "$MOCK_RESPONSE" "$output"
    printf '%s' "${MOCK_HTTP_STATUS:-200}"
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
export MOCK_RESPONSE="$work/valid.json"
export RUNNER_TEMP="$work/runner"

candidate="$work/candidate.json"
"$RESOLVER" "$candidate" "$HEAD_SHA" >"$work/success.out" 2>&1 ||
  fail 'valid release manifest was rejected'
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
' "$candidate" >/dev/null || fail 'valid candidate has the wrong contract'
[[ "$(stat -c '%a' "$candidate")" == 600 ]] || fail 'candidate mode is not 0600'
grep -Fxq "Authorization: Bearer $TEST_JWT" "$work/capture/auth-header" ||
  fail 'resolver did not use the short-lived Bearer JWT'

for case_name in forbidden malformed oversized; do
  case "$case_name" in
    forbidden)
      response="$work/valid.json"; status=403; expected=api_http_403 ;;
    malformed)
      printf '{"encoding":"base64","content":"bm90LWpzb24="}\n' >"$work/malformed.json"
      response="$work/malformed.json"; status=200; expected=manifest_invalid ;;
    oversized)
      dd if=/dev/zero of="$work/oversized.json" bs=1048577 count=1 status=none
      response="$work/oversized.json"; status=200; expected=manifest_oversized ;;
  esac
  case_candidate="$work/$case_name-candidate.json"
  MOCK_RESPONSE="$response" MOCK_HTTP_STATUS="$status" \
    "$RESOLVER" "$case_candidate" "$HEAD_SHA" >"$work/$case_name.out" 2>&1
  jq -e --arg reason "$expected" '
    .retrieval == {valid: false, reasons: [$reason]} and .source == {}
  ' "$case_candidate" >/dev/null || fail "$case_name returned the wrong fail-safe candidate"
done

marker="$work/curl-invoked"
cat >"$work/curl-never" <<MOCK
#!/usr/bin/env bash
touch '$marker'
exit 99
MOCK
chmod +x "$work/curl-never"
missing_candidate="$work/missing-candidate.json"
env -u ACTIONS_ID_TOKEN_REQUEST_URL -u ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  CURL_BIN="$work/curl-never" "$RESOLVER" "$missing_candidate" "$HEAD_SHA" \
  >"$work/missing.out" 2>&1
jq -e '.retrieval == {valid: false, reasons: ["oidc_unavailable"]}' \
  "$missing_candidate" >/dev/null || fail 'missing OIDC did not fail safe'
[[ ! -e "$marker" ]] || fail 'missing OIDC reached curl'

if CURL_BIN="$work/curl-never" "$RESOLVER" "$work/invalid-head.json" invalid \
    >"$work/invalid-head.out" 2>&1; then
  fail 'invalid exact-head binding was accepted'
fi
[[ ! -e "$marker" ]] || fail 'invalid exact-head binding reached curl'

printf '[test-resolve-deployed-source] OIDC candidate and isolation cases passed\n'
