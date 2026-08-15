#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '[dispatch-deploy-dev] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: dispatch-deploy-dev.sh SOURCE_SHA\n' >&2
  exit 2
}
readonly SOURCE_SHA="$1"
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ \
  && "$SOURCE_SHA" != "0000000000000000000000000000000000000000" ]] ||
  fail "source SHA must be one exact non-zero lowercase object ID"

: "${CODEWIRE_DEPLOY_PROMOTION_TOKEN:?CODEWIRE_DEPLOY_PROMOTION_TOKEN is required}"
deploy_token="$CODEWIRE_DEPLOY_PROMOTION_TOKEN"
unset CODEWIRE_DEPLOY_PROMOTION_TOKEN
[[ "$deploy_token" =~ ^[A-Za-z0-9._~-]{20,512}$ ]] || {
  deploy_token=''
  fail "deploy dispatch token is malformed"
}

curl_bin="${CURL_BIN:-curl}"
if [[ "$curl_bin" == */* ]]; then
  [[ -x "$curl_bin" ]] || fail "curl is required for deploy workflow dispatch"
elif ! command -v "$curl_bin" >/dev/null 2>&1; then
  fail "curl is required for deploy workflow dispatch"
fi

readonly dispatch_url='https://forgejo.example.invalid/api/v1/repos/codewire/deploy/actions/workflows/promote-dev.yaml/dispatches'
umask 077
work="$(mktemp -d)"
auth_header="$work/auth-header"
request_body="$work/request.json"
response_body="$work/response.json"
cleanup() {
  deploy_token=''
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

printf 'Authorization: token %s\n' "$deploy_token" >"$auth_header"
deploy_token=''
printf '{"ref":"main","inputs":{"source_sha":"%s"}}\n' \
  "$SOURCE_SHA" >"$request_body"

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
[[ "$status" == '204' ]] ||
  fail "Forgejo rejected the deploy workflow dispatch (HTTP $status)"

printf '[dispatch-deploy-dev] accepted canonical source %s\n' "$SOURCE_SHA"
