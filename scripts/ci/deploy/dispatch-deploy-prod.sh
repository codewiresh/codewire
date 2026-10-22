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
readonly dispatch_url="${server_url%/}/api/v1/repos/codewire/deploy/actions/workflows/promote-prod.yaml/dispatches"
umask 077
work="$(mktemp -d)"
auth_header="$work/auth-header"
token_file="$work/token"
request_body="$work/request.json"
response_body="$work/response.json"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

"$(dirname "$0")/../setup/fetch-forgejo-deploy-prod-token.sh" "$token_file" ||
  fail 'unable to obtain the production deploy integration token'
{
  printf 'Authorization: Bearer '
  tr -d '\n' <"$token_file"
  printf '\n'
} >"$auth_header"
shred -u "$token_file"
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

# Do not hold a protected source runner while the independently authorized
# deploy workflow executes. Release acceptance verifies this exact run later.
printf '[dispatch-deploy-prod] accepted signed source tag %s as deploy run %s / #%s\n' \
  "$SOURCE_TAG" "$run_id" "$run_number"
