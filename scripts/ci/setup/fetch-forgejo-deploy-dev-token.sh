#!/usr/bin/env bash
# Request the Dev-only source-to-Deploy Authorized Integration JWT and write it
# directly to one new private file. The integration audience is an identifier,
# not a credential; keeping it here gives both consumers one exact contract.
# Its paired declaration is the system cluster's
# access/forgejo-codewire-source-deploy-authorized-integration.json in the
# infrastructure repository.
set -euo pipefail

fail() {
  printf '[fetch-forgejo-deploy-dev-token] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: fetch-forgejo-deploy-dev-token.sh TOKEN_FILE\n' >&2
  exit 2
}
readonly token_file="$1"
readonly audience='u:36:cf95ede8-4fae-4121-b18a-05ca39e69bb9'

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"

[[ -d "$(dirname "$token_file")" && ! -e "$token_file" && ! -L "$token_file" ]] ||
  fail 'token output must be a new nonsymlink path in an existing directory'

curl_bin="${CURL_BIN:-curl}"
if [[ "$curl_bin" == */* ]]; then
  [[ -x "$curl_bin" ]] || fail 'curl is required for Forgejo OIDC'
elif ! command -v "$curl_bin" >/dev/null 2>&1; then
  fail 'curl is required for Forgejo OIDC'
fi

oidc_request_token="$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN
[[ "$oidc_request_token" =~ ^[A-Za-z0-9._~-]{20,4096}$ ]] || {
  oidc_request_token=''
  fail 'Forgejo OIDC request token is malformed'
}

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-forgejo-deploy-dev.XXXXXX")"
cleanup() {
  oidc_request_token=''
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

{
  printf 'header = "Authorization: Bearer '
  printf '%s' "$oidc_request_token"
  printf '"\nsilent\nshow-error\nfail\n'
} >"$work/forgejo.curl"
chmod 0600 "$work/forgejo.curl"
oidc_request_token=''

"$curl_bin" --config "$work/forgejo.curl" \
  --connect-timeout 10 --max-time 30 \
  --output "$work/forgejo-response.json" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${audience}" ||
  fail 'Forgejo OIDC request failed'

jq -er '
  .value
  | strings
  | select(test("^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$"))
' "$work/forgejo-response.json" >"$work/token" ||
  fail 'Forgejo OIDC response did not contain a JWT'
chmod 0600 "$work/token"
mv "$work/token" "$token_file"
printf '[fetch-forgejo-deploy-dev-token] wrote one private short-lived token\n'
