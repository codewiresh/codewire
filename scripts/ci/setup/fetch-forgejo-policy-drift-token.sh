#!/usr/bin/env bash
# Request the read-only policy-drift Authorized Integration JWT and write it
# directly to one new private file (#3821). It reads codewire/deploy and the
# infrastructure repository's main, and only policy-drift.yml's
# pull_request_target job on main can obtain it. The integration audience is an identifier, not a credential;
# its paired declaration is the system cluster's
# access/forgejo-codewire-policy-drift-authorized-integration.json in the
# infrastructure repository. The owner created the integration on 2026-11-12;
# without an audience this refuses rather than requesting a token.
set -euo pipefail

fail() {
  printf '[fetch-forgejo-policy-drift-token] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: fetch-forgejo-policy-drift-token.sh TOKEN_FILE\n' >&2
  exit 2
}
readonly token_file="$1"
readonly audience='u:36:45a19952-b088-48b9-9115-0f6cc22c79c5'

[[ "$audience" =~ ^u:36:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
  fail 'the policy-drift integration has no recorded audience yet'

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
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-forgejo-policy-drift.XXXXXX")"
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
printf '[fetch-forgejo-policy-drift-token] wrote one private short-lived token\n'
