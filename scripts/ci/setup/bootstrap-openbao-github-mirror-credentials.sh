#!/usr/bin/env bash
# One-time, create-only migration of the existing Forgejo GitHub App tuple into
# the protected OpenBao KV document consumed by the canonical mirror workflow.
set -euo pipefail

fail() {
  printf '[bootstrap-openbao-github-mirror-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
: "${OPENBAO_GITHUB_ROLE:?OpenBao GitHub mirror role is required}"
: "${OPENBAO_GITHUB_AUDIENCE:?OpenBao GitHub mirror audience is required}"
: "${MIRROR_GITHUB_APP_ID:?Existing Forgejo GitHub App ID is required}"
: "${MIRROR_GITHUB_INSTALLATION_ID:?Existing Forgejo GitHub App installation ID is required}"
: "${MIRROR_GITHUB_PRIVATE_KEY:?Existing Forgejo GitHub App private key is required}"

if [ "$OPENBAO_GITHUB_ROLE|$OPENBAO_GITHUB_AUDIENCE" != \
    'codewire-source-github-mirror|openbao-codewire-source-github-mirror' ]; then
  fail 'OpenBao role and audience are not the protected-main mirror pair'
fi

readonly openbao_addr='https://openbao.example.invalid'
readonly github_path='/v1/platform/data/ci/codewire/github-mirror'
readonly -a curl_bounds=(--connect-timeout 10 --max-time 30)

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-github-bootstrap.XXXXXX")"
cleanup() {
  oidc_request_token=''
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

printf '%s' "$MIRROR_GITHUB_APP_ID" >"$work/app-id"
printf '%s' "$MIRROR_GITHUB_INSTALLATION_ID" >"$work/installation-id"
printf '%s' "$MIRROR_GITHUB_PRIVATE_KEY" >"$work/private-key"
unset MIRROR_GITHUB_APP_ID MIRROR_GITHUB_INSTALLATION_ID MIRROR_GITHUB_PRIVATE_KEY
grep -Eq '^[1-9][0-9]*$' "$work/app-id" || fail 'GitHub App ID is malformed'
grep -Eq '^[1-9][0-9]*$' "$work/installation-id" ||
  fail 'GitHub App installation ID is malformed'
grep -Eq '^-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----$' "$work/private-key" ||
  fail 'GitHub App private key header is malformed'
grep -Eq '^-----END ([A-Z0-9 ]+ )?PRIVATE KEY-----$' "$work/private-key" ||
  fail 'GitHub App private key footer is malformed'

oidc_request_token="$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN
[[ "$oidc_request_token" =~ ^[A-Za-z0-9._~-]{20,4096}$ ]] || {
  oidc_request_token=''
  fail 'Forgejo OIDC request token is malformed'
}
{
  printf 'header = "Authorization: bearer '
  printf '%s' "$oidc_request_token"
  printf '"\nsilent\nshow-error\nfail\n'
} >"$work/forgejo.curl"
chmod 0600 "$work/forgejo.curl"
oidc_request_token=''
curl --config "$work/forgejo.curl" "${curl_bounds[@]}" \
  --output "$work/forgejo-response.json" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${OPENBAO_GITHUB_AUDIENCE}"
jq -erj '.value | strings | select(length > 0)' \
  "$work/forgejo-response.json" >"$work/forgejo.jwt"
chmod 0600 "$work/forgejo.jwt"

jq -n --arg role "$OPENBAO_GITHUB_ROLE" --rawfile jwt "$work/forgejo.jwt" \
  '{role:$role, jwt:$jwt}' >"$work/openbao-login.json"
curl --silent --show-error --fail "${curl_bounds[@]}" \
  --header 'Content-Type: application/json' \
  --data-binary @"$work/openbao-login.json" \
  --output "$work/openbao-response.json" \
  "$openbao_addr/v1/auth/forgejo-jwt/login"
jq -erj '.auth.client_token | strings | select(length > 0)' \
  "$work/openbao-response.json" >"$work/openbao.token"
chmod 0600 "$work/openbao.token"

{
  printf 'header = "X-Vault-Token: '
  cat "$work/openbao.token"
  printf '"\nsilent\nshow-error\n'
} >"$work/openbao.curl"
chmod 0600 "$work/openbao.curl"

read_document() {
  local status
  status="$(curl --config "$work/openbao.curl" "${curl_bounds[@]}" \
    --output "$work/github.json" --write-out '%{http_code}' \
    "$openbao_addr$github_path")" || fail 'OpenBao GitHub App document read failed'
  case "$status" in
    200) return 0 ;;
    404) return 1 ;;
    *) fail "OpenBao GitHub App document read returned HTTP $status" ;;
  esac
}

verify_document() {
  jq -erj '.data.data.appId | strings | select(length > 0)' \
    "$work/github.json" >"$work/stored-app-id"
  jq -erj '.data.data.installationId | strings | select(length > 0)' \
    "$work/github.json" >"$work/stored-installation-id"
  jq -erj '.data.data.privateKey | strings | select(length > 0)' \
    "$work/github.json" >"$work/stored-private-key"
  chmod 0600 "$work/stored-app-id" "$work/stored-installation-id" \
    "$work/stored-private-key"
  cmp -s "$work/app-id" "$work/stored-app-id" ||
    fail 'existing OpenBao GitHub App ID differs from the Forgejo source'
  cmp -s "$work/installation-id" "$work/stored-installation-id" ||
    fail 'existing OpenBao GitHub App installation ID differs from the Forgejo source'
  cmp -s "$work/private-key" "$work/stored-private-key" ||
    fail 'existing OpenBao GitHub App private key differs from the Forgejo source'
}

if read_document; then
  verify_document
  printf '[bootstrap-openbao-github-mirror-credentials] existing OpenBao tuple verified\n'
  exit 0
fi

jq -n \
  --rawfile appId "$work/app-id" \
  --rawfile installationId "$work/installation-id" \
  --rawfile privateKey "$work/private-key" \
  '{options:{cas:0},data:{appId:$appId,installationId:$installationId,privateKey:$privateKey}}' \
  >"$work/create.json"
curl --config "$work/openbao.curl" --fail "${curl_bounds[@]}" \
  --header 'Content-Type: application/json' \
  --request POST --data-binary @"$work/create.json" \
  --output "$work/create-response.json" \
  "$openbao_addr$github_path"

read_document || fail 'OpenBao GitHub App document remained absent after create'
verify_document
printf '[bootstrap-openbao-github-mirror-credentials] create-only OpenBao tuple verified\n'
