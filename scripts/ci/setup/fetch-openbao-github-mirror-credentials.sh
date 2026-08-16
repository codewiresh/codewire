#!/usr/bin/env bash
# Exchange this exact protected Forgejo workflow's OIDC token for one OpenBao
# role and write the GitHub App tuple directly to private files.
set -euo pipefail

fail() {
  printf '[fetch-openbao-github-mirror-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || {
  printf 'usage: fetch-openbao-github-mirror-credentials.sh APP_ID_FILE INSTALLATION_ID_FILE PRIVATE_KEY_FILE\n' >&2
  exit 2
}
readonly app_id_file="$1"
readonly installation_id_file="$2"
readonly private_key_file="$3"

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
: "${OPENBAO_GITHUB_ROLE:?OpenBao GitHub mirror role is required}"
: "${OPENBAO_GITHUB_AUDIENCE:?OpenBao GitHub mirror audience is required}"

case "${OPENBAO_GITHUB_ROLE}|${OPENBAO_GITHUB_AUDIENCE}" in
  codewire-source-github-mirror\|openbao-codewire-source-github-mirror | \
  codewire-source-cli-github-mirror\|openbao-codewire-source-cli-github-mirror) ;;
  *) fail 'OpenBao role and audience are not an approved GitHub mirror pair' ;;
esac

for output in "$app_id_file" "$installation_id_file" "$private_key_file"; do
  [[ -d "$(dirname "$output")" && ! -e "$output" && ! -L "$output" ]] ||
    fail 'credential output must be a new nonsymlink path in an existing directory'
done

readonly openbao_addr='https://openbao.example.invalid'
readonly -a curl_bounds=(--connect-timeout 10 --max-time 30)
oidc_request_token="$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN
[[ "$oidc_request_token" =~ ^[A-Za-z0-9._~-]{20,4096}$ ]] || {
  oidc_request_token=''
  fail 'Forgejo OIDC request token is malformed'
}
umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-github.XXXXXX")"
cleanup() {
  oidc_request_token=''
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

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
jq -er '.value | strings | select(length > 0)' \
  "$work/forgejo-response.json" >"$work/forgejo.jwt"
chmod 0600 "$work/forgejo.jwt"

jq -n --arg role "$OPENBAO_GITHUB_ROLE" --rawfile jwt "$work/forgejo.jwt" \
  '{role:$role, jwt:($jwt | rtrimstr("\n"))}' >"$work/openbao-login.json"
curl --silent --show-error --fail "${curl_bounds[@]}" \
  --header 'Content-Type: application/json' \
  --data-binary @"$work/openbao-login.json" \
  --output "$work/openbao-response.json" \
  "$openbao_addr/v1/auth/forgejo-jwt/login"
jq -er '.auth.client_token | strings | select(length > 0)' \
  "$work/openbao-response.json" >"$work/openbao.token"
chmod 0600 "$work/openbao.token"

{
  printf 'header = "X-Vault-Token: '
  tr -d '\n' <"$work/openbao.token"
  printf '"\nsilent\nshow-error\nfail\n'
} >"$work/openbao.curl"
chmod 0600 "$work/openbao.curl"
curl --config "$work/openbao.curl" "${curl_bounds[@]}" \
  --output "$work/github.json" \
  "$openbao_addr/v1/platform/data/ci/codewire/github-mirror"

jq -er '.data.data.appId | strings | select(length > 0)' \
  "$work/github.json" >"$work/app-id"
jq -er '.data.data.installationId | strings | select(length > 0)' \
  "$work/github.json" >"$work/installation-id"
jq -er '.data.data.privateKey | strings | select(length > 0)' \
  "$work/github.json" >"$work/private-key"
chmod 0600 "$work/app-id" "$work/installation-id" "$work/private-key"
mv "$work/app-id" "$app_id_file"
mv "$work/installation-id" "$installation_id_file"
mv "$work/private-key" "$private_key_file"
printf '[fetch-openbao-github-mirror-credentials] wrote one private GitHub App tuple\n'
