#!/usr/bin/env bash
# Exchange the current Forgejo job OIDC token for one exact OpenBao role and
# write the paired GHCR publisher credential directly to private files.
set -euo pipefail

[[ $# -eq 2 ]] || {
  echo 'Usage: fetch-openbao-ghcr-credentials.sh USERNAME_FILE TOKEN_FILE' >&2
  exit 2
}

username_file="$1"
token_file="$2"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
: "${OPENBAO_GHCR_ROLE:?OpenBao GHCR role is required}"
: "${OPENBAO_GHCR_AUDIENCE:?OpenBao GHCR audience is required}"

readonly OPENBAO_ADDR='https://openbao.example.invalid'
readonly -a CURL_BOUNDS=(--connect-timeout 10 --max-time 30)
case "${OPENBAO_GHCR_ROLE}|${OPENBAO_GHCR_AUDIENCE}" in
  codewire-source-dev-ghcr-publisher\|openbao-codewire-source-dev-ghcr-publisher | \
  codewire-source-support-ghcr-publisher\|openbao-codewire-source-support-ghcr-publisher | \
  codewire-source-prod-ghcr-publisher\|openbao-codewire-source-prod-ghcr-publisher) ;;
  *)
    echo 'OpenBao role and audience are not an approved GHCR publisher pair' >&2
    exit 1
    ;;
esac

for output in "$username_file" "$token_file"; do
  [[ -d "$(dirname "$output")" && ! -e "$output" && ! -L "$output" ]] || {
    echo 'Credential output must be a new nonsymlink path in an existing directory' >&2
    exit 1
  }
done

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-ghcr.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

{
  printf 'header = "Authorization: bearer '
  printf '%s' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
  printf '"\nsilent\nshow-error\nfail\n'
} >"$work/forgejo.curl"
chmod 0600 "$work/forgejo.curl"
curl --config "$work/forgejo.curl" \
  "${CURL_BOUNDS[@]}" \
  --output "$work/forgejo-response.json" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${OPENBAO_GHCR_AUDIENCE}"
jq -er '.value | strings | select(length > 0)' \
  "$work/forgejo-response.json" >"$work/forgejo.jwt"
chmod 0600 "$work/forgejo.jwt"

jq -n --arg role "$OPENBAO_GHCR_ROLE" --rawfile jwt "$work/forgejo.jwt" \
  '{role:$role, jwt:($jwt | rtrimstr("\n"))}' >"$work/openbao-login.json"
curl --silent --show-error --fail \
  "${CURL_BOUNDS[@]}" \
  --header 'Content-Type: application/json' \
  --data-binary @"$work/openbao-login.json" \
  --output "$work/openbao-response.json" \
  "$OPENBAO_ADDR/v1/auth/forgejo-jwt/login"
jq -er '.auth.client_token | strings | select(length > 0)' \
  "$work/openbao-response.json" >"$work/openbao.token"
chmod 0600 "$work/openbao.token"

{
  printf 'header = "X-Vault-Token: '
  tr -d '\n' <"$work/openbao.token"
  printf '"\nsilent\nshow-error\nfail\n'
} >"$work/openbao.curl"
chmod 0600 "$work/openbao.curl"
curl --config "$work/openbao.curl" \
  "${CURL_BOUNDS[@]}" \
  --output "$work/ghcr.json" \
  "$OPENBAO_ADDR/v1/platform/data/ci/codewire/ghcr-publisher"

jq -er '.data.data.username | strings | select(length > 0)' \
  "$work/ghcr.json" >"$work/username"
jq -er '.data.data.token | strings | select(length > 0)' \
  "$work/ghcr.json" >"$work/token"
chmod 0600 "$work/username" "$work/token"
mv -f "$work/username" "$username_file"
mv -f "$work/token" "$token_file"
printf 'Fetched the paired GHCR publisher credential into private files\n'
