#!/usr/bin/env bash
# Exchange the current Forgejo job OIDC token for one exact OpenBao role and
# write the paired Nexus credential directly to private files.
set -euo pipefail

[[ $# -eq 2 ]] || {
  echo 'Usage: fetch-openbao-nexus-credentials.sh USERNAME_FILE PASSWORD_FILE' >&2
  exit 2
}

username_file="$1"
password_file="$2"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
: "${OPENBAO_ROLE:?OpenBao role is required}"
: "${OPENBAO_AUDIENCE:?OpenBao audience is required}"

readonly OPENBAO_ADDR='https://openbao.example.invalid'
case "${OPENBAO_ROLE}|${OPENBAO_AUDIENCE}" in
  codewire-source-dev-publisher\|openbao-codewire-source-dev-publisher | \
  codewire-source-support-publisher\|openbao-codewire-source-support-publisher | \
  codewire-source-prod-publisher\|openbao-codewire-source-prod-publisher) ;;
  *)
    echo 'OpenBao role and audience are not an approved source publisher pair' >&2
    exit 1
    ;;
esac

for output in "$username_file" "$password_file"; do
  [[ -d "$(dirname "$output")" && ! -e "$output" && ! -L "$output" ]] || {
    echo 'Credential output must be a new nonsymlink path in an existing directory' >&2
    exit 1
  }
done

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-nexus.XXXXXX")"
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
  --output "$work/forgejo-response.json" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${OPENBAO_AUDIENCE}"
jq -er '.value | strings | select(length > 0)' \
  "$work/forgejo-response.json" >"$work/forgejo.jwt"
chmod 0600 "$work/forgejo.jwt"

jq -n --arg role "$OPENBAO_ROLE" --rawfile jwt "$work/forgejo.jwt" \
  '{role:$role, jwt:($jwt | rtrimstr("\n"))}' >"$work/openbao-login.json"
curl --silent --show-error --fail \
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
  --output "$work/nexus.json" \
  "$OPENBAO_ADDR/v1/platform/data/nexus/oci-promoter"

jq -er '.data.data.username | strings | select(length > 0)' \
  "$work/nexus.json" >"$work/username"
jq -er '.data.data.password | strings | select(length > 0)' \
  "$work/nexus.json" >"$work/password"
chmod 0600 "$work/username" "$work/password"
mv -f "$work/username" "$username_file"
mv -f "$work/password" "$password_file"
printf 'Fetched the paired Nexus publisher credential into private files\n'
