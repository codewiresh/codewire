#!/usr/bin/env bash
# Exchange this exact Codewire CI job's Forgejo OIDC token for its R2 cache
# credential and write it as a private AWS credentials file. A canonical-main
# push receives the main bucket's read-write token. A pull request receives the
# main bucket's read-only token, or, for the labelled cache experiments only
# (CODEWIRE_R2_CACHE_TRUST=untrusted), the untrusted bucket's token. Pull
# requests can read main's caches and never write them.
set -euo pipefail

fail() {
  printf '[fetch-openbao-sccache-r2-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: fetch-openbao-sccache-r2-credentials.sh AWS_CREDENTIALS_FILE\n' >&2
  exit 2
}
readonly credentials_file="$1"

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
: "${GITHUB_EVENT_NAME:?Forgejo event name is required}"
: "${GITHUB_REF:?Forgejo ref is required}"

case "$GITHUB_EVENT_NAME|$GITHUB_REF" in
  pull_request\|refs/pull/*/head)
    readonly openbao_role='codewire-source-ci-sccache-r2-pr'
    readonly openbao_audience='openbao-codewire-source-ci-sccache-r2-pr'
    case "${CODEWIRE_R2_CACHE_TRUST:-protected-read}" in
      protected-read|untrusted) readonly trust="${CODEWIRE_R2_CACHE_TRUST:-protected-read}" ;;
      *) fail 'a pull request may use only the protected-read or untrusted cache' ;;
    esac
    ;;
  push\|refs/heads/main)
    readonly openbao_role='codewire-source-ci-sccache-r2-main'
    readonly openbao_audience='openbao-codewire-source-ci-sccache-r2-main'
    [[ "${CODEWIRE_R2_CACHE_TRUST:-main}" == main ]] ||
      fail 'canonical main uses only the main cache'
    readonly trust=main
    ;;
  *) fail 'event and ref are not approved for a CI R2 cache' ;;
esac

[[ -d "$(dirname "$credentials_file")" && ! -e "$credentials_file" && ! -L "$credentials_file" ]] ||
  fail 'credential output must be a new nonsymlink path in an existing directory'

readonly openbao_addr="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
# Canonical main writes the one CI cache with the protected token, shared with
# the other main-only builders; protected-read is that cache's read-only token.
case "$trust" in
  main) readonly secret_path='platform/data/ci/codewire/sccache-r2/protected' ;;
  *) readonly secret_path="platform/data/ci/codewire/sccache-r2/$trust" ;;
esac
readonly -a curl_bounds=(--connect-timeout 10 --max-time 30)
oidc_request_token="$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN
[[ "$oidc_request_token" =~ ^[A-Za-z0-9._~-]{20,4096}$ ]] || {
  oidc_request_token=''
  fail 'Forgejo OIDC request token is malformed'
}

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-sccache-r2.XXXXXX")"
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
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${openbao_audience}"
jq -er '.value | strings | select(length > 0)' \
  "$work/forgejo-response.json" >"$work/forgejo.jwt"
chmod 0600 "$work/forgejo.jwt"

jq -n --arg role "$openbao_role" --rawfile jwt "$work/forgejo.jwt" \
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
  --output "$work/r2.json" \
  "$openbao_addr/v1/$secret_path"

jq -er '.data.data.accessKeyId | strings | select(test("^[A-Za-z0-9_-]{16,256}$"))' \
  "$work/r2.json" >"$work/access-key-id"
jq -er '.data.data.secretAccessKey | strings | select(test("^[A-Za-z0-9_+/-]{32,512}$"))' \
  "$work/r2.json" >"$work/secret-access-key"
{
  printf '[default]\naws_access_key_id = '
  tr -d '\n' <"$work/access-key-id"
  printf '\naws_secret_access_key = '
  tr -d '\n' <"$work/secret-access-key"
  printf '\n'
} >"$work/aws-credentials"
chmod 0600 "$work/aws-credentials"
mv "$work/aws-credentials" "$credentials_file"
printf '[fetch-openbao-sccache-r2-credentials] wrote one private %s-cache credential file\n' "$trust"
