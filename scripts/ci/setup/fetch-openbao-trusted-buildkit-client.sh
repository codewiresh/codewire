#!/usr/bin/env bash
# Exchange the current Forgejo job OIDC token for one of the three protected
# publisher OpenBao roles (deploy-dev.yaml's Dev publisher, support-images.yaml's
# support publisher, deploy-prod.yaml's production publisher) and write the
# trusted BuildKit builder's mutual-TLS client tuple (infra
# runbooks/ci-buildkit-trusted.md, infra#1534) into a private directory:
# ca.crt, client.crt and client.key, each mode 0600. Nothing is printed. The
# caller owns the directory and shreds it when its builds end.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
source "$ROOT/scripts/ci/setup/curl-transport-retry.sh"

fail() {
  printf '[fetch-openbao-trusted-buildkit-client] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  echo 'Usage: fetch-openbao-trusted-buildkit-client.sh PRIVATE_OUTPUT_DIRECTORY' >&2
  exit 2
}
readonly output_dir="$1"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
: "${OPENBAO_ROLE:?OpenBao role is required}"
: "${OPENBAO_AUDIENCE:?OpenBao audience is required}"

readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly CREDENTIAL_PATH='platform/data/ci/codewire/trusted-buildkit-client'
readonly -a CURL_BOUNDS=(--connect-timeout 10 --max-time 30)
# Only the three protected-main publishers may read the builder's client
# tuple; OpenBao enforces the same set (forgejo-codewire-trusted-buildkit-client).
case "$OPENBAO_ROLE|$OPENBAO_AUDIENCE" in
  'codewire-source-dev-publisher|openbao-codewire-source-dev-publisher' | \
    'codewire-source-support-publisher|openbao-codewire-source-support-publisher' | \
    'codewire-source-prod-publisher|openbao-codewire-source-prod-publisher') ;;
  *) fail 'only the Dev, support and production publisher roles read the trusted BuildKit client certificate' ;;
esac
[[ "$output_dir" == /* && -d "$output_dir" && ! -L "$output_dir" \
  && "$(stat -c '%u %a' -- "$output_dir")" == "$(id -u) 700" \
  && -z "$(find "$output_dir" -mindepth 1 -print -quit)" ]] ||
  fail 'output must be an empty private directory (mode 0700) owned by this user'

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-trusted-buildkit.XXXXXX")"
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
curl_with_transport_retry --config "$work/forgejo.curl" \
  "${CURL_BOUNDS[@]}" \
  --output "$work/forgejo-response.json" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${OPENBAO_AUDIENCE}" ||
  fail 'the Forgejo job OIDC token could not be read'
jq -er '.value | strings | select(length > 0)' \
  "$work/forgejo-response.json" >"$work/forgejo.jwt" ||
  fail 'the Forgejo job OIDC token is malformed'

jq -n --arg role "$OPENBAO_ROLE" --rawfile jwt "$work/forgejo.jwt" \
  '{role:$role, jwt:($jwt | rtrimstr("\n"))}' >"$work/openbao-login.json"
curl_with_transport_retry --silent --show-error --fail \
  "${CURL_BOUNDS[@]}" \
  --header 'Content-Type: application/json' \
  --data-binary @"$work/openbao-login.json" \
  --output "$work/openbao-response.json" \
  "$OPENBAO_ADDR/v1/auth/forgejo-jwt/login" ||
  fail "OpenBao refused the $OPENBAO_ROLE login"
jq -er '.auth.client_token | strings | select(length > 0)' \
  "$work/openbao-response.json" >"$work/openbao.token" ||
  fail 'OpenBao returned no client token'

{
  printf 'header = "X-Vault-Token: '
  tr -d '\n' <"$work/openbao.token"
  printf '"\nsilent\nshow-error\nfail\n'
} >"$work/openbao.curl"
curl_with_transport_retry --config "$work/openbao.curl" \
  "${CURL_BOUNDS[@]}" \
  --output "$work/client.json" \
  "$OPENBAO_ADDR/v1/$CREDENTIAL_PATH" ||
  fail "the trusted BuildKit client certificate is not readable at $CREDENTIAL_PATH with role $OPENBAO_ROLE"

pem() {
  local field="$1" begin="$2" file="$3"
  jq -er --arg field "$field" '.data.data[$field] | strings | select(length > 0)' \
    "$work/client.json" >"$work/$file" ||
    fail "the trusted BuildKit client document has no $field"
  grep -Eq "^-----BEGIN $begin-----\$" "$work/$file" ||
    fail "the trusted BuildKit client document's $field is not PEM"
}
pem caCertificate CERTIFICATE ca.crt
pem certificate CERTIFICATE client.crt
pem privateKey '(EC |RSA )?PRIVATE KEY' client.key
chmod 0600 "$work/ca.crt" "$work/client.crt" "$work/client.key"
mv -f "$work/ca.crt" "$work/client.crt" "$work/client.key" "$output_dir/"
printf 'Fetched the trusted BuildKit client certificate into a private directory\n'
