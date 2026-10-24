#!/usr/bin/env bash
# Exchange the current Forgejo job OIDC token for one exact OpenBao role and
# write the paired Harbor credential directly to private files. The publisher
# robot pushes codewire/ images; the pull robot is the same pull-only account
# Dev, Prod and sandbox consumers use, so publication proves consumer access.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
source "$ROOT/scripts/ci/setup/curl-transport-retry.sh"

credential_kind=publisher
if [[ "${1:-}" == --pull ]]; then
  credential_kind=pull
  shift
fi

[[ $# -eq 2 ]] || {
  echo 'Usage: fetch-openbao-harbor-credentials.sh [--pull] USERNAME_FILE PASSWORD_FILE' >&2
  exit 2
}

username_file="$1"
password_file="$2"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
: "${OPENBAO_ROLE:?OpenBao role is required}"
: "${OPENBAO_AUDIENCE:?OpenBao audience is required}"

readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly -a CURL_BOUNDS=(--connect-timeout 10 --max-time 30)
case "${OPENBAO_ROLE}|${OPENBAO_AUDIENCE}" in
  codewire-source-dev-publisher\|openbao-codewire-source-dev-publisher | \
  codewire-source-support-publisher\|openbao-codewire-source-support-publisher | \
  codewire-source-prod-publisher\|openbao-codewire-source-prod-publisher | \
  codewire-source-prod-publisher-schedule\|openbao-codewire-source-prod-publisher-schedule) ;;
  *)
    echo 'OpenBao role and audience are not an approved source publisher pair' >&2
    exit 1
    ;;
esac
# A schedule role is read only by the release schedule's own first attempt
# (#2892).
# shellcheck source=scripts/ci/setup/release-run-identity.sh
. "$(dirname "$0")/release-run-identity.sh"
release_schedule_guard "${OPENBAO_ROLE}" || {
  printf '%s\n' "only the release schedule's first attempt reads a schedule role" >&2
  exit 1
}

case "$credential_kind" in
  publisher)
    credential_path='platform/data/ci/codewire/harbor-publisher'
    credential_label='publisher'
    ;;
  pull)
    credential_path='platform/data/deploy/codewire/harbor-pull'
    credential_label='pull'
    ;;
  *)
    echo 'Harbor credential kind is not recognized' >&2
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
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-harbor.XXXXXX")"
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
curl_with_transport_retry --config "$work/forgejo.curl" \
  "${CURL_BOUNDS[@]}" \
  --output "$work/forgejo-response.json" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${OPENBAO_AUDIENCE}"
jq -er '.value | strings | select(length > 0)' \
  "$work/forgejo-response.json" >"$work/forgejo.jwt"
chmod 0600 "$work/forgejo.jwt"

jq -n --arg role "$OPENBAO_ROLE" --rawfile jwt "$work/forgejo.jwt" \
  '{role:$role, jwt:($jwt | rtrimstr("\n"))}' >"$work/openbao-login.json"
curl_with_transport_retry --silent --show-error --fail \
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
curl_with_transport_retry --config "$work/openbao.curl" \
  "${CURL_BOUNDS[@]}" \
  --output "$work/harbor.json" \
  "$OPENBAO_ADDR/v1/$credential_path"

jq -er '.data.data.username | strings | select(length > 0)' \
  "$work/harbor.json" >"$work/username"
jq -er '.data.data.password | strings | select(length > 0)' \
  "$work/harbor.json" >"$work/password"
chmod 0600 "$work/username" "$work/password"
mv -f "$work/username" "$username_file"
mv -f "$work/password" "$password_file"
printf 'Fetched the paired Harbor %s credential into private files\n' "$credential_label"
