#!/usr/bin/env bash
# Exchange an SDK release workflow's Forgejo OIDC token for the one OpenBao
# role that may read that registry's publish token, and write it into one new
# private file for publish-sdk.py.
#
#   npm   sdk-release-npm.yaml   platform/ci/codewire/npm-publisher   (npm granular token, @codewire packages only)
#   pypi  sdk-release-pypi.yaml  platform/ci/codewire/pypi-publisher  (PyPI token, project codewire)
#
# Each registry has its own workflow and its own role, bound to exactly that
# workflow on protected main dispatched by noel (infra), so neither workflow
# can read the other's token. The OpenBao role is authoritative; these checks
# refuse locally first. The OIDC/OpenBao tokens live for minutes, but the
# registry token does not expire with them: keep the output file private and
# shred it after the upload.
set -euo pipefail
set +x
umask 077

fail() {
  printf '[fetch-openbao-sdk-publish-token] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 2 ]] || {
  printf 'usage: fetch-openbao-sdk-publish-token.sh npm|pypi TOKEN_FILE\n' >&2
  exit 2
}
readonly registry="$1" token_file="$2"
case "$registry" in
  npm) readonly token_pattern='^npm_[A-Za-z0-9]{36}$' ;;
  pypi) readonly token_pattern='^pypi-[A-Za-z0-9_-]{50,500}$' ;;
  *) fail "unknown registry: $registry" ;;
esac

readonly openbao_addr="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly openbao_role="codewire-source-sdk-$registry-publish"
readonly openbao_audience="openbao-codewire-source-sdk-$registry-publish"
readonly secret_path="platform/data/ci/codewire/$registry-publisher"
readonly repository='codewire/codewire'
readonly subject='repo:codewire-41/codewire-58:ref:refs/heads/main'
readonly workflow_ref="codewire/codewire/.gitea/workflows/sdk-release-$registry.yaml@refs/heads/main"
readonly -a curl_bounds=(--connect-timeout 10 --max-time 30)

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
[[ "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}|${GITHUB_ACTOR:-}|${GITHUB_REPOSITORY:-}" == \
  "workflow_dispatch|refs/heads/main|noel|$repository" ]] ||
  fail 'only the SDK release dispatched by noel on protected main may read a publish token'
for name in NPM_TOKEN NODE_AUTH_TOKEN TWINE_PASSWORD PYPI_TOKEN BAO_TOKEN VAULT_TOKEN; do
  [[ -z "${!name:-}" ]] || fail "ambient $name is set; refusing a cached or ambient credential"
done
[[ -d "$(dirname "$token_file")" && ! -e "$token_file" && ! -L "$token_file" ]] ||
  fail 'token output must be a new nonsymlink path in an existing directory'

oidc_request_token="$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN
[[ "$oidc_request_token" =~ ^[A-Za-z0-9._~-]{20,4096}$ ]] || {
  oidc_request_token=''
  fail 'Forgejo OIDC request token is malformed'
}

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-sdk-$registry-publish.XXXXXX")"
cleanup() {
  local result=$?
  trap - EXIT
  oidc_request_token=''
  if ! { find "$work" -type f -exec shred -u {} + && rm -rf "$work"; }; then
    printf '[fetch-openbao-sdk-publish-token] ERROR: private cleanup failed\n' >&2
    result=1
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

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
jq -er '.value | strings | select(test("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"))' \
  "$work/forgejo-response.json" >"$work/forgejo.jwt" || fail 'Forgejo returned no OIDC token'
chmod 0600 "$work/forgejo.jwt"

# The token's own claims must be this exact run before it is presented.
payload="$(cut -d. -f2 <"$work/forgejo.jwt" | tr '_-' '/+')"
while (( ${#payload} % 4 )); do payload="$payload="; done
printf '%s' "$payload" | base64 -d >"$work/claims.json" 2>/dev/null || fail 'OIDC token claims are malformed'
payload=''
jq -e --arg aud "$openbao_audience" --arg sub "$subject" --arg repository "$repository" \
  --arg workflow_ref "$workflow_ref" '
    (.aud == $aud or (.aud | type == "array" and . == [$aud])) and .sub == $sub and
    .repository == $repository and .actor == "noel" and .workflow_ref == $workflow_ref and
    .ref == "refs/heads/main" and .event_name == "workflow_dispatch"
  ' "$work/claims.json" >/dev/null 2>&1 ||
  fail "OIDC token claims are not the protected $registry SDK release"

jq -n --arg role "$openbao_role" --rawfile jwt "$work/forgejo.jwt" \
  '{role:$role, jwt:($jwt | rtrimstr("\n"))}' >"$work/openbao-login.json"
curl --silent --show-error --fail "${curl_bounds[@]}" \
  --header 'Content-Type: application/json' \
  --data-binary @"$work/openbao-login.json" \
  --output "$work/openbao-response.json" \
  "$openbao_addr/v1/auth/forgejo-jwt/login"
jq -er '.auth.client_token | strings | select(length > 0)' \
  "$work/openbao-response.json" >"$work/openbao.token" || fail 'OpenBao returned no token'
chmod 0600 "$work/openbao.token"

{
  printf 'header = "X-Vault-Token: '
  tr -d '\n' <"$work/openbao.token"
  printf '"\nsilent\nshow-error\nfail\n'
} >"$work/openbao.curl"
chmod 0600 "$work/openbao.curl"
curl --config "$work/openbao.curl" "${curl_bounds[@]}" \
  --output "$work/document.json" \
  "$openbao_addr/v1/$secret_path"

jq -e '.data.data | type == "object" and (keys == ["token"])' "$work/document.json" >/dev/null 2>&1 ||
  fail "$registry publisher document is not exactly token"
jq -ej --arg pattern "$token_pattern" '.data.data.token | strings | select(test($pattern))' \
  "$work/document.json" >"$work/token" || fail "$registry publish token is malformed"
chmod 0600 "$work/token"
mv "$work/token" "$token_file"
printf '[fetch-openbao-sdk-publish-token] wrote one private %s publish token file\n' "$registry"
