#!/usr/bin/env bash
# Exchange the protected-main support-image workflow's Forgejo OIDC token for
# the one OpenBao role that may read the workspace-pin bot token, and write it
# into one new private file. The token belongs to the restricted Forgejo user
# codewire-workspace-pin-bot and is limited to write:repository on
# codewire/codewire; the bot can open pull requests but never merge them.
#
# The OpenBao role is authoritative; these checks refuse locally first. The
# OIDC/OpenBao tokens live for minutes, but the bot token does not expire with
# them: keep the output file private and shred it after the proposal.
set -euo pipefail
set +x
umask 077

fail() {
  printf '[fetch-openbao-workspace-pin-bot-token] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: fetch-openbao-workspace-pin-bot-token.sh TOKEN_FILE\n' >&2
  exit 2
}
readonly token_file="$1"

readonly openbao_addr="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly openbao_role='codewire-source-workspace-pin-propose'
readonly openbao_audience='openbao-codewire-source-workspace-pin-propose'
readonly secret_path='platform/data/ci/codewire/workspace-pin-bot'
readonly repository='codewire/codewire'
readonly subject='repo:codewire-41/codewire-58:ref:refs/heads/main'
readonly workflow_ref='codewire/codewire/.gitea/workflows/support-images.yaml@refs/heads/main'
readonly -a curl_bounds=(--connect-timeout 10 --max-time 30)

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
[[ "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}|${GITHUB_ACTOR:-}|${GITHUB_REPOSITORY:-}" == \
  "push|refs/heads/main|noel|$repository" ]] ||
  fail 'only the protected-main support-image push run by noel may read the workspace-pin bot token'
for name in GITEA_TOKEN WORKSPACE_PIN_BOT_TOKEN BAO_TOKEN VAULT_TOKEN; do
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

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-workspace-pin-bot.XXXXXX")"
cleanup() {
  local result=$?
  trap - EXIT
  oidc_request_token=''
  if ! { find "$work" -type f -exec shred -u {} + && rm -rf "$work"; }; then
    printf '[fetch-openbao-workspace-pin-bot-token] ERROR: private cleanup failed\n' >&2
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
    .ref == "refs/heads/main" and .event_name == "push"
  ' "$work/claims.json" >/dev/null 2>&1 ||
  fail 'OIDC token claims are not the protected support-image workflow'

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
  fail 'workspace-pin bot document is not exactly token'
jq -ej '.data.data.token | strings | select(test("^[A-Za-z0-9_-]{20,255}$"))' \
  "$work/document.json" >"$work/token" || fail 'workspace-pin bot token is malformed'
chmod 0600 "$work/token"
mv "$work/token" "$token_file"
printf '[fetch-openbao-workspace-pin-bot-token] wrote one private workspace-pin bot token file\n'
