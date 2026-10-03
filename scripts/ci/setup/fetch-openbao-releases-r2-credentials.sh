#!/usr/bin/env bash
# Exchange the protected-main cw release workflow's Forgejo OIDC token for the
# one OpenBao role that may read the release publisher's R2 credential, and
# write it as a private AWS credentials file for cw_release_r2.py.
#
# The OpenBao role is authoritative; these checks refuse locally first. The
# OIDC/OpenBao tokens live for minutes, but the R2 key itself does not expire
# with them: keep the output file private and remove it after publication.
set -euo pipefail
set +x
umask 077

fail() {
  printf '[fetch-openbao-releases-r2-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: fetch-openbao-releases-r2-credentials.sh AWS_CREDENTIALS_FILE\n' >&2
  exit 2
}
readonly credentials_file="$1"

readonly openbao_addr='https://openbao.example.invalid'
readonly openbao_role='codewire-source-cli-releases-r2'
readonly openbao_audience='openbao-codewire-source-cli-releases-r2'
readonly secret_path='platform/data/ci/codewire/releases-r2'
readonly repository='codewire/codewire'
readonly subject='repo:codewire-41/codewire-58:ref:refs/heads/main'
readonly workflow_ref='codewire/codewire/.gitea/workflows/cli-release.yaml@refs/heads/main'
readonly -a curl_bounds=(--connect-timeout 10 --max-time 30)

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
[[ "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}|${GITHUB_ACTOR:-}|${GITHUB_REPOSITORY:-}" == \
  "workflow_dispatch|refs/heads/main|noel|$repository" ]] ||
  fail 'only the protected-main workflow_dispatch run by noel may read the release credential'
for name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN BAO_TOKEN VAULT_TOKEN; do
  [[ -z "${!name:-}" ]] || fail "ambient $name is set; refusing a cached or ambient credential"
done
[[ -d "$(dirname "$credentials_file")" && ! -e "$credentials_file" && ! -L "$credentials_file" ]] ||
  fail 'credential output must be a new nonsymlink path in an existing directory'

oidc_request_token="$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN
[[ "$oidc_request_token" =~ ^[A-Za-z0-9._~-]{20,4096}$ ]] || {
  oidc_request_token=''
  fail 'Forgejo OIDC request token is malformed'
}

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-releases-r2.XXXXXX")"
cleanup() {
  local result=$?
  trap - EXIT
  oidc_request_token=''
  if ! { find "$work" -type f -exec shred -u {} + && rmdir "$work"; }; then
    printf '[fetch-openbao-releases-r2-credentials] ERROR: private cleanup failed\n' >&2
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
  fail 'OIDC token claims are not the protected release workflow'

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
  --output "$work/r2.json" \
  "$openbao_addr/v1/$secret_path"

jq -e '.data.data | type == "object" and (keys == ["accessKeyId", "secretAccessKey"])' \
  "$work/r2.json" >/dev/null 2>&1 || fail 'release credential document is not exactly accessKeyId and secretAccessKey'
jq -er '.data.data.accessKeyId | strings | select(test("^[A-Za-z0-9]{16,256}$"))' \
  "$work/r2.json" >"$work/access-key-id" || fail 'release access key ID is malformed'
jq -er '.data.data.secretAccessKey | strings | select(test("^[A-Za-z0-9_+/-]{32,512}$"))' \
  "$work/r2.json" >"$work/secret-access-key" || fail 'release secret access key is malformed'
{
  printf '[default]\naws_access_key_id = '
  tr -d '\n' <"$work/access-key-id"
  printf '\naws_secret_access_key = '
  tr -d '\n' <"$work/secret-access-key"
  printf '\n'
} >"$work/aws-credentials"
chmod 0600 "$work/aws-credentials"
mv "$work/aws-credentials" "$credentials_file"
printf '[fetch-openbao-releases-r2-credentials] wrote one private release-publisher credential file\n'
