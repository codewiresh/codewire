#!/usr/bin/env bash
# Exchange the protected-main cw release workflow's Forgejo OIDC token for the
# one OpenBao role that may read the release-signing key, and write it into a
# new private directory: private-key.asc, passphrase and key-id. The key was
# generated directly into OpenBao and is never handled by a person.
#
# The OpenBao role is authoritative; these checks refuse locally first. The
# OIDC/OpenBao tokens live for minutes, but the signing key does not expire
# with them: keep the output directory private and shred it after signing.
set -euo pipefail
set +x
umask 077

fail() {
  printf '[fetch-openbao-release-signing-key] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: fetch-openbao-release-signing-key.sh KEY_DIRECTORY\n' >&2
  exit 2
}
readonly key_directory="$1"

readonly openbao_addr="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly base_openbao_role='codewire-source-cli-release-signing'
readonly base_openbao_audience='openbao-codewire-source-cli-release-signing'
readonly secret_path='platform/data/ci/codewire/release-signing'
readonly repository='codewire/codewire'
readonly subject='repo:codewire-41/codewire-58:ref:refs/heads/main'
readonly workflow_ref='codewire/codewire/.gitea/workflows/cli-release.yaml@refs/heads/main'
readonly -a curl_bounds=(--connect-timeout 10 --max-time 30)

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
# shellcheck source=scripts/ci/setup/release-run-identity.sh
. "$(dirname "$0")/release-run-identity.sh"
release_run_identity "$base_openbao_role" "$base_openbao_audience" ||
  fail 'only a protected-main release, the owner'"'"'s dispatch or the schedule, may read the release-signing key'
readonly openbao_role="$release_role" openbao_audience="$release_audience"
for name in CW_RELEASE_GPG_PRIVATE_KEY CW_RELEASE_GPG_PASSPHRASE CW_RELEASE_GPG_KEY_ID BAO_TOKEN VAULT_TOKEN; do
  [[ -z "${!name:-}" ]] || fail "ambient $name is set; refusing a cached or ambient credential"
done
[[ -d "$(dirname "$key_directory")" && ! -e "$key_directory" && ! -L "$key_directory" ]] ||
  fail 'key output must be a new nonsymlink path in an existing directory'

oidc_request_token="$ACTIONS_ID_TOKEN_REQUEST_TOKEN"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN
[[ "$oidc_request_token" =~ ^[A-Za-z0-9._~-]{20,4096}$ ]] || {
  oidc_request_token=''
  fail 'Forgejo OIDC request token is malformed'
}

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-release-signing.XXXXXX")"
cleanup() {
  local result=$?
  trap - EXIT
  oidc_request_token=''
  if ! { find "$work" -type f -exec shred -u {} + && rm -rf "$work"; }; then
    printf '[fetch-openbao-release-signing-key] ERROR: private cleanup failed\n' >&2
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
  --arg workflow_ref "$workflow_ref" --arg actor "$release_actor" --arg event "$release_event" \
  --arg attempt "$release_attempt" '
    (.aud == $aud or (.aud | type == "array" and . == [$aud])) and .sub == $sub and
    .repository == $repository and .actor == $actor and .workflow_ref == $workflow_ref and
    .ref == "refs/heads/main" and .event_name == $event and
    ($attempt == "" or .run_attempt == $attempt)
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
  --output "$work/signing.json" \
  "$openbao_addr/v1/$secret_path"

jq -e '.data.data | type == "object" and (keys == ["keyId", "passphrase", "privateKey", "publicKey"])' \
  "$work/signing.json" >/dev/null 2>&1 ||
  fail 'release-signing document is not exactly keyId, passphrase, privateKey and publicKey'
mkdir -m 0700 "$work/key"
jq -er '.data.data.privateKey | strings | select(length <= 65536)
    | select(test("^-----BEGIN PGP PRIVATE KEY BLOCK-----\n[\\s\\S]*\n-----END PGP PRIVATE KEY BLOCK-----\\s*$"))' \
  "$work/signing.json" >"$work/key/private-key.asc" || fail 'release-signing private key is malformed'
jq -ej '.data.data.passphrase | strings | select(test("^[!-~]{16,256}$"))' \
  "$work/signing.json" >"$work/key/passphrase" || fail 'release-signing passphrase is malformed'
jq -ej '.data.data.keyId | strings | select(test("^[0-9A-F]{40}$"))' \
  "$work/signing.json" >"$work/key/key-id" || fail 'release-signing key ID is not one exact fingerprint'
chmod 0600 "$work/key/private-key.asc" "$work/key/passphrase" "$work/key/key-id"
mv "$work/key" "$key_directory"
printf '[fetch-openbao-release-signing-key] wrote one private release-signing key directory\n'
