#!/usr/bin/env bash
# Exchange the protected-main cw release workflow's Forgejo OIDC token for the
# release-signing OpenBao role and write the macOS signing material into a new
# private directory: the Developer ID Application certificate and its private
# key (developer-id.pem), and the App Store Connect API key that submits to
# Apple's notary service (notary-key.p8, notary-key-id, notary-issuer-id).
# Both documents were stored create-only; no person handles them afterwards.
#
# The OpenBao role is authoritative; these checks refuse locally first. The
# OIDC/OpenBao tokens live for minutes, but the keys do not expire with them:
# keep the output directory private and shred it after signing.
set -euo pipefail
set +x
umask 077

fail() {
  printf '[fetch-openbao-macos-signing] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: fetch-openbao-macos-signing.sh KEY_DIRECTORY\n' >&2
  exit 2
}
readonly key_directory="$1"

readonly openbao_addr="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly base_openbao_role='codewire-source-cli-release-signing'
readonly base_openbao_audience='openbao-codewire-source-cli-release-signing'
readonly developer_id_path='platform/data/ci/codewire/macos-developer-id'
readonly notarization_path='platform/data/ci/codewire/macos-notarization'
# The Apple team whose Developer ID signs cw; the certificate's own team is
# checked again in the signature it produces (sign-macos-cw.sh).
readonly team_id='PXQZM3GLP5'
readonly repository='codewire/codewire'
readonly subject='repo:codewire-41/codewire-58:ref:refs/heads/main'
readonly workflow_ref='codewire/codewire/.gitea/workflows/cli-release.yaml@refs/heads/main'
readonly -a curl_bounds=(--connect-timeout 10 --max-time 30)

: "${ACTIONS_ID_TOKEN_REQUEST_URL:?Forgejo OIDC request URL is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?Forgejo OIDC request token is required}"
# shellcheck source=scripts/ci/setup/release-run-identity.sh
. "$(dirname "$0")/release-run-identity.sh"
release_run_identity "$base_openbao_role" "$base_openbao_audience" ||
  fail 'only a protected-main release, the owner'"'"'s dispatch or the schedule, may read the macOS signing keys'
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

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-openbao-macos-signing.XXXXXX")"
cleanup() {
  local result=$?
  trap - EXIT
  oidc_request_token=''
  if ! { find "$work" -type f -exec shred -u {} + && rm -rf "$work"; }; then
    printf '[fetch-openbao-macos-signing] ERROR: private cleanup failed\n' >&2
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
  --output "$work/developer-id.json" \
  "$openbao_addr/v1/$developer_id_path"
curl --config "$work/openbao.curl" "${curl_bounds[@]}" \
  --output "$work/notarization.json" \
  "$openbao_addr/v1/$notarization_path"

jq -e '.data.data | type == "object" and (keys == ["certificate", "privateKey", "teamId"])' \
  "$work/developer-id.json" >/dev/null 2>&1 ||
  fail 'Developer ID document is not exactly certificate, privateKey and teamId'
jq -e '.data.data | type == "object" and (keys == ["issuerId", "keyId", "privateKey"])' \
  "$work/notarization.json" >/dev/null 2>&1 ||
  fail 'notarization document is not exactly issuerId, keyId and privateKey'
jq -e --arg team "$team_id" '.data.data.teamId == $team' "$work/developer-id.json" >/dev/null 2>&1 ||
  fail 'Developer ID document is not for the admitted Apple team'

mkdir -m 0700 "$work/key"
# One certificate, then its RSA or PKCS#8 private key: rcodesign's --pem-file.
{
  jq -er '.data.data.certificate | strings | select(length <= 16384)
      | select(test("^-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+\n-----END CERTIFICATE-----\\s*$"))
      | rtrimstr("\n")' "$work/developer-id.json" &&
    jq -er '.data.data.privateKey | strings | select(length <= 16384)
      | select(test("^-----BEGIN (RSA )?PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+\n-----END (RSA )?PRIVATE KEY-----\\s*$"))
      | rtrimstr("\n")' "$work/developer-id.json"
} >"$work/key/developer-id.pem" || fail 'Developer ID certificate or private key is malformed'
jq -er '.data.data.privateKey | strings | select(length <= 4096)
    | select(test("^-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PRIVATE KEY-----\\s*$"))' \
  "$work/notarization.json" >"$work/key/notary-key.p8" || fail 'notary API private key is malformed'
jq -ej '.data.data.keyId | strings | select(test("^[A-Z0-9]{10}$"))' \
  "$work/notarization.json" >"$work/key/notary-key-id" || fail 'notary API key ID is malformed'
jq -ej '.data.data.issuerId | strings
    | select(test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))' \
  "$work/notarization.json" >"$work/key/notary-issuer-id" || fail 'notary API issuer ID is malformed'
chmod 0600 "$work/key/developer-id.pem" "$work/key/notary-key.p8" \
  "$work/key/notary-key-id" "$work/key/notary-issuer-id"
mv "$work/key" "$key_directory"
printf '[fetch-openbao-macos-signing] wrote one private macOS signing directory\n'
