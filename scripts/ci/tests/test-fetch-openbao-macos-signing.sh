#!/usr/bin/env bash
# Synthetic proof for the release job's exact-path macOS signing key reader.
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-macos-signing.sh"
CASES=0

fail() {
  printf '[test-fetch-openbao-macos-signing] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-macos-signing.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output" "$work/runner"

b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
jwt() {
  local claims="$1"
  printf '%s.%s.%s' "$(printf '{"alg":"RS256"}' | b64url)" "$(printf '%s' "$claims" | b64url)" \
    "$(printf 'synthetic-signature' | b64url)"
}
readonly GOOD_CLAIMS='{"aud":"openbao-codewire-source-cli-release-signing","sub":"repo:codewire-41/codewire-58:ref:refs/heads/main","repository":"codewire/codewire","actor":"noel","workflow_ref":"codewire/codewire/.gitea/workflows/cli-release.yaml@refs/heads/main","ref":"refs/heads/main","event_name":"workflow_dispatch"}'

cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output=''
url=''
data_file=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --data-binary) data_file="${2#@}"; shift 2 ;;
    --config|--header|--connect-timeout|--max-time) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$url" ]]
case "$url" in
  https://git.example.invalid/*audience=openbao-"${FAKE_EXPECTED_ROLE:-codewire-source-cli-release-signing}")
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -e --arg role "${FAKE_EXPECTED_ROLE:-codewire-source-cli-release-signing}" '.role == $role' "$data_file" >/dev/null
    printf 'login\n' >>"$FAKE_EVENTS"
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/macos-developer-id)
    printf 'read developer id\n' >>"$FAKE_EVENTS"
    jq -n --arg certificate "${FAKE_CERTIFICATE:?}" --arg privateKey "${FAKE_SIGNING_KEY:?}" \
      --arg teamId "${FAKE_TEAM_ID:?}" --argjson extra "${FAKE_DEVELOPER_ID_EXTRA:-{\}}" \
      '{data:{data:({certificate:$certificate,privateKey:$privateKey,teamId:$teamId} + $extra)}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/macos-notarization)
    printf 'read notarization\n' >>"$FAKE_EVENTS"
    jq -n --arg privateKey "${FAKE_NOTARY_KEY:?}" --arg keyId "${FAKE_NOTARY_KEY_ID:?}" \
      --arg issuerId "${FAKE_ISSUER_ID:?}" --argjson extra "${FAKE_NOTARIZATION_EXTRA:-{\}}" \
      '{data:{data:({privateKey:$privateKey,keyId:$keyId,issuerId:$issuerId} + $extra)}}' >"$output"
    ;;
  *) exit 91 ;;
esac
MOCK
chmod +x "$work/bin/curl"

export PATH="$work/bin:$PATH"
export FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_EVENTS="$work/events"
FAKE_FORGEJO_JWT="$(jwt "$GOOD_CLAIMS")"
export FAKE_FORGEJO_JWT
export FAKE_OPENBAO_TOKEN='synthetic-openbao-token-0123456789'
# The synthetic PEM framing is assembled at run time so no private-key literal
# is committed for secret scanners to match.
pem() { printf -- '-----%s %s-----' "$1" "$2"; }
FAKE_CERTIFICATE="$(pem BEGIN CERTIFICATE)"$'\nc3ludGhldGljY2VydGlmaWNhdGU=\n'"$(pem END CERTIFICATE)"
FAKE_SIGNING_KEY="$(pem BEGIN 'RSA PRIVATE KEY')"$'\nc3ludGhldGljc2lnbmluZ2tleQ==\n'"$(pem END 'RSA PRIVATE KEY')"
FAKE_NOTARY_KEY="$(pem BEGIN 'PRIVATE KEY')"$'\nc3ludGhldGljbm90YXJ5a2V5\n'"$(pem END 'PRIVATE KEY')"
export FAKE_CERTIFICATE FAKE_SIGNING_KEY FAKE_NOTARY_KEY
export FAKE_TEAM_ID='PXQZM3GLP5'
export FAKE_NOTARY_KEY_ID='SYNTHET1C0'
export FAKE_ISSUER_ID='01234567-89ab-cdef-0123-456789abcdef'
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export GITHUB_EVENT_NAME=workflow_dispatch
export GITHUB_REF=refs/heads/main
export GITHUB_ACTOR=noel
export GITHUB_REPOSITORY=codewire/codewire
export RUNNER_TEMP="$work/runner"
unset CW_RELEASE_GPG_PRIVATE_KEY CW_RELEASE_GPG_PASSPHRASE CW_RELEASE_GPG_KEY_ID BAO_TOKEN VAULT_TOKEN

fetch() {
  local output="$1"
  shift
  ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token-0123456789' "$@" "$FETCHER" "$output"
}

# The exact protected run writes one private key directory.
: >"$FAKE_EVENTS"
fetch "$work/output/keys" env >"$work/success.out" 2>&1 || fail "$(cat "$work/success.out")"
[[ "$(stat -c '%a' "$work/output/keys")" == 700 ]] || fail 'key directory mode is not 0700'
[[ "$(find "$work/output/keys" -mindepth 1 -printf '%f:%m\n' | sort | tr '\n' ' ')" == \
  'developer-id.pem:600 notary-issuer-id:600 notary-key-id:600 notary-key.p8:600 ' ]] ||
  fail 'key directory is not exactly the four private files'
[[ "$(cat "$work/output/keys/developer-id.pem")" == "$FAKE_CERTIFICATE"$'\n'"$FAKE_SIGNING_KEY" ]] ||
  fail 'the Developer ID PEM is not the certificate then its key'
[[ "$(cat "$work/output/keys/notary-key.p8")" == "$FAKE_NOTARY_KEY" ]] || fail 'notary key differs'
[[ "$(cat "$work/output/keys/notary-key-id")" == "$FAKE_NOTARY_KEY_ID" ]] || fail 'notary key ID differs'
[[ "$(cat "$work/output/keys/notary-issuer-id")" == "$FAKE_ISSUER_ID" ]] || fail 'issuer ID differs'
[[ "$(cat "$FAKE_EVENTS")" == $'login\nread developer id\nread notarization' ]] ||
  fail 'the reader did not log in once and read exactly the two documents'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'OIDC or OpenBao material survived cleanup'
for secret in synthetic-request-token-0123456789 "$FAKE_FORGEJO_JWT" "$FAKE_OPENBAO_TOKEN" \
    c3ludGhldGljc2lnbmluZ2tleQ c3ludGhldGljbm90YXJ5a2V5; do
  if grep -qF -- "$secret" "$FAKE_CURL_CALLS" "$work/success.out"; then
    fail 'key or token material reached curl arguments or output'
  fi
done
[[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -eq 4 ]] ||
  fail 'a request lacks the reviewed network deadline'
pass

# A PKCS#8 signing key is admitted as well as a PKCS#1 one.
pkcs8="$(pem BEGIN 'PRIVATE KEY')"$'\nc3ludGhldGljc2lnbmluZ2tleQ==\n'"$(pem END 'PRIVATE KEY')"
FAKE_SIGNING_KEY="$pkcs8" fetch "$work/output/pkcs8" env >"$work/pkcs8.out" 2>&1 || fail "$(cat "$work/pkcs8.out")"
pass

# Wrong actor, ref, event or repository is refused before any request.
for override in GITHUB_ACTOR=mallory GITHUB_REF=refs/heads/feature GITHUB_REF=refs/tags/v0.4.2 \
    GITHUB_EVENT_NAME=push GITHUB_EVENT_NAME=pull_request GITHUB_REPOSITORY=codewire/fork; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  name="${override//[^A-Za-z0-9]/-}"
  if fetch "$work/output/$name" env "$override" >"$work/$name.out" 2>&1; then
    fail "unapproved $override was accepted"
  fi
  [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail "$override reached a request"
  [[ ! -e "$work/output/$name" ]] || fail "$override wrote a key"
  pass
done

# The schedule's pickup of a pushed release tag (#2892) reads through its own
# role, with its own claims: event schedule, by Forgejo's Actions user, in the
# run's first attempt.
schedule_claims="$(jq -c '.aud = "openbao-codewire-source-cli-release-signing-schedule" | .actor = "forgejo-actions"
  | .event_name = "schedule" | .run_attempt = "1"' <<<"$GOOD_CLAIMS")"
: >"$FAKE_EVENTS"
FAKE_FORGEJO_JWT="$(jwt "$schedule_claims")" FAKE_EXPECTED_ROLE=codewire-source-cli-release-signing-schedule \
  fetch "$work/output/schedule-keys" env GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=1 \
  >"$work/schedule.out" 2>&1 || fail "a scheduled release could not read its credential: $(cat "$work/schedule.out")"
grep -qx login "$FAKE_EVENTS" || fail 'the scheduled release did not log in'
pass
# Each scheduled claim is checked on its own, before OpenBao: a dispatch's
# actor or event, a rerun's later attempt, or no attempt at all.
n=0
for change in '.actor = "noel"' '.event_name = "workflow_dispatch"' '.run_attempt = "2"' 'del(.run_attempt)'; do
  n=$((n + 1))
  : >"$FAKE_EVENTS"
  if FAKE_FORGEJO_JWT="$(jwt "$(jq -c "$change" <<<"$schedule_claims")")" FAKE_EXPECTED_ROLE=codewire-source-cli-release-signing-schedule \
      fetch "$work/output/claim-$n" env GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=1 \
      >"$work/claim.out" 2>&1; then
    fail "a scheduled run whose claims were changed by $change was accepted"
  fi
  grep -Fq 'OIDC token claims are not the protected release workflow' "$work/claim.out" ||
    fail "$change was not refused by the claim check: $(cat "$work/claim.out")"
  [[ ! -s "$FAKE_EVENTS" ]] || fail "$change reached OpenBao"
  pass
done

# Ambient or cached credentials are never a fallback.
for ambient in CW_RELEASE_GPG_PRIVATE_KEY=ambient BAO_TOKEN=ambient VAULT_TOKEN=ambient; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  if fetch "$work/output/ambient" env "$ambient" >"$work/ambient.out" 2>&1; then
    fail "ambient $ambient was accepted"
  fi
  [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail "ambient $ambient reached a request"
  pass
done

# A token whose own claims are not this exact run never reaches OpenBao.
for claim in '.actor = "mallory"' '.workflow_ref = "codewire/codewire/.gitea/workflows/ci.yaml@refs/heads/main"' \
    '.ref = "refs/heads/feature"' '.event_name = "push"' '.aud = "openbao-codewire-source-cli-releases-r2"' \
    '.sub = "repo:codewire-41/codewire-58:pull_request"' 'del(.workflow_ref)'; do
  : >"$FAKE_EVENTS"
  bad_jwt="$(jwt "$(jq -c "$claim" <<<"$GOOD_CLAIMS")")"
  if FAKE_FORGEJO_JWT="$bad_jwt" fetch "$work/output/claims" env >"$work/claims.out" 2>&1; then
    fail "mismatched claim $claim was accepted"
  fi
  grep -Fq 'OIDC token claims are not the protected release workflow' "$work/claims.out" ||
    fail "claim $claim was not refused by the claim check"
  [[ ! -s "$FAKE_EVENTS" ]] || fail "claim $claim reached OpenBao"
  [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'refused claims left private material'
  pass
done

# Each document must contain exactly its well-formed fields, for the admitted team.
for extra in 'FAKE_DEVELOPER_ID_EXTRA={"passphrase":"synthetic"}' 'FAKE_NOTARIZATION_EXTRA={"teamId":"PXQZM3GLP5"}'; do
  if env "$extra" ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token-0123456789' \
      "$FETCHER" "$work/output/extra" >"$work/extra.out" 2>&1; then
    fail "a document with ${extra#*=} was accepted"
  fi
  [[ ! -e "$work/output/extra" ]] || fail 'an extra-field document wrote a key'
  pass
done
two_certificates="$FAKE_CERTIFICATE"$'\n'"$FAKE_CERTIFICATE"
encrypted="$(pem BEGIN 'RSA PRIVATE KEY')"$'\nProc-Type: 4,ENCRYPTED\nc3ludGhldGlj\n'"$(pem END 'RSA PRIVATE KEY')"
for malformed in FAKE_TEAM_ID=ABCDE12345 FAKE_TEAM_ID=pxqzm3glp5 \
    "FAKE_CERTIFICATE=$two_certificates" FAKE_CERTIFICATE=not-a-certificate \
    "FAKE_SIGNING_KEY=$encrypted" "FAKE_SIGNING_KEY=$FAKE_CERTIFICATE" \
    "FAKE_NOTARY_KEY=$FAKE_SIGNING_KEY" FAKE_NOTARY_KEY=not-a-key \
    FAKE_NOTARY_KEY_ID=synthet1c0 FAKE_NOTARY_KEY_ID=SYNTHET1C FAKE_NOTARY_KEY_ID=SYNTHET1C0X \
    FAKE_ISSUER_ID=0123456789abcdef FAKE_ISSUER_ID=01234567-89AB-CDEF-0123-456789ABCDEF \
    'FAKE_ISSUER_ID=01234567-89ab-cdef-0123-456789abcdef extra'; do
  if env "$malformed" ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token-0123456789' \
      "$FETCHER" "$work/output/malformed" >"$work/malformed.out" 2>&1; then
    fail "malformed ${malformed%%=*} (${malformed#*=}) was accepted"
  fi
  [[ ! -e "$work/output/malformed" ]] || fail "malformed ${malformed%%=*} wrote a key"
  [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'a refused document left private material'
  pass
done
if fetch "$work/output/keys" env >"$work/existing.out" 2>&1; then
  fail 'an existing output path was overwritten'
fi
pass

printf 'test-fetch-openbao-macos-signing: PASS cases=%s\n' "$CASES"
