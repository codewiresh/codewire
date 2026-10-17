#!/usr/bin/env bash
# Synthetic proof for the release job's exact-path signing-key reader.
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-release-signing-key.sh"
CASES=0

fail() {
  printf '[test-fetch-openbao-release-signing-key] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-release-signing.XXXXXX")"
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
  https://git.example.invalid/*audience=openbao-codewire-source-cli-release-signing)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -e '.role == "codewire-source-cli-release-signing"' "$data_file" >/dev/null
    printf 'login\n' >>"$FAKE_EVENTS"
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/release-signing)
    printf 'read\n' >>"$FAKE_EVENTS"
    jq -n --arg privateKey "${FAKE_PRIVATE_KEY:?}" --arg publicKey "${FAKE_PUBLIC_KEY:?}" \
      --arg passphrase "${FAKE_PASSPHRASE:?}" --arg keyId "${FAKE_KEY_ID:?}" \
      --argjson extra "${FAKE_EXTRA_FIELDS:-{\}}" \
      '{data:{data:({privateKey:$privateKey,publicKey:$publicKey,passphrase:$passphrase,keyId:$keyId} + $extra)}}' >"$output"
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
# The synthetic armor is assembled at run time so no private-key literal is
# committed for secret scanners to match.
armor() { printf -- '-----%s PGP %s KEY BLOCK-----' "$1" "$2"; }
FAKE_PRIVATE_KEY="$(armor BEGIN PRIVATE)"$'\n\nsyntheticprivatekeymaterial0123456789\n'"$(armor END PRIVATE)"
export FAKE_PRIVATE_KEY
export FAKE_PUBLIC_KEY=$'-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nsyntheticpublickey\n-----END PGP PUBLIC KEY BLOCK-----'
export FAKE_PASSPHRASE='synthetic-release-passphrase-0123456789'
export FAKE_KEY_ID='0123456789ABCDEF0123456789ABCDEF01234567'
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
fetch "$work/output/key" env >"$work/success.out" 2>&1 || fail "$(cat "$work/success.out")"
[[ "$(stat -c '%a' "$work/output/key")" == 700 ]] || fail 'key directory mode is not 0700'
[[ "$(find "$work/output/key" -mindepth 1 -printf '%f:%m\n' | sort | tr '\n' ' ')" == \
  'key-id:600 passphrase:600 private-key.asc:600 ' ]] || fail 'key directory is not exactly the three private files'
[[ "$(cat "$work/output/key/private-key.asc")" == "$FAKE_PRIVATE_KEY" ]] || fail 'private key differs'
[[ "$(cat "$work/output/key/passphrase")" == "$FAKE_PASSPHRASE" ]] || fail 'passphrase differs'
[[ "$(cat "$work/output/key/key-id")" == "$FAKE_KEY_ID" ]] || fail 'key ID differs'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'OIDC or OpenBao material survived cleanup'
for secret in synthetic-request-token-0123456789 "$FAKE_FORGEJO_JWT" "$FAKE_OPENBAO_TOKEN" \
    syntheticprivatekeymaterial0123456789 "$FAKE_PASSPHRASE"; do
  if grep -qF -- "$secret" "$FAKE_CURL_CALLS" "$work/success.out"; then
    fail 'key or token material reached curl arguments or output'
  fi
done
[[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -eq 3 ]] ||
  fail 'a request lacks the reviewed network deadline'
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

# Ambient or cached credentials are never a fallback.
for ambient in CW_RELEASE_GPG_PRIVATE_KEY=ambient CW_RELEASE_GPG_KEY_ID=ambient BAO_TOKEN=ambient; do
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

# The document must contain exactly the four well-formed fields.
for extra in '{"rotationOf":"39F95DC66BA8EFBEAF49FAEF39D46239F95F4632"}' '{"accessKeyId":"SYNTHETIC"}'; do
  if FAKE_EXTRA_FIELDS="$extra" fetch "$work/output/extra" env >"$work/extra.out" 2>&1; then
    fail "key document with $extra was accepted"
  fi
  [[ ! -e "$work/output/extra" ]] || fail 'an extra-field document wrote a key'
  pass
done
for malformed in FAKE_PASSPHRASE=short FAKE_KEY_ID=0123456789abcdef0123456789abcdef01234567 \
    FAKE_KEY_ID=0123456789ABCDEF FAKE_PRIVATE_KEY=not-an-armored-key \
    "FAKE_PRIVATE_KEY=$FAKE_PUBLIC_KEY"; do
  if env "$malformed" ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token-0123456789' \
      "$FETCHER" "$work/output/malformed" >"$work/malformed.out" 2>&1; then
    fail "malformed ${malformed%%=*} was accepted"
  fi
  [[ ! -e "$work/output/malformed" ]] || fail "malformed ${malformed%%=*} wrote a key"
  [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'a refused document left private material'
  pass
done
if fetch "$work/output/key" env >"$work/existing.out" 2>&1; then
  fail 'an existing output path was overwritten'
fi
pass

printf 'test-fetch-openbao-release-signing-key: PASS cases=%s\n' "$CASES"
