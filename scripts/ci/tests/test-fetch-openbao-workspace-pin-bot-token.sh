#!/usr/bin/env bash
# Synthetic proof for the pin proposal's exact-path workspace-pin bot token reader.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-workspace-pin-bot-token.sh"
CASES=0

fail() {
  printf '[test-fetch-openbao-workspace-pin-bot-token] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

work="$(mktemp -d "${TMPDIR:-/tmp}/fetch-openbao-workspace-pin-bot.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output" "$work/runner"

b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
jwt() {
  local claims="$1"
  printf '%s.%s.%s' "$(printf '{"alg":"RS256"}' | b64url)" "$(printf '%s' "$claims" | b64url)" \
    "$(printf 'synthetic-signature' | b64url)"
}
readonly GOOD_CLAIMS='{"aud":"openbao-codewire-source-workspace-pin-propose","sub":"repo:codewire-41/codewire-58:ref:refs/heads/main","repository":"codewire/codewire","actor":"noel","workflow_ref":"codewire/codewire/.gitea/workflows/support-images.yaml@refs/heads/main","ref":"refs/heads/main","event_name":"push"}'

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
  https://git.example.invalid/*audience=openbao-codewire-source-workspace-pin-propose)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -e '.role == "codewire-source-workspace-pin-propose"' "$data_file" >/dev/null
    printf 'login\n' >>"$FAKE_EVENTS"
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/workspace-pin-bot)
    printf 'read\n' >>"$FAKE_EVENTS"
    jq -n --arg token "${FAKE_BOT_TOKEN:?}" --argjson extra "${FAKE_EXTRA_FIELDS:-{\}}" \
      '{data:{data:({token:$token} + $extra)}}' >"$output"
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
# Assembled at run time so no token-shaped literal is committed for secret
# scanners to match.
FAKE_BOT_TOKEN="synthetic$(printf '0%.0s' {1..31})"
export FAKE_BOT_TOKEN
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export GITHUB_EVENT_NAME=push
export GITHUB_REF=refs/heads/main
export GITHUB_ACTOR=noel
export GITHUB_REPOSITORY=codewire/codewire
export RUNNER_TEMP="$work/runner"
unset GITEA_TOKEN WORKSPACE_PIN_BOT_TOKEN BAO_TOKEN VAULT_TOKEN

fetch() {
  local output="$1"
  shift
  ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token-0123456789' "$@" "$FETCHER" "$output"
}

# The exact protected run writes one private token file without a newline.
: >"$FAKE_EVENTS"
fetch "$work/output/token" env >"$work/success.out" 2>&1 || fail "$(cat "$work/success.out")"
[[ -f "$work/output/token" && ! -L "$work/output/token" ]] || fail 'token output is not a regular file'
[[ "$(stat -c '%a' "$work/output/token")" == 600 ]] || fail 'token file mode is not 0600'
cmp -s "$work/output/token" <(printf '%s' "$FAKE_BOT_TOKEN") || fail 'token file differs from the document'
[[ "$(cat "$FAKE_EVENTS")" == $'login\nread' ]] || fail 'the fetcher did not log in once and read once'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'OIDC or OpenBao material survived cleanup'
for secret in synthetic-request-token-0123456789 "$FAKE_FORGEJO_JWT" "$FAKE_OPENBAO_TOKEN" "$FAKE_BOT_TOKEN"; do
  if grep -qF -- "$secret" "$FAKE_CURL_CALLS" "$work/success.out"; then
    fail 'token material reached curl arguments or output'
  fi
done
[[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -eq 3 ]] ||
  fail 'a request lacks the reviewed network deadline'
pass

# Wrong actor, ref, event or repository is refused before any request.
for override in GITHUB_ACTOR=mallory GITHUB_ACTOR=codewire-workspace-pin-bot \
    GITHUB_REF=refs/heads/automation/workspace-image-pin GITHUB_REF=refs/tags/v0.4.2 \
    GITHUB_EVENT_NAME=workflow_dispatch GITHUB_EVENT_NAME=pull_request GITHUB_REPOSITORY=codewire/fork; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  name="${override//[^A-Za-z0-9]/-}"
  if fetch "$work/output/$name" env "$override" >"$work/$name.out" 2>&1; then
    fail "unapproved $override was accepted"
  fi
  [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail "$override reached a request"
  [[ ! -e "$work/output/$name" ]] || fail "$override wrote a token"
  pass
done

# Ambient or cached credentials are never a fallback, including the job token.
for ambient in GITEA_TOKEN=ambient WORKSPACE_PIN_BOT_TOKEN=ambient BAO_TOKEN=ambient VAULT_TOKEN=ambient; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  if fetch "$work/output/ambient" env "$ambient" >"$work/ambient.out" 2>&1; then
    fail "ambient $ambient was accepted"
  fi
  [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] || fail "ambient $ambient reached a request"
  pass
done

# A token whose own claims are not this exact run never reaches OpenBao.
for claim in '.actor = "mallory"' '.workflow_ref = "codewire/codewire/.gitea/workflows/ci.yaml@refs/heads/main"' \
    '.workflow_ref = "codewire/codewire/.gitea/workflows/support-images.yaml@refs/heads/automation/workspace-image-pin"' \
    '.ref = "refs/heads/feature"' '.event_name = "workflow_dispatch"' \
    '.aud = "openbao-codewire-source-support-publisher"' \
    '.sub = "repo:codewire-41/codewire-58:pull_request"' 'del(.workflow_ref)'; do
  : >"$FAKE_EVENTS"
  bad_jwt="$(jwt "$(jq -c "$claim" <<<"$GOOD_CLAIMS")")"
  if FAKE_FORGEJO_JWT="$bad_jwt" fetch "$work/output/claims" env >"$work/claims.out" 2>&1; then
    fail "mismatched claim $claim was accepted"
  fi
  grep -Fq 'OIDC token claims are not the protected support-image workflow' "$work/claims.out" ||
    fail "claim $claim was not refused by the claim check"
  [[ ! -s "$FAKE_EVENTS" ]] || fail "claim $claim reached OpenBao"
  [[ ! -e "$work/output/claims" ]] || fail "claim $claim wrote a token"
  [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'refused claims left private material'
  pass
done

# The document must contain exactly one well-formed token field.
for extra in '{"username":"codewire-workspace-pin-bot"}' '{"password":"synthetic"}'; do
  if FAKE_EXTRA_FIELDS="$extra" fetch "$work/output/extra" env >"$work/extra.out" 2>&1; then
    fail "token document with $extra was accepted"
  fi
  [[ ! -e "$work/output/extra" ]] || fail 'an extra-field document wrote a token'
  pass
done
for malformed in FAKE_BOT_TOKEN=short 'FAKE_BOT_TOKEN=has space 0123456789abcdef' \
    "FAKE_BOT_TOKEN=$(printf 'a%.0s' {1..256})"; do
  if env "$malformed" ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token-0123456789' \
      "$FETCHER" "$work/output/malformed" >"$work/malformed.out" 2>&1; then
    fail "malformed ${malformed%%=*} was accepted"
  fi
  [[ ! -e "$work/output/malformed" ]] || fail "malformed ${malformed%%=*} wrote a token"
  [[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] || fail 'a refused document left private material'
  pass
done

# An existing path or a symlink is never overwritten.
if fetch "$work/output/token" env >"$work/existing.out" 2>&1; then
  fail 'an existing output path was overwritten'
fi
ln -s "$work/elsewhere" "$work/output/link"
if fetch "$work/output/link" env >"$work/link.out" 2>&1; then
  fail 'a symlink output path was followed'
fi
[[ ! -e "$work/elsewhere" ]] || fail 'a symlink output path received the token'
pass

printf 'test-fetch-openbao-workspace-pin-bot-token: PASS cases=%s\n' "$CASES"
