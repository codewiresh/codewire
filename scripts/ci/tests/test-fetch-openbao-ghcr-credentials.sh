#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-ghcr-credentials.sh"

fail() {
  printf '[test-fetch-openbao-ghcr-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-ghcr.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output"

forgejo_jwt='synthetic-forgejo-jwt'
openbao_token='synthetic-openbao-token'
ghcr_username='synthetic-ghcr-publisher'
ghcr_token='synthetic-ghcr-token'

cat >"$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output=''
url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --config|--header|--data-binary) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$url" ]]
case "$url" in
  https://forgejo.example.invalid/*audience=openbao-codewire-source-dev-ghcr-publisher)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/ghcr-publisher)
    jq -n --arg username "${FAKE_GHCR_USERNAME:?}" \
      --arg token "${FAKE_GHCR_TOKEN:?}" \
      '{data:{data:{username:$username,token:$token}}}' >"$output"
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$work/bin/curl"

export PATH="$work/bin:$PATH"
export FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_FORGEJO_JWT="$forgejo_jwt"
export FAKE_OPENBAO_TOKEN="$openbao_token"
export FAKE_GHCR_USERNAME="$ghcr_username"
export FAKE_GHCR_TOKEN="$ghcr_token"
export ACTIONS_ID_TOKEN_REQUEST_URL='https://forgejo.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export OPENBAO_GHCR_ROLE='codewire-source-dev-ghcr-publisher'
export OPENBAO_GHCR_AUDIENCE='openbao-codewire-source-dev-ghcr-publisher'
export RUNNER_TEMP="$work/runner"
mkdir -p "$RUNNER_TEMP"

username_file="$work/output/username"
token_file="$work/output/token"
"$FETCHER" "$username_file" "$token_file" >/dev/null
[[ "$(<"$username_file")" == "$ghcr_username" ]] || fail 'GHCR username differs'
[[ "$(<"$token_file")" == "$ghcr_token" ]] || fail 'GHCR token differs'
[[ "$(stat -c '%a' "$username_file")" == 600 ]] || fail 'username mode is not 0600'
[[ "$(stat -c '%a' "$token_file")" == 600 ]] || fail 'token mode is not 0600'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'temporary OIDC or OpenBao material survived cleanup'
for secret in "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$forgejo_jwt" "$openbao_token" \
  "$ghcr_username" "$ghcr_token"; do
  if grep -qF "$secret" "$FAKE_CURL_CALLS"; then
    fail 'credential material reached curl arguments'
  fi
done

calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
if OPENBAO_GHCR_ROLE='unapproved-role' "$FETCHER" \
    "$work/output/rejected-username" "$work/output/rejected-token" \
    >"$work/rejected.out" 2>&1; then
  fail 'unapproved OpenBao role was accepted'
fi
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'unapproved role reached an external request'
[[ ! -e "$work/output/rejected-username" && ! -e "$work/output/rejected-token" ]] ||
  fail 'unapproved role created credential outputs'

printf 'do-not-overwrite' >"$work/output/existing"
chmod 0600 "$work/output/existing"
calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
if "$FETCHER" "$work/output/existing" "$work/output/new-token" \
    >"$work/existing.out" 2>&1; then
  fail 'pre-existing credential output was accepted'
fi
[[ "$(<"$work/output/existing")" == 'do-not-overwrite' ]] ||
  fail 'pre-existing output was changed'
[[ ! -e "$work/output/new-token" ]] || fail 'second output was created after rejection'
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'pre-existing output reached an external request'

echo 'fetch-openbao-ghcr-credentials tests passed'
