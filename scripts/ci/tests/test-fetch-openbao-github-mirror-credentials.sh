#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-github-mirror-credentials.sh"

fail() {
  printf '[test-fetch-openbao-github-mirror-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-github.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output" "$work/runner"

cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output=''
url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --config|--header|--data-binary|--connect-timeout|--max-time) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$url" ]]
case "$url" in
  https://git.example.invalid/*audience=openbao-codewire-source-github-mirror)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/github-mirror)
    jq -n --arg appId "${FAKE_APP_ID:?}" \
      --arg installationId "${FAKE_INSTALLATION_ID:?}" \
      --arg privateKey "${FAKE_PRIVATE_KEY:?}" \
      '{data:{data:{appId:$appId,installationId:$installationId,privateKey:$privateKey}}}' \
      >"$output"
    ;;
  *) exit 91 ;;
esac
MOCK
chmod +x "$work/bin/curl"

export PATH="$work/bin:$PATH"
export FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_FORGEJO_JWT='synthetic-forgejo-jwt'
export FAKE_OPENBAO_TOKEN='synthetic-openbao-token'
export FAKE_APP_ID='12345'
export FAKE_INSTALLATION_ID='67890'
export FAKE_PRIVATE_KEY='synthetic-private-key'
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export OPENBAO_GITHUB_ROLE='codewire-source-github-mirror'
export OPENBAO_GITHUB_AUDIENCE='openbao-codewire-source-github-mirror'
export RUNNER_TEMP="$work/runner"

"$FETCHER" \
  "$work/output/app-id" "$work/output/installation-id" "$work/output/private-key" \
  >/dev/null
[[ "$(<"$work/output/app-id")" == "$FAKE_APP_ID" ]] || fail 'App ID differs'
[[ "$(<"$work/output/installation-id")" == "$FAKE_INSTALLATION_ID" ]] ||
  fail 'installation ID differs'
[[ "$(<"$work/output/private-key")" == "$FAKE_PRIVATE_KEY" ]] || fail 'private key differs'
for output in app-id installation-id private-key; do
  [[ "$(stat -c '%a' "$work/output/$output")" == 600 ]] || fail "$output mode is not 0600"
done
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'temporary OIDC or OpenBao material survived cleanup'
for secret in "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$FAKE_FORGEJO_JWT" \
    "$FAKE_OPENBAO_TOKEN" "$FAKE_PRIVATE_KEY"; do
  if grep -qF "$secret" "$FAKE_CURL_CALLS"; then
    fail 'credential material reached curl arguments'
  fi
done
[[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -eq 3 ]] ||
  fail 'OIDC or OpenBao request lacks the reviewed network deadline'

calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
if OPENBAO_GITHUB_ROLE=unapproved "$FETCHER" \
    "$work/output/no-app" "$work/output/no-installation" "$work/output/no-key" \
    >"$work/rejected.out" 2>&1; then
  fail 'unapproved role was accepted'
fi
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'unapproved role reached an external request'

printf '[test-fetch-openbao-github-mirror-credentials] exact-role private-file contract passed\n'
