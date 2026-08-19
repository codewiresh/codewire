#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-nexus-credentials.sh"

fail() {
  printf '[test-fetch-openbao-nexus-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-nexus.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output"

forgejo_jwt='synthetic-forgejo-jwt'
openbao_token='synthetic-openbao-token'
nexus_username='synthetic-nexus-publisher'
nexus_password='synthetic-nexus-password'
approved_username='synthetic-nexus-approved-reader'
approved_password='synthetic-nexus-approved-password'

cat >"$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"
output=''
url=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    --config|--header|--data-binary)
      shift 2
      ;;
    --silent|--show-error|--fail)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done
[[ -n "$output" && -n "$url" ]]
case "$url" in
  https://git.example.invalid/*audience=openbao-codewire-source-dev-publisher)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/nexus/oci-promoter)
    jq -n --arg username "${FAKE_NEXUS_USERNAME:?}" \
      --arg password "${FAKE_NEXUS_PASSWORD:?}" \
      '{data:{data:{username:$username,password:$password}}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/nexus/ci-pull)
    jq -n --arg username "${FAKE_APPROVED_USERNAME:?}" \
      --arg password "${FAKE_APPROVED_PASSWORD:?}" \
      '{data:{data:{username:$username,password:$password}}}' >"$output"
    ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$work/bin/curl"

export PATH="$work/bin:$PATH"
export FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_FORGEJO_JWT="$forgejo_jwt"
export FAKE_OPENBAO_TOKEN="$openbao_token"
export FAKE_NEXUS_USERNAME="$nexus_username"
export FAKE_NEXUS_PASSWORD="$nexus_password"
export FAKE_APPROVED_USERNAME="$approved_username"
export FAKE_APPROVED_PASSWORD="$approved_password"
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export OPENBAO_ROLE='codewire-source-dev-publisher'
export OPENBAO_AUDIENCE='openbao-codewire-source-dev-publisher'
export RUNNER_TEMP="$work/runner"
mkdir -p "$RUNNER_TEMP"

username_file="$work/output/username"
password_file="$work/output/password"
"$FETCHER" "$username_file" "$password_file" >/dev/null
[[ "$(<"$username_file")" == "$nexus_username" ]] || fail 'Nexus username differs'
[[ "$(<"$password_file")" == "$nexus_password" ]] || fail 'Nexus password differs'
[[ "$(stat -c '%a' "$username_file")" == 600 ]] || fail 'username mode is not 0600'
[[ "$(stat -c '%a' "$password_file")" == 600 ]] || fail 'password mode is not 0600'
approved_username_file="$work/output/approved-username"
approved_password_file="$work/output/approved-password"
"$FETCHER" --approved "$approved_username_file" "$approved_password_file" >/dev/null
[[ "$(<"$approved_username_file")" == "$approved_username" ]] ||
  fail 'approved Nexus username differs'
[[ "$(<"$approved_password_file")" == "$approved_password" ]] ||
  fail 'approved Nexus password differs'
[[ "$(stat -c '%a' "$approved_username_file")" == 600 ]] ||
  fail 'approved username mode is not 0600'
[[ "$(stat -c '%a' "$approved_password_file")" == 600 ]] ||
  fail 'approved password mode is not 0600'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'temporary OIDC or OpenBao material survived cleanup'
for secret in "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$forgejo_jwt" "$openbao_token" \
  "$nexus_username" "$nexus_password" "$approved_username" "$approved_password"; do
  if grep -qF "$secret" "$FAKE_CURL_CALLS"; then
    fail 'credential material reached curl arguments'
  fi
done

calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
if OPENBAO_ROLE='unapproved-role' "$FETCHER" \
    "$work/output/rejected-username" "$work/output/rejected-password" \
    >"$work/rejected.out" 2>&1; then
  fail 'unapproved OpenBao role was accepted'
fi
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'unapproved role reached an external request'
[[ ! -e "$work/output/rejected-username" && ! -e "$work/output/rejected-password" ]] ||
  fail 'unapproved role created credential outputs'

printf 'do-not-overwrite' >"$work/output/existing"
chmod 0600 "$work/output/existing"
calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
if "$FETCHER" "$work/output/existing" "$work/output/new-password" \
    >"$work/existing.out" 2>&1; then
  fail 'pre-existing credential output was accepted'
fi
[[ "$(<"$work/output/existing")" == 'do-not-overwrite' ]] ||
  fail 'pre-existing output was changed'
[[ ! -e "$work/output/new-password" ]] || fail 'second output was created after rejection'
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'pre-existing output reached an external request'

echo 'fetch-openbao-nexus-credentials tests passed'
