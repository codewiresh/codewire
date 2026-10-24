#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-harbor-credentials.sh"

fail() {
  printf '[test-fetch-openbao-harbor-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-harbor.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output"

forgejo_jwt='synthetic-forgejo-jwt'
openbao_token='synthetic-openbao-token'
publisher_username='synthetic-harbor-publisher'
publisher_password='synthetic-harbor-password'
pull_username='synthetic-harbor-pull-reader'
pull_password='synthetic-harbor-pull-password'

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
    --config|--header|--data-binary|--connect-timeout|--max-time)
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
  https://openbao.example.invalid/v1/platform/data/ci/codewire/harbor-publisher)
    jq -n --arg username "${FAKE_PUBLISHER_USERNAME:?}" \
      --arg password "${FAKE_PUBLISHER_PASSWORD:?}" \
      '{data:{data:{username:$username,password:$password}}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/deploy/codewire/harbor-pull)
    jq -n --arg username "${FAKE_PULL_USERNAME:?}" \
      --arg password "${FAKE_PULL_PASSWORD:?}" \
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
export FAKE_PUBLISHER_USERNAME="$publisher_username"
export FAKE_PUBLISHER_PASSWORD="$publisher_password"
export FAKE_PULL_USERNAME="$pull_username"
export FAKE_PULL_PASSWORD="$pull_password"
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export OPENBAO_ROLE='codewire-source-dev-publisher'
export OPENBAO_AUDIENCE='openbao-codewire-source-dev-publisher'
export RUNNER_TEMP="$work/runner"
mkdir -p "$RUNNER_TEMP"

username_file="$work/output/username"
password_file="$work/output/password"
"$FETCHER" "$username_file" "$password_file" >/dev/null
[[ "$(<"$username_file")" == "$publisher_username" ]] || fail 'Harbor publisher username differs'
[[ "$(<"$password_file")" == "$publisher_password" ]] || fail 'Harbor publisher password differs'
[[ "$(stat -c '%a' "$username_file")" == 600 ]] || fail 'username mode is not 0600'
[[ "$(stat -c '%a' "$password_file")" == 600 ]] || fail 'password mode is not 0600'
pull_username_file="$work/output/pull-username"
pull_password_file="$work/output/pull-password"
"$FETCHER" --pull "$pull_username_file" "$pull_password_file" >/dev/null
[[ "$(<"$pull_username_file")" == "$pull_username" ]] ||
  fail 'Harbor pull username differs'
[[ "$(<"$pull_password_file")" == "$pull_password" ]] ||
  fail 'Harbor pull password differs'
[[ "$(stat -c '%a' "$pull_username_file")" == 600 ]] ||
  fail 'pull username mode is not 0600'
[[ "$(stat -c '%a' "$pull_password_file")" == 600 ]] ||
  fail 'pull password mode is not 0600'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'temporary OIDC or OpenBao material survived cleanup'
for secret in "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$forgejo_jwt" "$openbao_token" \
  "$publisher_username" "$publisher_password" "$pull_username" "$pull_password"; do
  if grep -qF "$secret" "$FAKE_CURL_CALLS"; then
    fail 'credential material reached curl arguments'
  fi
done
[[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -eq 6 ]] ||
  fail 'Harbor OIDC or OpenBao request lacks the reviewed network deadline'

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

# A schedule role is read only by the release schedule's own first attempt
# (#2892): under the owner's dispatch, or on a rerun, it is refused before any
# request; the schedule's first attempt passes the guard.
for identity in 'GITHUB_EVENT_NAME=workflow_dispatch GITHUB_ACTOR=noel GITHUB_RUN_ATTEMPT=1' \
    'GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=2' \
    'GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=1'; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  # shellcheck disable=SC2086 # Each identity is three assignments.
  env $identity GITHUB_REF=refs/heads/main GITHUB_REPOSITORY=codewire/codewire \
    OPENBAO_ROLE=codewire-source-prod-publisher-schedule OPENBAO_AUDIENCE=openbao-codewire-source-prod-publisher-schedule \
    "$FETCHER" "$work/output/schedule-username" "$work/output/schedule-password" >"$work/schedule-guard.out" 2>&1 && guarded=0 || guarded=$?
  if [[ "$identity" == *GITHUB_RUN_ATTEMPT=1 && "$identity" == *schedule* ]]; then
    ! grep -Fq "only the release schedule's first attempt" "$work/schedule-guard.out" ||
      fail "the schedule's first attempt was refused a schedule role"
  else
    [[ "$guarded" -ne 0 ]] || fail "a schedule role was read under $identity"
    grep -Fq "only the release schedule's first attempt" "$work/schedule-guard.out" ||
      fail "a schedule role under $identity was not refused by the guard: $(cat "$work/schedule-guard.out")"
    [[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
      fail "a schedule role under $identity reached a request"
  fi
done

echo 'fetch-openbao-harbor-credentials tests passed'
