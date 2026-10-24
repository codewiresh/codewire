#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

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
    --config|--header|--data-binary|--connect-timeout|--max-time) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
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
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export OPENBAO_GHCR_ROLE='codewire-source-dev-publisher'
export OPENBAO_GHCR_AUDIENCE='openbao-codewire-source-dev-publisher'
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
[[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -eq 3 ]] ||
  fail 'OIDC or OpenBao request lacks the reviewed network deadline'

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

if OPENBAO_GHCR_ROLE='codewire-source-dev-ghcr-publisher' \
    OPENBAO_GHCR_AUDIENCE='openbao-codewire-source-dev-ghcr-publisher' \
    "$FETCHER" "$work/output/retired-username" "$work/output/retired-token" \
    >"$work/retired.out" 2>&1; then
  fail 'retired same-workflow role was accepted'
fi
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'retired role reached an external request'
[[ ! -e "$work/output/retired-username" && ! -e "$work/output/retired-token" ]] ||
  fail 'retired role created credential outputs'

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

source "$ROOT/scripts/ci/setup/curl-transport-retry.sh"
transport_attempts=0
transport_sleeps=0
curl() {
  transport_attempts="$((transport_attempts + 1))"
  [[ "$transport_attempts" -gt 1 ]] || return 6
}
sleep() {
  [[ "$1" == 2 ]]
  transport_sleeps="$((transport_sleeps + 1))"
}
curl_with_transport_retry synthetic-request
[[ "$transport_attempts" -eq 2 && "$transport_sleeps" -eq 1 ]] ||
  fail 'transient curl transport failure did not recover once with one delay'

transport_attempts=0
transport_sleeps=0
curl() {
  transport_attempts="$((transport_attempts + 1))"
  return 22
}
if curl_with_transport_retry synthetic-request; then
  fail 'HTTP failure was accepted by the transport retry contract'
fi
[[ "$transport_attempts" -eq 1 && "$transport_sleeps" -eq 0 ]] ||
  fail 'HTTP failure was retried instead of failing immediately'

transport_attempts=0
transport_sleeps=0
curl() {
  transport_attempts="$((transport_attempts + 1))"
  return 6
}
if curl_with_transport_retry synthetic-request; then
  fail 'exhausted DNS failure was accepted'
fi
[[ "$transport_attempts" -eq 5 && "$transport_sleeps" -eq 4 ]] ||
  fail 'DNS retry exhaustion did not use the exact bounded contract'

# A schedule role is read only by the release schedule's own first attempt
# (#2892): under the owner's dispatch, or on a rerun, it is refused before any
# request; the schedule's first attempt passes the guard.
for identity in 'GITHUB_EVENT_NAME=workflow_dispatch GITHUB_ACTOR=noel GITHUB_RUN_ATTEMPT=1' \
    'GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=2' \
    'GITHUB_EVENT_NAME=schedule GITHUB_ACTOR=forgejo-actions GITHUB_RUN_ATTEMPT=1'; do
  calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
  # shellcheck disable=SC2086 # Each identity is three assignments.
  env $identity GITHUB_REF=refs/heads/main GITHUB_REPOSITORY=codewire/codewire \
    OPENBAO_GHCR_ROLE=codewire-source-prod-publisher-schedule OPENBAO_GHCR_AUDIENCE=openbao-codewire-source-prod-publisher-schedule \
    "$FETCHER" "$work/output/schedule-username" "$work/output/schedule-token" >"$work/schedule-guard.out" 2>&1 && guarded=0 || guarded=$?
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

echo 'fetch-openbao-ghcr-credentials tests passed'
