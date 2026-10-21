#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-sccache-r2-protected-credentials.sh"

fail() {
  printf '[test-fetch-openbao-sccache-r2-protected-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-sccache-r2-protected.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output" "$work/runner"

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
  https://git.example.invalid/*audience=openbao-codewire-source-dev-publisher|\
  https://git.example.invalid/*audience=openbao-codewire-source-support-publisher)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    [[ -n "$data_file" ]]
    jq -e --arg role "${FAKE_EXPECTED_ROLE:?}" '.role == $role' "$data_file" >/dev/null
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/sccache-r2/protected)
    [[ "${FAKE_R2_FAIL:-0}" != 1 ]] || exit 92
    jq -n --arg accessKeyId "${FAKE_ACCESS_KEY_ID:?}" \
      --arg secretAccessKey "${FAKE_SECRET_ACCESS_KEY:?}" \
      '{data:{data:{accessKeyId:$accessKeyId,secretAccessKey:$secretAccessKey}}}' \
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
export FAKE_ACCESS_KEY_ID='syntheticaccesskey123456'
export FAKE_SECRET_ACCESS_KEY='syntheticsecretaccesskey1234567890abcdef'
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export GITHUB_EVENT_NAME=push
export GITHUB_REF=refs/heads/main
export FAKE_EXPECTED_ROLE=codewire-source-dev-publisher
export OPENBAO_ROLE=codewire-source-dev-publisher
export RUNNER_TEMP="$work/runner"

credentials_file="$work/output/aws-credentials"
"$FETCHER" "$credentials_file" >/dev/null
[[ "$(stat -c '%a' "$credentials_file")" == 600 ]] || fail 'credential mode is not 0600'
grep -Fxq '[default]' "$credentials_file" || fail 'AWS profile header is absent'
grep -Fxq "aws_access_key_id = $FAKE_ACCESS_KEY_ID" "$credentials_file" ||
  fail 'AWS access-key ID differs'
grep -Fxq "aws_secret_access_key = $FAKE_SECRET_ACCESS_KEY" "$credentials_file" ||
  fail 'AWS secret access key differs'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'temporary OIDC or OpenBao material survived cleanup'
for secret in "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$FAKE_FORGEJO_JWT" \
    "$FAKE_OPENBAO_TOKEN" "$FAKE_SECRET_ACCESS_KEY"; do
  if grep -qF "$secret" "$FAKE_CURL_CALLS"; then
    fail 'credential material reached curl arguments'
  fi
done
[[ "$(grep -Fc -- '--connect-timeout 10 --max-time 30' "$FAKE_CURL_CALLS")" -eq 3 ]] ||
  fail 'OIDC or OpenBao request lacks the reviewed network deadline'
[[ "$(grep -Fc 'sccache-r2/protected' "$FAKE_CURL_CALLS")" -eq 1 ]] ||
  fail 'protected fetcher did not read exactly the protected document'
if grep -q 'sccache-r2/untrusted' "$FAKE_CURL_CALLS"; then
  fail 'protected fetcher consulted the untrusted cache document'
fi

calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
if GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1748/head \
    "$FETCHER" "$work/output/unapproved-pr" \
    >"$work/unapproved-pr.out" 2>&1; then
  fail 'pull-request ref was accepted for the protected cache'
fi
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'pull-request ref reached an external request'
[[ ! -e "$work/output/unapproved-pr" ]] || fail 'pull-request ref wrote credentials'
grep -Fq 'not approved for the protected cache' "$work/unapproved-pr.out" ||
  fail 'pull-request rejection was not attributable'

if GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/feature \
    "$FETCHER" "$work/output/unapproved-branch" \
    >"$work/unapproved-branch.out" 2>&1; then
  fail 'non-main push was accepted for the protected cache'
fi
[[ ! -e "$work/output/unapproved-branch" ]] || fail 'non-main push wrote credentials'

if GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main \
    "$FETCHER" "$work/output/unapproved-dispatch" \
    >"$work/unapproved-dispatch.out" 2>&1; then
  fail 'manual dispatch was accepted for the protected cache'
fi
[[ ! -e "$work/output/unapproved-dispatch" ]] || fail 'manual dispatch wrote credentials'

if FAKE_SECRET_ACCESS_KEY='short' "$FETCHER" "$work/output/malformed-secret" \
    >"$work/malformed-secret.out" 2>&1; then
  fail 'malformed protected secret access key was accepted'
fi
[[ ! -e "$work/output/malformed-secret" ]] || fail 'malformed protected secret wrote credentials'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'malformed protected secret left temporary identity material'
grep -Fq 'has no well-formed secretAccessKey' "$work/malformed-secret.out" ||
  fail 'malformed protected secret was not attributable'

if FAKE_ACCESS_KEY_ID='bad key' "$FETCHER" "$work/output/malformed-id" \
    >"$work/malformed-id.out" 2>&1; then
  fail 'malformed protected access-key ID was accepted'
fi
[[ ! -e "$work/output/malformed-id" ]] || fail 'malformed protected access-key ID wrote credentials'
grep -Fq 'has no well-formed accessKeyId' "$work/malformed-id.out" ||
  fail 'malformed protected access-key ID was not attributable'

export FAKE_R2_FAIL=1
if "$FETCHER" "$work/output/failed-fetch" >"$work/failed-fetch.out" 2>&1; then
  fail 'failed protected R2 read was accepted'
fi
[[ ! -e "$work/output/failed-fetch" ]] || fail 'failed protected R2 read left a credential file'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'failed protected R2 read left temporary identity material'
grep -Fq 'protected cache document read failed' "$work/failed-fetch.out" ||
  fail 'failed protected R2 read was not attributable'
unset FAKE_R2_FAIL

# The support-images publisher writes the same one CI cache with the same
# document; no other role may (infra#1544).
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
: >"$FAKE_CURL_CALLS"
OPENBAO_ROLE=codewire-source-support-publisher FAKE_EXPECTED_ROLE=codewire-source-support-publisher \
  "$FETCHER" "$work/output/support-credentials" >/dev/null ||
  fail 'the support publisher could not read the protected cache document'
grep -Fq 'audience=openbao-codewire-source-support-publisher' "$FAKE_CURL_CALLS" ||
  fail 'the support publisher did not request its own audience'
grep -Fq 'sccache-r2/protected ' "$FAKE_CURL_CALLS" || fail 'the support publisher read another document'
for role in codewire-source-prod-publisher codewire-source-ci-sccache-r2-pr ''; do
  export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
  : >"$FAKE_CURL_CALLS"
  if OPENBAO_ROLE="$role" "$FETCHER" "$work/output/refused-role" >/dev/null 2>&1; then
    fail "role '$role' was accepted for the protected cache"
  fi
  [[ ! -s "$FAKE_CURL_CALLS" && ! -e "$work/output/refused-role" ]] ||
    fail "role '$role' reached an external request or wrote credentials"
done

printf '[test-fetch-openbao-sccache-r2-protected-credentials] protected-main private-file contract passed\n'
