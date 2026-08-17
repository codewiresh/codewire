#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh"
readonly WORKFLOW="$ROOT/.gitea/workflows/ci.yaml"

fail() {
  printf '[test-fetch-openbao-sccache-r2-credentials] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-openbao-sccache-r2.XXXXXX")"
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
  https://forgejo.example.invalid/*audience=openbao-codewire-source-ci-sccache-r2-pr)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://forgejo.example.invalid/*audience=openbao-codewire-source-ci-sccache-r2-main)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    [[ -n "$data_file" ]]
    jq -e --arg role "${FAKE_EXPECTED_ROLE:?}" '.role == $role' "$data_file" >/dev/null
    jq -n --arg token "${FAKE_OPENBAO_TOKEN:?}" '{auth:{client_token:$token}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/sccache-r2/untrusted)
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
export ACTIONS_ID_TOKEN_REQUEST_URL='https://forgejo.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export GITHUB_EVENT_NAME=pull_request
export GITHUB_REF=refs/pull/1748/head
export FAKE_EXPECTED_ROLE=codewire-source-ci-sccache-r2-pr
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

export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export GITHUB_EVENT_NAME=push
export GITHUB_REF=refs/heads/main
export FAKE_EXPECTED_ROLE=codewire-source-ci-sccache-r2-main
main_credentials_file="$work/output/main-aws-credentials"
"$FETCHER" "$main_credentials_file" >/dev/null
grep -Fxq "aws_access_key_id = $FAKE_ACCESS_KEY_ID" "$main_credentials_file" ||
  fail 'protected-main role wrote a different AWS credential'

calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
if GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/heads/feature \
    "$FETCHER" "$work/output/unapproved" \
    >"$work/unapproved.out" 2>&1; then
  fail 'unapproved event/ref pair was accepted'
fi
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'unapproved event/ref pair reached an external request'
[[ ! -e "$work/output/unapproved" ]] || fail 'unapproved event wrote credentials'

export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export FAKE_R2_FAIL=1
if GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1748/head \
    FAKE_EXPECTED_ROLE=codewire-source-ci-sccache-r2-pr \
    "$FETCHER" "$work/output/failed-fetch" >"$work/failed-fetch.out" 2>&1; then
  fail 'failed R2 read was accepted'
fi
[[ ! -e "$work/output/failed-fetch" ]] || fail 'failed R2 read left a credential file'
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'failed R2 read left temporary identity material'

grep -Fq 'enable-openid-connect: true' "$WORKFLOW" ||
  fail 'CI does not request Forgejo OIDC'
grep -Fq "scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh \"\$credentials_file\"" \
  "$WORKFLOW" || fail 'Kind does not obtain the private cache credential'
grep -Fq 'CODEWIRE_CI_CACHE state=cache-unavailable fallback=local' "$WORKFLOW" ||
  fail 'Kind does not report its cold-safe identity fallback'
grep -Fq "shred -u \"\$credentials_file\"" "$WORKFLOW" ||
  fail 'Kind does not remove the private cache credential'
grep -Fq 'CODEWIRE_SCCACHE_PREFIX: untrusted/codewire/v1' "$WORKFLOW" ||
  fail 'Kind remote cache is outside the explicit untrusted prefix'

printf '[test-fetch-openbao-sccache-r2-credentials] exact-claim private-file contract passed\n'
