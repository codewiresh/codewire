#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh"
readonly SELECTOR="$ROOT/scripts/ci/setup/select-untrusted-rust-cache.sh"
readonly FINISHER="$ROOT/scripts/ci/setup/finish-untrusted-rust-cache.sh"
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
  https://git.example.invalid/*audience=openbao-codewire-source-ci-sccache-r2-pr)
    jq -n --arg value "${FAKE_FORGEJO_JWT:?}" '{value:$value}' >"$output"
    ;;
  https://git.example.invalid/*audience=openbao-codewire-source-ci-sccache-r2-main)
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
export ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic'
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

if grep -q '^enable-openid-connect:' "$WORKFLOW"; then
  fail 'CI exposes Forgejo OIDC to every verification job'
fi
cache_jobs=(
  cw-release-assets
  workspace-image
  standard
  rust-compile
  rust-packages
  rust-features
  rust-transport
  database
  services-control
  services-runtime
  kind-workspace
  kind-product
  kind-daemon
  kind-smokes
  workspace-cache-measurement
  workspace-cache-probes
)
[[ "$(grep -Fc '    enable-openid-connect: true' "$WORKFLOW")" -eq "${#cache_jobs[@]}" ]] ||
  fail 'CI OIDC is not confined to the declared cache-consuming jobs'
for job in "${cache_jobs[@]}"; do
  job_block="$(awk -v wanted="$job" '
    $0 == "  " wanted ":" { capture = 1 }
    capture && /^  [A-Za-z0-9_-]+:$/ && $0 != "  " wanted ":" { exit }
    capture { print }
  ' "$WORKFLOW")"
  grep -Fq '    enable-openid-connect: true' <<<"$job_block" ||
    fail "$job cannot request its untrusted cache identity"
  cache_selector=select-untrusted-rust-cache.sh
  if [[ "$job" == workspace-image || "$job" == kind-workspace \
      || "$job" == workspace-cache-measurement || "$job" == workspace-cache-probes ]]; then
    cache_selector=select-untrusted-workspace-cache.sh
  fi
  grep -Fq "scripts/ci/setup/$cache_selector \"\$RUNNER_TEMP/codewire-sccache-r2.aws\"" \
    <<<"$job_block" || fail "$job does not select the shared cache"
  grep -Fq "scripts/ci/setup/finish-untrusted-rust-cache.sh \"\$RUNNER_TEMP/codewire-sccache-r2.aws\"" \
    <<<"$job_block" || fail "$job does not clean the cache credential"
done

grep -Fq "readonly fetcher=\"\${OPENBAO_SCCACHE_FETCHER:-\$ROOT/scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh}\"" \
  "$SELECTOR" || fail 'cache selector does not use the reviewed OpenBao exchange'
grep -Fq "shred -u -- \"\$credentials_file\"" "$FINISHER" ||
  fail 'cache finisher does not remove its private credential'
if grep -Eq '^      (SCCACHE_BUCKET|SCCACHE_ENDPOINT|CODEWIRE_SCCACHE_PREFIX):' "$WORKFLOW"; then
  fail 'workflow exposes remote cache configuration outside selected cache steps'
fi

printf '[test-fetch-openbao-sccache-r2-credentials] exact-claim %s-job private-file contract passed\n' "${#cache_jobs[@]}"
