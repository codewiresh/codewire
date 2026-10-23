#!/usr/bin/env bash
# Prove the protected compiler-cache selector fails open to the job-local
# cache, and that only the canonical-main Dev publisher job can reach the
# protected bucket, prefix, or credential while untrusted lanes cannot.
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR ARM64_BUILDKIT_HOST  # the tests exercise the script defaults

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# shellcheck source=scripts/ci/tests/fixtures/ci-runners.sh
source "$ROOT/scripts/ci/tests/fixtures/ci-runners.sh"
readonly SELECTOR="$ROOT/scripts/ci/setup/select-protected-rust-cache.sh"
readonly FETCHER_NAME='fetch-openbao-sccache-r2-protected-credentials.sh'
readonly DEPLOY_WORKFLOW="$ROOT/.gitea/workflows/deploy-dev.yaml"

fail() {
  printf '[test-select-protected-rust-cache] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/select-protected-rust-cache.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/runner"

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
    --config|--header|--connect-timeout|--max-time|--data-binary) shift 2 ;;
    --silent|--show-error|--fail) shift ;;
    *) url="$1"; shift ;;
  esac
done
[[ -n "$output" && -n "$url" ]]
case "$url" in
  https://git.example.invalid/*audience=openbao-codewire-source-dev-publisher|\
  https://git.example.invalid/*audience=openbao-codewire-source-support-publisher)
    jq -n '{value:"synthetic-forgejo-jwt"}' >"$output"
    ;;
  https://openbao.example.invalid/v1/auth/forgejo-jwt/login)
    # OpenBao unreachable or the role rejecting this job.
    [[ "${FAKE_LOGIN_FAIL:-0}" != 1 ]] || exit 7
    jq -n '{auth:{client_token:"synthetic-openbao-token"}}' >"$output"
    ;;
  https://openbao.example.invalid/v1/platform/data/ci/codewire/sccache-r2/protected)
    # The document does not exist yet, or the policy is not yet reconciled.
    [[ "${FAKE_DOCUMENT_FAIL:-0}" != 1 ]] || exit 22
    jq -n --arg secret "${FAKE_SECRET_ACCESS_KEY:?}" \
      '{data:{data:{accessKeyId:"syntheticaccesskey123456",secretAccessKey:$secret}}}' \
      >"$output"
    ;;
  *) exit 91 ;;
esac
MOCK
chmod 0755 "$work/bin/curl"

readonly synthetic_secret='syntheticsecretaccesskey1234567890abcdef'
export FAKE_CURL_CALLS="$work/curl-calls"
: >"$FAKE_CURL_CALLS"

# run_selector NAME EVENT REF [ENV=VALUE...]: run one selection with a fresh
# credential path and step-output file; print nothing on success.
run_selector() {
  local name="$1" event="$2" ref="$3"
  shift 3
  : >"$work/$name.output"
  env PATH="$work/bin:$PATH" \
    RUNNER_TEMP="$work/runner" \
    GITHUB_OUTPUT="$work/$name.output" \
    GITHUB_EVENT_NAME="$event" \
    GITHUB_REF="$ref" \
    OPENBAO_ROLE="${SELECT_ROLE:-codewire-source-dev-publisher}" \
    ACTIONS_ID_TOKEN_REQUEST_URL='https://git.example.invalid/api/actions/oidc?job=synthetic' \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token' \
    FAKE_SECRET_ACCESS_KEY="$synthetic_secret" \
    "$@" \
    "$SELECTOR" "$work/runner/$name.aws" >"$work/$name.out" 2>&1
}

assert_local_fallback() {
  local name="$1" reason="$2"
  [[ "$(cat "$work/$name.output")" == 'mode=local' ]] ||
    fail "$reason did not fall back to the job-local cache"
  grep -Fxq '::warning::Protected R2 compiler cache is unavailable; building with the job-local cache' \
    "$work/$name.out" || fail "$reason fallback is not visible as a warning"
  grep -Fxq 'CODEWIRE_CI_CACHE state=cache-unavailable fallback=local trust=protected' \
    "$work/$name.out" || fail "$reason fallback is not recorded"
  [[ ! -e "$work/runner/$name.aws" ]] || fail "$reason fallback retained a credential file"
  [[ -z "$(find "$work/runner" -mindepth 1 -print -quit)" ]] ||
    fail "$reason fallback left temporary identity material"
}

# The canonical-main deploy job selects the protected R2 cache.
run_selector selected push refs/heads/main ||
  fail 'canonical-main selection failed'
[[ "$(cat "$work/selected.output")" == 'mode=r2' ]] ||
  fail 'canonical-main deploy job did not select the protected R2 cache'
grep -Fxq 'CODEWIRE_CI_CACHE state=remote-selected backend=r2 trust=protected' \
  "$work/selected.out" || fail 'protected R2 selection is not recorded'
[[ "$(stat -c '%a' "$work/runner/selected.aws")" == 600 ]] ||
  fail 'protected cache credential is not private'
grep -Fxq "aws_secret_access_key = $synthetic_secret" "$work/runner/selected.aws" ||
  fail 'protected cache credential file is incomplete'
if grep -rqF "$synthetic_secret" "$work/selected.output" "$work/selected.out" "$FAKE_CURL_CALLS"; then
  fail 'protected cache credential value escaped into step output, logs, or arguments'
fi
grep -Fq 'sccache-r2/protected' "$FAKE_CURL_CALLS" ||
  fail 'selector did not read the protected cache document'
if grep -Fq 'sccache-r2/untrusted' "$FAKE_CURL_CALLS"; then
  fail 'protected selector consulted the untrusted cache document'
fi
rm -f -- "$work/runner/selected.aws"

# Every way the credential can be unavailable fails open, never closed.
run_selector missing-document push refs/heads/main FAKE_DOCUMENT_FAIL=1 ||
  fail 'a missing protected cache document failed delivery'
assert_local_fallback missing-document 'a missing protected cache document'

run_selector openbao-outage push refs/heads/main FAKE_LOGIN_FAIL=1 ||
  fail 'an OpenBao outage in cache selection failed delivery'
assert_local_fallback openbao-outage 'an OpenBao outage'

run_selector malformed-secret push refs/heads/main FAKE_SECRET_ACCESS_KEY='short' ||
  fail 'a malformed protected cache credential failed delivery'
assert_local_fallback malformed-secret 'a malformed protected cache credential'

# Untrusted events never obtain the protected credential, even through the
# selector: they are rejected before any network request and build locally.
calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
run_selector pull-request pull_request refs/pull/2354/head ||
  fail 'pull-request selection failed instead of falling back'
assert_local_fallback pull-request 'a pull-request event'
run_selector feature-push push refs/heads/feature ||
  fail 'non-main push selection failed instead of falling back'
assert_local_fallback feature-push 'a non-main push'
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'an untrusted event reached Forgejo OIDC or OpenBao for the protected cache'

# The selector's only failures are static contract violations.
if env RUNNER_TEMP="$work/runner" GITHUB_OUTPUT="$work/escape.output" \
    "$SELECTOR" "$work/escape.aws" >/dev/null 2>&1; then
  fail 'selector accepted a credential path outside RUNNER_TEMP'
fi
touch "$work/runner/existing.aws"
if env RUNNER_TEMP="$work/runner" GITHUB_OUTPUT="$work/existing.output" \
    "$SELECTOR" "$work/runner/existing.aws" >/dev/null 2>&1; then
  fail 'selector accepted an existing credential path'
fi
rm -f -- "$work/runner/existing.aws"

# Only the canonical-main Dev deploy and support-images publisher jobs use the
# protected cache, the one cache main-only builders write (infra#1544).
# PCRE patterns: retired protected-workspace names must not match these.
readonly -a protected_markers=(
  'select-protected-rust-cache\.sh'
  "${FETCHER_NAME//./\\.}"
  'SCCACHE_BUCKET: \$\{\{ vars\.CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED'
  'protected/codewire/(?!workspace/)'
  'sccache-r2/protected(?!-workspace)'
)
readonly SUPPORT_WORKFLOW="$ROOT/.gitea/workflows/support-images.yaml"
while IFS= read -r -d '' workflow; do
  [[ "$workflow" == "$DEPLOY_WORKFLOW" || "$workflow" == "$SUPPORT_WORKFLOW" ]] && continue
  for marker in "${protected_markers[@]}"; do
    if grep -Pq -- "$marker" "$workflow"; then
      fail "${workflow#"$ROOT/"} references the protected compiler cache ($marker)"
    fi
  done
done < <(find "$ROOT/.gitea/workflows" "$ROOT/.forgejo/workflows" "$ROOT/.github/workflows" \
  -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 2>/dev/null)
# Each support build leg selects the protected cache as the support publisher,
# on the protected runner tier, and removes the credential afterwards.
for job_header in '  build-support-amd64:' '  build-support-arm64:'; do
  support_job="$(awk -v header="$job_header" '
    /^  [A-Za-z0-9_-]+:$/ { capture = ($0 == header) }
    capture { print }
  ' "$SUPPORT_WORKFLOW")"
  [[ -n "$support_job" ]] || fail "Support images lacks its build job${job_header%:}"
  grep -Fq 'select-protected-rust-cache.sh' <<<"$support_job" ||
    fail "support build job${job_header%:} does not select the protected compiler cache"
  grep -Fxq "    runs-on: ${RUNS_ON_TRUSTED_LIGHT}" <<<"$support_job" ||
    fail 'protected compiler cache is reachable outside the protected runner tier'
  grep -Fxq '      OPENBAO_ROLE: codewire-source-support-publisher' <<<"$support_job" ||
    fail 'support cache job is not the support publisher identity'
  # shellcheck disable=SC2016 # Match the literal workflow expression.
  grep -Fxq '          SCCACHE_BUCKET: ${{ vars.CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED }}' <<<"$support_job" ||
    fail "support build job${job_header%:} does not name the protected bucket"
  grep -Fq 'shred -u' <<<"$support_job" || fail "support build job${job_header%:} does not remove the credential"
done

# Only the two protected build halves reference the protected compiler cache;
# the publishing job and deploy selection never do.
readonly -a protected_cache_jobs=('  build-service-images:' '  build-daemon-image:')
outside_build_jobs="$(awk '
  /^  [A-Za-z0-9_-]+:$/ { capture = ($0 != "  build-service-images:" && $0 != "  build-daemon-image:") }
  capture { print }
' "$DEPLOY_WORKFLOW")"
for marker in "${protected_markers[@]}"; do
  if grep -Pq -- "$marker" <<<"$outside_build_jobs"; then
    fail "Deploy Dev references the protected compiler cache outside its build jobs ($marker)"
  fi
done
for job_header in "${protected_cache_jobs[@]}"; do
  build_job="$(awk -v header="$job_header" '
    /^  [A-Za-z0-9_-]+:$/ { capture = ($0 == header) }
    capture { print }
  ' "$DEPLOY_WORKFLOW")"
  [[ -n "$build_job" ]] || fail "Deploy Dev lacks the protected build job${job_header%:}"
  grep -Fq 'select-protected-rust-cache.sh' <<<"$build_job" ||
    fail "Deploy Dev build job${job_header%:} does not select the protected compiler cache"
  grep -Fxq "    runs-on: ${RUNS_ON_TRUSTED_LIGHT}" <<<"$build_job" ||
    fail 'protected compiler cache is reachable outside the protected runner tier'
  grep -Fxq '      OPENBAO_ROLE: codewire-source-dev-publisher' <<<"$build_job" ||
    fail 'protected compiler cache job is not the Dev publisher identity'
done
# The trigger block ends at its first blank line; the workflow's `concurrency`
# block follows it. No other `on:` key may exist anywhere in the file.
[[ "$(sed -n '/^on:$/,/^$/p' "$DEPLOY_WORKFLOW")" == "$(printf '%s\n' \
    'on:' '  push:' '    branches: [main]' '')" ]] ||
  fail 'Deploy Dev is reachable from an event other than a canonical-main push'
[[ "$(grep -c '^on:$' "$DEPLOY_WORKFLOW")" -eq 1 ]] ||
  fail 'Deploy Dev declares more than one trigger block'
# Between them sit only the concurrency block and the site configuration env.
[[ "$(sed -n '/^on:$/,/^jobs:$/p' "$DEPLOY_WORKFLOW" | grep -Eo '^[a-z-]+:' | tr '\n' ' ')" == \
    'on: concurrency: env: jobs: ' ]] ||
  fail 'Deploy Dev declares an unexpected key between its trigger and its jobs'

# ci.yaml cache selection reads and, on main, writes the same one CI cache
# (infra#1544), but never through the Dev publisher's selector or fetcher; the
# protected selector never names the untrusted cache.
for untrusted in \
    scripts/ci/setup/select-untrusted-rust-cache.sh \
    scripts/ci/setup/select-untrusted-workspace-cache.sh \
    scripts/ci/setup/finish-untrusted-rust-cache.sh \
    scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh; do
  for marker in "${protected_markers[@]:0:2}"; do
    if grep -Pq -- "$marker" "$ROOT/$untrusted"; then
      fail "$untrusted references the protected compiler cache ($marker)"
    fi
  done
done
for protected in \
    scripts/ci/setup/select-protected-rust-cache.sh \
    "scripts/ci/setup/$FETCHER_NAME"; do
  for marker in CODEWIRE_CI_SCCACHE_BUCKET_UNTRUSTED untrusted/codewire sccache-r2/untrusted \
      codewire-source-ci-sccache-r2; do
    if grep -Fq -- "$marker" "$ROOT/$protected"; then
      fail "$protected references the untrusted compiler cache ($marker)"
    fi
  done
done

# Kind image builds refuse a prefix outside the reviewed caches before any build.
printf '[default]\n' >"$work/kind.aws"
chmod 0600 "$work/kind.aws"
if env CODEWIRE_DOCKER_BIN=/bin/false \
    CODEWIRE_SCCACHE_MODE=r2 \
    SCCACHE_BUCKET=example-ci-cache-untrusted \
    SCCACHE_ENDPOINT=https://r2-cache.example.invalid \
    CODEWIRE_SCCACHE_PREFIX=other/codewire/v1 \
    CODEWIRE_SCCACHE_CREDENTIALS_FILE="$work/kind.aws" \
    "$ROOT/scripts/ci/images/build-kind-images.sh" >"$work/kind.out" 2>&1; then
  fail 'Kind image build accepted a prefix outside the reviewed caches'
fi
grep -Fq 'Kind sccache prefix must remain below untrusted/codewire/' "$work/kind.out" ||
  fail 'untrusted Kind image build rejection was not attributable'

printf '[test-select-protected-rust-cache] fail-open protected cache selection contract passed\n'
