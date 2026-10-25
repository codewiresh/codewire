#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

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
  https://openbao.example.invalid/v1/platform/data/ci/codewire/sccache-r2/protected-read|\
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

# A pull request reads main's caches through the read-only document by default.
grep -Fq 'sccache-r2/protected-read' "$FAKE_CURL_CALLS" && ! grep -Eq 'sccache-r2/(untrusted|protected |main )' "$FAKE_CURL_CALLS" ||
  fail 'a pull request must read only the protected-read cache document by default'
[[ "$(grep -c 'sccache-r2/' "$FAKE_CURL_CALLS")" == 1 ]] || fail 'a pull request read more than one cache document'

# Nothing else: the untrusted bucket's document is refused like main's.
for refused in untrusted main other; do
  export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
  : >"$FAKE_CURL_CALLS"
  if CODEWIRE_R2_CACHE_TRUST="$refused" "$FETCHER" "$work/output/refused-$refused" >/dev/null 2>&1; then
    fail "a pull request obtained the $refused cache"
  fi
  [[ ! -s "$FAKE_CURL_CALLS" && ! -e "$work/output/refused-$refused" ]] ||
    fail "a refused pull-request cache request reached an external request"
done

# A canonical-main push reads only the main bucket's document, never the
# untrusted one a pull request can write through.
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
export GITHUB_EVENT_NAME=push
export GITHUB_REF=refs/heads/main
export FAKE_EXPECTED_ROLE=codewire-source-ci-sccache-r2-main
main_credentials_file="$work/output/main-aws-credentials"
: >"$FAKE_CURL_CALLS"
"$FETCHER" "$main_credentials_file" >"$work/main.out"
grep -Fxq "aws_access_key_id = $FAKE_ACCESS_KEY_ID" "$main_credentials_file" ||
  fail 'protected-main role wrote a different AWS credential'
grep -Fq 'sccache-r2/protected ' "$FAKE_CURL_CALLS" && ! grep -Eq 'sccache-r2/(untrusted|protected-read|main )' "$FAKE_CURL_CALLS" ||
  fail 'canonical main must read only the protected cache document'
grep -Fq 'wrote one private main-cache credential file' "$work/main.out" ||
  fail 'canonical main did not report its main cache credential'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-request-token'
if CODEWIRE_R2_CACHE_TRUST=protected-read "$FETCHER" "$work/output/protected-read-on-main" >/dev/null 2>&1; then
  fail 'canonical main accepted a cache other than main'
fi

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
# Compile once (infra#1632): the compile job builds in its build runner's own
# warm folder and requests no identity, so it is not a cache job.
cache_jobs=(
  standard
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
  if [[ "$job" == kind-workspace ]]; then
    cache_selector=select-untrusted-workspace-cache.sh
  fi
  grep -Fq "scripts/ci/setup/$cache_selector \"\$RUNNER_TEMP/codewire-sccache-r2.aws\"" \
    <<<"$job_block" || fail "$job does not select the shared cache"
  grep -Fq "scripts/ci/setup/finish-untrusted-rust-cache.sh \"\$RUNNER_TEMP/codewire-sccache-r2.aws\"" \
    <<<"$job_block" || fail "$job does not clean the cache credential"
done

# A main push writes the one protected cache, which only main-only builders on
# fresh metal VMs may write (infra#1544). A job that fetches cache credentials
# therefore runs main pushes on the trusted Heavy runner variable (the metal-only
# sized label), or forces its job-local caches on a main push: a job on the
# trusted Kind runner (an unsized label) can land on a PR-shared cloud pod.
readonly main_push="github.event_name == 'push' && github.ref == 'refs/heads/main'"
# Only the main-push branch of the expression matters here; pull requests read.
readonly sized_runs_on="    runs-on: \${{ $main_push && (vars.CODEWIRE_CI_RUNNER_TRUSTED_HEAVY || "
check_main_cache_runners() {
  local workflow="$1" job block step checked=0
  while IFS= read -r job; do
    block="$(awk -v wanted="$job" '
      $0 == "  " wanted ":" { capture = 1 }
      capture && /^  [A-Za-z0-9_-]+:$/ && $0 != "  " wanted ":" { exit }
      capture { print }
    ' "$workflow")"
    grep -Eq 'scripts/ci/setup/select-untrusted-(rust|workspace)-cache\.sh' <<<"$block" || continue
    checked=$((checked + 1))
    grep -Fq -- "$sized_runs_on" <<<"$block" && continue
    # Unsized: every selector step must force local caches on a main push.
    while IFS= read -r -d '' step; do
      grep -Eq 'select-untrusted-(rust|workspace)-cache\.sh' <<<"$step" || continue
      grep -Fq "CODEWIRE_SCCACHE_REQUEST: \${{ $main_push && 'local' || " <<<"$step" &&
        { ! grep -q 'select-untrusted-workspace-cache\.sh' <<<"$step" ||
          grep -Fq "CODEWIRE_BUILDKIT_CACHE_REQUEST: \${{ $main_push && 'local' || " <<<"$step"; } || {
        printf 'job %s fetches the protected cache on main without the metal-only sized runner\n' "$job" >&2
        return 1
      }
    done < <(awk '/^      - / { if (step != "") printf "%s%c", step, 0; step = "" } { step = step $0 "\n" } END { if (step != "") printf "%s%c", step, 0 }' <<<"$block")
  done < <(awk '/^jobs:$/ { jobs = 1; next } jobs && /^  [A-Za-z0-9_-]+:$/ { sub(/^  /, ""); sub(/:$/, ""); print }' "$workflow")
  [[ "$checked" -gt 0 ]]
}
check_main_cache_runners "$WORKFLOW" || fail 'a main cache job may run on a PR-shared Heavy pod'
# Fixtures: one sized cache job moved to the unsized main runner, and one
# unsized job that no longer forces local caches on a main push.
sed '/^  rust-packages:$/,/^  rust-features:$/s/&& (vars\.CODEWIRE_CI_RUNNER_TRUSTED_HEAVY /\&\& (vars.CODEWIRE_CI_RUNNER_TRUSTED_KIND /' \
  "$WORKFLOW" >"$work/unsized-ci.yaml"
! cmp -s "$WORKFLOW" "$work/unsized-ci.yaml" || fail 'the unsized fixture changed nothing'
if check_main_cache_runners "$work/unsized-ci.yaml" 2>"$work/unsized.err"; then
  fail 'an unsized main cache job was accepted'
fi
grep -Fq 'without the metal-only sized runner' "$work/unsized.err" || fail 'the unsized refusal did not name its job'
python3 - "$WORKFLOW" "$work/unforced-ci.yaml" "CODEWIRE_SCCACHE_REQUEST: \${{ $main_push && 'local' || " <<'PY'
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
Path(sys.argv[2]).write_text(text.replace(sys.argv[3], "CODEWIRE_SCCACHE_REQUEST: ${{ ", 1))
PY
! cmp -s "$WORKFLOW" "$work/unforced-ci.yaml" || fail 'the unforced fixture changed nothing'
if check_main_cache_runners "$work/unforced-ci.yaml" 2>"$work/unforced.err"; then
  fail 'an unsized cache job that fetches on main was accepted'
fi

grep -Fq "readonly fetcher=\"\${OPENBAO_SCCACHE_FETCHER:-\$ROOT/scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh}\"" \
  "$SELECTOR" || fail 'cache selector does not use the reviewed OpenBao exchange'
grep -Fq "shred -u -- \"\$credentials_file\"" "$FINISHER" ||
  fail 'cache finisher does not remove its private credential'
if grep -Eq '^      (SCCACHE_BUCKET|SCCACHE_ENDPOINT|CODEWIRE_SCCACHE_PREFIX):' "$WORKFLOW"; then
  fail 'workflow exposes remote cache configuration outside selected cache steps'
fi

printf '[test-fetch-openbao-sccache-r2-credentials] exact-claim %s-job private-file contract passed\n' "${#cache_jobs[@]}"
