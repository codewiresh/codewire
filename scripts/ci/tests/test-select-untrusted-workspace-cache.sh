#!/usr/bin/env bash
# Synthetic identity only; exercise the independent request matrix and cleanup.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
selector="$ROOT/scripts/ci/setup/select-untrusted-workspace-cache.sh"
test_source="$(git -C "$ROOT" rev-parse HEAD)"
test_tree="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/workspace-cache-selector-test.XXXXXX")"
credential_work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-workspace-selector-data.XXXXXX")"
trap 'rm -rf "$work" "$credential_work"' EXIT
mkdir "$credential_work/runner" "$work/bin" "$work/minbin"
for tool in bash dirname realpath stat shred rm chmod; do
  ln -s "$(command -v "$tool")" "$work/minbin/$tool"
done
cat >"$work/bin/sccache" <<'SH'
#!/usr/bin/env bash
printf 'sccache %s\n' "${FAKE_SCCACHE_VERSION:-0.17.0}"
SH
chmod 0755 "$work/bin/sccache"
printf '{}\n' >"$work/event.json"
cat >"$work/fetch" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'fetch %s\n' "${CODEWIRE_R2_CACHE_TRUST:-unset}" >>"$FETCH_CALLS"
umask 077
printf '%s\n' '[default]' 'aws_access_key_id = synthetic-cache-access' \
  'aws_secret_access_key = synthetic-cache-secret' >"$1"
case "${FETCH_RESULT:-success}" in
  success) ;;
  unavailable) exit 1 ;;
  public) chmod 0644 "$1" ;;
esac
SH
chmod 0755 "$work/fetch"
select_cache() {
  local rust="$1" layer="$2" file="$3"
  PATH="${TEST_PATH:-$work/bin:$PATH}" RUNNER_TEMP="$credential_work/runner" GITHUB_WORKSPACE="$ROOT" GITHUB_ENV="$work/env" \
    GITHUB_EVENT_NAME="${TEST_EVENT_NAME:-push}" GITHUB_EVENT_PATH="$work/event.json" \
    GITHUB_SHA="$test_source" GITHUB_REF="${TEST_REF:-refs/pull/2047/head}" \
    GITHUB_REPOSITORY=codewire/codewire \
    CODEWIRE_EXPECTED_SOURCE_SHA="$test_source" CODEWIRE_EXPECTED_SOURCE_TREE="$test_tree" \
    FETCH_CALLS="$work/fetch-calls" OPENBAO_SCCACHE_FETCHER="$work/fetch" \
    CODEWIRE_SCCACHE_REQUEST="$rust" CODEWIRE_BUILDKIT_CACHE_REQUEST="$layer" \
    "$selector" "$file"
}
for rust in disabled local auto; do
  for layer in disabled local auto; do
    : >"$work/env"; : >"$work/fetch-calls"
    file="$credential_work/runner/$rust-$layer.aws"
    select_cache "$rust" "$layer" "$file" >"$work/output"
    expected_rust="$rust" expected_layer="$layer" expected_fetch=0
    if [[ "$rust" == auto ]]; then expected_rust=r2; expected_fetch=1; fi
    if [[ "$layer" == auto ]]; then expected_layer=r2; expected_fetch=1; fi
    grep -Fxq "CODEWIRE_SCCACHE_MODE=$expected_rust" "$work/env"
    grep -Fxq "CODEWIRE_BUILDKIT_CACHE_MODE=$expected_layer" "$work/env"
    [[ "$(wc -l <"$work/fetch-calls")" == "$expected_fetch" ]]
    if [[ "$expected_fetch" == 1 ]]; then
      [[ "$(stat -c %a "$file")" == 600 ]]
      grep -Fxq "CODEWIRE_SCCACHE_CREDENTIALS_FILE=$file" "$work/env"
    else
      [[ ! -e "$file" ]]
      ! grep -q '^CODEWIRE_SCCACHE_CREDENTIALS_FILE=' "$work/env" || exit 1
    fi
    ! grep -Eq 'synthetic-cache-(access|secret)' "$work/env" "$work/output" || exit 1
  done
done
# Pull requests read main's caches read-only; canonical main reads and writes them.
grep -Fxq SCCACHE_BUCKET=example-ci-cache-protected "$work/env"
grep -Fxq CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 "$work/env"
grep -Fxq CODEWIRE_R2_CACHE_TRUST=protected-read "$work/env"
grep -Fxq SCCACHE_S3_RW_MODE=READ_ONLY "$work/env"
grep -Fxq 'fetch protected-read' "$work/fetch-calls"
! grep -Fq untrusted "$work/env" || exit 1
: >"$work/env"; : >"$work/fetch-calls"
TEST_REF=refs/heads/main select_cache auto auto "$credential_work/runner/main.aws" >"$work/output"
grep -Fxq SCCACHE_BUCKET=example-ci-cache-protected "$work/env"
grep -Fxq CODEWIRE_SCCACHE_PREFIX=protected/codewire/v1 "$work/env"
grep -Fxq SCCACHE_S3_KEY_PREFIX=protected/codewire/v1 "$work/env"
grep -Fxq CODEWIRE_R2_CACHE_TRUST=main "$work/env"
grep -Fxq 'fetch main' "$work/fetch-calls"
! grep -Eq 'untrusted|READ_ONLY' "$work/env" || exit 1
grep -Fq 'trust=main' "$work/output"
: >"$work/env"; : >"$work/fetch-calls"
FETCH_RESULT=unavailable select_cache auto auto "$credential_work/runner/fallback.aws" >"$work/output"
grep -Fxq CODEWIRE_SCCACHE_MODE=local "$work/env"
grep -Fxq CODEWIRE_BUILDKIT_CACHE_MODE=local "$work/env"
[[ ! -e "$credential_work/runner/fallback.aws" && "$(wc -l <"$work/fetch-calls")" == 1 ]]
! grep -q '^SCCACHE_BUCKET=' "$work/env" || exit 1
: >"$work/env"; : >"$work/fetch-calls"
if select_cache disabled invalid "$credential_work/runner/invalid.aws" >/dev/null 2>&1; then exit 1; fi
[[ ! -s "$work/env" && ! -s "$work/fetch-calls" ]]
for file in "$work/escape.aws" "$credential_work/runner/../escape.aws" "$credential_work/runner/auto-auto.aws"; do
  if select_cache auto auto "$file" >/dev/null 2>&1; then exit 1; fi
done
ln -s "$credential_work/runner/auto-auto.aws" "$credential_work/runner/link.aws"
if select_cache auto auto "$credential_work/runner/link.aws" >/dev/null 2>&1; then exit 1; fi
if FETCH_RESULT=public select_cache auto auto "$credential_work/runner/public.aws" >/dev/null 2>&1; then exit 1; fi
[[ ! -e "$credential_work/runner/public.aws" ]]
for availability in missing wrong; do
  : >"$work/env"; : >"$work/fetch-calls"
  test_path="$work/minbin"
  [[ "$availability" != wrong ]] || test_path="$work/bin:$work/minbin"
  TEST_PATH="$test_path" FAKE_SCCACHE_VERSION=0.16.0 \
    select_cache auto auto "$credential_work/runner/$availability.aws" >"$work/output"
  grep -Fxq CODEWIRE_SCCACHE_MODE=disabled "$work/env"
  grep -Fxq CODEWIRE_BUILDKIT_CACHE_MODE=r2 "$work/env"
  [[ "$(wc -l <"$work/fetch-calls")" == 1 ]]
  if grep -q '^RUSTC_WRAPPER=' "$work/env"; then exit 1; fi
  : >"$work/env"; : >"$work/fetch-calls"
  TEST_PATH="$test_path" FAKE_SCCACHE_VERSION=0.16.0 \
    select_cache auto local "$credential_work/runner/$availability-local.aws" >"$work/output"
  grep -Fxq CODEWIRE_SCCACHE_MODE=disabled "$work/env"
  [[ ! -s "$work/fetch-calls" && ! -e "$credential_work/runner/$availability-local.aws" ]]
done
for event in unlabeled null_labels omitted_labels exact other manual; do
  case "$event" in
    exact|manual) printf '{"pull_request":{"labels":[{"name":"ci/r2-cache-canary"}]}}\n' >"$work/event.json" ;;
    other) printf '{"pull_request":{"labels":[{"name":"ci/r2-cache-canary-extra"}]}}\n' >"$work/event.json" ;;
    unlabeled) printf '{"pull_request":{"labels":[]}}\n' >"$work/event.json" ;;
    null_labels) printf '{"pull_request":{"labels":null}}\n' >"$work/event.json" ;;
    omitted_labels) printf '{"pull_request":{}}\n' >"$work/event.json" ;;
  esac
  jq --arg source "$test_source" '.repository={full_name:"codewire/codewire"} | .pull_request += {number:2047,head:{sha:$source,ref:"ci/cache-fixture"},base:{ref:"main",repo:{full_name:"codewire/codewire"}}}' \
    "$work/event.json" >"$work/event-complete.json"
  mv "$work/event-complete.json" "$work/event.json"
  for request in '' auto local disabled; do
    : >"$work/env"; : >"$work/fetch-calls"
    event_name=pull_request
    [[ "$event" != manual ]] || event_name=workflow_dispatch
    TEST_EVENT_NAME="$event_name" select_cache disabled "$request" "$credential_work/runner/label-$event-${request:-implicit}.aws" >"$work/output"
    expected_canary=false expected_layers="${request:-local}"
    [[ "$expected_layers" != auto ]] || expected_layers=r2
    if [[ "$event" == exact && ( -z "$request" || "$request" == auto ) ]]; then
      expected_canary=true expected_layers=r2
    fi
    grep -Fxq "CODEWIRE_WORKSPACE_CACHE_CANARY=$expected_canary" "$work/env"
    grep -Fxq "CODEWIRE_BUILDKIT_CACHE_MODE=$expected_layers" "$work/env"
    # Only a labelled pull-request experiment uses the disposable untrusted bucket.
    if [[ "$expected_layers" == r2 ]]; then
      expected_trust=protected-read
      [[ "$event" != exact ]] || expected_trust=untrusted
      grep -Fxq "CODEWIRE_R2_CACHE_TRUST=$expected_trust" "$work/env"
      grep -Fxq "fetch $expected_trust" "$work/fetch-calls"
    fi
  done
done
printf '{"pull_request":{"labels":[{"name":"ci/r2-cache-canary"}]}}\n' >"$work/event.json"
jq --arg source "$test_source" '.repository={full_name:"codewire/codewire"} | .pull_request += {number:2047,head:{sha:$source,ref:"ci/cache-fixture"},base:{ref:"main",repo:{full_name:"codewire/codewire"}}}' \
  "$work/event.json" >"$work/event-complete.json"
mv "$work/event-complete.json" "$work/event.json"
: >"$work/env"; : >"$work/fetch-calls"
TEST_EVENT_NAME=pull_request FETCH_RESULT=unavailable select_cache disabled '' "$credential_work/runner/label-unavailable.aws" >"$work/output"
grep -Fxq CODEWIRE_WORKSPACE_CACHE_CANARY=true "$work/env"
grep -Fxq CODEWIRE_BUILDKIT_CACHE_MODE=local "$work/env"
for malformed in 'not-json' '{"pull_request":{"labels":false}}' \
  '{"pull_request":{"labels":true}}' '{"pull_request":{"labels":"ci/r2-cache-canary"}}'; do
  printf '%s\n' "$malformed" >"$work/event.json"
  : >"$work/fetch-calls"
  if TEST_EVENT_NAME=pull_request select_cache disabled '' "$credential_work/runner/label-malformed.aws" >/dev/null 2>&1; then exit 1; fi
  [[ ! -s "$work/fetch-calls" ]]
done
printf 'workspace cache selector: 9 mode pairs, one-fetch fallback and private-path rejection passed\n'
