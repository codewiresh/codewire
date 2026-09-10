#!/usr/bin/env bash
# Bind one explicitly requested experiment case before any workspace build.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
[[ $# == 1 ]] || { echo 'usage: prepare-workspace-cache-measurement.sh CASE' >&2; exit 2; }
case_name="$1"
case "$case_name" in
  seed|warm-1|warm-2) compiler=r2 layers=r2 ;;
  cold) compiler=disabled layers=disabled ;;
  compiler) compiler=r2 layers=disabled ;;
  *) echo 'invalid workspace measurement case' >&2; exit 2 ;;
esac
[[ "${CODEWIRE_SCCACHE_MODE:-}" == "$compiler" && "${CODEWIRE_BUILDKIT_CACHE_MODE:-}" == "$layers" ]] || {
  echo 'workspace measurement did not resolve both required cache modes' >&2; exit 1;
}
# Each case deliberately supplies its own cache requests. Validate the shared
# cost request independently, using the same stored event/source predicate.
selected="$(CODEWIRE_BUILDKIT_CACHE_REQUEST=auto python3 "$ROOT/scripts/ci/setup/select-workspace-cache-experiment.py")"
jq -e '.selected == true' <<<"$selected" >/dev/null
: "${GITHUB_ENV:?}" "${RUNNER_TEMP:?}"
report="$RUNNER_TEMP/workspace-cache-measurement-$case_name"
[[ "$report" == /* && "$(realpath -m -- "$report")" == "$report" && ! -e "$report" && ! -L "$report" ]] || exit 2
[[ "$report" != *$'\n'* ]] || exit 2
seed=''
if [[ "$case_name" != seed ]]; then
  seed="$(python3 "$ROOT/scripts/ci/verify/workspace-cache-report.py" seed-id)"
fi
{
  printf 'CODEWIRE_WORKSPACE_CACHE_CASE=%s\n' "$case_name"
  printf 'CODEWIRE_WORKSPACE_CACHE_REPORT_DIR=%s\n' "$report"
  printf 'CODEWIRE_WORKSPACE_CACHE_SEED_ID=%s\n' "$seed"
  printf 'CODEWIRE_WORKSPACE_IMAGE_REUSE=disabled\n'
} >>"$GITHUB_ENV"
