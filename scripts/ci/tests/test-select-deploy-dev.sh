#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SELECTOR="$ROOT/scripts/ci/select/select-deploy-dev.sh"

tmp="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

head_sha="$(git -C "$ROOT" rev-parse HEAD)"

output="$(
  cd "$ROOT"
  env -u GITHUB_OUTPUT "$SELECTOR" invalid-baseline "$head_sha"
)"
grep -Fxq 'deploy_dev=true' <<<"$output"
grep -Fxq 'reason=baseline_unavailable' <<<"$output"

github_output="$tmp/github-output"
(
  cd "$ROOT"
  GITHUB_OUTPUT="$github_output" "$SELECTOR" "$head_sha" "$head_sha" >/dev/null
)
grep -Fxq 'deploy_dev=false' "$github_output"
grep -Fxq 'reason=no_changes' "$github_output"

python3 "$ROOT/scripts/ci/tests/test-artifact-impact.py"
python3 "$ROOT/scripts/ci/select/artifact-impact.py" check-contract --mode runtime

printf '[test-select-deploy-dev] wrapper fail-safe and artifact-impact cases passed\n'
