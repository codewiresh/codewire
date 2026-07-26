#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

sha256sum --strict --quiet -c tests/fixtures/accepted-bytes.sha256

for retired in \
  apps/api/db \
  apps/api/internal/sandbox/testdata \
  apps/api/internal/worker/testdata \
  tests/contract/billing/testdata \
  tests/contract/coordinator/testdata \
  tests/contract/orchestration/testdata; do
  if [ -e "$retired" ]; then
    echo "retired fixture authority remains: $retired" >&2
    exit 1
  fi
done

for generator in \
  apps/api/internal/sandbox/exec_golden_test.go \
  apps/api/internal/sandbox/golden_test.go \
  apps/api/internal/worker/setup_scripts_golden_test.go; do
  if [ -e "$generator" ]; then
    echo "retired Go golden generator remains: $generator" >&2
    exit 1
  fi
done

# The path selector intentionally names the retired migration home to reject
# resurrection; its dedicated self-test proves that fail-closed case.
if rg -n \
    'apps/api/(db/migrations|internal/sandbox/testdata|internal/worker/testdata)' \
    crates deployments/docker scripts/ci/verify \
    scripts/dev/kind \
    docs/dev/DATABASE-MIGRATIONS.md docs/ARCHITECTURE.md; then
  echo 'active Rust, image, test, or current architecture source retains a retired fixture path' >&2
  exit 1
fi

echo 'rust-owned schema and fixtures: OK'
