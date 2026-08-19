#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ASSERTION="$ROOT/scripts/ci/setup/assert-ci-runner-image.sh"
WORKFLOW_DIR="$ROOT/.gitea/workflows"
WORKFLOWS=(
  "$ROOT/.gitea/workflows/ci.yaml"
  "$ROOT/.gitea/workflows/cli-release.yaml"
  "$ROOT/.gitea/workflows/manual-diagnostics.yaml"
)

test -x "$ASSERTION"

for package in \
  libgtk-3-dev \
  libprotobuf-dev \
  libwebkit2gtk-4.1-dev \
  libxkbcommon-x11-dev \
  pkg-config \
  postgresql-client \
  protobuf-compiler; do
  grep -Fq "$package" "$ASSERTION"
done

grep -Fq '/usr/include/google/protobuf/duration.proto' "$ASSERTION"
grep -Fq '/usr/include/google/protobuf/timestamp.proto' "$ASSERTION"

if rg -n '\bapt-get\b' "$WORKFLOW_DIR"; then
  echo 'CI workflows must consume the immutable runner image instead of installing OS packages at job time' >&2
  exit 1
fi

for workflow in "${WORKFLOWS[@]}"; do
  grep -Fq 'scripts/ci/setup/assert-ci-runner-image.sh' "$workflow"
done

grep -Fq '    runs-on: ci-heavy' \
  "$ROOT/.gitea/workflows/manual-diagnostics.yaml" || {
  echo 'manual Docker/Postgres diagnostics must use the explicit heavy profile' >&2
  exit 1
}
if grep -qE '^permissions:' "$ROOT/.gitea/workflows/manual-diagnostics.yaml"; then
  echo 'manual diagnostics rely on ignored GitHub permissions syntax' >&2
  exit 1
fi

grep -Fq 'scripts/ci/tests/test-ci-runner-image-contract.sh' \
  "$ROOT/.gitea/workflows/ci.yaml"

echo 'CI runner image workflow contract tests: OK'
