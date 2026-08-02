#!/usr/bin/env bash
# Build and inspect the workspace image without publishing it. This runs in
# pull-request CI and intentionally proves the user-facing agent contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
tag="codewire-workspace-verify:${GITHUB_SHA:-local}"
docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"

# Use the same isolated Docker-container builder locally and in CI. The helper
# loads the exact result into Docker without changing the selected builder.
CODEWIRE_DOCKER_BIN="$docker_bin" "$ROOT/scripts/ci/images/build-local-image.sh" \
  "$tag" \
  "$ROOT/images/workspace/Dockerfile" \
  "$ROOT"

"$docker_bin" run --rm --interactive --pids-limit=2048 --user codewire --entrypoint bash \
  "$tag" -eu -s <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"
