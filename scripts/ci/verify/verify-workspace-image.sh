#!/usr/bin/env bash
# Build and inspect the workspace image without publishing it. This runs in
# pull-request CI and intentionally proves the user-facing agent contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
tag="codewire-workspace-verify:${GITHUB_SHA:-local}"

# Gitea runners use Buildx's docker-container driver. Request a local image
# explicitly so the inspection below never falls back to a registry pull.
docker buildx build \
  --load \
  --tag "$tag" \
  --file "$ROOT/images/workspace/Dockerfile" \
  "$ROOT"

docker run --rm --user codewire --entrypoint sh "$tag" -eu -c '
  test "$(id -un)" = codewire
  for agent in codex claude gemini kimi pi aider; do
    executable="$(command -v "$agent")"
    test -n "$executable"
    test -O "$(readlink -f "$executable")"
    "$agent" --version
  done

  # Codex is installed in the interactive-user npm prefix. A dry run proves
  # the real vendor update path without mutating the verification image.
  npm update --global --dry-run @openai/codex
'
