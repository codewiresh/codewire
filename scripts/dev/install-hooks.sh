#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

git config core.hooksPath "$REPO_ROOT/.githooks"
chmod +x .githooks/pre-push scripts/dev/preflight.sh

echo "hooks installed: core.hooksPath = $REPO_ROOT/.githooks"
echo "  pre-push resolves scripts/dev/preflight.sh from the worktree invoking git push"
