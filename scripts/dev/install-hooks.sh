#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

COMMON_DIR="$(git rev-parse --path-format=absolute --git-common-dir)"
DISPATCHER_DIR="$COMMON_DIR/codewire-hooks"
install -d -m 755 "$DISPATCHER_DIR"
install -m 755 .githooks/pre-push "$DISPATCHER_DIR/pre-push"
git config core.hooksPath "$DISPATCHER_DIR"
chmod +x scripts/dev/preflight.sh

echo "hooks installed: core.hooksPath = $DISPATCHER_DIR"
echo "  stable pre-push dispatcher copied into the common Git directory"
echo "  dispatcher resolves scripts/dev/preflight.sh from the pushing worktree"
