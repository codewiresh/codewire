#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-.}"

if [ "$(git -C "$repo_root" rev-parse --is-inside-work-tree 2>/dev/null || true)" != true ]; then
  echo "resolve-cargo-target-dir: not a Git worktree: $repo_root" >&2
  exit 1
fi

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  case "$CARGO_TARGET_DIR" in
    /*) printf '%s\n' "$CARGO_TARGET_DIR" ;;
    *) printf '%s/%s\n' "$(pwd -P)" "$CARGO_TARGET_DIR" ;;
  esac
  exit 0
fi

common_dir="$(
  git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir
)"
printf '%s/target\n' "$(dirname "$common_dir")"
