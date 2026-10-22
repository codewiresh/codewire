#!/usr/bin/env bash
# Worktree-owned pre-push policy. The shared .githooks/pre-push dispatcher
# execs this file from the pushing worktree, so the policy versions with the
# tree it checks.
#
# A feature-branch push runs the fast push check: formatting, lints and unit
# tests for the changed crates, and quick checks for the changed file types.
# Pull-request CI is the merge gate (#3119 step 2); nothing local qualifies a
# merge, and main takes changes only through pull requests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFLIGHT="$ROOT/scripts/dev/preflight.sh"

push_count=0
delete_count=0
local_ref=""
head_sha=""
remote_ref=""
if [ ! -t 0 ]; then
  while read -r candidate_local_ref candidate_head candidate_remote_ref _candidate_base; do
    [ -n "${candidate_head:-}" ] || continue
    push_count=$((push_count + 1))
    [[ "$candidate_head" =~ ^0+$ ]] && delete_count=$((delete_count + 1))
    local_ref="$candidate_local_ref"
    head_sha="$candidate_head"
    remote_ref="$candidate_remote_ref"
  done
fi
# Every check below runs with stdin closed; the ref list is consumed.
exec </dev/null

# Deleting refs needs no check, so a push of deletions only may name any
# number of them.
if [ "$push_count" -gt 0 ] && [ "$delete_count" -eq "$push_count" ]; then
  exit 0
fi
if [ "$push_count" -gt 1 ]; then
  echo "pre-push: multi-ref pushes are unsupported; push one ref at a time" >&2
  exit 1
fi

if [ "$push_count" -eq 1 ]; then
  if [[ "$local_ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    && [ "$remote_ref" = "$local_ref" ]; then
    export PREFLIGHT_HEAD_SHA="$head_sha"
    export PREFLIGHT_RELEASE_TAG_REF="$local_ref"
    export PREFLIGHT_RELEASE_TAG_OBJECT_SHA="$head_sha"
    export PREFLIGHT_PUSH_REMOTE_NAME="${1:-}"
    export PREFLIGHT_RECEIPT_ONLY=true
    exec "$PREFLIGHT"
  fi
  if [ "$remote_ref" = refs/heads/main ]; then
    echo "pre-push: main takes changes only through pull requests; push a branch and open one" >&2
    exit 1
  fi
  # The push check reads the worktree, so it runs only for the commit this
  # worktree has checked out.
  if [ "$(git rev-parse HEAD)" != "$head_sha" ]; then
    printf 'pre-push: %s is not checked out here; push from the worktree that holds it\n' \
      "$head_sha" >&2
    exit 1
  fi
fi

if ! "$PREFLIGHT" --for-push; then
  echo 'pre-push: push check failed; fix it and push again' >&2
  exit 1
fi
