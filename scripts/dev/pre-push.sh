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
remote_sha=""
if [ ! -t 0 ]; then
  while read -r candidate_local_ref candidate_head candidate_remote_ref candidate_remote_sha; do
    [ -n "${candidate_head:-}" ] || continue
    push_count=$((push_count + 1))
    [[ "$candidate_head" =~ ^0+$ ]] && delete_count=$((delete_count + 1))
    local_ref="$candidate_local_ref"
    head_sha="$candidate_head"
    remote_ref="$candidate_remote_ref"
    remote_sha="$candidate_remote_sha"
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
    exec "$PREFLIGHT"
  fi
  # A Go module version tag for a library under libs/ (#3512) is not a
  # Codewire release: no release checks, and no release workflow picks it up.
  # It must be an annotated tag naming a commit already on the remote's main,
  # and new there: Go's checksum database records each version once, so a
  # moved version breaks `go get` for good. Its message is public once the
  # mirror carries it.
  if [[ "$local_ref" =~ ^refs/tags/libs/(gen-go|sdk-go)/v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    && [ "$remote_ref" = "$local_ref" ]; then
    module_remote="${1:-origin}"
    if [[ -n "$remote_sha" && ! "$remote_sha" =~ ^0+$ ]]; then
      printf 'pre-push: %s is already on %s; a Go module version is never moved\n' \
        "${local_ref#refs/tags/}" "$module_remote" >&2
      exit 1
    fi
    if [ "$(git cat-file -t "$head_sha" 2>/dev/null)" != tag ]; then
      printf 'pre-push: %s is not an annotated tag\n' "${local_ref#refs/tags/}" >&2
      exit 1
    fi
    module_commit="$(git rev-parse --verify --quiet "${head_sha}^{commit}")" || {
      printf 'pre-push: %s names no commit\n' "${local_ref#refs/tags/}" >&2
      exit 1
    }
    module_main="$(git ls-remote "$module_remote" refs/heads/main |
      awk '$2 == "refs/heads/main" { print $1 }')" || module_main=''
    [[ "$module_main" =~ ^[0-9a-f]{40}$ ]] || {
      printf "pre-push: %s's main is unavailable\n" "$module_remote" >&2
      exit 1
    }
    if [ "$module_commit" != "$module_main" ]; then
      git cat-file -e "${module_main}^{commit}" 2>/dev/null ||
        git fetch --quiet --no-tags "$module_remote" refs/heads/main || {
          printf "pre-push: could not fetch %s's main\n" "$module_remote" >&2
          exit 1
        }
      git merge-base --is-ancestor "$module_commit" "$module_main" || {
        printf "pre-push: %s names %s, which is not on %s's main\n" \
          "${local_ref#refs/tags/}" "$module_commit" "$module_remote" >&2
        exit 1
      }
    fi
    exit 0
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
