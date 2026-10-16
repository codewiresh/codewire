#!/usr/bin/env bash
# Worktree-owned pre-push policy. The shared .githooks/pre-push dispatcher
# execs this file from the pushing worktree, so the policy versions with the
# tree it verifies.
#
# A feature-branch push needs only the fast push check. With no receipt for
# the pushed tree, the hook runs it now (a few minutes on a warm worktree).
# A direct update of canonical main needs merge qualification
# (scripts/dev/preflight.sh --for-merge --emit-receipt).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFLIGHT="$ROOT/scripts/dev/preflight.sh"
LOCAL_RECEIPT="$ROOT/scripts/ci/receipts/local-prepush-receipt.py"

preflight_mode="${CODEWIRE_PREFLIGHT_MODE:-default}"
case "$preflight_mode" in
  default|integration|kind|full|ci) ;;
  *)
    echo "pre-push: CODEWIRE_PREFLIGHT_MODE must be default, integration, kind, full, or ci" >&2
    exit 2
    ;;
esac
export CODEWIRE_PREFLIGHT_MODE="$preflight_mode"

push_count=0
delete_count=0
local_ref=""
head_sha=""
base_sha=""
remote_ref=""
if [ ! -t 0 ]; then
  while read -r candidate_local_ref candidate_head candidate_remote_ref candidate_base; do
    [ -n "${candidate_head:-}" ] || continue
    push_count=$((push_count + 1))
    [[ "$candidate_head" =~ ^0+$ ]] && delete_count=$((delete_count + 1))
    local_ref="$candidate_local_ref"
    head_sha="$candidate_head"
    base_sha="$candidate_base"
    remote_ref="$candidate_remote_ref"
  done
fi
# Every check below runs with stdin closed; the ref list is consumed.
exec </dev/null

if [ "$push_count" -gt 1 ] && [ "$delete_count" -eq "$push_count" ]; then
  # Deleting refs needs no verification, so a push of deletions only may name
  # any number of them; it carries no commit to check.
  if [ "$preflight_mode" = ci ]; then
    echo "pre-push: CI-owned verification does not authorize ref deletion" >&2
    exit 1
  fi
  exit 0
elif [ "$push_count" -gt 1 ]; then
  echo "pre-push: multi-ref pushes are unsupported; push one ref at a time" >&2
  exit 1
elif [ "$push_count" -eq 1 ]; then
  if [[ "$head_sha" =~ ^0+$ ]]; then
    if [ "$preflight_mode" = ci ]; then
      echo "pre-push: CI-owned verification does not authorize ref deletion" >&2
      exit 1
    fi
    exit 0
  fi
  export PREFLIGHT_HEAD_SHA="$head_sha"
  if [[ "$local_ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    && [ "$remote_ref" = "$local_ref" ]; then
    export PREFLIGHT_RELEASE_TAG_REF="$local_ref"
    export PREFLIGHT_RELEASE_TAG_OBJECT_SHA="$head_sha"
    export PREFLIGHT_PUSH_REMOTE_NAME="${1:-}"
    export PREFLIGHT_RECEIPT_ONLY=true
    exec "$PREFLIGHT"
  fi
  # Feature branches are always compared with canonical main so the local
  # selection matches pull-request CI. A direct main push compares the exact
  # remote before/after range supplied by Git.
  if [ "$remote_ref" = refs/heads/main ] && [[ ! "$base_sha" =~ ^0+$ ]]; then
    export PREFLIGHT_BASE_SHA="$base_sha"
  fi
fi

if [ "$preflight_mode" = ci ]; then
  if [ "$push_count" -ne 1 ] \
      || [[ ! "$remote_ref" =~ ^refs/heads/ ]] \
      || [ "$remote_ref" = refs/heads/main ]; then
    echo "pre-push: CI-owned verification is limited to one non-main feature-branch update" >&2
    exit 1
  fi

  if ! clean_output="$($LOCAL_RECEIPT check-clean 2>&1)"; then
    printf '%s\n' "$clean_output" >&2
    echo "pre-push: CI-owned verification requires a clean worktree" >&2
    exit 1
  fi

  remote_name="${1:-origin}"
  canonical_ref="refs/remotes/$remote_name/main"
  if ! canonical_base="$(git rev-parse --verify "$canonical_ref^{commit}" 2>/dev/null)"; then
    printf 'pre-push: CI-owned verification cannot resolve canonical base %s\n' \
      "$canonical_ref" >&2
    exit 1
  fi
  if ! git merge-base --is-ancestor "$canonical_base" "$head_sha"; then
    printf 'pre-push: CI-owned verification requires head %s to contain canonical base %s\n' \
      "$head_sha" "$canonical_base" >&2
    exit 1
  fi

  printf 'pre-push: deferring exact-tree verification to required Forgejo CI head=%s base=%s\n' \
    "$head_sha" "$canonical_base"
  exit 0
fi

accept_scope=any
if [ "$remote_ref" = refs/heads/main ]; then
  accept_scope=merge
fi
receipt_args=(verify --head "${head_sha:-HEAD}" --accept-scope "$accept_scope")
if [ -n "${PREFLIGHT_BASE_SHA:-}" ]; then
  receipt_args+=(--base "$PREFLIGHT_BASE_SHA")
fi
if [ -n "${1:-}" ]; then
  receipt_args+=(--remote-name "$1")
fi

accept_receipt() {
  local output scope not_run verified_base
  output="$($LOCAL_RECEIPT "${receipt_args[@]}" 2>&1)" || {
    printf '%s\n' "$output"
    return 1
  }
  scope="$(sed -n 's/^scope=//p' <<<"$output")"
  not_run="$(sed -n 's/^not_run=//p' <<<"$output")"
  verified_base="$(sed -n 's/^verified_base=//p' <<<"$output")"
  if [ -n "$verified_base" ]; then
    # Main moved forward since the check, with no commit touching the change.
    printf 'pre-push: local %s receipt accepted for %s; checked against main at %s, which has since moved outside the change\n' \
      "$scope" "${head_sha:-HEAD}" "$verified_base"
  else
    printf 'pre-push: exact-tree local %s receipt accepted for %s\n' "$scope" "${head_sha:-HEAD}"
  fi
  if [ -n "$not_run" ]; then
    printf 'pre-push: not run locally: %s; post-merge CI owns it\n' "$not_run"
  fi
}

receipt_reason() {
  local reason
  reason="$(sed -n 's/^reason=//p' <<<"$1" | tail -n 1)"
  [[ "$reason" =~ ^[a-z0-9-]+$ ]] || reason=checker-failed
  printf '%s\n' "$reason"
}

if receipt_output="$(accept_receipt)"; then
  printf '%s\n' "$receipt_output"
  exit 0
fi
reason="$(receipt_reason "$receipt_output")"

if [ "$accept_scope" = merge ]; then
  printf 'pre-push: no valid merge receipt (%s). Run exactly: scripts/dev/preflight.sh --for-merge --emit-receipt\n' \
    "$reason" >&2
  exit 1
fi

# Run the fast check here only for the commit this worktree has checked out.
if [ -n "$head_sha" ] && [ "$(git rev-parse HEAD)" != "$head_sha" ]; then
  printf 'pre-push: no valid receipt (%s) and the pushed commit is not checked out here. Run exactly: scripts/dev/preflight.sh --for-push --emit-receipt\n' \
    "$reason" >&2
  exit 1
fi
printf 'pre-push: no valid receipt (%s); running the fast push check\n' "$reason"
if ! env -u PREFLIGHT_HEAD_SHA -u PREFLIGHT_BASE_SHA -u CODEWIRE_PREFLIGHT_MODE \
    "$PREFLIGHT" --for-push --emit-receipt; then
  echo 'pre-push: push check failed; fix it and push again' >&2
  exit 1
fi
if ! receipt_output="$(accept_receipt)"; then
  printf 'pre-push: push check passed but its receipt was rejected (%s)\n' \
    "$(receipt_reason "$receipt_output")" >&2
  exit 1
fi
printf '%s\n' "$receipt_output"
