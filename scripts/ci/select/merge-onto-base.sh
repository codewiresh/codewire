#!/usr/bin/env bash
# merge-onto-base.sh BASE_REF: a pull request run builds and tests its head
# merged onto the base branch's current tip, not the head alone (#5146). The
# build runner's warm folder then tracks the base branch, and a build compiles
# little more than the pull request's own change, where the head alone
# recompiled whatever differed from the last pull request built there (about
# 131 crates for a one-line change in run 58138).
#
# Run from selection's full checkout of the head. Writes merge_onto (the tip)
# and merged_tree (the tree the merge must give) to GITHUB_OUTPUT. A head that
# does not merge cleanly onto the tip fails here, before anything builds.
set -euo pipefail
[[ $# -eq 1 && "$1" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo 'usage: merge-onto-base.sh BASE_REF' >&2; exit 2; }
base_ref="$1"
head="$(git rev-parse --verify 'HEAD^{commit}')"
tip="$(git rev-parse --verify "refs/remotes/origin/$base_ref^{commit}")" || {
  echo "::error::merge-onto-base: origin/$base_ref is not in this checkout" >&2
  exit 1
}
if ! tree="$(git merge-tree --write-tree "$tip" "$head")"; then
  echo "::error::this pull request does not merge cleanly onto $base_ref at ${tip:0:12}: merge $base_ref into it and push" >&2
  exit 1
fi
tree="$(head -n 1 <<<"$tree")"
[[ "$tree" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::merge-onto-base: unexpected merge-tree output" >&2; exit 1; }
echo "merge-onto-base: head ${head:0:12} merges onto $base_ref ${tip:0:12}, tree ${tree:0:12}"
{
  echo "merge_onto=$tip"
  echo "merged_tree=$tree"
} >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
