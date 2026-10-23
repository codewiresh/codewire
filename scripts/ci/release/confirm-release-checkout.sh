#!/usr/bin/env bash
# Confirm that a job's release checkout is the release release-selection
# verified. Each job checks the tag out again, so a tag moved or recreated
# after selection would otherwise build different source under the same name.
set -euo pipefail

usage() {
  echo 'usage: confirm-release-checkout.sh DIR (with RELEASE_TAG, SOURCE_SHA and TAG_OBJECT_SHA set)' >&2
  exit 2
}

fail() {
  printf 'release checkout refused: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || usage
dir="$1"
tag="${RELEASE_TAG:-}"
source_sha="${SOURCE_SHA:-}"
tag_object_sha="${TAG_OBJECT_SHA:-}"

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "release tag '$tag' is not exact semver"
valid_object_id() {
  [[ "$1" =~ ^[0-9a-f]{40}$ || "$1" =~ ^[0-9a-f]{64}$ ]]
}
valid_object_id "$source_sha" || fail 'selected source is not a commit ID'
valid_object_id "$tag_object_sha" || fail 'selected tag object is not an object ID'

head="$(git -C "$dir" rev-parse --verify HEAD 2>/dev/null)" ||
  fail "$dir has no checkout"
[[ "$head" == "$source_sha" ]] ||
  fail "$dir is at $head, not the selected source $source_sha"
object="$(git -C "$dir" rev-parse --verify "refs/tags/$tag" 2>/dev/null)" ||
  fail "$dir has no tag $tag"
[[ "$object" == "$tag_object_sha" ]] ||
  fail "tag $tag is now object $object, not the selected $tag_object_sha"
[[ "$(git -C "$dir" cat-file -t "$object")" == tag ]] ||
  fail "tag $tag is not an annotated tag object"

printf 'release checkout confirmed: tag=%s object=%s commit=%s\n' "$tag" "$object" "$head"
