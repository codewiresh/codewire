#!/usr/bin/env bash
# finish-prod-release.sh: publish the release's support pair and deliver the
# release to Production (#3246). deploy-prod's publishing job runs it once the
# runtime bundle is published. A release builds nothing (#2892): the pair is
# the one main published.
#
#   1. verify the published base and workspace indexes
#      (join-release-support-image.sh), and publish both to Harbor;
#   2. dispatch the signed tag to codewire/deploy promote-prod and wait for
#      Production to accept it (dispatch-deploy-prod.sh);
#   3. mirror them to GHCR, which never gates the release. Production pulls
#      from Harbor, so the mirror follows delivery instead of delaying it;
#      cli-release waits for this whole run, mirror included (#4492).
#
# Environment: RELEASE_TAG, SOURCE_SHA, CODEWIRE_SOURCE_DIR (the release
# checkout), CODEWIRE_IMAGE_REGISTRY, and SUPPORT_PROVENANCE_REVISION, the
# commit the reused pair was built from
# (release-support-pair-state.sh): the release's own source, or the earlier
# commit main aliased it from, whose base and workspace inputs it proved
# identical.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

fail() {
  printf '[finish-prod-release] ERROR: %s\n' "$*" >&2
  exit 1
}

readonly tag="${RELEASE_TAG:?RELEASE_TAG is required}"
readonly source_sha="${SOURCE_SHA:?SOURCE_SHA is required}"
readonly source_dir="${CODEWIRE_SOURCE_DIR:?CODEWIRE_SOURCE_DIR names the release checkout}"
readonly registry="${CODEWIRE_IMAGE_REGISTRY:?CODEWIRE_IMAGE_REGISTRY is required}"
provenance_revision="${SUPPORT_PROVENANCE_REVISION:-$source_sha}"
[[ "$provenance_revision" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'SUPPORT_PROVENANCE_REVISION must be a full lowercase commit ID'
readonly provenance_revision

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-finish-prod-release.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# join IMAGE DOCKERFILE CONTEXT: the verified source-SHA index of IMAGE that
# main published.
join() {
  local image="$1" ref sha
  : >"$work/$image.output"
  GITHUB_OUTPUT="$work/$image.output" CODEWIRE_RELEASE_TAG="$tag" CODEWIRE_SOURCE_SHA="$source_sha" \
    CODEWIRE_PROVENANCE_REVISION="$provenance_revision" \
    "$ROOT/scripts/ci/images/join-release-support-image.sh" "$image" "$2" "$3" ||
    fail "the $image index did not join or verify"
  ref="$(sed -n 's/^candidate_ref=//p' "$work/$image.output" | tail -1)"
  sha="$(sed -n 's/^source_sha=//p' "$work/$image.output" | tail -1)"
  [[ "$sha" == "$source_sha" ]] || fail "the $image index is from ${sha:-no source}, not $source_sha"
  [[ -n "$ref" ]] || fail "the $image index reported no candidate"
  printf '%s' "$ref" >"$work/$image.ref"
}

join base "$source_dir/images/base/Dockerfile" "$source_dir/images/base"
join workspace "$source_dir/images/workspace/Dockerfile" "$source_dir"

for image in base workspace; do
  "$ROOT/scripts/ci/images/publish-image-to-harbor.sh" \
    "$(<"$work/$image.ref")" "$registry/codewire/$image" "$source_sha" "$tag"
done

"$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh" "$tag"

# Harbor serves every consumer; the public GHCR copy never gates release.
for image in base workspace; do
  "$ROOT/scripts/ci/images/publish-image-to-ghcr.sh" \
    "$(<"$work/$image.ref")" "ghcr.io/codewiresh/$image" "$source_sha" "$tag" ||
    printf '::warning::the %s GHCR mirror failed; Harbor holds the release\n' "$image"
done
