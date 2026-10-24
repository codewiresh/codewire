#!/usr/bin/env bash
# finish-prod-release.sh: publish the release's support pair and deliver the
# release to Production (#3246). deploy-prod runs it once the runtime bundle is
# published: in the publishing job when the release reuses the support pair
# main published, or after the native platform builds otherwise.
#
#   1. join and verify the base and workspace indexes, or reuse the published
#      ones (join-release-support-image.sh), and publish both to Harbor;
#   2. mirror them to GHCR, which never gates the release;
#   3. dispatch the signed tag to codewire/deploy promote-prod and wait for
#      Production to accept it (dispatch-deploy-prod.sh).
#
# Environment: RELEASE_TAG, SOURCE_SHA, CODEWIRE_SOURCE_DIR (the release
# checkout), CODEWIRE_IMAGE_REGISTRY, BUILD_SUPPORT_PAIR (true or false), and
# with true the four platform digests BASE_AMD64_DIGEST, BASE_ARM64_DIGEST,
# WORKSPACE_AMD64_DIGEST and WORKSPACE_ARM64_DIGEST.
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
case "${BUILD_SUPPORT_PAIR:-}" in
  true|false) ;;
  *) fail 'BUILD_SUPPORT_PAIR must be true or false' ;;
esac

work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-finish-prod-release.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# join IMAGE DOCKERFILE CONTEXT AMD64 ARM64: the verified source-SHA index of
# IMAGE, joined from the release's platform digests or reused from main.
join() {
  local image="$1" amd64="" arm64="" ref sha
  if [[ "$BUILD_SUPPORT_PAIR" == true ]]; then
    amd64="$4" arm64="$5"
  fi
  : >"$work/$image.output"
  GITHUB_OUTPUT="$work/$image.output" CODEWIRE_RELEASE_TAG="$tag" CODEWIRE_SOURCE_SHA="$source_sha" \
    AMD64_DIGEST="$amd64" ARM64_DIGEST="$arm64" \
    "$ROOT/scripts/ci/images/join-release-support-image.sh" "$image" "$2" "$3" ||
    fail "the $image index did not join or verify"
  ref="$(sed -n 's/^candidate_ref=//p' "$work/$image.output" | tail -1)"
  sha="$(sed -n 's/^source_sha=//p' "$work/$image.output" | tail -1)"
  [[ "$sha" == "$source_sha" ]] || fail "the $image index is from ${sha:-no source}, not $source_sha"
  [[ -n "$ref" ]] || fail "the $image index reported no candidate"
  printf '%s' "$ref" >"$work/$image.ref"
}

join base "$source_dir/images/base/Dockerfile" "$source_dir/images/base" \
  "${BASE_AMD64_DIGEST:-}" "${BASE_ARM64_DIGEST:-}"
join workspace "$source_dir/images/workspace/Dockerfile" "$source_dir" \
  "${WORKSPACE_AMD64_DIGEST:-}" "${WORKSPACE_ARM64_DIGEST:-}"

for image in base workspace; do
  "$ROOT/scripts/ci/images/publish-image-to-harbor.sh" \
    "$(<"$work/$image.ref")" "$registry/codewire/$image" "$source_sha" "$tag"
done

# Harbor serves every consumer; the public GHCR copy never gates release.
for image in base workspace; do
  "$ROOT/scripts/ci/images/publish-image-to-ghcr.sh" \
    "$(<"$work/$image.ref")" "ghcr.io/codewiresh/$image" "$source_sha" "$tag" ||
    printf '::warning::the %s GHCR mirror failed; Harbor holds the release\n' "$image"
done

"$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh" "$tag"
