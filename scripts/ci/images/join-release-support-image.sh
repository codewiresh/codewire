#!/usr/bin/env bash
# Join one image of a release's support pair, or reuse the one main published,
# for deploy-prod.yaml's publish job. With BUILD_SUPPORT_PAIR=true it joins the
# two platform digests the release's platform jobs built and verified (amd64
# then arm64) into the source-SHA index, which build-push-image.sh verifies
# whole before it tags it. With BUILD_SUPPORT_PAIR=false the published index
# must already exist. Either way nothing is built here, so no platform can be
# built under emulation.
#
# Usage: join-release-support-image.sh base|workspace DOCKERFILE CONTEXT
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILDER="${RELEASE_SUPPORT_IMAGE_BUILDER:-$ROOT/scripts/ci/images/build-push-image.sh}"

fail() {
  printf '[join-release-support-image] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || {
  echo 'usage: join-release-support-image.sh base|workspace DOCKERFILE CONTEXT' >&2
  exit 2
}
case "$1" in
  base|workspace) ;;
  *) fail "not a support image: $1" ;;
esac
readonly digest_pattern='^sha256:[0-9a-f]{64}$'
case "${BUILD_SUPPORT_PAIR:-}" in
  true)
    [[ "${AMD64_DIGEST:-}" =~ $digest_pattern && "${ARM64_DIGEST:-}" =~ $digest_pattern ]] ||
      fail "the release built its $1 pair but did not report both exact platform digests"
    exec env -u REQUIRE_EXISTING_SOURCE_IMAGE -u CODEWIRE_IMAGE_PLATFORM \
      CODEWIRE_IMAGE_JOIN="$AMD64_DIGEST $ARM64_DIGEST" "$BUILDER" "$@"
    ;;
  false)
    [[ -z "${AMD64_DIGEST:-}" && -z "${ARM64_DIGEST:-}" ]] ||
      fail "a reused $1 index takes no platform digests"
    exec env -u CODEWIRE_IMAGE_JOIN -u CODEWIRE_IMAGE_PLATFORM \
      REQUIRE_EXISTING_SOURCE_IMAGE=1 "$BUILDER" "$@"
    ;;
  *) fail 'BUILD_SUPPORT_PAIR must be true or false' ;;
esac
