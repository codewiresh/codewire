#!/usr/bin/env bash
# Verify one image of the support pair main published for a release, for
# deploy-prod.yaml's publish job. The source-SHA index must already exist, and
# build-push-image.sh verifies it whole; a release builds nothing (#2892). A
# reused index may carry the provenance of the earlier commit it was aliased
# from: CODEWIRE_PROVENANCE_REVISION names that commit (finish-prod-release.sh).
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
exec env -u CODEWIRE_IMAGE_JOIN -u CODEWIRE_IMAGE_PLATFORM \
  REQUIRE_EXISTING_SOURCE_IMAGE=1 "$BUILDER" "$@"
