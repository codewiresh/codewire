#!/usr/bin/env bash
# Whether main already published the support pair (base and workspace) for a
# release's exact source commit. deploy-prod.yaml reuses a published pair as
# it is, and otherwise builds the pair one platform per job, linux/arm64 on the
# protected arm64 BuildKit node, never under emulation. Harbor is read with the
# pull-only robot. Writes build=false (both published) or build=true (neither
# published) to $GITHUB_OUTPUT. When only the base is published (a cancelled
# release published it), build=true with base_amd64_digest and
# base_arm64_digest, that index's platform images: the release builds only the
# workspace, from exactly that base. A workspace without its base is refused.
#
# Usage: release-support-pair-state.sh SOURCE_SHA
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly REGISTRY_HOST='registry.example.invalid'
readonly REPOSITORY_PREFIX="$REGISTRY_HOST/codewire"

fail() {
  printf '[release-support-pair-state] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'usage: release-support-pair-state.sh SOURCE_SHA (40 lowercase hex)' >&2
  exit 2
}
readonly source_sha="$1"
output="${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
credential_fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-$ROOT/scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/codewire-release-support-pair.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir -m 0700 "$work/docker-config"

"$credential_fetcher" --pull "$work/username" "$work/password" ||
  fail 'the Harbor pull credential could not be read'
DOCKER_CONFIG="$work/docker-config" docker login "$REGISTRY_HOST" \
  -u "$(<"$work/username")" --password-stdin <"$work/password" >/dev/null 2>"$work/login.err" || {
  sed -n '1,20p' "$work/login.err" >&2
  fail "Harbor refused the pull robot at $REGISTRY_HOST"
}

# state IMAGE prints published or missing for IMAGE's source-SHA index.
state() {
  local image="$1" reference="$REPOSITORY_PREFIX/$1:$source_sha"
  if DOCKER_CONFIG="$work/docker-config" docker buildx imagetools inspect \
      --format '{{json .Manifest}}' "$reference" >"$work/$image.json" 2>"$work/$image.err"; then
    jq -e '.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")' "$work/$image.json" >/dev/null ||
      fail "Harbor returned no exact digest for $reference"
    printf 'published\n'
    return
  fi
  if grep -Eqi '(manifest unknown|manifest[^[:cntrl:]]*not found|name unknown|: not found|status code: 404|unexpected status[^[:cntrl:]]*404)' \
      "$work/$image.err"; then
    printf 'missing\n'
    return
  fi
  sed -n '1,20p' "$work/$image.err" >&2
  fail "could not determine whether $reference is published"
}

# platform_digest ARCH prints the published base index's linux/ARCH image.
platform_digest() {
  local digest
  DOCKER_CONFIG="$work/docker-config" docker buildx imagetools inspect --raw \
      "$REPOSITORY_PREFIX/base:$source_sha" >"$work/base-index.json" 2>"$work/base-index.err" || {
    sed -n '1,20p' "$work/base-index.err" >&2
    fail "could not read the published base index for $source_sha"
  }
  digest="$(jq -er --arg arch "$1" '
      [.manifests[]? | select(.platform.os == "linux" and .platform.architecture == $arch) | .digest]
      | select(length == 1) | .[0] | select(test("^sha256:[0-9a-f]{64}$"))' "$work/base-index.json")" ||
    fail "the published base index for $source_sha has no single linux/$1 image"
  printf '%s\n' "$digest"
}

base="$(state base)"
workspace="$(state workspace)"
base_outputs=''
case "$base:$workspace" in
  published:published)
    build=false
    printf 'Reusing the support pair main published for %s\n' "$source_sha" ;;
  missing:missing)
    build=true
    printf 'Main published no support pair for %s; building it here, linux/arm64 on the native node\n' "$source_sha" ;;
  published:missing)
    build=true
    base_outputs="base_amd64_digest=$(platform_digest amd64)
base_arm64_digest=$(platform_digest arm64)"
    printf 'Only the base is published for %s; building the workspace from it, linux/arm64 on the native node\n' "$source_sha" ;;
  *)
    fail "the workspace is published without its base for $source_sha (base $base, workspace $workspace); repair the publication before releasing" ;;
esac
printf 'build=%s\n' "$build" >>"$output"
[[ -z "$base_outputs" ]] || printf '%s\n' "$base_outputs" >>"$output"
