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
# A published pair also writes provenance_revision, the one commit both
# indexes' provenance names. That is the source itself when main built the
# pair for it. When main aliased the pair from an earlier commit with the same
# base and workspace inputs (#3504), the indexes keep that commit's
# provenance, and verify-support-alias.py must derive the same alias from Git
# before the release accepts it; finish-prod-release.sh then verifies the
# indexes against that commit.
#
# Usage: release-support-pair-state.sh SOURCE_SHA
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly REGISTRY_HOST="${CODEWIRE_IMAGE_REGISTRY:?set to the image registry host}"
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
alias_verifier="${RELEASE_SUPPORT_ALIAS_VERIFIER:-$ROOT/scripts/ci/plan/verify-support-alias.py}"

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

# provenance_revision IMAGE prints the one commit that every platform's
# provenance in IMAGE's published index names. build-push-image.sh verifies
# the whole provenance against it later; this only reads which commit it is.
provenance_revision() {
  local reference="$REPOSITORY_PREFIX/$1:$source_sha" revision
  DOCKER_CONFIG="$work/docker-config" docker buildx imagetools inspect \
      --format '{{json .Provenance}}' "$reference" >"$work/$1.provenance.json" 2>"$work/$1.provenance.err" || {
    sed -n '1,20p' "$work/$1.provenance.err" >&2
    fail "could not read the provenance of $reference"
  }
  revision="$(jq -er '
      [to_entries[]? | .value.SLSA | (.predicate // .)
        | .runDetails.metadata.buildkit_metadata.vcs.revision]
      | unique | select(length == 1) | .[0]
      | select(type == "string" and test("^[0-9a-f]{40}$"))' "$work/$1.provenance.json")" ||
    fail "the provenance of $reference does not name one source commit for every platform"
  printf '%s\n' "$revision"
}

index_digest() {
  jq -er '.digest' "$work/$1.json"
}

base="$(state base)"
workspace="$(state workspace)"
extra_outputs=''
case "$base:$workspace" in
  published:published)
    build=false
    base_revision="$(provenance_revision base)"
    workspace_revision="$(provenance_revision workspace)"
    [[ "$base_revision" == "$workspace_revision" ]] ||
      fail "the published base was built for $base_revision and the workspace for $workspace_revision; a pair has one source"
    if [[ "$base_revision" == "$source_sha" ]]; then
      printf 'Reusing the support pair main published for %s\n' "$source_sha"
    else
      "$alias_verifier" --repository "$ROOT" --source "$source_sha" --origin "$base_revision" \
        --base-digest "$(index_digest base)" --workspace-digest "$(index_digest workspace)" ||
        fail "the support pair published for $source_sha was built for $base_revision, and is not its alias"
      printf 'Reusing the support pair main published for %s, built for %s with the same base and workspace inputs\n' \
        "$source_sha" "$base_revision"
    fi
    extra_outputs="provenance_revision=$base_revision" ;;
  missing:missing)
    build=true
    printf 'Main published no support pair for %s; building it here, linux/arm64 on the native node\n' "$source_sha" ;;
  published:missing)
    build=true
    extra_outputs="base_amd64_digest=$(platform_digest amd64)
base_arm64_digest=$(platform_digest arm64)"
    printf 'Only the base is published for %s; building the workspace from it, linux/arm64 on the native node\n' "$source_sha" ;;
  *)
    fail "the workspace is published without its base for $source_sha (base $base, workspace $workspace); repair the publication before releasing" ;;
esac
printf 'build=%s\n' "$build" >>"$output"
[[ -z "$extra_outputs" ]] || printf '%s\n' "$extra_outputs" >>"$output"
