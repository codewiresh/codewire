#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILDKIT_IMAGE='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'

: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

case "${CODEWIRE_SCCACHE_MODE:-local}" in
  disabled|local) ;;
  *)
    echo 'Protected runtime builds may use only job-local or disabled sccache' >&2
    exit 2
    ;;
esac

umask 077
mkdir -p "${RUNNER_TEMP:-$ROOT/.tmp}"
work="$(mktemp -d "${RUNNER_TEMP:-$ROOT/.tmp}/codewire-runtime-images.XXXXXX")"
docker_config="$work/docker-config"
buildkit_config="$work/buildkitd.toml"
builder="codewire-runtime-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${BASHPID}"

cleanup() {
  DOCKER_CONFIG="$docker_config" docker buildx rm --force "$builder" \
    >/dev/null 2>&1 || true
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -m 0700 "$docker_config"
printf '%s\n' \
  '[worker.oci]' \
  '  max-parallelism = 2' >"$buildkit_config"

DOCKER_CONFIG="$docker_config" docker buildx create \
  --name "$builder" \
  --driver docker-container \
  --driver-opt "image=$BUILDKIT_IMAGE" \
  --buildkitd-config "$buildkit_config" \
  --bootstrap >/dev/null

build_one() {
  local image_name="$1"
  local dockerfile="$2"
  local output candidate_ref local_ref candidate_id local_id profile promotable revision

  output="$work/$image_name.output"
  GITHUB_OUTPUT="$output" \
    CODEWIRE_EXTERNAL_BUILDX_BUILDER="$builder" \
    CODEWIRE_EXTERNAL_DOCKER_CONFIG="$docker_config" \
    CODEWIRE_SCCACHE_MODE="${CODEWIRE_SCCACHE_MODE:-local}" \
    scripts/ci/images/build-push-image.sh "$image_name" "$dockerfile" .

  candidate_ref="$(sed -n 's/^candidate_ref=//p' "$output")"
  if [[ ! "$candidate_ref" =~ ^nexus-system-cluster\.private\.invalid/oci-promoted/codewire/${image_name}@sha256:[0-9a-f]{64}$ ]]; then
    echo "Runtime build returned an invalid $image_name candidate reference" >&2
    exit 1
  fi

  # Nexus is the protected candidate boundary. Pull the immutable manifest
  # back by digest and give its selected local platform image the disposable
  # names consumed by Kind. GHCR publication and deploy dispatch occur only
  # after the complete exact-image suite passes in the same job.
  local_ref="codewire-${image_name}:e2e"
  DOCKER_CONFIG="$docker_config" docker pull "$candidate_ref" >/dev/null
  docker image tag "$candidate_ref" "$local_ref"
  candidate_id="$(docker image inspect --format '{{.Id}}' "$candidate_ref")"
  local_id="$(docker image inspect --format '{{.Id}}' "$local_ref")"
  profile="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.build.profile" }}' "$local_ref")"
  promotable="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.promotable" }}' "$local_ref")"
  revision="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$local_ref")"
  if [ -z "$candidate_id" ] || [ "$candidate_id" != "$local_id" ] \
      || [ "$profile" != release ] || [ "$promotable" != true ] \
      || [ "$revision" != "$GITHUB_SHA" ]; then
    echo "Runtime candidate $image_name did not preserve its exact release identity locally" >&2
    exit 1
  fi
  printf '%s_candidate_ref=%s\n' "$image_name" "$candidate_ref" >>"$GITHUB_OUTPUT"
}

# One protected job and one transient BuildKit daemon share only job-local
# content and compiler objects. Product targets remain separate so Cargo
# feature unification and the gateway lockfile cannot change shipped binaries.
build_one services deployments/docker/services.Dockerfile
build_one mesh deployments/docker/mesh.Dockerfile
build_one dashboard apps/dashboard/Dockerfile
build_one gateway deployments/docker/gateway.Dockerfile
build_one derp deployments/docker/derp.Dockerfile

echo 'Built and locally materialized the exact five-image runtime candidate set with one bounded transient BuildKit daemon'
