#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly BUILDKIT_IMAGE='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
readonly PROVENANCE_BUILDER_ID='https://git.example.invalid/infra/ci/builders/protected-delivery/v1'
readonly NEXUS_REGISTRY_HOST='nexus-system-cluster.example.invalid'
readonly NEXUS_APPROVED_REGISTRY_HOST='nexus.example.invalid'
source "$ROOT/scripts/ci/images/nexus-publication-retry-contract.sh"

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
  --driver-opt provenance-add-gha=false \
  --buildkitd-config "$buildkit_config" \
  --bootstrap >/dev/null

is_nexus_backup_unavailable() {
  local log_file="$1"

  if ! grep -Fq "https://${NEXUS_REGISTRY_HOST}/v2/" "$log_file" \
      && ! grep -Fq "https://${NEXUS_APPROVED_REGISTRY_HOST}/v2/" "$log_file"; then
    return 1
  fi
  grep -Eq '503 Service (Temporarily )?Unavailable' "$log_file"
}

run_protected_build() {
  local image_name="$1"
  local dockerfile="$2"
  local output="$3"
  local build_runtime_set="$4"
  local attempt build_log build_status tee_status
  local -a pipeline_status

  for (( attempt = 1; attempt <= NEXUS_BACKUP_RETRY_ATTEMPTS; attempt++ )); do
    build_log="$work/$image_name.build-attempt.log"
    : >"$output"
    : >"$build_log"

    set +e
    GITHUB_OUTPUT="$output" \
      CODEWIRE_EXTERNAL_BUILDX_BUILDER="$builder" \
      CODEWIRE_EXTERNAL_DOCKER_CONFIG="$docker_config" \
      CODEWIRE_PROVENANCE_BUILDER_ID="$PROVENANCE_BUILDER_ID" \
      CODEWIRE_SCCACHE_MODE="${CODEWIRE_SCCACHE_MODE:-local}" \
      CODEWIRE_BUILD_RUNTIME_SET="$build_runtime_set" \
      scripts/ci/images/build-push-image.sh "$image_name" "$dockerfile" . \
        2>&1 | tee "$build_log"
    pipeline_status=("${PIPESTATUS[@]}")
    build_status="${pipeline_status[0]}"
    tee_status="${pipeline_status[1]}"
    set -e

    if [ "$build_status" -eq 0 ] && [ "$tee_status" -eq 0 ]; then
      return 0
    fi
    if [ "$tee_status" -ne 0 ]; then
      return "$tee_status"
    fi
    if [ "$attempt" -ge "$NEXUS_BACKUP_RETRY_ATTEMPTS" ] \
        || ! is_nexus_backup_unavailable "$build_log"; then
      return "$build_status"
    fi

    printf 'Nexus is temporarily unavailable during protected publication; retrying the exact %s build (%d/%d)\n' \
      "$image_name" "$((attempt + 1))" "$NEXUS_BACKUP_RETRY_ATTEMPTS" >&2
    sleep "$NEXUS_BACKUP_RETRY_DELAY_SECONDS"
  done
}

build_one() {
  local image_name="$1"
  local dockerfile="$2"
  local build_runtime_set="${3:-0}"
  local output candidate_ref local_ref candidate_id local_id profile promotable revision

  output="$work/$image_name.output"
  run_protected_build "$image_name" "$dockerfile" "$output" "$build_runtime_set"

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

# One five-target Bake graph lets BuildKit schedule at most two independent
# product builds concurrently while deduplicating their shared rust-base target.
# Product targets remain separate so Cargo feature unification and the gateway
# lockfile cannot change shipped binaries. The remaining helper calls find the
# exact source tags from that transaction and perform the existing per-image
# provenance, SBOM, immutable-tag, and bundle checks without rebuilding.
build_one services deployments/docker/services.Dockerfile 1
build_one mesh deployments/docker/mesh.Dockerfile
build_one dashboard apps/dashboard/Dockerfile
build_one gateway deployments/docker/gateway.Dockerfile
build_one derp deployments/docker/derp.Dockerfile

echo 'Built the exact five-image runtime candidate set in one bounded Bake graph and materialized every candidate locally'
