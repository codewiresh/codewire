#!/usr/bin/env bash
# Build and push one protected half of the exact five-image runtime set.
#
#   build-push-runtime-images.sh services   # dashboard, services, mesh, derp
#   build-push-runtime-images.sh daemon     # the static CW producer and daemon
#
# Each half runs in its own protected job, so the daemon's static CW
# producer, the longest single build, runs beside the service Bake instead of
# before it. Both build on the trusted BuildKit builder (trusted-buildkit.sh). The halves never share a target, so they never race
# for an immutable source tag. The publishing job joins both halves by the
# exact digests these jobs report.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# shellcheck source=scripts/ci/images/pipeline-identity.sh
source "$ROOT/scripts/ci/images/pipeline-identity.sh"
# shellcheck source=scripts/ci/setup/trusted-buildkit.sh
source "$ROOT/scripts/ci/setup/trusted-buildkit.sh"
readonly BUILDKIT_IMAGE='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
readonly PROVENANCE_BUILDER_ID="$PIPELINE_BUILDER_ID"
readonly PUBLISH_REGISTRY_HOST="${CODEWIRE_IMAGE_REGISTRY:?set to the image registry host}"

: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

if [ "$#" -ne 1 ]; then
  echo 'Usage: build-push-runtime-images.sh services|daemon' >&2
  exit 2
fi
readonly runtime_group="$1"
case "$runtime_group" in
  services) image_families=(services mesh dashboard derp) ;;
  daemon) image_families=(daemon) ;;
  *)
    echo 'Runtime image group must be exactly services or daemon' >&2
    exit 2
    ;;
esac
readonly image_families

case "${CODEWIRE_SCCACHE_MODE:-local}" in
  disabled|local) ;;
  r2)
    # The shared cache is admitted only in the dedicated protected bucket,
    # below the protected prefix: that bucket's R2 credential is readable
    # solely by this canonical-main deploy lane's own publisher identity, so
    # untrusted builds can never poison the objects protected builds consume.
    # build-push-image.sh re-validates the full r2 contract (bucket, endpoint,
    # prefix, private credentials file) per image.
    case "${CODEWIRE_SCCACHE_PREFIX:-}" in
      protected/codewire/*) ;;
      *)
        echo 'Protected runtime builds may use only the protected R2 compiler-cache prefix' >&2
        exit 2
        ;;
    esac
    if [ -z "${CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED:-}" ]; then
      echo 'CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED: set to the protected CI compiler-cache bucket (docs/dev/CI-CONFIGURATION.md)' >&2
      exit 2
    fi
    if [ "${SCCACHE_BUCKET:-}" != "$CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED" ] \
        || [ "${SCCACHE_ENDPOINT:-}" != "${CODEWIRE_R2_CACHE_ENDPOINT:?set to the CI cache R2 endpoint URL}" ]; then
      echo 'Protected runtime builds may use only the protected R2 compiler-cache bucket' >&2
      exit 2
    fi
    ;;
  *)
    echo 'Protected runtime builds may use only job-local, disabled, or protected-prefix R2 sccache' >&2
    exit 2
    ;;
esac

umask 077
mkdir -p "${RUNNER_TEMP:-$ROOT/.tmp}"
work="$(mktemp -d "${RUNNER_TEMP:-$ROOT/.tmp}/codewire-runtime-images.XXXXXX")"
docker_config="$work/docker-config"
buildkit_config="$work/buildkitd.toml"
builder="codewire-runtime-${runtime_group}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${BASHPID}"

cleanup() {
  DOCKER_CONFIG="$docker_config" docker buildx rm --force "$builder" \
    >/dev/null 2>&1 || true
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -m 0700 "$docker_config"
# Both halves build on the trusted BuildKit builder and its persistent layer
# cache; the owner's explicit recovery builds them in this job instead.
if trusted_buildkit_in_job; then
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
else
  mkdir -m 0700 "$work/trusted-buildkit-tls"
  trusted_buildkit_attach "$builder" "$docker_config" "$work/trusted-buildkit-tls"
fi

# The deploy-selection job's trusted planner certifies, per runtime image
# family, whether the exact canonical head changes that family's inputs
# relative to the currently deployed baseline source. When carry-forward is
# explicitly enabled, a family the planner certifies unaffected is not
# rebuilt: the immutable source tag the previous deploy's protected build
# created for the baseline source resolves to the exact candidate digest,
# which carries forward into the new bundle unchanged. Every ambiguity
# (carry disabled, missing or invalid planner state, unresolvable baseline
# tag, identity mismatch) fails closed to a full source build.
carry_forward="${CODEWIRE_RUNTIME_CARRY_FORWARD:-0}"
baseline_sha=''
declare -a carried_families=()
declare -a build_families=()

if [ "$carry_forward" != 0 ] && [ "$carry_forward" != 1 ]; then
  echo 'CODEWIRE_RUNTIME_CARRY_FORWARD must be exactly 0 or 1' >&2
  exit 2
fi
if [ "$carry_forward" = 1 ]; then
  baseline_sha="${CODEWIRE_DEPLOY_BASELINE_SHA:-}"
  if [[ ! "$baseline_sha" =~ ^[0-9a-f]{40}$ \
      || "$baseline_sha" == 0000000000000000000000000000000000000000 ]]; then
    echo 'Runtime carry-forward requires the exact planner-certified deployed baseline source SHA' >&2
    exit 2
  fi
  for family in "${image_families[@]}"; do
    state_var="CODEWIRE_IMAGE_STATE_${family^^}"
    state="${!state_var:-}"
    if [ "$state" = unaffected ]; then
      carried_families+=("$family")
    else
      case "$state" in
        affected|unclassified) ;;
        *)
          printf 'Runtime image %s has no trusted planner state; building it from source\n' \
            "$family" >&2
          ;;
      esac
      build_families+=("$family")
    fi
  done
else
  build_families=("${image_families[@]}")
fi

registry_logged_in=0
runtime_registry_login() {
  [ "$registry_logged_in" = 0 ] || return 0
  local credential_fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"
  local registry_username
  [ -x "$credential_fetcher" ] || {
    echo "OpenBao Harbor credential fetcher is missing or not executable" >&2
    return 1
  }
  "$credential_fetcher" "$work/harbor-username" "$work/harbor-password" || return 1
  registry_username="$(<"$work/harbor-username")"
  [[ -n "$registry_username" && "$registry_username" != *$'\n'* ]] || {
    echo 'Registry username is malformed' >&2
    return 1
  }
  DOCKER_CONFIG="$docker_config" docker login "$PUBLISH_REGISTRY_HOST" \
    -u "$registry_username" --password-stdin <"$work/harbor-password" >/dev/null || return 1
  registry_logged_in=1
}

inspect_source_digest() {
  local reference="$1" inspect_output
  if ! inspect_output="$(DOCKER_CONFIG="$docker_config" docker buildx imagetools inspect \
      --format '{{json .Manifest}}' "$reference")"; then
    return 1
  fi
  jq -er '.digest | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))' \
    <<<"$inspect_output"
}

# Prove a pulled candidate's release identity by its immutable digest. Every
# job on a runner shares one Docker daemon and deliveries overlap, so a local
# tag names whatever another delivery tagged last (Deploy Dev 35294).
candidate_has_release_identity() {
  local reference="$1" expected_revision="$2" profile promotable revision
  profile="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.build.profile" }}' "$reference")"
  promotable="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.promotable" }}' "$reference")"
  revision="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$reference")"
  [ "$profile" = runtime ] && [ "$promotable" = true ] && [ "$revision" = "$expected_revision" ]
}

# Resolve the previous deploy's exact candidate for one certified-unaffected
# family, prove its local release identity, and pin the new source tag to the
# same immutable digest so the shared Bake transaction never rebuilds it. Any
# failure rejects the carry so the caller can rebuild the family from source.
carry_one() {
  local image_name="$1"
  local repository="$PUBLISH_REGISTRY_HOST/codewire/$image_name"
  local baseline_ref="$repository:$baseline_sha"
  local head_ref="$repository:$GITHUB_SHA"
  local digest head_digest

  runtime_registry_login || return 1
  if ! digest="$(inspect_source_digest "$baseline_ref")"; then
    echo "Unable to resolve the deployed baseline image $baseline_ref" >&2
    return 1
  fi

  DOCKER_CONFIG="$docker_config" docker pull "$repository@$digest" >/dev/null || return 1
  if ! candidate_has_release_identity "$repository@$digest" "$baseline_sha"; then
    echo "Carried runtime image $image_name does not preserve the deployed baseline release identity" >&2
    return 1
  fi

  if head_digest="$(inspect_source_digest "$head_ref")"; then
    if [ "$head_digest" != "$digest" ]; then
      echo "Refusing to replace immutable image tag $head_ref: expected $digest, found $head_digest" >&2
      return 1
    fi
  else
    DOCKER_CONFIG="$docker_config" docker buildx imagetools create \
      --tag "$head_ref" "$repository@$digest" >/dev/null || return 1
  fi

  printf '%s_candidate_ref=%s\n' "$image_name" "$repository@$digest" >>"$GITHUB_OUTPUT"
  printf '%s_built_from=%s\n' "$image_name" "$baseline_sha" >>"$GITHUB_OUTPUT"
  printf 'Carried forward the exact deployed %s image: %s@%s\n' \
    "$image_name" "$repository" "$digest"
}

is_carried() {
  local needle="$1" family
  for family in ${carried_families[@]+"${carried_families[@]}"}; do
    [ "$family" = "$needle" ] && return 0
  done
  return 1
}

run_protected_build() {
  local image_name="$1"
  local dockerfile="$2"
  local output="$3"
  local build_runtime_set="$4"

  : >"$output"
  GITHUB_OUTPUT="$output" \
    CODEWIRE_EXTERNAL_BUILDX_BUILDER="$builder" \
    CODEWIRE_EXTERNAL_DOCKER_CONFIG="$docker_config" \
    CODEWIRE_CW_IMAGE_WORK="$work/cw-images" \
    CODEWIRE_PROVENANCE_BUILDER_ID="$PROVENANCE_BUILDER_ID" \
    CODEWIRE_SCCACHE_MODE="${CODEWIRE_SCCACHE_MODE:-local}" \
    CODEWIRE_BUILD_RUNTIME_SET="$build_runtime_set" \
    scripts/ci/images/build-push-image.sh "$image_name" "$dockerfile" .
}

build_one() {
  local image_name="$1"
  local dockerfile="$2"
  local build_runtime_set="${3:-0}"
  local output candidate_ref

  if is_carried "$image_name"; then
    return 0
  fi

  output="$work/$image_name.output"
  run_protected_build "$image_name" "$dockerfile" "$output" "$build_runtime_set"

  candidate_ref="$(sed -n 's/^candidate_ref=//p' "$output")"
  if [[ ! "$candidate_ref" =~ ^"$PUBLISH_REGISTRY_HOST/codewire/$image_name"@sha256:[0-9a-f]{64}$ ]]; then
    echo "Runtime build returned an invalid $image_name candidate reference" >&2
    exit 1
  fi

  # Harbor is the protected candidate boundary. Pull the immutable manifest
  # back by digest and check its selected local platform image. The publishing
  # job takes these digests, so nothing needs a local name for the image.
  DOCKER_CONFIG="$docker_config" docker pull "$candidate_ref" >/dev/null
  if ! candidate_has_release_identity "$candidate_ref" "$GITHUB_SHA"; then
    echo "Runtime candidate $image_name did not preserve its exact release identity locally" >&2
    exit 1
  fi
  printf '%s_candidate_ref=%s\n' "$image_name" "$candidate_ref" >>"$GITHUB_OUTPUT"
  printf '%s_built_from=%s\n' "$image_name" "$GITHUB_SHA" >>"$GITHUB_OUTPUT"
}

# Carries resolve first so their new immutable source tags exist before the
# Bake transaction computes its missing set. A carry that fails closed joins
# the source-build set instead of weakening the exact-image contract.
resolved_carried=()
for family in ${carried_families[@]+"${carried_families[@]}"}; do
  if carry_one "$family"; then
    resolved_carried+=("$family")
  else
    printf 'Carry-forward of %s failed closed; rebuilding it from source\n' "$family" >&2
    build_families+=("$family")
  fi
done
carried_families=(${resolved_carried[@]+"${resolved_carried[@]}"})

# One Bake graph anchored by services lets BuildKit schedule at most two
# independent service builds concurrently while deduplicating their shared
# rust-base target. Product targets remain separate so Cargo feature
# unification and the derp lockfile cannot change shipped binaries. The
# anchor engages only when services itself builds; carried families already
# have exact source tags and drop out of the transaction's missing set. The
# daemon half builds its single target directly.
services_runtime_set=0
for family in ${build_families[@]+"${build_families[@]}"}; do
  if [ "$family" = services ]; then
    services_runtime_set=1
    break
  fi
done

if [ "$runtime_group" = services ]; then
  build_one services deployments/docker/services.Dockerfile "$services_runtime_set"
  build_one mesh deployments/docker/mesh.Dockerfile
  build_one dashboard apps/dashboard/Dockerfile
  build_one derp deployments/docker/derp.Dockerfile
else
  build_one daemon deployments/docker/daemon.Dockerfile
fi

if [ "${#carried_families[@]}" -gt 0 ]; then
  printf 'Carried forward %d exact runtime image(s) from deployed source %s: %s\n' \
    "${#carried_families[@]}" "$baseline_sha" "${carried_families[*]}"
fi
printf 'Materialized the exact %s runtime candidates (%s) and verified every candidate locally\n' \
  "$runtime_group" "${image_families[*]}"
