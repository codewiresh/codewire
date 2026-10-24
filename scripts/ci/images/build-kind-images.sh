#!/usr/bin/env bash
# Build Kind product images once through the canonical Bake graph and load the
# exact results into the job-local Docker store. With no arguments it builds all
# four (the local gate). CI names its family: the three service images on one
# worker, the daemon image (the static CW producer) on another.
#
# usage: build-kind-images.sh [dashboard] [services] [mesh] [daemon]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "$ROOT/scripts/ci/images/cw-image-consumer.sh"
# shellcheck source=scripts/ci/images/buildx-builder.sh
source "$ROOT/scripts/ci/images/buildx-builder.sh"
readonly BUILDKIT_IMAGE='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
metadata_file="${CODEWIRE_BAKE_METADATA_FILE:-$ROOT/.tmp/kind-image-build-metadata.json}"
progress="${CODEWIRE_BUILDX_PROGRESS:-plain}"
sccache_mode="${CODEWIRE_SCCACHE_MODE:-local}"
retain_cw_assets="${CODEWIRE_KIND_RETAIN_CW_ASSETS:-0}"
case "$retain_cw_assets" in
  0|1) ;;
  *) echo 'CODEWIRE_KIND_RETAIN_CW_ASSETS must be 0 or 1' >&2; exit 2 ;;
esac
families=()
for family in "$@"; do
  case "$family" in
    dashboard|services|mesh|daemon) ;;
    *) printf 'unknown Kind image family: %s\n' "$family" >&2; exit 2 ;;
  esac
  case " ${families[*]} " in
    *" $family "*) printf 'repeated Kind image family: %s\n' "$family" >&2; exit 2 ;;
  esac
  families+=("$family")
done
if [ "${#families[@]}" -eq 0 ]; then
  families=(dashboard services mesh daemon)
fi
family_targets=("${families[@]/%/-ci}")
if [ "$#" -eq 0 ]; then
  bake_targets=(kind)
else
  bake_targets=("${family_targets[@]}")
fi

case "$sccache_mode" in
  disabled|local) ;;
  r2)
    : "${SCCACHE_BUCKET:?SCCACHE_BUCKET is required in r2 mode}"
    : "${SCCACHE_ENDPOINT:?SCCACHE_ENDPOINT is required in r2 mode}"
    : "${CODEWIRE_SCCACHE_PREFIX:?CODEWIRE_SCCACHE_PREFIX is required in r2 mode}"
    credentials_file="${CODEWIRE_SCCACHE_CREDENTIALS_FILE:?CODEWIRE_SCCACHE_CREDENTIALS_FILE is required in r2 mode}"
    case "$credentials_file" in
      /*) ;;
      *)
        echo 'Kind sccache credentials file must be an absolute path' >&2
        exit 2
        ;;
    esac
    [ -f "$credentials_file" ] && [ -r "$credentials_file" ] && [ -s "$credentials_file" ] || {
      echo 'Kind sccache credentials file must be a readable nonempty regular file' >&2
      exit 2
    }
    case "$(stat -c '%a' -- "$credentials_file")" in
      400|600) ;;
      *)
        echo 'Kind sccache credentials file must have mode 0400 or 0600' >&2
        exit 2
        ;;
    esac
    case "$credentials_file" in
      *','*|*$'\n'*)
        echo 'Kind sccache credentials file path contains an unsupported character' >&2
        exit 2
        ;;
    esac
    case "$CODEWIRE_SCCACHE_PREFIX" in
      untrusted/codewire/*|protected/codewire/*) ;;
      *)
        echo 'Kind sccache prefix must remain below untrusted/codewire/ or protected/codewire/' >&2
        exit 2
        ;;
    esac
    ;;
  *)
    printf 'Invalid CODEWIRE_SCCACHE_MODE: %s\n' "$sccache_mode" >&2
    exit 2
    ;;
esac

case "$metadata_file" in
  /*) ;;
  *) metadata_file="$ROOT/$metadata_file" ;;
esac
mkdir -p "$(dirname "$metadata_file")"

# Bake may compile four large Rust graphs concurrently. Keep one BuildKit
# daemon for cross-target layer/object reuse, but bound its solver so nested
# build containers cannot exhaust the dedicated CPX42 worker. A CI job gets a
# transient daemon. A local Kind run selects CODEWIRE_KIND_IMAGE_BUILDER=
# persistent (#2965): one daemon whose layer cache and cache mounts, the
# compiler cache among them, survive runs, so an unchanged image costs only its
# export and a changed one rebuilds warm. The GC policy bounds what it keeps
# (the kind-dev builder's), and the name carries the configuration's digest so a
# changed configuration gets its own daemon.
case "${CODEWIRE_KIND_IMAGE_BUILDER:-transient}" in
  transient|persistent) ;;
  *) echo 'CODEWIRE_KIND_IMAGE_BUILDER must be transient or persistent' >&2; exit 2 ;;
esac
umask 077
mkdir -p "${RUNNER_TEMP:-$ROOT/.tmp}"
work="$(mktemp -d "${RUNNER_TEMP:-$ROOT/.tmp}/codewire-kind-images.XXXXXX")"
buildkit_config="$work/buildkitd.toml"
printf '%s\n' \
  '[worker.oci]' \
  '  max-parallelism = 2' \
  '  gc = true' \
  '  [[worker.oci.gcpolicy]]' \
  '    filters = ["type==source.local", "type==source.git.checkout"]' \
  '    keepDuration = "48h"' \
  '    maxUsedSpace = "512MB"' \
  '  [[worker.oci.gcpolicy]]' \
  '    keepDuration = "336h"' \
  '    reservedSpace = "40GB"' \
  '    maxUsedSpace = "80GB"' \
  '    minFreeSpace = "40GB"' \
  '  [[worker.oci.gcpolicy]]' \
  '    all = true' \
  '    reservedSpace = "40GB"' \
  '    maxUsedSpace = "80GB"' \
  '    minFreeSpace = "40GB"' >"$buildkit_config"
if [ "${CODEWIRE_KIND_IMAGE_BUILDER:-transient}" = persistent ]; then
  persistent_builder=true
  builder="codewire-kind-images-$(sha256sum "$buildkit_config" | cut -c1-8)"
else
  persistent_builder=false
  builder="codewire-kind-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${BASHPID}"
fi
node="${builder}-node"
builder_created=false

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM
  if [ "$builder_created" = true ]; then
    buildx_builder_remove "$docker_bin" "$builder" "$node" 'Kind image build cleanup' || cleanup_status=$?
  fi
  if [ "$retain_cw_assets" = 1 ]; then
    # Retain original producer and consumer paths, including failed evidence.
    # Only the actual complete caller exit can qualify a successful image build.
    printf 'CODEWIRE_KIND_CW_ASSETS work=%s build_status=%s cleanup_status=%s\n' \
      "$work" "$status" "$cleanup_status" >&2
  else
    rm -rf "$work"
  fi
  if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
    echo "Kind image build: failed to remove transient builder $builder" >&2
    status="$cleanup_status"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$persistent_builder" = true ] && "$docker_bin" buildx inspect "$builder" >/dev/null 2>&1; then
  printf 'Kind image build: reusing the persistent builder %s\n' "$builder" >&2
  "$docker_bin" buildx inspect --bootstrap "$builder" >/dev/null
else
  # The builder name reserves the cleanup scope even when create stops after
  # writing only part of its state. A persistent builder is never removed here.
  [ "$persistent_builder" = true ] || builder_created=true
  if ! "$docker_bin" buildx create \
      --name "$builder" \
      --node "$node" \
      --driver docker-container \
      --driver-opt "image=$BUILDKIT_IMAGE" \
      --buildkitd-config "$buildkit_config" \
      --bootstrap >/dev/null; then
    # Another local run created the persistent builder first: use it.
    [ "$persistent_builder" = true ] && "$docker_bin" buildx inspect --bootstrap "$builder" >/dev/null || exit 1
  fi
fi
buildx_builder_cap "$builder"

started_at="$(date +%s)"
bake_args=(
  --builder "$builder"
  --file "$ROOT/docker-bake.hcl"
  --metadata-file "$metadata_file"
  --progress "$progress"
  --pull
  --load
)
if [ "$sccache_mode" = r2 ]; then
  for target in "${family_targets[@]}"; do
    bake_args+=(
      --set "$target.secrets+=id=aws_shared_credentials,src=$credentials_file"
    )
  done
fi
case " ${families[*]} " in
  *' daemon '*)
    # The daemon's static CW producer is most of a daemon build. Admit it first
    # so its own duration and compiler summary are reported; the image solve
    # below reuses this exact producer (cw_image_prepare is idempotent).
    producer_started_at="$(date +%s)"
    CODEWIRE_SCCACHE_MODE="$sccache_mode" cw_image_prepare runtime "$ROOT" "$work"
    printf 'CODEWIRE_CI_PHASE name=cw-producer seconds=%s\n' "$(( $(date +%s) - producer_started_at ))"
    while IFS= read -r producer_log; do
      grep -E 'Finished `|CODEWIRE_CI_PHASE|Compile requests  |Cache hits rate  |Cache misses  |Non-cacheable calls|Average compiler' \
        "$producer_log" | sed 's/^/cw-producer: /' || true
      # Every producer step that took at least five seconds, with its name.
      awk '
        match($0, /^#[0-9]+ \[/) { id = substr($1, 2); if (!(id in name)) name[id] = substr($0, RSTART + RLENGTH - 1, 120) }
        $2 == "DONE" && $1 ~ /^#[0-9]+$/ { id = substr($1, 2); seconds = $3; sub(/s$/, "", seconds)
          if (seconds + 0 >= 5) printf "cw-producer step: %6.1fs %s\n", seconds, name[id] }
      ' "$producer_log" || true
    done < <(find "$work" -path '*/cw-producer.*' -name build.log -type f 2>/dev/null)
    ;;
esac
CODEWIRE_SCCACHE_MODE="$sccache_mode" \
  cw_image_run runtime "$ROOT" "$work" "$docker_bin" buildx bake "${bake_args[@]}" "${bake_targets[@]}"
elapsed="$(( $(date +%s) - started_at ))"

for image in "${families[@]}"; do
  image_ref="codewire-${image}:e2e"
  "$docker_bin" image inspect "$image_ref" >/dev/null
  # Kind runs the profile Dev and Production run; only promotability differs.
  [ "$("$docker_bin" image inspect --format '{{ index .Config.Labels "dev.codewire.build.profile" }}' "$image_ref")" = runtime ] || {
    printf 'Kind image is not marked with the runtime profile: %s\n' "$image_ref" >&2
    exit 1
  }
  [ "$("$docker_bin" image inspect --format '{{ index .Config.Labels "dev.codewire.promotable" }}' "$image_ref")" = false ] || {
    printf 'Kind image is not marked non-promotable: %s\n' "$image_ref" >&2
    exit 1
  }
done

printf 'CODEWIRE_CI_PHASE name=product-image-build seconds=%s images=%s metadata=%s\n' \
  "$elapsed" "$(IFS=,; printf '%s' "${families[*]}")" "$metadata_file"

if [ "$retain_cw_assets" = 1 ]; then
  # These are the admitted original producer selected by cw_image_run, not a
  # reconstructed receipt or proof of the later sandbox acceptance journey.
  [ -n "${cw_image_reference:-}" ] && [ -n "${cw_image_reference_sha:-}" ] || {
    echo 'retained Kind CW producer reference is missing' >&2
    exit 1
  }
  printf 'CODEWIRE_KIND_CW_PRODUCER path=%s sha256=%s\n' \
    "$cw_image_reference" "$cw_image_reference_sha"
fi
