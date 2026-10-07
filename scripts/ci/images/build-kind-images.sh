#!/usr/bin/env bash
# Build every Kind product image once through the canonical Bake graph and load
# the exact results into the job-local Docker store.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly BUILDKIT_IMAGE='docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
metadata_file="${CODEWIRE_BAKE_METADATA_FILE:-$ROOT/.tmp/kind-image-build-metadata.json}"
progress="${CODEWIRE_BUILDX_PROGRESS:-plain}"
sccache_mode="${CODEWIRE_SCCACHE_MODE:-local}"

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
      untrusted/codewire/*) ;;
      *)
        echo 'Kind sccache prefix must remain below untrusted/codewire/' >&2
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

# Bake may compile four large Rust graphs concurrently. Keep one transient
# BuildKit daemon for cross-target layer/object reuse, but bound its solver so
# nested build containers cannot exhaust the dedicated CPX42 worker.
umask 077
mkdir -p "${RUNNER_TEMP:-$ROOT/.tmp}"
work="$(mktemp -d "${RUNNER_TEMP:-$ROOT/.tmp}/codewire-kind-images.XXXXXX")"
buildkit_config="$work/buildkitd.toml"
builder="codewire-kind-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${BASHPID}"

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM
  "$docker_bin" buildx rm --force "$builder" >/dev/null 2>&1 || cleanup_status=$?
  rm -rf "$work"
  if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
    echo "Kind image build: failed to remove transient builder $builder" >&2
    status="$cleanup_status"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s\n' \
  '[worker.oci]' \
  '  max-parallelism = 2' >"$buildkit_config"

"$docker_bin" buildx create \
  --name "$builder" \
  --driver docker-container \
  --driver-opt "image=$BUILDKIT_IMAGE" \
  --buildkitd-config "$buildkit_config" \
  --bootstrap >/dev/null

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
  for target in dashboard-ci services-ci mesh-ci daemon-ci; do
    bake_args+=(
      --set "$target.secrets+=id=aws_shared_credentials,src=$credentials_file"
    )
  done
fi
CODEWIRE_SCCACHE_MODE="$sccache_mode" \
  "$docker_bin" buildx bake "${bake_args[@]}" kind
elapsed="$(( $(date +%s) - started_at ))"

for image in dashboard services mesh daemon; do
  image_ref="codewire-${image}:e2e"
  "$docker_bin" image inspect "$image_ref" >/dev/null
  [ "$("$docker_bin" image inspect --format '{{ index .Config.Labels "dev.codewire.build.profile" }}' "$image_ref")" = ci ] || {
    printf 'Kind image is not marked with the ci profile: %s\n' "$image_ref" >&2
    exit 1
  }
  [ "$("$docker_bin" image inspect --format '{{ index .Config.Labels "dev.codewire.promotable" }}' "$image_ref")" = false ] || {
    printf 'Kind image is not marked non-promotable: %s\n' "$image_ref" >&2
    exit 1
  }
done

printf 'CODEWIRE_CI_PHASE name=product-image-build seconds=%s metadata=%s\n' \
  "$elapsed" "$metadata_file"
