#!/usr/bin/env bash
# Build every Kind product image once through the canonical Bake graph and load
# the exact results into the job-local Docker store.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
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
    : "${AWS_IAM_CREDENTIALS_URL:?AWS_IAM_CREDENTIALS_URL is required in r2 mode}"
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

started_at="$(date +%s)"
bake_args=(
  --file "$ROOT/docker-bake.hcl"
  --metadata-file "$metadata_file"
  --progress "$progress"
  --pull
  --load
)
if [ "$sccache_mode" = r2 ]; then
  for target in dashboard-ci services-ci mesh-ci gateway-ci; do
    bake_args+=(
      --set "$target.secret=id=aws_iam_credentials_url,env=AWS_IAM_CREDENTIALS_URL"
    )
  done
fi
CODEWIRE_SCCACHE_MODE="$sccache_mode" \
  "$docker_bin" buildx bake "${bake_args[@]}" kind
elapsed="$(( $(date +%s) - started_at ))"

for image in dashboard services mesh gateway; do
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
