#!/usr/bin/env bash
# User-facing entrypoint for the canonical product Bake graph.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
arguments=("$@")
if [[ "$#" == 0 ]]; then
  arguments=(default)
fi
source "$ROOT/scripts/ci/images/cw-image-consumer.sh"
umask 077
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/cw-product-images.XXXXXX")"
command=("$docker_bin" buildx bake --file "$ROOT/docker-bake.hcl" "${arguments[@]}")
# Every target, Kind's included, builds the one runtime profile.
cw_image_run runtime "$ROOT" "$work" "${command[@]}"
