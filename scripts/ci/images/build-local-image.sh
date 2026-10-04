#!/usr/bin/env bash
# Build one image through an isolated Docker-container Buildx builder and load
# the result into the caller's Docker image store for immediate verification.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
source "$ROOT/scripts/ci/images/cw-image-consumer.sh"

usage() {
  echo "usage: $0 TAG DOCKERFILE CONTEXT [BUILDX_ARG ...]" >&2
}

if [[ $# -lt 3 ]]; then
  usage
  exit 2
fi

readonly tag="$1"
readonly dockerfile="$2"
readonly context="$3"
readonly docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
shift 3
readonly -a build_args=("$@")

builder=""
cw_local_work=""

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM

  if [[ -n "$builder" ]]; then
    "$docker_bin" buildx rm --force "$builder" >/dev/null 2>&1 || cleanup_status=$?
  fi

  if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
    echo "local image build: failed to remove ephemeral builder $builder" >&2
    status="$cleanup_status"
  fi
  if [[ -n "$cw_local_work" ]]; then
    if [[ "$status" -eq 0 ]]; then
      rm -rf -- "$cw_local_work"
    else
      echo "local image build: retained failed CW build evidence at $cw_local_work" >&2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Let Buildx generate the name. Its daemon-wide allocator avoids collisions
# between concurrent runner containers even when their PID namespaces overlap.
builder="$("$docker_bin" buildx create --driver docker-container)"
if [[ ! "$builder" =~ ^[[:alnum:]][[:alnum:]_.-]*$ ]]; then
  echo "local image build: Buildx returned an invalid builder name" >&2
  exit 1
fi

command=("$docker_bin" buildx build
  --builder "$builder" \
  --pull \
  --load \
  --tag "$tag" \
  --file "$dockerfile" \
  "${build_args[@]}" \
  "$context")
case "$(realpath -m -- "$dockerfile")" in
  "$(realpath -m -- "$context")/deployments/docker/gateway.Dockerfile"|"$(realpath -m -- "$context")/images/workspace/Dockerfile")
    umask 077
    mkdir -p "$ROOT/.tmp"
    cw_local_work="$(mktemp -d "$ROOT/.tmp/cw-local-image.XXXXXX")"
    cw_image_run "${CODEWIRE_RUST_PROFILE:-release}" "$(realpath -m -- "$context")" "$cw_local_work" "${command[@]}"
    ;;
  *) "${command[@]}" ;;
esac
