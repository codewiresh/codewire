#!/usr/bin/env bash
set -euo pipefail

# Official quay.io/skopeo/stable linux/amd64 image, Skopeo 1.22.2.
readonly SKOPEO_IMAGE='quay.io/skopeo/stable@sha256:8b23fe434af822adf71bc7c8674a8dfab379771aa1400fb81ff655a5cecfca87'
docker_bin="${DOCKER_BIN:-docker}"

[[ $# -gt 0 ]] || {
  echo 'Usage: run-skopeo-container.sh SKOPEO_ARGUMENT...' >&2
  exit 2
}
if [[ "$docker_bin" == */* ]]; then
  [ -x "$docker_bin" ] || {
    echo 'Docker is required for the pinned Skopeo runtime' >&2
    exit 1
  }
elif ! command -v "$docker_bin" >/dev/null 2>&1; then
  echo 'Docker is required for the pinned Skopeo runtime' >&2
  exit 1
fi

docker_args=(
  run
  --rm
  -i
  --env GOMAXPROCS=2
  # Podman's Docker API can otherwise assign an unusable default PID cgroup to
  # nested containers. Keep enough headroom for Skopeo's Go runtime while
  # retaining a finite host-safety boundary.
  --pids-limit=256
  --cap-drop=ALL
  --security-opt=no-new-privileges
  --network=bridge
)
auth_volume="${SKOPEO_AUTH_VOLUME:-}"
if [ -n "$auth_volume" ]; then
  [[ "$auth_volume" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || {
    echo 'Skopeo auth volume name is malformed' >&2
    exit 1
  }
  docker_args+=(
    --mount "type=volume,src=$auth_volume,dst=/auth"
  )
fi

retry_delay="${SKOPEO_STARTUP_RETRY_DELAY_SECONDS:-10}"
[[ "$retry_delay" =~ ^[0-9]+$ ]] || {
  echo 'Skopeo startup retry delay must be a non-negative integer' >&2
  exit 1
}

umask 077
work="$(mktemp -d)"
stdin_file="$work/stdin"
stdout_file="$work/stdout"
stderr_file="$work/stderr"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
if [ -t 0 ]; then
  : >"$stdin_file"
else
  cat >"$stdin_file"
fi

for attempt in 1 2 3; do
  : >"$stdout_file"
  : >"$stderr_file"
  if "$docker_bin" "${docker_args[@]}" "$SKOPEO_IMAGE" "$@" \
      <"$stdin_file" >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file"
    exit 0
  else
    status=$?
  fi

  if [ "$attempt" -lt 3 ] &&
      grep -Fq 'runtime/cgo: pthread_create failed: Resource temporarily unavailable' \
        "$stderr_file"; then
    printf '[skopeo-runtime] transient thread exhaustion; retrying startup (%d/3)\n' \
      "$((attempt + 1))" >&2
    sleep "$((retry_delay * attempt))"
    continue
  fi

  cat "$stdout_file"
  cat "$stderr_file" >&2
  exit "$status"
done
