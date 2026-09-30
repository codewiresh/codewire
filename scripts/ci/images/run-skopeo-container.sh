#!/usr/bin/env bash
set -euo pipefail

# Official quay.io/skopeo/stable linux/amd64 image, Skopeo 1.22.2, copied
# byte-for-byte through the reviewed promotion boundary into Harbor. Disposable
# runners must preload this exact internal reference before registration.
readonly SKOPEO_IMAGE='registry.example.invalid/oci-approved/skopeo/stable@sha256:8b23fe434af822adf71bc7c8674a8dfab379771aa1400fb81ff655a5cecfca87'
docker_bin="${DOCKER_BIN:-docker}"

[[ $# -gt 0 ]] || {
  echo 'Usage: run-skopeo-container.sh [--check | SKOPEO_ARGUMENT...]' >&2
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

runtime_available() {
  "$docker_bin" image inspect --format '{{.Id}}' "$SKOPEO_IMAGE" \
    >/dev/null 2>&1
}

if [ "$1" = --check ]; then
  [ "$#" -eq 1 ] || {
    echo 'Skopeo runtime check does not accept additional arguments' >&2
    exit 2
  }
  if ! runtime_available; then
    echo '[skopeo-runtime] class=runtime-unavailable detail=approved-image-missing' >&2
    exit 1
  fi
  echo 'SKOPEO_RUNTIME_READY'
  exit 0
fi

if ! runtime_available; then
  echo '[skopeo-runtime] class=runtime-unavailable detail=approved-image-missing' >&2
  exit 1
fi

docker_args=(
  run
  --rm
  -i
  --pull=never
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
network_retry_delay="${SKOPEO_NETWORK_RETRY_DELAY_SECONDS:-5}"
[[ "$network_retry_delay" =~ ^[0-9]+$ ]] || {
  echo 'Skopeo network retry delay must be a non-negative integer' >&2
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

  if grep -Eqi \
      '(dial (tcp|udp)[^[:cntrl:]]*(i/o timeout|connection refused|network is unreachable)|tls handshake timeout|connection reset by peer|connection timed out|context deadline exceeded|temporary failure in name resolution|no such host|unexpected eof)' \
      "$stderr_file"; then
    if [ "$attempt" -lt 3 ]; then
      printf '[skopeo-network] transient registry connectivity; retrying operation (%d/3)\n' \
        "$((attempt + 1))" >&2
      cat "$stdout_file"
      cat "$stderr_file" >&2
      sleep "$((network_retry_delay * attempt))"
      continue
    fi
    echo '[skopeo-network] class=transient-exhausted' >&2
  fi

  cat "$stdout_file"
  cat "$stderr_file" >&2
  exit "$status"
done
