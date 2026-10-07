#!/usr/bin/env bash
# Copy one exact Harbor manifest, unchanged, to another tag in its Harbor
# repository (the registry every deployment pulls from) or to the public GHCR
# mirror. Images are built and pushed to Harbor; nothing reads Nexus here.
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 SOURCE_DIGEST_REF TARGET_REPOSITORY TAG [TAG...]" >&2
  exit 2
fi

source_ref="$1"
target_repository="$2"
shift 2
tags=("$@")

# `gateway` is the daemon image's repository before its rename to `daemon`:
# the compiled-in default daemon image still names a digest there, which
# --pinned-defaults keeps until that default moves to a `daemon` digest.
readonly source_pattern='^registry\.example\.invalid/codewire/(dashboard|derp|daemon|gateway|services|mesh|base|workspace|confidential-probe)@sha256:([0-9a-f]{64})$'
if [[ ! "$source_ref" =~ $source_pattern ]]; then
  echo "Source must be an exact supported Harbor digest reference" >&2
  exit 1
fi
image_name="${BASH_REMATCH[1]}"
expected_digest="sha256:${BASH_REMATCH[2]}"

if [ "$target_repository" = "ghcr.io/codewiresh/$image_name" ]; then
  target_label=GHCR
  target_host=ghcr.io
elif [ "$target_repository" = "registry.example.invalid/codewire/$image_name" ]; then
  target_label=Harbor
  target_host=registry.example.invalid
else
  echo "Target repository must be the Harbor or GHCR repository of the supported source image family" >&2
  exit 1
fi

declare -A seen_tags=()
for tag in "${tags[@]}"; do
  if [ "$tag" = latest ]; then
    if [[ ! "$image_name" =~ ^(base|workspace)$ ]]; then
      echo "The mutable latest alias is restricted to base and workspace compatibility" >&2
      exit 1
    fi
  elif [ "$target_label" = Harbor ] && [ "$tag" = "keep-${expected_digest/:/-}" ]; then
    # Harbor retains immutable keep-* tags. This one pins a digest the product
    # references by default, such as the compiled-in workspace image.
    :
  elif [[ ! "$tag" =~ ^[0-9a-f]{40}$ ]] \
    && [[ ! "$tag" =~ ^[0-9a-f]{64}$ ]] \
    && [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Destination tags must be an exact source object ID, stable SemVer, an approved support-image latest alias, or the Harbor keep tag of the exact digest" >&2
    exit 1
  fi
  if [[ -n "${seen_tags[$tag]:-}" ]]; then
    echo "Duplicate destination tag: $tag" >&2
    exit 1
  fi
  seen_tags[$tag]=1
done

# The Harbor publisher reads every source and writes Harbor alias tags.
: "${HARBOR_PUBLISH_USERNAME:?HARBOR_PUBLISH_USERNAME is required}"
: "${HARBOR_PUBLISH_PASSWORD_FILE:?HARBOR_PUBLISH_PASSWORD_FILE is required}"
if [ "$target_label" = GHCR ]; then
  : "${GHCR_PUBLISH_USERNAME:?GHCR_PUBLISH_USERNAME is required}"
  : "${GHCR_PUBLISH_TOKEN_FILE:?GHCR_PUBLISH_TOKEN_FILE is required}"
  target_username="$GHCR_PUBLISH_USERNAME"
  target_credential_file="$GHCR_PUBLISH_TOKEN_FILE"
else
  target_username="$HARBOR_PUBLISH_USERNAME"
  target_credential_file="$HARBOR_PUBLISH_PASSWORD_FILE"
fi
skopeo_runner="${SKOPEO_RUNNER:-scripts/ci/images/run-skopeo-container.sh}"
docker_bin="${DOCKER_BIN:-docker}"

for secret_file in "$HARBOR_PUBLISH_PASSWORD_FILE" "$target_credential_file"; do
  if [ ! -f "$secret_file" ] || [ ! -s "$secret_file" ]; then
    echo "Registry credential file is missing or empty" >&2
    exit 1
  fi
done
if [ ! -x "$skopeo_runner" ]; then
  echo "Pinned Skopeo container runner is required" >&2
  exit 1
fi
if [[ "$docker_bin" == */* ]]; then
  docker_available=false
  [ -x "$docker_bin" ] && docker_available=true
else
  docker_available=false
  command -v "$docker_bin" >/dev/null 2>&1 && docker_available=true
fi
if [ "$docker_available" != true ]; then
  echo "Docker is required for exact-manifest registry copy" >&2
  exit 1
fi

umask 077
work="$(mktemp -d)"
inspect_error="$work/inspect.error"
auth_volume=''
cleanup() {
  if [ -n "$auth_volume" ]; then
    "$docker_bin" volume rm "$auth_volume" >/dev/null 2>&1 || true
  fi
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
auth_volume="$("$docker_bin" volume create)"
[[ "$auth_volume" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || {
  echo "Docker returned a malformed auth volume name" >&2
  exit 1
}
readonly auth_volume

registry_auth_error() {
  grep -Eqi \
    '(unauthorized|invalid username/password|authorization failed|failed to authorize|status[^[:cntrl:]]*401|status code: 401)' \
    "$1"
}

registry_connectivity_error() {
  grep -Eqi \
    '(\[skopeo-network\] class=transient-exhausted|dial (tcp|udp)[^[:cntrl:]]*(i/o timeout|connection refused|network is unreachable)|tls handshake timeout|connection reset by peer|connection timed out|context deadline exceeded|temporary failure in name resolution|no such host|unexpected eof)' \
    "$1"
}

registry_login() {
  local label="$1" host="$2" username="$3" credential_file="$4"
  local login_error attempt
  for attempt in 1 2 3; do
    login_error="$(mktemp "$work/login-error.XXXXXX")"
    if SKOPEO_AUTH_VOLUME="$auth_volume" \
      "$skopeo_runner" login --authfile /auth/auth.json --username "$username" \
      --password-stdin "$host" <"$credential_file" \
      >/dev/null 2>"$login_error"; then
      return 0
    fi
    if grep -Fq '[skopeo-runtime] class=runtime-unavailable' "$login_error"; then
      echo 'Skopeo runtime became unavailable during registry operation' >&2
      sed -n '1,20p' "$login_error" >&2
      return 1
    fi
    if registry_connectivity_error "$login_error"; then
      printf 'Unable to reach %s registry after bounded retries\n' "$label" >&2
      sed -n '1,20p' "$login_error" >&2
      return 1
    fi
    if registry_auth_error "$login_error" && [ "$attempt" -lt 3 ]; then
      printf '%s registry login was rejected; retrying authentication (attempt %s/3)\n' \
        "$label" "$((attempt + 1))" >&2
      continue
    fi
    printf 'Unable to authenticate to %s registry\n' "$label" >&2
    sed -n '1,20p' "$login_error" >&2
    return 1
  done
}

readonly HARBOR_HOST='registry.example.invalid'
[[ -n "$HARBOR_PUBLISH_USERNAME" && "$HARBOR_PUBLISH_USERNAME" != *$'\n'* ]] || {
  echo 'Harbor username is malformed' >&2
  exit 1
}
registry_login Harbor "$HARBOR_HOST" "$HARBOR_PUBLISH_USERNAME" "$HARBOR_PUBLISH_PASSWORD_FILE"
if [ "$target_label" = GHCR ]; then
  [[ -n "$target_username" && "$target_username" != *$'\n'* ]] || {
    echo 'GHCR username is malformed' >&2
    exit 1
  }
  registry_login GHCR "$target_host" "$target_username" "$target_credential_file"
fi

inspect_digest() {
  local ref="$1"
  SKOPEO_AUTH_VOLUME="$auth_volume" \
    "$skopeo_runner" inspect --authfile /auth/auth.json \
      --format '{{.Digest}}' "docker://$ref"
}

source_digest="$(inspect_digest "$source_ref")"
if [ "$source_digest" != "$expected_digest" ]; then
  echo "Canonical Harbor manifest digest does not match its immutable reference" >&2
  exit 1
fi

first_target_ref=""
for tag in "${tags[@]}"; do
  target_ref="$target_repository:$tag"
  [ -n "$first_target_ref" ] || first_target_ref="$target_ref"
  : >"$inspect_error"
  if existing_digest="$(inspect_digest "$target_ref" 2>"$inspect_error")"; then
    if [ "$existing_digest" != "$expected_digest" ]; then
      if [ "$tag" != latest ]; then
        echo "Refusing to replace immutable $target_label tag with a different digest: $target_ref" >&2
        exit 1
      fi
      printf 'Updating support-image compatibility alias: %s (%s -> %s)\n' \
        "$target_ref" "$existing_digest" "$expected_digest"
    else
      printf '%s tag already matches canonical digest: %s@%s\n' "$target_label" \
        "$target_ref" "$expected_digest"
      continue
    fi
  elif ! grep -Eiq 'manifest unknown|name unknown|not found|status code: 404|status: 404' \
      "$inspect_error"; then
    echo "Unable to determine whether $target_label tag is absent: $target_ref" >&2
    sed -n '1,20p' "$inspect_error" >&2
    exit 1
  fi

  SKOPEO_AUTH_VOLUME="$auth_volume" \
    "$skopeo_runner" copy --all --preserve-digests --retry-times 3 \
    --src-authfile /auth/auth.json --dest-authfile /auth/auth.json \
    "docker://$source_ref" "docker://$target_ref"

  mirrored_digest="$(inspect_digest "$target_ref")"
  if [ "$mirrored_digest" != "$expected_digest" ]; then
    echo "$target_label manifest digest diverged after exact copy: $target_ref" >&2
    exit 1
  fi
  printf 'Copied canonical image manifest: %s@%s\n' \
    "$target_ref" "$expected_digest"
done

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'source_digest=%s\n' "$expected_digest"
    if [ "$target_label" = GHCR ]; then
      printf 'ghcr_ref=%s\n' "$first_target_ref"
      printf 'ghcr_digest=%s\n' "$expected_digest"
    else
      printf 'harbor_ref=%s\n' "$first_target_ref"
      printf 'harbor_digest=%s\n' "$expected_digest"
    fi
  } >>"$GITHUB_OUTPUT"
fi
