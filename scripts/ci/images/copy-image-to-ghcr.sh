#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 SOURCE_DIGEST_REF GHCR_REPOSITORY TAG [TAG...]" >&2
  exit 2
fi

source_ref="$1"
target_repository="$2"
shift 2
tags=("$@")

readonly source_pattern='^git\.example\.invalid/codewire/(dashboard|derp|gateway|services|mesh|base|workspace)@sha256:([0-9a-f]{64})$'
if [[ ! "$source_ref" =~ $source_pattern ]]; then
  echo "Source must be an exact supported git.example.invalid digest reference" >&2
  exit 1
fi
image_name="${BASH_REMATCH[1]}"
expected_digest="sha256:${BASH_REMATCH[2]}"

if [ "$target_repository" != "ghcr.io/codewiresh/$image_name" ]; then
  echo "GHCR repository must match the supported source image family" >&2
  exit 1
fi

declare -A seen_tags=()
for tag in "${tags[@]}"; do
  if [ "$tag" = latest ]; then
    if [[ ! "$image_name" =~ ^(base|workspace)$ ]]; then
      echo "The mutable latest alias is restricted to base and workspace compatibility" >&2
      exit 1
    fi
  elif [[ ! "$tag" =~ ^[0-9a-f]{40}$ ]] \
    && [[ ! "$tag" =~ ^[0-9a-f]{64}$ ]] \
    && [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Destination tags must be an exact source object ID, stable SemVer, or an approved support-image latest alias" >&2
    exit 1
  fi
  if [[ -n "${seen_tags[$tag]:-}" ]]; then
    echo "Duplicate destination tag: $tag" >&2
    exit 1
  fi
  seen_tags[$tag]=1
done

: "${GITEA_REGISTRY_TOKEN_FILE:?GITEA_REGISTRY_TOKEN_FILE is required}"
: "${GHCR_PUBLISH_USERNAME:?GHCR_PUBLISH_USERNAME is required}"
: "${GHCR_PUBLISH_TOKEN_FILE:?GHCR_PUBLISH_TOKEN_FILE is required}"
gitea_username="${GITEA_REGISTRY_USERNAME:-ci}"
skopeo_runner="${SKOPEO_RUNNER:-scripts/ci/images/run-skopeo-container.sh}"
docker_bin="${DOCKER_BIN:-docker}"

for secret_file in "$GITEA_REGISTRY_TOKEN_FILE" "$GHCR_PUBLISH_TOKEN_FILE"; do
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

SKOPEO_AUTH_VOLUME="$auth_volume" \
  "$skopeo_runner" login --authfile /auth/auth.json --username "$gitea_username" \
  --password-stdin git.example.invalid <"$GITEA_REGISTRY_TOKEN_FILE" >/dev/null
SKOPEO_AUTH_VOLUME="$auth_volume" \
  "$skopeo_runner" login --authfile /auth/auth.json --username "$GHCR_PUBLISH_USERNAME" \
  --password-stdin ghcr.io <"$GHCR_PUBLISH_TOKEN_FILE" >/dev/null

inspect_digest() {
  local ref="$1"
  SKOPEO_AUTH_VOLUME="$auth_volume" \
    "$skopeo_runner" inspect --authfile /auth/auth.json \
      --format '{{.Digest}}' "docker://$ref"
}

source_digest="$(inspect_digest "$source_ref")"
if [ "$source_digest" != "$expected_digest" ]; then
  echo "Canonical Gitea manifest digest does not match its immutable reference" >&2
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
        echo "Refusing to replace immutable GHCR tag with a different digest: $target_ref" >&2
        exit 1
      fi
      printf 'Updating support-image compatibility alias: %s (%s -> %s)\n' \
        "$target_ref" "$existing_digest" "$expected_digest"
    else
      printf 'GHCR tag already matches canonical digest: %s@%s\n' \
        "$target_ref" "$expected_digest"
      continue
    fi
  elif ! grep -Eiq 'manifest unknown|name unknown|not found|status code: 404|status: 404' \
      "$inspect_error"; then
    echo "Unable to determine whether GHCR tag is absent: $target_ref" >&2
    exit 1
  fi

  SKOPEO_AUTH_VOLUME="$auth_volume" \
    "$skopeo_runner" copy --all --preserve-digests --retry-times 3 \
    --src-authfile /auth/auth.json --dest-authfile /auth/auth.json \
    "docker://$source_ref" "docker://$target_ref"

  mirrored_digest="$(inspect_digest "$target_ref")"
  if [ "$mirrored_digest" != "$expected_digest" ]; then
    echo "GHCR manifest digest diverged after exact copy: $target_ref" >&2
    exit 1
  fi
  printf 'Copied canonical image manifest: %s@%s\n' \
    "$target_ref" "$expected_digest"
done

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'source_digest=%s\n' "$expected_digest"
    printf 'ghcr_ref=%s\n' "$first_target_ref"
    printf 'ghcr_digest=%s\n' "$expected_digest"
  } >>"$GITHUB_OUTPUT"
fi
