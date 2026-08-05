#!/usr/bin/env bash
set -euo pipefail

readonly source_pattern='^git\.example\.invalid/codewire/(dashboard|derp|gateway|services|mesh|base|workspace)@sha256:([0-9a-f]{64})$'

usage() {
  echo "Usage: $0 SOURCE_DIGEST_REF GHCR_REPOSITORY TAG [TAG...]" >&2
  echo "       $0 --support-pair BASE_DIGEST_REF WORKSPACE_DIGEST_REF SOURCE_SHA" >&2
  exit 2
}

support_pair=false
if [ "${1:-}" = --support-pair ]; then
  [ "$#" -eq 4 ] || usage
  support_pair=true
  base_source_ref="$2"
  workspace_source_ref="$3"
  source_sha="$4"
  [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Support image source must be an exact Git object ID" >&2
    exit 1
  }
  if [[ ! "$base_source_ref" =~ $source_pattern ]] \
      || [ "${BASH_REMATCH[1]:-}" != base ]; then
    echo "Support base must be an exact git.example.invalid/codewire/base digest reference" >&2
    exit 1
  fi
  base_digest="sha256:${BASH_REMATCH[2]}"
  if [[ ! "$workspace_source_ref" =~ $source_pattern ]] \
      || [ "${BASH_REMATCH[1]:-}" != workspace ]; then
    echo "Support workspace must be an exact git.example.invalid/codewire/workspace digest reference" >&2
    exit 1
  fi
  workspace_digest="sha256:${BASH_REMATCH[2]}"
  base_repository='ghcr.io/codewiresh/base'
  workspace_repository='ghcr.io/codewiresh/workspace'
else
  [ "$#" -ge 3 ] || usage
  source_ref="$1"
  target_repository="$2"
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
fi
: "${GHCR_PUBLISH_USERNAME:?GHCR_PUBLISH_USERNAME is required}"

secret_fetcher="${INFISICAL_SECRET_FETCHER:-scripts/ci/setup/fetch-infisical-ci-secret.sh}"
copy_helper="${GHCR_COPY_HELPER:-scripts/ci/images/copy-image-to-ghcr.sh}"
skopeo_runner="${SKOPEO_RUNNER:-scripts/ci/images/run-skopeo-container.sh}"
for helper in "$secret_fetcher" "$copy_helper"; do
  if [ ! -x "$helper" ]; then
    echo "Required GHCR publication helper is missing or not executable" >&2
    exit 1
  fi
done
if [ ! -x "$skopeo_runner" ]; then
  echo "Pinned Skopeo container runner is required for GHCR verification" >&2
  exit 1
fi

if [ "$support_pair" = true ]; then
  for public_repository in "$base_repository" "$workspace_repository"; do
    if ! "$skopeo_runner" list-tags --no-creds \
        "docker://$public_repository" >/dev/null; then
      echo "Support package must be anonymously readable before GHCR mutation: $public_repository" >&2
      exit 1
    fi
  done
fi

umask 077
work="$(mktemp -d)"
gitea_token_file="$work/gitea-registry-token"
ghcr_token_file="$work/ghcr-publish-token"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

"$secret_fetcher" GITEA_REGISTRY_TOKEN "$gitea_token_file"
"$secret_fetcher" GHCR_PUBLISH_TOKEN "$ghcr_token_file"

copy_image() {
  GITEA_REGISTRY_TOKEN_FILE="$gitea_token_file" \
  GHCR_PUBLISH_TOKEN_FILE="$ghcr_token_file" \
    "$copy_helper" "$@"
}

anonymous_digest() {
  local public_ref="$1"
  "$skopeo_runner" inspect --no-creds --format '{{.Digest}}' \
    "docker://$public_ref"
}

verify_anonymous_digest() {
  local public_ref="$1" expected="$2" public_digest
  public_digest="$(anonymous_digest "$public_ref")"
  if [ "$public_digest" != "$expected" ]; then
    echo "Anonymous GHCR manifest digest does not match the canonical image: $public_ref" >&2
    exit 1
  fi
  printf 'Anonymous GHCR digest accepted: %s\n' "$public_ref"
}

if [ "$support_pair" = true ]; then
  base_public_ref="$base_repository@$base_digest"
  workspace_public_ref="$workspace_repository@$workspace_digest"

  copy_image "$base_source_ref" "$base_repository" "$source_sha"
  verify_anonymous_digest "$base_public_ref" "$base_digest"
  copy_image "$workspace_source_ref" "$workspace_repository" "$source_sha"
  verify_anonymous_digest "$workspace_public_ref" "$workspace_digest"

  copy_image "$base_source_ref" "$base_repository" latest
  copy_image "$workspace_source_ref" "$workspace_repository" latest

  for token_file in "$gitea_token_file" "$ghcr_token_file"; do
    shred -u "$token_file" 2>/dev/null || rm -f "$token_file"
  done

  verify_anonymous_digest "$base_repository:latest" "$base_digest"
  verify_anonymous_digest "$workspace_repository:latest" "$workspace_digest"

  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      printf 'base_ghcr_public_ref=%s\n' "$base_public_ref"
      printf 'workspace_ghcr_public_ref=%s\n' "$workspace_public_ref"
    } >>"$GITHUB_OUTPUT"
  fi
  exit 0
fi

copy_image "$@"

for token_file in "$gitea_token_file" "$ghcr_token_file"; do
  shred -u "$token_file" 2>/dev/null || rm -f "$token_file"
done

public_ref="$target_repository@$expected_digest"
verify_anonymous_digest "$public_ref" "$expected_digest"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'ghcr_public_ref=%s\n' "$public_ref" >>"$GITHUB_OUTPUT"
fi
