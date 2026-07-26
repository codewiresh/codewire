#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 SOURCE_DIGEST_REF GHCR_REPOSITORY TAG [TAG...]" >&2
  exit 2
fi

source_ref="$1"
target_repository="$2"
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

GITEA_REGISTRY_TOKEN_FILE="$gitea_token_file" \
GHCR_PUBLISH_TOKEN_FILE="$ghcr_token_file" \
  "$copy_helper" "$@"

for token_file in "$gitea_token_file" "$ghcr_token_file"; do
  shred -u "$token_file" 2>/dev/null || rm -f "$token_file"
done

public_ref="$target_repository@$expected_digest"
public_digest="$(
  "$skopeo_runner" inspect --no-creds --format '{{.Digest}}' \
    "docker://$public_ref"
)"
if [ "$public_digest" != "$expected_digest" ]; then
  echo "Anonymous GHCR manifest digest does not match the canonical image" >&2
  exit 1
fi

printf 'Anonymous GHCR digest accepted: %s\n' "$public_ref"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'ghcr_public_ref=%s\n' "$public_ref" >>"$GITHUB_OUTPUT"
fi
