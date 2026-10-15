#!/usr/bin/env bash
# A release tag names a commit whose support pair main has published: the base
# and workspace indexes tagged with that exact source commit, each serving
# linux/amd64 and linux/arm64. support-images.yaml publishes the pair to
# Harbor and mirrors the same index to the public GHCR repositories, which this
# check reads anonymously, so it needs no credential. A commit without its pair
# is refused: tag one that support-images published.
#
# Usage: verify-release-support-pair.sh COMMIT_SHA
set -euo pipefail

readonly REGISTRY="${RELEASE_SUPPORT_PAIR_REGISTRY:-https://ghcr.io}"
readonly REPOSITORY_PREFIX='codewiresh'
readonly -a CURL_BOUNDS=(--connect-timeout 10 --max-time 30)

fail() {
  printf 'release support pair: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'usage: verify-release-support-pair.sh COMMIT_SHA (40 lowercase hex)' >&2
  exit 2
}
readonly commit="$1"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

for image in base workspace; do
  repository="$REPOSITORY_PREFIX/$image"
  curl --silent --show-error --fail "${CURL_BOUNDS[@]}" --proto '=https' \
    --output "$work/$image.token" \
    "$REGISTRY/token?scope=repository:$repository:pull" ||
    fail "could not read an anonymous pull token for $repository"
  token="$(jq -er '.token | select(type == "string" and length > 0)' "$work/$image.token")" ||
    fail "the registry issued no pull token for $repository"
  status="$(curl --silent --show-error "${CURL_BOUNDS[@]}" --proto '=https' \
    --output "$work/$image.json" --write-out '%{http_code}' \
    --header "Authorization: Bearer $token" \
    --header 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json' \
    "$REGISTRY/v2/$repository/manifests/$commit")" ||
    fail "could not read $repository:$commit"
  case "$status" in
    200) ;;
    404) fail "$repository:$commit is not published; tag a commit whose support pair support-images published (base and workspace, linux/amd64 and linux/arm64)" ;;
    *) fail "reading $repository:$commit returned HTTP $status" ;;
  esac
  platforms="$(jq -r '[.manifests[]? | .platform | select(. != null and .os != "unknown")
      | "\(.os)/\(.architecture)"] | unique | join(",")' "$work/$image.json")" ||
    fail "$repository:$commit is not an image index"
  [[ "$platforms" == linux/amd64,linux/arm64 ]] ||
    fail "$repository:$commit serves [$platforms], not exactly linux/amd64 and linux/arm64"
  printf 'release support pair: %s:%s serves %s\n' "$repository" "$commit" "$platforms"
done
