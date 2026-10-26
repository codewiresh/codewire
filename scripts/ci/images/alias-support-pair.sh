#!/usr/bin/env bash
# Publish a main commit's support pair as aliases of an earlier published pair
# whose support inputs are identical, so every main commit has the pair a
# release tag needs (verify-release-support-pair.sh) without a rebuild.
#
# support-images.yaml runs this when its planner found the commit's base and
# workspace fingerprints equal to those of the validated published pair of
# FROM_SHA (apply-support-plan.py alias_support_pair). BASE_DIGEST and
# WORKSPACE_DIGEST are the index digests the planner validated. The script
#   1. refuses unless Harbor's own FROM_SHA tags name exactly those indexes;
#   2. tags those indexes, by digest and unchanged, as SOURCE_SHA in Harbor
#      and in the GHCR mirror, with the existing publishers and credentials;
#   3. proves that both tags in both registries resolve to the same digests,
#      and that GHCR serves the pair as a release checks it.
# It never moves latest: the alias names an older pair only for this commit.
#
# Usage: alias-support-pair.sh SOURCE_SHA FROM_SHA BASE_DIGEST WORKSPACE_DIGEST
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly REGISTRY_HOST="${CODEWIRE_IMAGE_REGISTRY:?set to the image registry host}"
readonly HARBOR_PREFIX="$REGISTRY_HOST/codewire"
readonly PUBLIC_PREFIX='ghcr.io/codewiresh'

fail() {
  printf '[alias-support-pair] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 4 ]] || {
  echo 'usage: alias-support-pair.sh SOURCE_SHA FROM_SHA BASE_DIGEST WORKSPACE_DIGEST' >&2
  exit 2
}
readonly source_sha="$1" from_sha="$2"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ && "$from_sha" =~ ^[0-9a-f]{40}$ ]] ||
  fail 'SOURCE_SHA and FROM_SHA must be full lowercase commit IDs'
[[ "$source_sha" != "$from_sha" ]] || fail 'a commit is not an alias of its own pair'
declare -A digests=([base]="$3" [workspace]="$4")
for image in base workspace; do
  [[ "${digests[$image]}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the $image digest is not an exact sha256 digest"
done
[[ "${digests[base]}" != "${digests[workspace]}" ]] || fail 'the base and workspace digests are the same'

credential_fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-$ROOT/scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"
harbor_publisher="${SUPPORT_ALIAS_HARBOR_PUBLISHER:-$ROOT/scripts/ci/images/publish-image-to-harbor.sh}"
ghcr_publisher="${SUPPORT_ALIAS_GHCR_PUBLISHER:-$ROOT/scripts/ci/images/publish-image-to-ghcr.sh}"
release_check="${SUPPORT_ALIAS_RELEASE_CHECK:-$ROOT/scripts/ci/release/verify-release-support-pair.sh}"
docker_bin="${DOCKER_BIN:-docker}"

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/codewire-support-alias.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir -m 0700 "$work/harbor-config" "$work/public-config"

"$credential_fetcher" --pull "$work/username" "$work/password" ||
  fail 'the Harbor pull credential could not be read'
DOCKER_CONFIG="$work/harbor-config" "$docker_bin" login "$REGISTRY_HOST" \
  -u "$(<"$work/username")" --password-stdin <"$work/password" >/dev/null 2>"$work/login.err" || {
  sed -n '1,20p' "$work/login.err" >&2
  fail "Harbor refused the pull robot at $REGISTRY_HOST"
}
shred -u "$work/password" 2>/dev/null || rm -f -- "$work/password"

# index_digest CONFIG REFERENCE prints the digest REFERENCE resolves to. The
# public configuration holds no credential, so GHCR is read anonymously, as a
# release reads it.
index_digest() {
  local config="$1" reference="$2"
  DOCKER_CONFIG="$work/$config" "$docker_bin" buildx imagetools inspect \
    --format '{{json .Manifest}}' "$reference" >"$work/inspect.json" 2>"$work/inspect.err" || {
    sed -n '1,20p' "$work/inspect.err" >&2
    fail "could not read $reference"
  }
  jq -er '.digest | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))' "$work/inspect.json" ||
    fail "$reference has no exact digest"
}

for image in base workspace; do
  found="$(index_digest harbor-config "$HARBOR_PREFIX/$image:$from_sha")"
  [[ "$found" == "${digests[$image]}" ]] ||
    fail "Harbor's $image:$from_sha is $found, not the planned ${digests[$image]}; refusing the alias"
done

for image in base workspace; do
  digest_ref="$HARBOR_PREFIX/$image@${digests[$image]}"
  "$harbor_publisher" "$digest_ref" "$HARBOR_PREFIX/$image" "$source_sha"
  "$ghcr_publisher" "$digest_ref" "$PUBLIC_PREFIX/$image" "$source_sha"
done

for image in base workspace; do
  harbor="$(index_digest harbor-config "$HARBOR_PREFIX/$image:$source_sha")"
  public="$(index_digest public-config "$PUBLIC_PREFIX/$image:$source_sha")"
  [[ "$harbor" == "${digests[$image]}" && "$public" == "${digests[$image]}" ]] ||
    fail "$image:$source_sha resolves to $harbor in Harbor and $public in GHCR, not ${digests[$image]}"
  printf 'support pair alias: %s:%s is %s, the pair published for %s\n' \
    "$image" "$source_sha" "${digests[$image]}" "$from_sha"
done
"$release_check" "$source_sha"
