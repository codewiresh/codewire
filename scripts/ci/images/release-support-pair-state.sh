#!/usr/bin/env bash
# Whether main already published the support pair (base and workspace) for a
# release's exact source commit. deploy-prod.yaml reuses a published pair as
# it is, and otherwise builds the pair one platform per job, linux/arm64 on the
# protected arm64 BuildKit node, never under emulation. Harbor is read with the
# pull-only robot. Writes build=false (both published) or build=true (neither
# published) to $GITHUB_OUTPUT. A pair published only in part is refused: its
# workspace would not be built from the published base.
#
# Usage: release-support-pair-state.sh SOURCE_SHA
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly REGISTRY_HOST='registry.example.invalid'
readonly REPOSITORY_PREFIX="$REGISTRY_HOST/codewire"

fail() {
  printf '[release-support-pair-state] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'usage: release-support-pair-state.sh SOURCE_SHA (40 lowercase hex)' >&2
  exit 2
}
readonly source_sha="$1"
output="${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
credential_fetcher="${OPENBAO_HARBOR_CREDENTIAL_FETCHER:-$ROOT/scripts/ci/setup/fetch-openbao-harbor-credentials.sh}"

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/codewire-release-support-pair.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir -m 0700 "$work/docker-config"

"$credential_fetcher" --pull "$work/username" "$work/password" ||
  fail 'the Harbor pull credential could not be read'
DOCKER_CONFIG="$work/docker-config" docker login "$REGISTRY_HOST" \
  -u "$(<"$work/username")" --password-stdin <"$work/password" >/dev/null 2>"$work/login.err" || {
  sed -n '1,20p' "$work/login.err" >&2
  fail "Harbor refused the pull robot at $REGISTRY_HOST"
}

# state IMAGE prints published or missing for IMAGE's source-SHA index.
state() {
  local image="$1" reference="$REPOSITORY_PREFIX/$1:$source_sha"
  if DOCKER_CONFIG="$work/docker-config" docker buildx imagetools inspect \
      --format '{{json .Manifest}}' "$reference" >"$work/$image.json" 2>"$work/$image.err"; then
    jq -e '.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")' "$work/$image.json" >/dev/null ||
      fail "Harbor returned no exact digest for $reference"
    printf 'published\n'
    return
  fi
  if grep -Eqi '(manifest unknown|manifest[^[:cntrl:]]*not found|name unknown|: not found|status code: 404|unexpected status[^[:cntrl:]]*404)' \
      "$work/$image.err"; then
    printf 'missing\n'
    return
  fi
  sed -n '1,20p' "$work/$image.err" >&2
  fail "could not determine whether $reference is published"
}

base="$(state base)"
workspace="$(state workspace)"
case "$base:$workspace" in
  published:published)
    build=false
    printf 'Reusing the support pair main published for %s\n' "$source_sha" ;;
  missing:missing)
    build=true
    printf 'Main published no support pair for %s; building it here, linux/arm64 on the native node\n' "$source_sha" ;;
  *)
    fail "only part of the support pair is published for $source_sha (base $base, workspace $workspace); repair the publication before releasing" ;;
esac
printf 'build=%s\n' "$build" >>"$output"
