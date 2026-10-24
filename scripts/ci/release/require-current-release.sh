#!/usr/bin/env bash
# require-current-release.sh TAG: refuse to publish TAG unless it is still
# the newest release tag on origin signed by the release tagger (#2892). Any
# same-repository job token can rerun an old release run's jobs, which keep
# that run's selection; this makes such a rerun publish nothing. Tags not
# signed by the release tagger are ignored, as the pickup ignores them.
set -euo pipefail

fail() {
  printf 'current release: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 && "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  fail 'usage: require-current-release.sh vX.Y.Z'
readonly tag="$1"
server_url="${GITHUB_SERVER_URL:-}"
server_url="${server_url%/}"
[[ "$server_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || fail 'GITHUB_SERVER_URL is unset or invalid'
[[ -n "${GITEA_TOKEN:-}" ]] || fail 'GITEA_TOKEN is required'
release_tagger="${CODEWIRE_RELEASE_TAGGER:-}"
[[ "$release_tagger" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fail 'CODEWIRE_RELEASE_TAGGER must name the release tagger'
release_api="$server_url/api/v1/repos/codewire/codewire"
release_tmp="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-current-release.XXXXXX")"
trap 'rm -rf "$release_tmp"' EXIT
release_token="$GITEA_TOKEN"
unset GITEA_TOKEN
# shellcheck source=scripts/ci/release/release-tags.sh
. "$(dirname "$0")/release-tags.sh"

release_tag_list >"$release_tmp/releases" || fail 'the release tags on origin are unavailable'
grep -q "^$tag " "$release_tmp/releases" || fail "$tag is not an annotated release tag on origin"
while read -r name object commit; do
  [[ "$name" != "$tag" ]] || { printf 'current release: %s is the newest release\n' "$tag"; exit 0; }
  release_tag_signed "$name" "$object" "$commit" && signed=0 || signed=$?
  [[ "$signed" -ne 2 ]] || fail "Forgejo's verification of $name is unavailable"
  [[ "$signed" -ne 0 ]] || fail "$name, a newer release, exists; $tag is not published again"
done <"$release_tmp/releases"
fail "$tag is not on origin"
