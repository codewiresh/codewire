#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '[mirror-github] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: mirror-github.sh REF\n' >&2
  exit 2
}
readonly ref="$1"
case "$ref" in
  refs/heads/main) ;;
  *) fail "unsupported mirror ref: $ref" ;;
esac

root="$(git rev-parse --show-toplevel)"
readonly root
readonly fetcher="${OPENBAO_GITHUB_FETCHER:-$root/scripts/ci/setup/fetch-openbao-github-mirror-credentials.sh}"
readonly minter="${GITHUB_APP_TOKEN_MINTER:-$root/scripts/ci/release/mint-github-app-token.sh}"
[[ -x "$fetcher" && -x "$minter" ]] || fail 'GitHub mirror credential helpers are unavailable'

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-github-mirror.XXXXXX")"
cleanup() {
  git -C "$root" remote remove github >/dev/null 2>&1 || true
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

"$fetcher" "$work/app-id" "$work/installation-id" "$work/private-key"
"$minter" "$work/app-id" "$work/installation-id" "$work/private-key" "$work/token"
{
  printf '[http "https://github.com/"]\n\textraHeader = Authorization: Basic '
  { printf 'x-access-token:'; tr -d '\n' <"$work/token"; } | base64 -w0
  printf '\n'
} >"$work/gitconfig"
chmod 0600 "$work/gitconfig"
git -C "$root" remote add github 'https://github.com/codewiresh/codewire.git'

GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1 \
  git -C "$root" ls-remote --exit-code github >/dev/null
GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1 \
  git -C "$root" push github HEAD:refs/heads/main
GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1 \
  "$root/scripts/ci/release/mirror-git-tags.sh" github
printf '[mirror-github] mirrored %s with one short-lived installation token\n' "$ref"
