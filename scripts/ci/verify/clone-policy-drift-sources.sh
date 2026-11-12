#!/usr/bin/env bash
# Clone the two repositories the pre-merge policy drift check reads (#3821):
# codewire/deploy main in full (its hosted guards walk its history) and the
# infrastructure repository's main tip (only the clusters' sandbox Kyverno
# policies are read), from the forge this job runs on (GITHUB_SERVER_URL).
# CODEWIRE_POLICY_DRIFT_INFRA_REPOSITORY names the infrastructure repository
# as OWNER/NAME; it is configuration, so no site name is built in.
# TOKEN_FILE is the read-only policy-drift JWT; it is moved into one private
# Git configuration outside both clones and shredded, so neither clone keeps a
# credential.
#
# Usage: clone-policy-drift-sources.sh TOKEN_FILE DEST
# Writes DEST/deploy and DEST/infra.
set -euo pipefail

fail() {
  printf '[clone-policy-drift-sources] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 2 ]] || {
  printf 'usage: clone-policy-drift-sources.sh TOKEN_FILE DEST\n' >&2
  exit 2
}
readonly token_file="$1" dest="$2"
readonly forgejo="${GITHUB_SERVER_URL:-}"
readonly infra_repository="${CODEWIRE_POLICY_DRIFT_INFRA_REPOSITORY:-}"
git_bin="${GIT_BIN:-git}"

[[ "$forgejo" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || fail 'GITHUB_SERVER_URL must be an https:// origin'
[[ "$infra_repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail 'CODEWIRE_POLICY_DRIFT_INFRA_REPOSITORY must be OWNER/NAME'
[[ -f "$token_file" && ! -L "$token_file" ]] || fail 'TOKEN_FILE must be a regular file'
[[ -d "$dest" && -z "$(ls -A "$dest")" ]] || fail 'DEST must be an empty directory'

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/codewire-policy-drift-git.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

token="$(tr -d '\n' <"$token_file")"
shred -u "$token_file"
[[ "$token" =~ ^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$ ]] || {
  token=''
  fail 'TOKEN_FILE does not hold a JWT'
}
{
  printf '[http "%s/"]\n\textraHeader = Authorization: Bearer ' "$forgejo"
  printf '%s' "$token"
  printf '\n'
} >"$work/gitconfig"
token=''

clone() {
  local repository="$1" target="$2"
  shift 2
  GIT_CONFIG_GLOBAL="$work/gitconfig" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 \
    timeout 300 "$git_bin" clone --quiet --no-tags --single-branch --branch main "$@" \
    "$forgejo/$repository.git" "$target" ||
    fail "cannot clone $repository main"
  # Only the private configuration above held the credential.
  ! "$git_bin" -C "$target" config --local --get-regexp '^(http\..*extraheader|credential\.)' >/dev/null ||
    fail "$repository's clone kept a credential"
  printf '[clone-policy-drift-sources] %s main at %s\n' \
    "$repository" "$("$git_bin" -C "$target" rev-parse HEAD)"
}

clone codewire/deploy "$dest/deploy"
clone "$infra_repository" "$dest/infra" --depth 1
