#!/usr/bin/env bash
# Revoke one GitHub App installation token (DELETE /installation/token) before
# GitHub would expire it. It runs from a step's EXIT trap, so it always exits 0:
# a token that is missing or already gone is reported, and the step's own exit
# status stands. The token is never printed or placed in arguments.
set -uo pipefail

[[ $# -eq 1 ]] || {
  printf 'usage: revoke-github-app-token.sh TOKEN_FILE\n' >&2
  exit 0
}
readonly token_file="$1"
if [[ ! -f "$token_file" || -L "$token_file" || ! -s "$token_file" ]]; then
  printf '[revoke-github-app-token] no installation token to revoke\n'
  exit 0
fi

umask 077
work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/github-app-revoke.XXXXXX")" || exit 0
trap 'find "$work" -type f -exec shred -u {} + 2>/dev/null; rm -rf "$work"' EXIT
{
  printf 'header = "Authorization: Bearer '
  tr -d '\n' <"$token_file"
  printf '"\nheader = "Accept: application/vnd.github+json"\n'
  printf 'header = "X-GitHub-Api-Version: 2022-11-28"\n'
  printf 'silent\nshow-error\nfail\nrequest = "DELETE"\n'
} >"$work/github.curl"
# The host is fixed: the token is only ever sent to GitHub's API.
if curl --config "$work/github.curl" --connect-timeout 10 --max-time 30 \
    --output /dev/null https://api.github.com/installation/token; then
  printf '[revoke-github-app-token] revoked the installation token\n'
else
  printf '::warning::[revoke-github-app-token] GitHub did not confirm the revocation; the token expires within an hour\n'
fi
exit 0
