#!/usr/bin/env bash
# Report whether this workflow's commit is still main's head (#2892).
#
#   require-main-head.sh signing|dispatching
#
# Deploy Dev signs a runtime set, and dispatches its commit to promote-dev,
# only while that commit is main's head. A run of any older commit, a rerun of
# a superseded run included, therefore signs and dispatches nothing: the newer
# commit's own delivery carries its change. Writes head=true or head=false to
# GITHUB_OUTPUT; an unreadable main fails closed.
set -euo pipefail

fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 && ( "$1" == signing || "$1" == dispatching ) ]] || {
  echo 'Usage: require-main-head.sh signing|dispatching' >&2
  exit 2
}
readonly purpose="$1"
readonly sha="${GITHUB_SHA:-}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail "GITHUB_SHA is not an exact commit; ${purpose} nothing"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

if ! remote="$(git ls-remote origin refs/heads/main)"; then
  fail "cannot read main's head; ${purpose} nothing"
fi
main_sha="$(awk '$2 == "refs/heads/main" { print $1 }' <<<"$remote")"
[[ "$main_sha" =~ ^[0-9a-f]{40}$ ]] || fail "cannot read main's head; ${purpose} nothing"

if [[ "$main_sha" == "$sha" ]]; then
  echo 'head=true' >>"$GITHUB_OUTPUT"
  printf "head check before %s: %s is main's head\n" "$purpose" "$sha"
else
  echo 'head=false' >>"$GITHUB_OUTPUT"
  printf "head check before %s: main is now %s, not %s; %s nothing, the newer commit's delivery carries this change\n" \
    "$purpose" "$main_sha" "$sha" "$purpose"
fi
