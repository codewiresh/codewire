#!/usr/bin/env bash
# Report whether this workflow's commit still moves Dev forward (#2892).
#
#   require-dev-descent.sh signing|dispatching
#
# Deploy Dev signs a runtime set, and dispatches its commit to promote-dev,
# only while the commit is a proper descendant of the source Dev runs now. It
# need not still be main's head (codewire-4f, 2026-10-21, on #2892): a commit
# its own main CI verified delivers even after main moved on, so steady merges
# cannot starve Dev. A commit Dev already runs, or one a delivered descendant
# superseded, signs and dispatches nothing; promote-dev's forward-only check
# is the second guard. Writes deliver=true or deliver=false to GITHUB_OUTPUT;
# an unreadable Dev source fails closed.
#
# One exception: a Dev source that is not in main's history at all (a history
# rewrite stranded it) cannot be descended from, so a verified commit signs and
# dispatches with a loud warning, and promote-dev's forward-only check, with
# its owner-only re-anchor inputs, decides whether Dev moves (codewire-4f,
# 2026-10-21).
set -euo pipefail

fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 && ( "$1" == signing || "$1" == dispatching ) ]] || {
  echo 'Usage: require-dev-descent.sh signing|dispatching' >&2
  exit 2
}
readonly purpose="$1"
readonly sha="${GITHUB_SHA:-}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail "GITHUB_SHA is not an exact commit; ${purpose} nothing"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
readonly candidate="$work/deployed-source.json"
"$(dirname "$0")/resolve-deployed-source.sh" "$candidate" "$sha" ||
  fail "cannot read the source Dev runs; ${purpose} nothing"
dev_sha="$(jq -er 'select(.retrieval.valid == true) | .source.sha' "$candidate" 2>/dev/null)" ||
  fail "cannot read the source Dev runs; ${purpose} nothing"
[[ "$dev_sha" =~ ^[0-9a-f]{40}$ ]] || fail "Dev's source is not an exact commit; ${purpose} nothing"

# Main's full history is present: a Dev source missing from it is not on main.
main_sha="$(git ls-remote origin refs/heads/main 2>/dev/null | awk '$2 == "refs/heads/main" { print $1 }')" || true
[[ "$main_sha" =~ ^[0-9a-f]{40}$ ]] || fail "cannot read main's head; ${purpose} nothing"
# Main can move after the job's checkout (Deploy Dev run 25510): fetch it, so
# descent is judged against the head just read, not the checkout's older one.
if ! git cat-file -e "${main_sha}^{commit}" 2>/dev/null; then
  git fetch --quiet --no-tags origin '+refs/heads/main:refs/remotes/origin/main' ||
    fail "main's head ${main_sha} is not in this checkout and fetching main failed; ${purpose} nothing"
  git cat-file -e "${main_sha}^{commit}" 2>/dev/null ||
    fail "main's head ${main_sha} is still not in this checkout after fetching main; ${purpose} nothing"
fi
[ "$(git rev-parse --is-shallow-repository)" = false ] ||
  fail "this checkout is shallow, so main's history is incomplete; ${purpose} nothing"
dev_present=true
git cat-file -e "${dev_sha}^{commit}" 2>/dev/null || dev_present=false

# Exit status 1 means "not an ancestor"; anything else is an error.
is_ancestor() {
  local status=0
  git merge-base --is-ancestor "$1" "$2" || status=$?
  ((status <= 1)) || fail "cannot compare ${1} with ${2}; ${purpose} nothing"
  return "$status"
}

if [[ "$dev_sha" == "$sha" ]]; then
  echo 'deliver=false' >>"$GITHUB_OUTPUT"
  printf 'descent check before %s: Dev already runs %s; %s nothing\n' "$purpose" "$sha" "$purpose"
elif [ "$dev_present" = true ] && is_ancestor "$dev_sha" "$sha"; then
  echo 'deliver=true' >>"$GITHUB_OUTPUT"
  printf "descent check before %s: %s descends from Dev's source %s\n" "$purpose" "$sha" "$dev_sha"
elif [ "$dev_present" = false ] || ! is_ancestor "$dev_sha" "$main_sha"; then
  echo 'deliver=true' >>"$GITHUB_OUTPUT"
  printf "::warning::descent check before %s: Dev's source %s is not in main's history (a history rewrite stranded it); %s %s anyway, and promote-dev's forward-only check decides whether Dev moves\n" \
    "$purpose" "$dev_sha" "$purpose" "$sha"
else
  echo 'deliver=false' >>"$GITHUB_OUTPUT"
  printf "descent check before %s: Dev runs %s, which %s does not move forward; %s nothing, Dev never moves backwards\n" \
    "$purpose" "$dev_sha" "$sha" "$purpose"
fi
