#!/usr/bin/env bash
# Decide whether a queued four-target dry run of SHA may skip its build because
# main has moved past it. Forgejo runs this workflow's main pushes one at a
# time and keeps every queued run, so without this each merge in a burst
# would wait its turn on the single Mac runner.
#
# A push run skips only when nothing it would check is lost:
#   - main has moved past SHA, and SHA is on canonical main;
#   - a later push to main touches this workflow's `paths`, so a newer dry run
#     is queued behind this one and builds the cumulative change; and
#   - this push did not select the local runtime build, or the newest such
#     push selects it too. The runtime build follows a push's own changes, so
#     a superseded push that changed a runtime input runs unless a newer full
#     build is queued.
# A dispatched or scheduled run always builds; dry-run-deferral.sh decided
# before this whether it builds at all. An unreadable or malformed canonical
# main fails the step. The workflow runs this when the run starts and again
# at the start of each builder job, on Linux and on the Mac.
#
# Usage: dry-run-superseded.sh SHA [BEFORE]   (writes superseded= to $GITHUB_OUTPUT)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/cw-release-dry-run.yaml"
readonly HEX40='^[0-9a-f]{40}$'

fail() {
  printf '[dry-run-superseded] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 || $# -eq 2 ]] || {
  echo 'usage: dry-run-superseded.sh SHA [BEFORE]' >&2
  exit 2
}
readonly SHA="$1" BEFORE="${2:-}"
[[ "$SHA" =~ $HEX40 ]] || fail 'the run commit is not a full object ID'
output="${GITHUB_OUTPUT:?}"

decide() {
  printf 'superseded=%s\n' "$1" >>"$output"
  printf '%s\n' "$2"
}

if [[ "${GITHUB_EVENT_NAME:-}" != push ]]; then
  decide false 'only a push to main can be superseded; this run builds'
  exit 0
fi

canonical_main_sha="$(
  git ls-remote origin refs/heads/main |
    awk '$2 == "refs/heads/main" { print $1 }'
)"
[[ "$canonical_main_sha" =~ $HEX40 ]] || fail 'canonical main is unreadable or malformed'
if [[ "$canonical_main_sha" == "$SHA" ]]; then
  decide false 'building the canonical main commit'
  exit 0
fi

# Judge the later pushes on the history actually fetched.
unshallow=()
[[ "$(git rev-parse --is-shallow-repository)" != true ]] || unshallow=(--unshallow)
# The Mac's bash 3.2 treats an empty array as unbound under set -u.
git fetch --quiet --no-tags ${unshallow[@]+"${unshallow[@]}"} origin '+refs/heads/main:refs/remotes/origin/main'
main="$(git rev-parse --verify 'refs/remotes/origin/main^{commit}')"
git merge-base --is-ancestor "$SHA" "$main" || fail "$SHA is not on canonical main $main"

# This workflow's own push paths, as Git glob pathspecs.
pathspecs=()
while IFS= read -r pattern; do
  pathspecs+=(":(glob)$pattern")
done < <(
  awk '
    /^    paths:$/ { scope = 1; next }
    scope && /^      - / { line = substr($0, 9); gsub(/^'\''|'\''$/, "", line); print line; next }
    scope { exit }
  ' "$WORKFLOW"
)
[[ "${#pathspecs[@]}" -gt 0 ]] || fail 'the workflow push paths were not read'

runtime_mode() {
  python3 "$ROOT/scripts/ci/release/local_runtime_parts.py" runtime-mode
}

# Each main push is one first-parent commit (a merged pull request), and its
# run diffs that commit against its first parent.
newest=''
while IFS= read -r commit; do
  if [[ -n "$(git diff --name-only "$commit^1" "$commit" -- "${pathspecs[@]}")" ]]; then
    newest="$commit"
  fi
done < <(git rev-list --first-parent --reverse "$SHA..$main")
if [[ -z "$newest" ]]; then
  decide false "main is now $main, but no later push runs this dry run"
  exit 0
fi

own_mode=full
if [[ "$BEFORE" =~ $HEX40 && ! "$BEFORE" =~ ^0+$ ]] && git cat-file -e "$BEFORE^{commit}" 2>/dev/null; then
  own_mode="$(git diff --name-only "$BEFORE" "$SHA" | runtime_mode)"
fi
newest_mode="$(git diff --name-only "$newest^1" "$newest" | runtime_mode)"
if [[ "$own_mode" == parts || "$newest_mode" == full ]]; then
  decide true "main is now $main; the queued dry run of $newest builds this commit's changes"
else
  decide false "main is now $main, but this push changed a runtime input the queued dry run of $newest does not build"
fi
