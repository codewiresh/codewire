#!/usr/bin/env bash
# Supply public-safe merge metadata explicitly; CLI defaults may contain URLs.
set -euo pipefail

if [[ $# == 1 && ( "$1" == --help || "$1" == -h ) ]]; then
  printf 'usage: scripts/dev/merge-pr.sh PR_NUMBER "COMMIT TITLE"\n'
  exit 0
fi
if [[ $# != 2 || ! "$1" =~ ^[1-9][0-9]*$ || -z "$2" || "$2" == *$'\n'* || "$2" == *$'\r'* || "$2" == *'Reviewed-on:'* ]]; then
  printf 'usage: scripts/dev/merge-pr.sh PR_NUMBER "COMMIT TITLE"\n' >&2
  exit 2
fi
pr="$1" title="$2"
[[ "$title" == *" (#$pr)" ]] || title="$title (#$pr)"

# A pull request's CI checks its own head, so two valid Cargo lockfiles can
# still merge textually into one Cargo refuses (b34cf2bb: a bare "base64" once
# main locked two). Check every lockfile of the merge itself before merging.
root="$(cd "$(dirname "$0")/../.." && pwd)"
git -C "$root" fetch -q origin "refs/pull/$pr/head"
head="$(git -C "$root" rev-parse FETCH_HEAD)"
git -C "$root" fetch -q origin main
base="$(git -C "$root" rev-parse FETCH_HEAD)"
if ! tree="$(git -C "$root" merge-tree --write-tree "$base" "$head")"; then
  printf 'merge-pr.sh: #%s does not merge cleanly with main\n' "$pr" >&2
  exit 1
fi
while IFS= read -r lock; do
  if ! git -C "$root" show "$tree:$lock" |
      python3 "$root/scripts/checks/repo_checks.py" cargo-lock-integrity --lock - --label "merged $lock"; then
    printf 'merge-pr.sh: #%s would leave main with a %s Cargo refuses; merge main into it and update the lock\n' \
      "$pr" "$lock" >&2
    exit 1
  fi
done < <(git -C "$root" ls-tree -r --name-only "$tree" | grep -E '(^|/)([A-Za-z0-9_-]+\.)?Cargo\.lock$')

exec fj pr -R origin merge "$pr" -M squash -t "$title" -m "Reviewed-on: #$pr"
