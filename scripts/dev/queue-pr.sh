#!/usr/bin/env bash
# Queue a pull request for the merge queue (infra tools/merge-queue, infra#2599),
# with merge-pr.sh's checks: a public-safe commit title and a merge Cargo
# accepts. The queue squashes it once its head is green and approved, as
# "TITLE (#N)" with "Reviewed-on: #N", the message merge-pr.sh writes.
set -euo pipefail

if [[ $# == 1 && ( "$1" == --help || "$1" == -h ) ]]; then
  printf 'usage: scripts/dev/queue-pr.sh PR_NUMBER "COMMIT TITLE"\n'
  exit 0
fi
if [[ $# != 2 || ! "$1" =~ ^[1-9][0-9]*$ || -z "$2" || "$2" == *$'\n'* || "$2" == *$'\r'* || "$2" == *'Reviewed-on:'* ]]; then
  printf 'usage: scripts/dev/queue-pr.sh PR_NUMBER "COMMIT TITLE"\n' >&2
  exit 2
fi
pr="$1" title="$2"
# The title becomes a commit on main and on the public mirror, and it cannot be
# changed afterwards. A placeholder is refused: #4834's pull request was
# created with the title "x", and main carries "x (#4834)". Among main's last
# 3,000 subjects the rule refuses only that one; the shortest real title is
# "style: rustfmt", 14 characters and two words.
subject="${title% (#"$pr")}"
read -ra words <<<"$subject"
if [[ ${#subject} -lt 10 || ${#words[@]} -lt 2 ]]; then
  printf 'queue-pr.sh: "%s" is not a commit title: it needs at least 10 characters and two words\n' "$subject" >&2
  exit 2
fi
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
  printf 'queue-pr.sh: #%s does not merge cleanly with main\n' "$pr" >&2
  exit 1
fi
while IFS= read -r lock; do
  if ! git -C "$root" show "$tree:$lock" |
      python3 "$root/scripts/checks/repo_checks.py" cargo-lock-integrity --lock - --label "merged $lock"; then
    printf 'queue-pr.sh: #%s would leave main with a %s Cargo refuses; merge main into it and update the lock\n' \
      "$pr" "$lock" >&2
    exit 1
  fi
done < <(git -C "$root" ls-tree -r --name-only "$tree" | grep -E '(^|/)([A-Za-z0-9_-]+\.)?Cargo\.lock$')

fj pr -R origin edit "$pr" title "$subject" >/dev/null
fj pr -R origin edit "$pr" labels -a merge-queue >/dev/null
printf 'queue-pr.sh: #%s is queued as "%s (#%s)"; the merge queue lands it once Required verification is green and codewire-review-bot approved its head\n' \
  "$pr" "$subject" "$pr"
