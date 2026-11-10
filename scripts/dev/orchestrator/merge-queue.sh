#!/usr/bin/env bash
# usage: scripts/dev/orchestrator/merge-queue.sh [--dry-run] [--timeout SECONDS] PR...
#
# Merge codewire pull requests one at a time, in the order given. A pull request
# merges only when Forgejo says it can be merged and both required statuses are
# Success on its exact head (read before and after the statuses, so a push in
# between stops the queue). The merge goes through scripts/dev/merge-pr.sh with
# the pull request's own title. After each merge the queue finds main's ci.yaml
# push run for the merged commit, by its head, and watches it to the end; it
# stops on anything but success, because the next merge would land on red.
#
# --dry-run checks each pull request and says what it would merge, merging
# nothing. --timeout bounds the wait for each main run (default 7200 seconds).
# Prints QUEUE-DONE when every pull request merged and its main run passed;
# otherwise STOP with the reason, and exits non-zero. Prints run IDs, heads and
# statuses only.
set -uo pipefail

usage() {
  printf 'usage: scripts/dev/orchestrator/merge-queue.sh [--dry-run] [--timeout SECONDS] PR...\n' >&2
  exit 2
}

dry_run=0 run_timeout=7200
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry_run=1 ;;
    --timeout) [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || usage; run_timeout="$2"; shift ;;
    -h|--help) printf 'usage: scripts/dev/orchestrator/merge-queue.sh [--dry-run] [--timeout SECONDS] PR...\n'; exit 0 ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
  shift
done
[[ $# -ge 1 ]] || usage
for pr in "$@"; do [[ "$pr" =~ ^[1-9][0-9]*$ ]] || usage; done

root="$(git rev-parse --show-toplevel)" || exit 2
cd "$root" || exit 2
readonly poll="${ORCHESTRATOR_POLL_SECONDS:-20}"
readonly required=(
  'CI / Required verification (pull_request)'
  'Supply-chain scan / Supply-chain scan (pull_request_target)'
)

stop() {
  printf '%s\n' "$*"
  printf 'STOP\n'
  exit 1
}

# plain: fj's text output without its Unicode direction isolates and style marks.
plain() { LC_ALL=C sed -e 's/\xe2\x81[\xa6-\xa9]//g' -e 's/STYLE()//g'; }

pr_head() { git ls-remote origin "refs/pull/$1/head" 2>/dev/null | cut -f1; }

# status_ok STATUS CONTEXT: CONTEXT's line in fj pr status says Success.
status_ok() {
  local line
  while IFS= read -r line; do
    [[ "$line" == "- Success "*" $2" ]] && return 0
  done <<<"$1"
  return 1
}

# merged_commit PR: the first-parent commit on origin/main that merged PR.
merged_commit() {
  git log origin/main --first-parent -50 --format='%H %s' |
    awk -v suffix=" (#$1)" 'length($0) > length(suffix) && substr($0, length($0) - length(suffix) + 1) == suffix { print $1; exit }'
}

for pr in "$@"; do
  git fetch -q origin || stop "#$pr: git fetch origin failed"
  head="$(pr_head "$pr")"
  [[ "$head" =~ ^[0-9a-f]{40}$ ]] || stop "#$pr: no head ref on origin"
  status="$(fj pr status "$pr" 2>&1 | plain)" || stop "#$pr: fj pr status failed"
  state="$(head -n 1 <<<"$status")"
  [[ "$state" == Open*"Can be merged" ]] || stop "#$pr: $state"
  for context in "${required[@]}"; do
    status_ok "$status" "$context" || stop "#$pr: '$context' is not Success on ${head:0:12}"
  done
  [[ "$(pr_head "$pr")" == "$head" ]] || stop "#$pr: the head moved while its statuses were read"
  title="$(fj pr view "$pr" 2>/dev/null | plain | head -n 1)"
  title="${title% #"$pr"}"
  [[ -n "$title" ]] || stop "#$pr: no title"

  if [[ "$dry_run" == 1 ]]; then
    printf '#%s: would merge %s as "%s (#%s)"\n' "$pr" "$head" "${title% (#"$pr")}" "$pr"
    continue
  fi

  printf '#%s: merging %s\n' "$pr" "$head"
  scripts/dev/merge-pr.sh "$pr" "$title" >/dev/null 2>&1
  merge_status=$?
  # The merge call can fail after Forgejo merged; the pull request's state decides.
  merged=''
  for ((i = 0; i < 6; i++)); do
    view="$(fj pr view "$pr" 2>/dev/null | plain | sed -n 2p)"
    [[ "$view" == *Merged* ]] && { merged=1; break; }
    sleep "$poll"
  done
  [[ -n "$merged" ]] || stop "#$pr: not merged (merge-pr.sh exit $merge_status)"

  commit=''
  for ((i = 0; i < 15; i++)); do
    git fetch -q origin main && commit="$(merged_commit "$pr")"
    [[ -n "$commit" ]] && break
    sleep "$poll"
  done
  [[ -n "$commit" ]] || stop "#$pr: merged, but no commit on origin/main ends in (#$pr)"
  printf '#%s: merged as %s\n' "$pr" "$commit"

  run=''
  for ((i = 0; i < 30; i++)); do
    run="$(fj actions runs list -R origin -L 5 --workflow ci.yaml --event push --head "$commit" --output json 2>/dev/null |
      jq -r --arg head "$commit" '[.runs[] | select(.head_sha == $head)][0].id // empty')"
    [[ -n "$run" ]] && break
    sleep "$poll"
  done
  [[ -n "$run" ]] || stop "#$pr: no ci.yaml push run on $commit"
  printf '#%s: main run %s on %s\n' "$pr" "$run" "$commit"

  outcome="$(timeout "$((run_timeout + 60))" fj actions runs watch -R origin "$run" --expect-head "$commit" \
    --timeout "${run_timeout}s" --output ndjson 2>/dev/null |
    jq -r 'select(.type == "summary") | .outcome')"
  printf '#%s: main run %s: %s\n' "$pr" "$run" "${outcome:-unknown}"
  [[ "$outcome" == success ]] || stop "#$pr: main run $run did not succeed"
done
printf 'QUEUE-DONE\n'
