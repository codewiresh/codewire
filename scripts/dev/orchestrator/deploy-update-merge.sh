#!/usr/bin/env bash
# usage: scripts/dev/orchestrator/deploy-update-merge.sh [--dry-run] [--timeout SECONDS] DEPLOY_DIR PR BRANCH
#
# Bring a codewire/deploy pull request up to date and merge it. In a throwaway
# detached worktree of the deploy checkout DEPLOY_DIR, merge origin/main into
# BRANCH (a merge, never a rebase: the branch may be someone else's), push it,
# wait until both deploy checks are Success on the pushed head and Forgejo can
# merge it, then merge with a body that carries no URL. The worktree is removed
# on every exit path.
#
# --dry-run makes the local merge and reports it, pushing and merging nothing.
# --timeout bounds the wait for the checks (default 1800 seconds). Exits 0 when
# merged, 1 on a conflict, a failed check, or a timeout. Prints heads and
# statuses only.
set -uo pipefail

usage() {
  printf 'usage: scripts/dev/orchestrator/deploy-update-merge.sh [--dry-run] [--timeout SECONDS] DEPLOY_DIR PR BRANCH\n' >&2
  exit 2
}

dry_run=0 timeout_seconds=1800
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) dry_run=1 ;;
    --timeout) [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || usage; timeout_seconds="$2"; shift ;;
    -h|--help) printf 'usage: scripts/dev/orchestrator/deploy-update-merge.sh [--dry-run] [--timeout SECONDS] DEPLOY_DIR PR BRANCH\n'; exit 0 ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
  shift
done
[[ $# -eq 3 && "$2" =~ ^[1-9][0-9]*$ && -n "$3" ]] || usage
deploy="$(git -C "$1" rev-parse --show-toplevel 2>/dev/null)" || { printf '%s is not a git checkout\n' "$1" >&2; exit 2; }
readonly deploy pr="$2" branch="$3"
git check-ref-format --branch "$branch" >/dev/null 2>&1 || usage
readonly poll="${ORCHESTRATOR_POLL_SECONDS:-20}"
readonly required=(
  'Supply-chain scan / Supply-chain scan (pull_request_target)'
  'Validate deploy release / validate (pull_request)'
)

stop() {
  printf '#%s: %s\n' "$pr" "$*"
  exit 1
}

worktree=''
cleanup() {
  [[ -n "$worktree" ]] || return 0
  git -C "$worktree" merge --abort >/dev/null 2>&1
  if git -C "$deploy" worktree remove "$worktree" 2>/dev/null; then
    git -C "$deploy" worktree prune
  else
    printf '#%s: could not remove the worktree %s; inspect it and remove it by hand\n' "$pr" "$worktree" >&2
  fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

plain() { LC_ALL=C sed -e 's/\xe2\x81[\xa6-\xa9]//g' -e 's/STYLE()//g'; }
pr_head() { git -C "$deploy" ls-remote origin "refs/pull/$pr/head" 2>/dev/null | cut -f1; }
status_ok() {
  local line
  while IFS= read -r line; do
    [[ "$line" == "- Success "*" $2" ]] && return 0
  done <<<"$1"
  return 1
}

git -C "$deploy" fetch -q origin main "+refs/heads/$branch:refs/remotes/origin/$branch" ||
  stop "could not fetch main and $branch from origin"
[[ "$(git -C "$deploy" rev-parse "origin/$branch")" == "$(pr_head)" ]] ||
  stop "$branch is not the head of pull request #$pr"

worktree="$(mktemp -d "${TMPDIR:-/tmp}/deploy-update-$pr.XXXXXX")" || stop 'mktemp failed'
rmdir "$worktree"
git -C "$deploy" worktree add -q --detach "$worktree" "origin/$branch" || { worktree=''; stop 'git worktree add failed'; }
before="$(git -C "$worktree" rev-parse HEAD)"
git -C "$worktree" merge -q --no-edit origin/main >/dev/null 2>&1 || stop "merging main into $branch conflicts; resolve it on the branch"
head="$(git -C "$worktree" rev-parse HEAD)"
if [[ "$head" == "$before" ]]; then
  printf '#%s: %s already contains main (%s)\n' "$pr" "$branch" "$head"
else
  printf '#%s: merged main into %s: %s\n' "$pr" "$branch" "$head"
fi
if [[ "$dry_run" == 1 ]]; then
  printf '#%s: dry run, nothing pushed or merged\n' "$pr"
  exit 0
fi
if [[ "$head" != "$before" ]]; then
  git -C "$worktree" push -q origin "HEAD:refs/heads/$branch" 2>&1 | grep -v '^remote:' >&2
  [[ "${PIPESTATUS[0]}" == 0 ]] || stop "push to $branch failed"
fi

deadline=$(($(date +%s) + timeout_seconds))
for ((;;)); do
  current="$(pr_head)"
  [[ -z "$current" || "$current" == "$head" ]] || stop "the head moved to $current; someone else pushed"
  status="$(fj -C "$deploy" pr status "$pr" 2>/dev/null | plain)"
  if grep -Eq '^- (Failure|Error) ' <<<"$status"; then
    grep -E '^- (Failure|Error) ' <<<"$status"
    stop "a check failed on $head"
  fi
  ready=1
  [[ "$current" == "$head" && "$(head -n 1 <<<"$status")" == Open*"Can be merged" ]] || ready=''
  for context in "${required[@]}"; do status_ok "$status" "$context" || ready=''; done
  [[ -n "$ready" ]] && break
  (( $(date +%s) < deadline )) || stop "the checks did not pass on $head within $timeout_seconds seconds"
  sleep "$poll"
done

fj -C "$deploy" pr merge "$pr" -M merge -d -m "Reviewed-on: #$pr" >/dev/null 2>&1
state="$(fj -C "$deploy" pr view "$pr" 2>/dev/null | plain | sed -n 2p)"
[[ "$state" == *Merged* ]] || stop "not merged: $state"
printf '#%s: merged %s\n' "$pr" "$head"
