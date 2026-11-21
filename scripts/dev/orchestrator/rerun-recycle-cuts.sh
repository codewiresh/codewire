#!/usr/bin/env bash
# usage: scripts/dev/orchestrator/rerun-recycle-cuts.sh SINCE UNTIL
#
# Rerun the runs a warm VM's scheduled recycle cut, each through rerun-run.sh.
# A light VM's recycler (05:00 and 17:00Z) waits 30 minutes for the VM to be
# idle, which waiting admission gates never let it be, then deletes the pod:
# every job still running on it after the 920 s grace ends with the runner's
# "context canceled" and fails its run (infra#1534, 2026-11-21 17:45:14Z: 11
# pull request runs). Rerunning a run keeps its ID, so a pull request run keeps
# its place in admission. The recycler itself holds no Forgejo credential, so
# a session runs this after each recycle.
#
# A run is cut when it ended failure with its stop time in [SINCE, UNTIL) (UTC,
# ISO 8601) and one of its failed jobs logged "[runner]: context canceled". A
# cancelled run is never one: a deliberate cancel (a newer push, a session's)
# ends its tasks the same way. A run that failed any other way is left alone.
# rerun-run.sh refuses a run while anything of it is alive; such a run is named,
# to be rerun once it ends.
# Exits 0 when every cut run was rerun (or there was none), 1 when one is still
# alive, 2 when a run or log could not be read or a rerun failed.
set -uo pipefail

usage() {
  printf 'usage: scripts/dev/orchestrator/rerun-recycle-cuts.sh SINCE UNTIL\n' >&2
  exit 2
}

if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
  printf 'usage: scripts/dev/orchestrator/rerun-recycle-cuts.sh SINCE UNTIL\n'
  exit 0
fi
time_re='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
[[ $# -eq 2 && "$1" =~ $time_re && "$2" =~ $time_re && "$1" < "$2" ]] || usage
since="$1" until_="$2"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Every page up to this bound is read: a cut run started before the cut, often
# long before, so no start time ends the scan early.
pages="${ORCHESTRATOR_RUN_PAGES:-6}"
[[ "$pages" =~ ^[1-9][0-9]*$ ]] || usage

# Runs ended in the window, newest first; a short page is the last one.
declare -A seen=()
candidates=()
for ((page = 1; page <= pages; page++)); do
  list="$(fj actions runs list -R origin -L 50 -p "$page" --output json 2>/dev/null)" || {
    printf 'unknown: cannot list runs (page %s)\n' "$page"
    exit 2
  }
  count="$(jq -er '.runs | length' <<<"$list" 2>/dev/null)" || { printf 'unknown: runs page %s is unreadable\n' "$page"; exit 2; }
  while read -r id; do
    [[ -n "$id" && -z "${seen[$id]:-}" ]] || continue
    seen[$id]=1
    candidates+=("$id")
  done < <(jq -r --arg since "$since" --arg until "$until_" '.runs[]
    | select(.status == "failure" and (.stopped_at // "") >= $since and (.stopped_at // "") < $until)
    | .id' <<<"$list")
  ((count >= 50)) || break
done

status=0 cut=0
for run in "${candidates[@]}"; do
  view="$(fj actions runs view -R origin "$run" --output json 2>/dev/null)" || { printf 'unknown: cannot read run %s\n' "$run"; status=2; continue; }
  jobs="$(jq -r '.jobs[] | select(.status == "failure") | .id' <<<"$view")"
  found=''
  for job in $jobs; do
    log="$(fj actions runs logs -R origin "$run" --job "$job" 2>/dev/null)" || { printf 'unknown: cannot read run %s job %s log\n' "$run" "$job"; status=2; continue 2; }
    if grep -Fq '[runner]: context canceled' <<<"$log"; then
      found="$job"
      break
    fi
  done
  if [[ -z "$found" ]]; then
    printf 'not cut: run %s failed without the runner'"'"'s context canceled\n' "$run"
    continue
  fi
  cut=$((cut + 1))
  out="$("$here/rerun-run.sh" "$run" 2>&1)"
  case $? in
    0) printf 'cut by the recycle (job %s): %s\n' "$found" "$(tail -n 1 <<<"$out")" ;;
    1) printf 'cut by the recycle (job %s), still alive, rerun once it ends: %s\n' "$found" "$(tr '\n' ' ' <<<"$out")"
       ((status == 2)) || status=1 ;;
    *) printf 'cut by the recycle (job %s), rerun failed: %s\n' "$found" "$(tr '\n' ' ' <<<"$out")"
       status=2 ;;
  esac
done
printf '%s cut run(s) between %s and %s\n' "$cut" "$since" "$until_"
exit "$status"
