#!/usr/bin/env bash
# usage: scripts/dev/orchestrator/rerun-run.sh RUN_ID
#
# Rerun every job of one workflow run, only once nothing of it is alive. A
# rerun started while a job's previous task still runs gives that job a new
# attempt but no new task: the old task's result completes it, and its outputs
# never reach the new attempt (#4141: in run 42471 the test jobs then had no
# archive). A run cancel can leave a task running after the run reads
# cancelled, so the run's own job states are not enough.
#
# Refuses, naming them, while any job of the run is running, waiting or
# blocked, or any task of it among the newest ORCHESTRATOR_TASK_PAGES pages of
# `fj actions tasks` (default 15, 20 tasks a page) is running or waiting.
#
# A cancelled run also waits RERUN_AFTER_CANCEL_SECONDS (60) from its stop.
# Forgejo 17.0.0 can lose a cancel: the task reads cancelled while its
# container still runs on a warm VM, which the task list cannot see, until
# infra's cancel reaper stops it (about 50 s after the cancel, infra#2650).
# A rerun inside that window attaches the job's new attempt to the old task,
# and the reaper's stop then records that attempt as failure.
# Exits 0 when it reran the run, 1 when something of it is still alive or its
# cancel is too recent, 2 when it cannot tell or Forgejo refused.
set -uo pipefail

usage() {
  printf 'usage: scripts/dev/orchestrator/rerun-run.sh RUN_ID\n' >&2
  exit 2
}

if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
  printf 'usage: scripts/dev/orchestrator/rerun-run.sh RUN_ID\n'
  exit 0
fi
[[ $# -eq 1 && "$1" =~ ^[1-9][0-9]*$ ]] || usage
run="$1"
pages="${ORCHESTRATOR_TASK_PAGES:-15}"
RERUN_AFTER_CANCEL_SECONDS=60
[[ "$pages" =~ ^[1-9][0-9]*$ ]] || usage
unknown() { printf 'unknown: %s\n' "$*"; exit 2; }

view="$(fj actions runs view -R origin "$run" --output json 2>/dev/null)" || unknown "cannot read run $run"
# Tasks name their run by its number in the repository, not its ID.
number="$(jq -er '.run.number' <<<"$view" 2>/dev/null)" || unknown "run $run has no number"
alive="$(jq -r '.jobs[] | select(.status == "running" or .status == "waiting" or .status == "blocked")
  | "job \(.id) is \(.status): \(.name)"' <<<"$view")" || unknown "cannot read run $run's jobs"

for ((page = 1; page <= pages; page++)); do
  tasks="$(fj actions tasks -R origin -p "$page" 2>/dev/null)" || unknown "cannot list tasks (page $page)"
  # "#NUMBER (SHA) STATUS NAME DURATION (EVENT): TITLE"; the title is dropped.
  alive+=$'\n'"$(awk -v run="#$number" '$1 == run && ($3 == "running" || $3 == "waiting") {
      line = $0; sub(/^#[0-9]+ \([0-9a-f]+\) /, "", line); sub(/ \([a-z_]+\): .*$/, "", line)
      print "task is " line }' <<<"$tasks")"
  # A short page is the last one.
  (($(grep -c '^#' <<<"$tasks") >= 20)) || break
done
alive="$(sed '/^$/d' <<<"$alive")"

if [[ "$(jq -r '.run.status' <<<"$view")" == cancelled ]]; then
  stopped="$(jq -er '.run.stopped_at' <<<"$view" 2>/dev/null)" || unknown "cancelled run $run has no stop time"
  stopped_epoch="$(date -u -d "$stopped" +%s 2>/dev/null)" || unknown "cancelled run $run has an unreadable stop time"
  age=$(( $(date -u +%s) - stopped_epoch ))
  if (( age < RERUN_AFTER_CANCEL_SECONDS )); then
    alive+=$'\n'"run was cancelled ${age}s ago (at $stopped); a cancelled task may still run until the cancel reaper stops it, so rerun after $((RERUN_AFTER_CANCEL_SECONDS - age))s"
    alive="$(sed '/^$/d' <<<"$alive")"
  fi
fi

if [[ -n "$alive" ]]; then
  printf 'not rerun: run %s (#%s) is still alive; rerun it once all of these have ended:\n%s\n' \
    "$run" "$number" "$alive"
  exit 1
fi
fj actions runs rerun -R origin "$run" >/dev/null 2>&1 || unknown "Forgejo refused to rerun run $run"
printf 'reran run %s (#%s): every job runs again\n' "$run" "$number"
