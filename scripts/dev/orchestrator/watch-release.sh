#!/usr/bin/env bash
# usage: scripts/dev/orchestrator/watch-release.sh [--timeout SECONDS] vMAJOR.MINOR.PATCH
#
# Watch the deploy-prod and cli-release runs that deliver a pushed release tag.
# Their scheduled runs pick the tag up within minutes, cli-release only after
# Production accepted it. A run is main's workflow, so its head is main's head,
# not the tag's commit: the run that delivers TAG is the one whose "Find the
# release to deliver" job emitted release_tag=TAG
# (scripts/ci/release/find-pending-release.sh). A run whose later jobs were
# all skipped delivered nothing and is never read.
#
# Exits 0 when both runs succeeded, 1 when either ended any other way (a failed
# deploy-prod stops the watch at once: cli-release would never pick the tag
# up), and 3 when --timeout (default 14400 seconds) passed first. Prints run
# IDs, heads and statuses only.
set -uo pipefail

usage() {
  printf 'usage: scripts/dev/orchestrator/watch-release.sh [--timeout SECONDS] vMAJOR.MINOR.PATCH\n' >&2
  exit 2
}

timeout_seconds=14400
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || usage; timeout_seconds="$2"; shift ;;
    -h|--help) printf 'usage: scripts/dev/orchestrator/watch-release.sh [--timeout SECONDS] vMAJOR.MINOR.PATCH\n'; exit 0 ;;
    -*) usage ;;
    *) break ;;
  esac
  shift
done
[[ $# -eq 1 && "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || usage
readonly tag="$1"

root="$(git rev-parse --show-toplevel)" || exit 2
cd "$root" || exit 2
readonly poll="${ORCHESTRATOR_POLL_SECONDS:-60}"
readonly finder='Find the release to deliver'
readonly workflows=(deploy-prod cli-release)
deadline=$(($(date +%s) + timeout_seconds))

# delivers RUN: RUN's finder job named this tag. Returns 0 yes, 1 no, 2 not
# known yet (the finder has not finished).
delivers() {
  local view job finder_status log
  view="$(fj actions runs view -R origin "$1" --output json 2>/dev/null)" || return 2
  finder_status="$(jq -r --arg name "$finder" '[.jobs[] | select(.name == $name)][0].status // "missing"' <<<"$view")"
  case "$finder_status" in
    success) ;;
    waiting|running|blocked|unknown) return 2 ;;
    *) return 1 ;;
  esac
  jq -e --arg name "$finder" 'any(.jobs[]; .name != $name and .status != "skipped")' <<<"$view" >/dev/null || return 1
  job="$(jq -r --arg name "$finder" '[.jobs[] | select(.name == $name)][0].id' <<<"$view")"
  # Read the whole log first: grep -q would stop reading early, and pipefail
  # would report the writer's SIGPIPE as no match.
  log="$(fj actions runs logs -R origin "$1" --job "$job" 2>/dev/null | tr -d '\r')" || return 2
  grep -Eq "(^|[[:space:]])release_tag=${tag//./\\.}\$" <<<"$log"
}

declare -A run=() head=() result=() seen=()
progress() {
  local state="${result[$1]:-}"
  [[ -n "$state" ]] || state="${run[$1]:+running}"
  printf '%s' "${state:-not picked up}"
}
for ((;;)); do
  for workflow in "${workflows[@]}"; do
    if [[ -z "${run[$workflow]:-}" ]]; then
      while read -r -u 3 id; do
        [[ -n "$id" && -z "${seen[$id]:-}" ]] || continue
        delivers "$id"
        case $? in
          0) run[$workflow]="$id"; break ;;
          1) seen[$id]=1 ;;
        esac
      done 3< <(fj actions runs list -R origin -L 30 --workflow "$workflow.yaml" --output json 2>/dev/null | jq -r '.runs[].id')
      if [[ -n "${run[$workflow]:-}" ]]; then
        head[$workflow]="$(fj actions runs view -R origin "${run[$workflow]}" --output json 2>/dev/null | jq -r '.run.head_sha')"
        printf '%s: run %s delivers %s (head %s)\n' "$workflow" "${run[$workflow]}" "$tag" "${head[$workflow]}"
      fi
    fi
    if [[ -n "${run[$workflow]:-}" && -z "${result[$workflow]:-}" ]]; then
      status="$(fj actions runs view -R origin "${run[$workflow]}" --output json 2>/dev/null |
        jq -r --arg head "${head[$workflow]}" 'if .run.head_sha == $head then .run.status else "head_mismatch" end')"
      case "$status" in
        waiting|running|blocked|unknown|'') ;;
        *)
          result[$workflow]="$status"
          printf '%s: run %s %s\n' "$workflow" "${run[$workflow]}" "$status"
          ;;
      esac
    fi
  done
  if [[ -n "${result[deploy-prod]:-}" && "${result[deploy-prod]}" != success ]]; then
    printf 'RELEASE-FAILED %s\n' "$tag"
    exit 1
  fi
  if [[ -n "${result[deploy-prod]:-}" && -n "${result[cli-release]:-}" ]]; then
    if [[ "${result[cli-release]}" == success ]]; then
      printf 'RELEASE-DONE %s\n' "$tag"
      exit 0
    fi
    printf 'RELEASE-FAILED %s\n' "$tag"
    exit 1
  fi
  if (( $(date +%s) >= deadline )); then
    printf 'RELEASE-TIMEOUT %s: deploy-prod %s, cli-release %s\n' "$tag" "$(progress deploy-prod)" "$(progress cli-release)"
    exit 3
  fi
  sleep "$poll"
done
