#!/usr/bin/env bash
# Decide whether this four-target dry run of SHA builds at all, before the
# supersession rule (dry-run-superseded.sh) decides whether a newer run covers
# it.
#
#   - A dispatched run always builds.
#   - A push to main builds only while scripts/ci/select/main-push-switch.sh
#     says a push runs the dry run (owner decision 2026-10-20).
#   - A scheduled run builds when one of this workflow's push paths changed
#     since SCHEDULE_BASELINE_SHA, the commit the last successful scheduled
#     dry run checked, or when that commit is unknown or not on this history.
#     While the switch gives pushes to main their dry run again, it builds
#     nothing.
#
# Writes build=true or build=false to $GITHUB_OUTPUT, and the reason as one
# line to stdout and to the step summary.
#
# Usage: dry-run-deferral.sh SHA
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/cw-release-dry-run.yaml"
readonly HEX40='^[0-9a-f]{40}$'

fail() {
  printf '[dry-run-deferral] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  echo 'usage: dry-run-deferral.sh SHA' >&2
  exit 2
}
readonly SHA="$1"
[[ "$SHA" =~ $HEX40 ]] || fail 'the run commit is not a full object ID'
output="${GITHUB_OUTPUT:?}"

decide() {
  printf 'build=%s\n' "$1" >>"$output"
  printf '%s\n' "$2"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '%s\n' "$2" >>"$GITHUB_STEP_SUMMARY"
  fi
}

MAIN_PUSH_RUNS_KIND_AND_DRY_RUN=true
if [[ -f "$ROOT/scripts/ci/select/main-push-switch.sh" ]]; then
  # shellcheck source=scripts/ci/select/main-push-switch.sh
  source "$ROOT/scripts/ci/select/main-push-switch.sh"
fi
case "$MAIN_PUSH_RUNS_KIND_AND_DRY_RUN" in
  true|false) ;;
  *) fail 'MAIN_PUSH_RUNS_KIND_AND_DRY_RUN must be true or false' ;;
esac

case "${GITHUB_EVENT_NAME:-}" in
  workflow_dispatch)
    decide true 'a dispatched dry run always builds'
    exit 0
    ;;
  push)
    if [[ "$MAIN_PUSH_RUNS_KIND_AND_DRY_RUN" == true ]]; then
      decide true 'a push to main runs the dry run'
    else
      decide false 'main push: release dry run deferred to the scheduled or dispatched dry run (owner decision 2026-10-20)'
    fi
    exit 0
    ;;
  schedule) ;;
  *)
    decide true "a ${GITHUB_EVENT_NAME:-unnamed} event builds the dry run"
    exit 0
    ;;
esac

if [[ "$MAIN_PUSH_RUNS_KIND_AND_DRY_RUN" == true ]]; then
  decide false 'schedule: a push to main runs the dry run (main-push-switch.sh); the schedule builds nothing'
  exit 0
fi
baseline="${SCHEDULE_BASELINE_SHA:-}"
if [[ ! "$baseline" =~ $HEX40 ]] || ! git cat-file -e "$baseline^{commit}" 2>/dev/null \
    || ! git merge-base --is-ancestor "$baseline" "$SHA" 2>/dev/null; then
  decide true 'schedule: no successful scheduled dry run on this history to compare with; the dry run builds'
  exit 0
fi

# This workflow's own push paths, as Git glob pathspecs, read the way
# dry-run-superseded.sh reads them.
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

if [[ -n "$(git diff --name-only "$baseline" "$SHA" -- "${pathspecs[@]}")" ]]; then
  decide true "schedule: a release input changed since $baseline; the dry run builds"
else
  decide false "schedule: no release input changed since $baseline; the dry run builds nothing"
fi
