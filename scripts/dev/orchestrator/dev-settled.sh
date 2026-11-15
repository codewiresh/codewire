#!/usr/bin/env bash
# usage: scripts/dev/orchestrator/dev-settled.sh DEPLOY_DIR [--kustomization NAMESPACE/NAME] [--kube ACCESS_COMMAND...]
#
# Say whether Dev runs codewire's current main with no Dev delivery in flight.
# Settled means: the latest "deploy(dev): promote source SHA" commit on the
# deploy checkout's origin/main names codewire's origin/main, or an ancestor of
# it whose every later main commit needs no Dev delivery (its deploy-dev run's
# selection skipped the delivery turn, as for a docs-only change); and nothing
# is delivering to Dev. A delivery is in flight while any of these is running,
# waiting or blocked:
#   - a deploy promote-dev.yaml run;
#   - a codewire deploy-dev.yaml run on main, unless it builds nothing (it
#     deferred, or its commit needs no Dev delivery) or all that is left is
#     handing the turn on after its publish job;
#   - a codewire main ci.yaml run whose commit's deploy-dev run built, or is
#     building, its images: that run's publish waits for this verdict, and main
#     CI's final job reruns it.
# Anything that touches Dev Sandboxes or their nodes waits for settled, so an
# acceptance run never fails because of it (infra#1822).
# With --kube, Flux must also have applied deploy's origin/main: the
# Dev Kustomization (default flux-system/codewire-deploy-dev) is Ready with
# that lastAppliedRevision. ACCESS_COMMAND is everything after --kube, a
# command prefix that runs kubectl against Dev with read access (for example
# your cluster's access wrapper followed by --). It must be last.
#
# Exits 0 when settled, 1 when not, with one "not settled:" line per reason,
# and 2 when it cannot tell. Prints SHAs, run ids, statuses and job names only.
set -uo pipefail

# deploy-dev.yaml's job names; the orchestrator scripts' test pins them to the
# workflow.
readonly SELECTION_JOB='Deploy selection'
readonly TURN_JOB='Dev delivery turn'
readonly BUILD_JOBS='["Build and push the service runtime images", "Build and push the daemon runtime image"]'
readonly PUBLISH_JOB='Publish the exact runtime image set'
readonly HAND_ON_JOB='Hand the Dev delivery turn on'

usage() {
  printf 'usage: scripts/dev/orchestrator/dev-settled.sh DEPLOY_DIR [--kustomization NAMESPACE/NAME] [--kube ACCESS_COMMAND...]\n' >&2
  exit 2
}

if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
  printf 'usage: scripts/dev/orchestrator/dev-settled.sh DEPLOY_DIR [--kustomization NAMESPACE/NAME] [--kube ACCESS_COMMAND...]\n'
  exit 0
fi
[[ $# -ge 1 && "$1" != -* ]] || usage
deploy="$(git -C "$1" rev-parse --show-toplevel 2>/dev/null)" || { printf '%s is not a git checkout\n' "$1" >&2; exit 2; }
shift
kustomization='flux-system/codewire-deploy-dev'
kube=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kustomization) [[ $# -ge 2 && "$2" =~ ^[a-z0-9-]+/[a-z0-9.-]+$ ]] || usage; kustomization="$2"; shift ;;
    --kube) shift; [[ $# -ge 1 ]] || usage; kube=("$@"); break ;;
    *) usage ;;
  esac
  shift
done

root="$(git rev-parse --show-toplevel)" || exit 2
unknown() { printf 'unknown: %s\n' "$*"; exit 2; }
# A helper run in $(...) prints its "unknown:" line into the capture; pass it on.
captured_unknown() { printf '%s\n' "$1"; exit 2; }
reasons=()
not_settled() { reasons+=("$*"); }

# Runs per list: the server's largest page. A full page may hide a run past
# it, so it cannot tell. Reading the next page instead could miss a run that
# moves up a page when one ahead of it finishes between the two reads.
readonly PAGE=50
# Main commits ahead of Dev's source that are read one by one; more cannot
# all be deliveries that need nothing.
readonly MAX_AHEAD=20

# "ID SHA STATUS" for each run of WORKFLOW in checkout DIR that is running,
# waiting or blocked on main. EVENT, when given, keeps pull-request runs of
# the same workflow off the page.
active_runs() { # DIR WORKFLOW [EVENT]
  local status out
  local event=(${3:+--event "$3"})
  for status in running waiting blocked; do
    out="$(fj -C "$1" actions runs list -R origin -L "$PAGE" --workflow "$2" "${event[@]}" --status "$status" --output json 2>/dev/null)" ||
      unknown "cannot list $status $2 runs"
    [[ "$(jq '.runs | length' <<<"$out")" -lt "$PAGE" ]] ||
      unknown "$PAGE or more $status $2 runs, more than one page"
    jq -r --arg status "$status" '.runs[] | select((.ref // "main") == "main") |
      "\(.id) \(.head_sha // "-") \($status)"' <<<"$out" || unknown "cannot read $status $2 runs"
  done | sort -u -k1,1
}

# The id of the deploy-dev run on main for commit SHA, or nothing.
deploy_dev_run() { # SHA
  local out
  out="$(fj -C "$root" actions runs list -R origin -L "$PAGE" --workflow deploy-dev.yaml --head "$1" --output json 2>/dev/null)" ||
    unknown "cannot list deploy-dev runs for $1"
  [[ "$(jq '.runs | length' <<<"$out")" -lt "$PAGE" ]] || unknown "$PAGE or more deploy-dev runs for $1, more than one page"
  jq -r '[.runs[] | select((.ref // "main") == "main")][0].id // ""' <<<"$out" ||
    unknown "cannot read deploy-dev runs for $1"
}

# What codewire deploy-dev run ID is doing: "no-delivery" when its selection
# skipped the delivery turn (the commit needs no Dev delivery), "builds-nothing"
# when both build jobs were skipped (it deferred), "handing-on" when only the
# hand-on job is left after its publish job, else the first job that has not
# finished.
delivery_state() { # ID
  local view
  view="$(fj -C "$root" actions runs view -R origin "$1" --output json 2>/dev/null)" ||
    unknown "cannot read deploy-dev run $1"
  jq -r --arg selection "$SELECTION_JOB" --arg turn "$TURN_JOB" --argjson builds "$BUILD_JOBS" \
    --arg publish "$PUBLISH_JOB" --arg hand "$HAND_ON_JOB" '
    def status($name): [.jobs[] | select(.name == $name) | .status][0] // "absent";
    def finished: IN("success", "failure", "cancelled", "skipped");
    if status($selection) == "success" and status($turn) == "skipped" then "no-delivery"
    elif [$builds[] as $b | status($b)] == ["skipped", "skipped"] then "builds-nothing"
    elif status($publish) == "success" and
      all(.jobs[] | select(.name != $hand); .status | finished) then "handing-on"
    else [.jobs[] | select(.status | finished | not) | .name][0] // "starting" end
  ' <<<"$view" || unknown "cannot read deploy-dev run $1's jobs"
}

git -C "$root" fetch -q origin main || unknown 'cannot fetch codewire main'
git -C "$deploy" fetch -q origin main || unknown 'cannot fetch deploy main'
main="$(git -C "$root" rev-parse origin/main)"
deploy_main="$(git -C "$deploy" rev-parse origin/main)"
source="$(git -C "$deploy" log origin/main --first-parent -500 --format=%s |
  sed -nE 's/^deploy\(dev\): promote source ([0-9a-f]{40})$/\1/p' | head -n 1)"
[[ -n "$source" ]] || unknown 'no dev promote commit in the last 500 deploy commits'
# Main may run ahead of Dev's source by commits that need no Dev delivery.
behind_reason="Dev's source is $source, codewire main is $main"
if [[ "$source" != "$main" ]]; then
  ahead=''
  if git -C "$root" merge-base --is-ancestor "$source" "$main" 2>/dev/null; then
    ahead="$(git -C "$root" rev-list --first-parent "$source..$main")"
  fi
  if [[ -z "$ahead" || "$(wc -l <<<"$ahead")" -gt "$MAX_AHEAD" ]]; then
    not_settled "$behind_reason"
  else
    while read -r commit; do
      run="$(deploy_dev_run "$commit")" || captured_unknown "$run"
      state=''
      if [[ -n "$run" ]]; then state="$(delivery_state "$run")" || captured_unknown "$state"; fi
      [[ "$state" == no-delivery ]] || { not_settled "$behind_reason"; break; }
    done <<<"$ahead"
  fi
fi

runs="$(active_runs "$deploy" promote-dev.yaml)" || captured_unknown "$runs"
while read -r id _ status; do
  [[ -n "$id" ]] || continue
  not_settled "promote-dev run $id is $status"
done <<<"$runs"

runs="$(active_runs "$root" deploy-dev.yaml)" || captured_unknown "$runs"
while read -r id sha status; do
  [[ -n "$id" ]] || continue
  state="$(delivery_state "$id")" || captured_unknown "$state"
  case "$state" in
    no-delivery|builds-nothing|handing-on) ;;
    *) not_settled "deploy-dev run $id (${sha:0:9}) is $status at \"$state\"" ;;
  esac
done <<<"$runs"

runs="$(active_runs "$root" ci.yaml push)" || captured_unknown "$runs"
while read -r id sha status; do
  [[ -n "$id" ]] || continue
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || unknown "main CI run $id has no commit"
  delivery="$(deploy_dev_run "$sha")" || captured_unknown "$delivery"
  [[ -n "$delivery" ]] || continue
  state="$(delivery_state "$delivery")" || captured_unknown "$state"
  [[ "$state" == no-delivery || "$state" == builds-nothing ]] ||
    not_settled "main CI run $id (${sha:0:9}) is $status, and deploy-dev run $delivery waits on its verdict"
done <<<"$runs"

if [[ ${#kube[@]} -gt 0 ]]; then
  flux="$("${kube[@]}" kubectl -n "${kustomization%%/*}" get kustomizations.kustomize.toolkit.fluxcd.io \
    "${kustomization#*/}" -o json 2>/dev/null)" || unknown "cannot read the Kustomization $kustomization"
  applied="$(jq -r '.status.lastAppliedRevision // ""' <<<"$flux")"
  ready="$(jq -r '[.status.conditions[]? | select(.type == "Ready")][0].status // "Unknown"' <<<"$flux")"
  [[ "${applied##*sha1:}" == "$deploy_main" ]] ||
    not_settled "Flux applied ${applied##*sha1:}, deploy main is $deploy_main"
  [[ "$ready" == True ]] || not_settled "$kustomization Ready is $ready"
fi
if [[ ${#reasons[@]} -gt 0 ]]; then
  printf 'not settled: %s\n' "${reasons[@]}"
  exit 1
fi
since=''
[[ "$source" == "$main" ]] || since=" (main $main needs no Dev delivery since)"
printf 'settled: Dev source %s%s, deploy main %s%s\n' "$source" "$since" "$deploy_main" "${kube[0]:+, applied and Ready}"
