#!/usr/bin/env bash
# usage: scripts/dev/orchestrator/dev-settled.sh DEPLOY_DIR [--kustomization NAMESPACE/NAME] [--kube ACCESS_COMMAND...]
#
# Say whether Dev runs codewire's current main. Settled means: the latest
# "deploy(dev): promote source SHA" commit on the deploy checkout's origin/main
# names codewire's origin/main, and no promote-dev.yaml run is running or
# waiting. With --kube, Flux must also have applied deploy's origin/main: the
# Dev Kustomization (default flux-system/codewire-deploy-dev) is Ready with
# that lastAppliedRevision. ACCESS_COMMAND is everything after --kube, a
# command prefix that runs kubectl against Dev with read access (for example
# your cluster's access wrapper followed by --). It must be last.
#
# Exits 0 when settled, 1 when not (with the reason), 2 when it cannot tell.
# Prints SHAs and statuses only.
set -uo pipefail

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
not_settled() { printf 'not settled: %s\n' "$*"; exit 1; }

git -C "$root" fetch -q origin main || unknown 'cannot fetch codewire main'
git -C "$deploy" fetch -q origin main || unknown 'cannot fetch deploy main'
main="$(git -C "$root" rev-parse origin/main)"
deploy_main="$(git -C "$deploy" rev-parse origin/main)"
source="$(git -C "$deploy" log origin/main --first-parent -500 --format=%s |
  sed -nE 's/^deploy\(dev\): promote source ([0-9a-f]{40})$/\1/p' | head -n 1)"
[[ -n "$source" ]] || unknown 'no dev promote commit in the last 500 deploy commits'
[[ "$source" == "$main" ]] || not_settled "Dev's source is $source, codewire main is $main"

for status in running waiting; do
  runs="$(fj -C "$deploy" actions runs list -R origin -L 5 --workflow promote-dev.yaml --status "$status" --output json 2>/dev/null |
    jq -r '.runs[].id')" || unknown "cannot list $status promote-dev runs"
  [[ -z "$runs" ]] || not_settled "promote-dev is $status: $(tr '\n' ' ' <<<"$runs")"
done

if [[ ${#kube[@]} -gt 0 ]]; then
  flux="$("${kube[@]}" kubectl -n "${kustomization%%/*}" get kustomizations.kustomize.toolkit.fluxcd.io \
    "${kustomization#*/}" -o json 2>/dev/null)" || unknown "cannot read the Kustomization $kustomization"
  applied="$(jq -r '.status.lastAppliedRevision // ""' <<<"$flux")"
  ready="$(jq -r '[.status.conditions[]? | select(.type == "Ready")][0].status // "Unknown"' <<<"$flux")"
  [[ "${applied##*sha1:}" == "$deploy_main" ]] ||
    not_settled "Flux applied ${applied##*sha1:}, deploy main is $deploy_main"
  [[ "$ready" == True ]] || not_settled "$kustomization Ready is $ready"
fi
printf 'settled: Dev source %s, deploy main %s%s\n' "$main" "$deploy_main" "${kube[0]:+, applied and Ready}"
