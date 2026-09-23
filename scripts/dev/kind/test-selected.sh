#!/usr/bin/env bash
# Run only the retained Kind suites the current change needs, on the kept
# cluster. The repository's one path classifier (scripts/dev/preflight.sh)
# selects capability tokens; this table maps them to suites. A change with no
# narrower suite asks for the full gate instead of guessing.
#
#   KIND_CLUSTER_NAME=<cluster> scripts/dev/kind/test-selected.sh
#   KIND_TEST_SUITES="credentials dashboard-browser" ...   # explicit suites
#   PREFLIGHT_BASE_SHA=<parent> ...                        # stacked branches
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
ORDER=(edge-contract credentials workspace-services dashboard-browser final-fencing runtime-acceptance)

log() { printf '[kind-test] %s\n' "$*" >&2; }
die() { printf '[kind-test] error: %s\n' "$*" >&2; exit 1; }

declare -A wanted=()
full_reasons=()

want() { local suite; for suite in "$@"; do wanted["$suite"]=1; done; }

map_token() {
  case "$1" in
    rust_pkg_codewire_credential_service | rust_pkg_codewire_credential_broker | \
      rust_pkg_codewire_credential_bridge | rust_pkg_codewire_platform_credentials | \
      rust_pkg_codewire_access | rust_pkg_codewire_local_credentials | \
      rust_pkg_codewire_cli | rust_pkg_codewire_cli_bin)
      want credentials ;;
    rust_pkg_codewire_dashboard_web | web) want dashboard-browser ;;
    rust_pkg_codewire_idp) want dashboard-browser edge-contract ;;
    rust_pkg_codewire_orchestration)
      want workspace-services final-fencing runtime-acceptance credentials ;;
    rust_pkg_codewire_daemon | rust_pkg_codewire_daemon_bridge | rust_pkg_codewire_gateway)
      want workspace-services ;;
    rust_pkg_codewire_client) want edge-contract workspace-services ;;
    # Workspace inputs, shared contracts, and crates without a narrower suite
    # yet: server-core (schema and migrations), billing, Mesh/coordinator.
    # `database` and `deploy` name CI check families, not changed schema or
    # manifests; manifest-only changes fall through to the no-suite rule.
    rust_workspace | workspace_image | contracts_proto | rust_pkg_*)
      full_reasons+=("$1") ;;
    # Kind relevance alone is decided after every token is mapped. Base
    # manifests select `deploy`, and the Kind cluster renders them too.
    edge_kind | kind | deploy) ;;
    # Families with no in-cluster behavior of their own.
    *) ;;
  esac
}

if [ -n "${KIND_TEST_SUITES:-}" ]; then
  read -r -a requested <<<"$KIND_TEST_SUITES"
  want "${requested[@]}"
  log "running requested suites"
else
  explain="$("$ROOT/scripts/dev/preflight.sh" --explain 2>&1)" \
    || { printf '%s\n' "$explain" >&2; die "preflight could not classify the change"; }
  classification="$(sed -n 's/^preflight classification: //p' <<<"$explain")"
  selection="$(sed -n 's/^preflight selection: //p' <<<"$explain")"
  [ -n "$selection" ] || die "preflight printed no selection"
  if [ "$classification" = unclassified ]; then
    full_reasons+=(unclassified)
  fi
  IFS='|' read -r -a tokens <<<"$selection"
  kind_relevant=false
  for token in "${tokens[@]}"; do
    [ -n "$token" ] || continue
    case "$token" in edge_kind | kind | deploy) kind_relevant=true ;; esac
    map_token "$token"
  done
  if [ "$kind_relevant" = true ] && [ "${#wanted[@]}" -eq 0 ] && [ "${#full_reasons[@]}" -eq 0 ]; then
    full_reasons+=("Kind-relevant change with no narrower suite")
  fi
fi

if [ "${#full_reasons[@]}" -gt 0 ]; then
  log "this change needs the full gate (${full_reasons[*]}):"
  log "  KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME} KEEP_KIND_CLUSTER=1 make e2e-kind"
  exit 3
fi
if [ "${#wanted[@]}" -eq 0 ]; then
  log "no Kind-relevant change; nothing to run"
  exit 0
fi

selected=()
for suite in "${ORDER[@]}"; do
  [ -n "${wanted[$suite]:-}" ] && selected+=("$suite")
done
for suite in "${!wanted[@]}"; do
  printf '%s\n' "${ORDER[@]}" | grep -Fxq "$suite" || die "unknown suite: ${suite}"
done
log "suites: ${selected[*]}"
for suite in "${selected[@]}"; do
  # Test the current source against the cluster as deployed, not only an
  # unchanged tree that matches the image receipt.
  KIND_CLUSTER_NAME="$KIND_CLUSTER_NAME" KIND_RETAINED_USE_CLUSTER_WORKSPACE=1 \
    "$ROOT/scripts/ci/verify/kind-e2e.sh" suite "$suite" || die "suite ${suite} failed"
done
log "all selected suites green"
