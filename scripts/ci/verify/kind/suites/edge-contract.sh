#!/usr/bin/env bash
# Retained edge contract: gateway host-key authorization, ingress routing and
# Connect edge probes. Read-only or self-cleaning; safe to repeat.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_edge_contract_suite() {
  require_tool curl
  require_tool jq
  require_tool kind
  require_tool kubectl

  trap retained_suite_cleanup EXIT
  validate_retained_cluster || return $?
  build_retained_kind_smokes || return $?
  host_key_authorization_smoke || return $?
  edge_routing_probes || return $?
  connect_edge_probes || return $?
  log "retained edge-contract suite green"
}
