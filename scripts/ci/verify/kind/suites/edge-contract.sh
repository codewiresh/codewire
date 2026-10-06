#!/usr/bin/env bash
# Retained edge contract: orchestration's narrow sandbox Secret authorization
# (which still bounds the one-time removal of legacy gateway host-key
# Secrets), ingress routing and Connect edge probes. Read-only or
# self-cleaning; safe to repeat.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_edge_contract_suite() {
  require_kind_errexit
  require_tool curl
  require_tool jq
  require_tool kind
  require_tool kubectl

  trap retained_suite_cleanup EXIT
  validate_retained_cluster
  build_retained_kind_smokes
  orchestration_authorization_smoke
  edge_routing_probes
  connect_edge_probes
  log "retained edge-contract suite green"
}
