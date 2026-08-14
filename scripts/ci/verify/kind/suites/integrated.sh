#!/usr/bin/env bash
# Complete integrated Kind gate. This order is the merge-boundary contract.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_integrated_kind_suite() {
  require_tool curl
  require_tool base64
  require_tool docker
  require_tool jq
  require_tool kind
  require_tool kubectl
  require_tool openssl
  require_tool psql
  require_tool ssh-keygen
  require_tool ssh-keyscan

  # The dedicated CI runner has capacity 1 and gives each replica its own DinD
  # sidecar. At job startup, every cluster with this exact CI-owned prefix on
  # the current daemon is therefore stale, including a retry of this run.
  reclaim_cancelled_ci_clusters "$KIND_CONFIG"

  trap cleanup EXIT

  ingress_path_drift_check
  # Cold image and smoke-binary compilation must not compete with an idle
  # nested control plane. Provision Kind only when every host-side build input
  # is ready, then prove the API settled after importing the large images.
  build_images_and_smokes
  create_cluster
  load_images_into_kind
  wait_for_kind_api_after_image_load
  deploy_overlay
  host_key_authorization_smoke
  edge_routing_probes
  connect_edge_probes
  internal_connect_listener_probes
  mesh_product_connect_ownership_smoke
  coordinator_ingress_smoke
  billing_contract_through_ingress
  deploy_agent_sandbox_and_smoke
  dashboard_browser_e2e
  assert_sandbox_supply_chain
  rust_reconciler_ttl_e2e
  log "green"
}
