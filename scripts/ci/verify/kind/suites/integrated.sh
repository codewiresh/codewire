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
  require_tool flock
  require_tool jq
  require_tool kind
  require_tool kubectl
  require_tool openssl
  require_tool psql
  require_tool python3
  require_tool ssh-keygen
  require_tool ssh-keyscan

  # Browser dependencies are host inputs, not cluster state. Reject a missing
  # frozen install or browser before the expensive image, smoke-binary and
  # disposable-control-plane transaction begins.
  require_dashboard_browser_host_dependencies || return $?

  # kind serializes each image through the host temp filesystem before
  # importing it. Reject or replace a saturated default before compiling or
  # creating a cluster, rather than misreporting the later bootstrap fallout.
  prepare_kind_temp_runtime

  # CI gives each replica a private DinD sidecar, while local worktrees share
  # fixed host ports, image tags, and the default cluster name. Serialize the
  # complete local transaction before reclaiming any CI-owned prior run.
  acquire_kind_host_lock

  # At job startup, the current transaction name and every cluster with this
  # CI-owned run-ID prefix on the current daemon are stale. Reclaim them only
  # after taking the host lock and before checking their fixed host ports.
  reclaim_cancelled_ci_clusters "$KIND_CONFIG"

  trap cleanup EXIT

  ingress_path_drift_check
  # Cold image and smoke-binary compilation must not compete with an idle
  # nested control plane. Provision Kind only when every host-side build input
  # is ready, then prove the API settles between every large image import.
  build_images_and_smokes
  create_cluster
  load_images_into_kind
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
  # TTL verifies provenance while its product-created workspace still exists.
  rust_reconciler_ttl_e2e
  log "green"
}
