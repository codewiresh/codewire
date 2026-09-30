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
  prepare_kind_temp_runtime || return $?

  # Saved profiles serialize only their own runtime. Legacy fixed-port callers
  # retain the host transaction lock; builds share a bounded publication lock.
  acquire_kind_host_lock || return $?

  # An existing cluster is never implicitly replaced, including legacy names.
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    python3 "$ROOT/scripts/dev/kind/cluster-profile.py" render-config \
      --cluster "$CLUSTER" --template "$ROOT/tests/e2e/kind/kind-config.yaml" >/dev/null || return $?
  fi
  reclaim_cancelled_ci_clusters "$KIND_CONFIG" || return $?

  trap cleanup EXIT

  ingress_path_drift_check
  # Cold image and smoke-binary compilation must not compete with an idle
  # nested control plane. Provision Kind only when every host-side build input
  # is ready, then prove the API settles between every large image import.
  build_images_and_smokes || return $?
  create_cluster || return $?
  load_images_into_kind || return $?
  deploy_overlay || return $?
  host_key_authorization_smoke
  edge_routing_probes
  connect_edge_probes
  coordinator_runtime_smokes
  billing_contract_through_ingress
  deploy_agent_sandbox_and_smoke
  dashboard_browser_e2e
  # TTL verifies provenance while its product-created workspace still exists.
  rust_reconciler_ttl_e2e
  if [ "$KEEP_KIND_CLUSTER" = 1 ]; then
    mark_retained_cluster_prepared || return $?
  fi
  log "green"
}
