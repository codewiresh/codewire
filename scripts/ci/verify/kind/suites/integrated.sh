#!/usr/bin/env bash
# Complete integrated Kind gate. This order is the merge-boundary contract.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_integrated_kind_suite() {
  require_kind_errexit
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

  # Browser dependencies are host inputs, not cluster state. Reject a missing
  # frozen install or browser before the expensive image, smoke-binary and
  # disposable-control-plane transaction begins.
  require_dashboard_browser_host_dependencies

  # kind serializes each image through the host temp filesystem before
  # importing it. Reject or replace a saturated default before compiling or
  # creating a cluster, rather than misreporting the later bootstrap fallout.
  prepare_kind_temp_runtime

  # Saved profiles serialize only their own runtime. Legacy fixed-port callers
  # retain the host transaction lock; builds share a bounded publication lock.
  acquire_kind_host_lock

  # An existing cluster is never implicitly replaced, including legacy names.
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    python3 "$ROOT/scripts/dev/kind/cluster-profile.py" render-config \
      --cluster "$CLUSTER" --template "$ROOT/tests/e2e/kind/kind-config.yaml" >/dev/null || return $?
  fi
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
  orchestration_authorization_smoke
  edge_routing_probes
  connect_edge_probes
  coordinator_runtime_smokes
  billing_contract_through_ingress
  deploy_agent_sandbox_and_smoke
  dashboard_browser_e2e
  # TTL verifies provenance while its product-created workspace still exists.
  rust_reconciler_ttl_e2e
  if [ "$KEEP_KIND_CLUSTER" = 1 ]; then
    mark_retained_cluster_prepared
  fi
  log "green"
}

# Retained integrated remainder: the coordinator runtime and billing Connect
# contract probes that no narrower retained suite covers. The complete gate
# above runs them between the edge probes and the sandbox/Temporal block; on a
# prepared cluster this suite reruns exactly those two probe groups.
run_retained_integrated_suite() {
  require_kind_errexit
  require_tool curl
  require_tool jq
  require_tool kind
  require_tool kubectl

  trap retained_suite_cleanup EXIT
  validate_retained_cluster
  build_retained_kind_smokes
  # The internal binding fixture owns a synthetic SandboxClaim whose status a
  # live agent-sandbox controller immediately rewrites, after which the
  # orchestration reconciler churns the fixture's runtime identity. The serial
  # gate runs these probes before the controller is deployed; quiesce it here
  # and restore it before the billing contract, mirroring file_service_smoke.
  local controller_replicas coordinator_status=0
  controller_replicas="$(kubectl -n agent-sandbox-system get deploy/agent-sandbox-controller \
    -o jsonpath='{.spec.replicas}')" || return $?
  if [[ ! "$controller_replicas" =~ ^[0-9]+$ ]]; then
    echo "::error::agent-sandbox controller replica count is invalid: ${controller_replicas:-missing}"
    return 1
  fi
  kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller --replicas=0 || return $?
  if [ "$controller_replicas" -gt 0 ]; then
    kubectl -n agent-sandbox-system wait pod -l app=agent-sandbox-controller \
      --for=delete --timeout=60s || return $?
  fi
  # Capture the probes' status to restore the controller first. A subshell
  # keeps errexit in force for them; `fn || status=$?` would disable it.
  set +e
  (set -e; coordinator_runtime_smokes)
  coordinator_status=$?
  set -e
  kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller \
    --replicas="$controller_replicas" || return $?
  if [ "$controller_replicas" -gt 0 ]; then
    kubectl -n agent-sandbox-system rollout status \
      deploy/agent-sandbox-controller --timeout=180s || return $?
  fi
  [ "$coordinator_status" -eq 0 ] || return "$coordinator_status"
  billing_contract_through_ingress
  log "retained integrated suite green"
}
