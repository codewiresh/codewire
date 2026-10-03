#!/usr/bin/env bash
# Bring up a retained Kind cluster for local development: the gate's image,
# cluster and deployment steps without its test suites. It never recreates or
# deletes an existing cluster; update services with `make kind-deploy`.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_kind_up() {
  require_kind_errexit
  local clusters
  require_tool curl
  require_tool base64
  require_tool docker
  require_tool flock
  require_tool jq
  require_tool kind
  require_tool kubectl
  require_tool openssl
  require_tool python3

  if [ "${KIND_CLUSTER_NAME_EXPLICIT:-0}" != "1" ] || [ -z "$KIND_CLUSTER_NAME" ]; then
    echo "::error::kind-e2e.sh up requires an explicit KIND_CLUSTER_NAME"
    return 2
  fi
  KEEP_KIND_CLUSTER=1
  prepare_kind_temp_runtime
  acquire_kind_host_lock
  clusters="$(kind get clusters)" || return $?
  if grep -Fxq "$KIND_CLUSTER_NAME" <<<"$clusters"; then
    if [ "${KIND_PROFILE:-0}" = 1 ]; then
      validate_retained_cluster
      log "cluster ${KIND_CLUSTER_NAME} is already up; saved identity and runtime accepted"
      return 0
    fi
    echo "::error::Kind cluster ${KIND_CLUSTER_NAME} already exists; update a service with make kind-deploy, or delete the cluster to recreate it"
    return 1
  fi
  require_kind_host_ports_available
  trap cleanup EXIT

  ingress_path_drift_check
  KIND_BUILD_SMOKES=0 build_images_and_smokes
  create_cluster
  load_images_into_kind
  deploy_overlay
  deploy_agent_sandbox
  mark_retained_cluster_prepared
}
