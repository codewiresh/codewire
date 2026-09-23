#!/usr/bin/env bash
# Retained workspace services: gateway host-key restart, exec, file service,
# environment setup/session/run, resize, and the Temporal workflow smoke.
# Designed to repeat; each run leaves one errored env-temporal-kind-* row.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_workspace_services_suite() {
  require_tool jq
  require_tool kind
  require_tool kubectl
  require_tool ssh-keygen
  require_tool ssh-keyscan

  trap retained_suite_cleanup EXIT
  validate_retained_cluster || return $?
  build_retained_kind_smokes || return $?
  workspace_service_smokes || return $?
  temporal_workflow_smoke || return $?
  log "retained workspace-services suite green"
}
