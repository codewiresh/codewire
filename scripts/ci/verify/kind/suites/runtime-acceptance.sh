#!/usr/bin/env bash
# Complete the live provenance and TTL gate on the already-built Kind runtime.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_runtime_acceptance_suite() {
  require_tool flock
  require_tool kind
  require_tool kubectl

  trap retained_suite_cleanup EXIT
  acquire_kind_host_lock || return $?
  validate_retained_cluster || return $?
  rust_reconciler_ttl_e2e || return $?
  log "retained runtime-acceptance suite green"
}
