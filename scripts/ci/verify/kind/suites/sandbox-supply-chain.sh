#!/usr/bin/env bash
# Read-only provenance observation while a real product workspace is running.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_sandbox_supply_chain_suite() {
  require_tool jq
  require_tool kind
  require_tool kubectl

  trap retained_suite_cleanup EXIT
  validate_retained_cluster || return $?
  assert_sandbox_supply_chain || return $?
  log "retained sandbox-supply-chain suite green"
}
