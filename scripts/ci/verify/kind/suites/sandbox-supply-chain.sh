#!/usr/bin/env bash
# Read-only provenance observation while a real product workspace is running.
# Every workspace-service fixture self-cleans, so on a freshly provisioned
# cluster this suite has positive provenance only while a product-created
# workspace or template is alive: CI invokes it nested inside the TTL
# acceptance (reconciler-ttl-smoke), never as a standalone shard suite.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_sandbox_supply_chain_suite() {
  require_kind_errexit
  require_tool jq
  require_tool kind
  require_tool kubectl

  trap retained_suite_cleanup EXIT
  validate_retained_cluster
  assert_sandbox_supply_chain
  log "retained sandbox-supply-chain suite green"
}
