#!/usr/bin/env bash
# Full dashboard browser suite for an explicitly named, retained prepared Kind
# cluster. This diagnoses the browser boundary without rebuilding images or
# owning cluster deletion.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_dashboard_browser_suite() {
  require_kind_errexit
  require_tool curl
  require_tool jq
  require_tool kind
  require_tool kubectl

  trap retained_suite_cleanup EXIT
  validate_retained_cluster
  dashboard_browser_e2e
  log "retained dashboard-browser suite green"
}
