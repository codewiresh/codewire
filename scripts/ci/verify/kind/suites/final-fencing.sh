#!/usr/bin/env bash
# Final Temporal fencing suite for an explicitly named, retained prepared Kind
# cluster. This suite diagnoses one capability; it never owns cluster deletion.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

run_retained_final_fencing_suite() {
  require_tool kind
  require_tool kubectl

  trap retained_suite_cleanup EXIT
  validate_retained_cluster || return $?
  if [ ! -x "$CARGO_CI_DIR/temporal-fencing-smoke" ]; then
    echo "::error::retained final-fencing suite requires executable ${CARGO_CI_DIR}/temporal-fencing-smoke"
    return 1
  fi
  temporal_fencing_smoke || return $?
  log "retained final-fencing suite green"
}
