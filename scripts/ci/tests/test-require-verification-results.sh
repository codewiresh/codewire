#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/select/require-verification-results.sh"

green_results=(
  VERIFICATION_SELECTION_RESULT=success
  VERIFICATION_TESTED_TREE_RECEIPT=fallback
  VERIFICATION_POLICY_RESULT=success
  VERIFICATION_STANDARD_RESULT=success
  VERIFICATION_RUST_TRANSPORT_RESULT=success
  VERIFICATION_DATABASE_RESULT=success
  VERIFICATION_SERVICES_CONTROL_RESULT=success
  VERIFICATION_SERVICES_RUNTIME_RESULT=success
  VERIFICATION_EDGE_KIND_RESULT=success
  VERIFICATION_CW_RELEASE_ASSETS_RESULT=success
  VERIFICATION_WORKSPACE_IMAGE_RESULT=success
)

expect_failure() {
  local name="$1" expected="$2"
  shift 2
  local output
  if output="$(env "${green_results[@]}" "$@" "$CHECK" 2>&1)"; then
    echo "$name: expected failure" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "$name: missing expected diagnostic: $expected" >&2
    echo "$output" >&2
    exit 1
  fi
}

env "${green_results[@]}" \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  "$CHECK" >/dev/null

env "${green_results[@]}" \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_TESTED_TREE_RECEIPT=accepted \
  VERIFICATION_TESTED_TREE_REASON=exact-tested-tree \
  VERIFICATION_TESTED_TREE_PR=42 \
  VERIFICATION_TESTED_TREE_HEAD=0123456789abcdef0123456789abcdef01234567 \
  VERIFICATION_TESTED_TREE_RUN=501 \
  "$CHECK" >/dev/null

expect_failure standard_failure 'standard capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_STANDARD_RESULT=failure

expect_failure policy_failure 'policy capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_POLICY_RESULT=failure

expect_failure rust_transport_cancel \
  'rust-transport capability group concluded cancelled' \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_RUST_TRANSPORT_RESULT=cancelled

expect_failure database_skip \
  'database capability group concluded skipped' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_DATABASE_RESULT=skipped

expect_failure services_control_skip \
  'services-control capability group concluded skipped' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_SERVICES_CONTROL_RESULT=skipped

expect_failure services_runtime_skip \
  'services-runtime capability group concluded skipped' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_SERVICES_RUNTIME_RESULT=skipped

expect_failure edge_kind_missing 'edge-kind capability group concluded missing' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_EDGE_KIND_RESULT=

expect_failure cw_release_assets_failure \
  'cw-release-assets capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_CW_RELEASE_ASSETS_RESULT=failure

expect_failure workspace_image_failure \
  'workspace-image capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_WORKSPACE_IMAGE_RESULT=failure

expect_failure malformed_selection 'verification selection is invalid or incomplete' \
  VERIFICATION_SELECTION='|valid:v3|policy|'

expect_failure failed_selector 'verification selection concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_SELECTION_RESULT=failure

expect_failure invalid_receipt 'tested-tree receipt has invalid result malformed' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_TESTED_TREE_RECEIPT=malformed

expect_failure accepted_receipt_missing_head \
  'accepted tested-tree receipt has invalid head' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_TESTED_TREE_RECEIPT=accepted \
  VERIFICATION_TESTED_TREE_REASON=exact-tested-tree \
  VERIFICATION_TESTED_TREE_PR=42 \
  VERIFICATION_TESTED_TREE_HEAD= \
  VERIFICATION_TESTED_TREE_RUN=501

echo 'required verification result tests: green'
