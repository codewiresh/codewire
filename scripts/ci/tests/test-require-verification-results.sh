#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/select/require-verification-results.sh"

green_results=(
  VERIFICATION_SELECTION_RESULT=success
  VERIFICATION_TESTED_TREE_RECEIPT=fallback
  VERIFICATION_POLICY_EXPECTED=true
  VERIFICATION_POLICY_RESULT=success
  VERIFICATION_STANDARD_EXPECTED=true
  VERIFICATION_STANDARD_RESULT=success
  VERIFICATION_TOOLING_EXPECTED=true
  VERIFICATION_TOOLING_RESULT=success
  VERIFICATION_RUST_TRANSPORT_EXPECTED=true
  VERIFICATION_RUST_TRANSPORT_RESULT=success
  VERIFICATION_RUST_COMPILE_EXPECTED=true
  VERIFICATION_RUST_COMPILE_RESULT=success
  VERIFICATION_RUST_SHARDS_EXPECTED=true
  VERIFICATION_RUST_PACKAGES_RESULT=success
  VERIFICATION_RUST_FEATURES_RESULT=success
  VERIFICATION_DATABASE_EXPECTED=true
  VERIFICATION_DATABASE_RESULT=success
  VERIFICATION_SERVICES_CONTROL_EXPECTED=true
  VERIFICATION_SERVICES_CONTROL_RESULT=success
  VERIFICATION_SERVICES_RUNTIME_EXPECTED=true
  VERIFICATION_SERVICES_RUNTIME_RESULT=success
  VERIFICATION_EDGE_KIND_EXPECTED=true
  VERIFICATION_EDGE_KIND_RESULT=success
  VERIFICATION_CW_RELEASE_ASSETS_EXPECTED=true
  VERIFICATION_CW_RELEASE_ASSETS_RESULT=success
  VERIFICATION_WORKSPACE_IMAGE_EXPECTED=true
  VERIFICATION_WORKSPACE_IMAGE_RESULT=success
)

unselected_results=(
  VERIFICATION_POLICY_EXPECTED=false
  VERIFICATION_POLICY_RESULT=skipped
  VERIFICATION_STANDARD_EXPECTED=false
  VERIFICATION_STANDARD_RESULT=skipped
  VERIFICATION_TOOLING_EXPECTED=false
  VERIFICATION_TOOLING_RESULT=skipped
  VERIFICATION_RUST_TRANSPORT_EXPECTED=false
  VERIFICATION_RUST_TRANSPORT_RESULT=skipped
  VERIFICATION_RUST_COMPILE_EXPECTED=false
  VERIFICATION_RUST_COMPILE_RESULT=skipped
  VERIFICATION_RUST_SHARDS_EXPECTED=false
  VERIFICATION_RUST_PACKAGES_RESULT=skipped
  VERIFICATION_RUST_FEATURES_RESULT=skipped
  VERIFICATION_DATABASE_EXPECTED=false
  VERIFICATION_DATABASE_RESULT=skipped
  VERIFICATION_SERVICES_CONTROL_EXPECTED=false
  VERIFICATION_SERVICES_CONTROL_RESULT=skipped
  VERIFICATION_SERVICES_RUNTIME_EXPECTED=false
  VERIFICATION_SERVICES_RUNTIME_RESULT=skipped
  VERIFICATION_EDGE_KIND_EXPECTED=false
  VERIFICATION_EDGE_KIND_RESULT=skipped
  VERIFICATION_CW_RELEASE_ASSETS_EXPECTED=false
  VERIFICATION_CW_RELEASE_ASSETS_RESULT=skipped
  VERIFICATION_WORKSPACE_IMAGE_EXPECTED=false
  VERIFICATION_WORKSPACE_IMAGE_RESULT=skipped
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
  "${unselected_results[@]}" \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_TESTED_TREE_RECEIPT=accepted \
  VERIFICATION_TESTED_TREE_REASON=exact-tested-tree \
  VERIFICATION_TESTED_TREE_PR=42 \
  VERIFICATION_TESTED_TREE_HEAD=0123456789abcdef0123456789abcdef01234567 \
  VERIFICATION_TESTED_TREE_RUN=501 \
  "$CHECK" >/dev/null

# A hosted quick pull request passes with only its quick groups: the policy
# core, ShellCheck in tooling and compiling every Rust target. Every other
# group is unselected and must stay skipped.
quick_results=(
  "${unselected_results[@]}"
  VERIFICATION_POLICY_EXPECTED=true
  VERIFICATION_POLICY_RESULT=success
  VERIFICATION_TOOLING_EXPECTED=true
  VERIFICATION_TOOLING_RESULT=success
  VERIFICATION_RUST_COMPILE_EXPECTED=true
  VERIFICATION_RUST_COMPILE_RESULT=success
)
quick_selection='|valid:v3|policy|policy_shell|policy_shell_omittable|pr_quick|rust_compile|complete|'
env "${green_results[@]}" "${quick_results[@]}" \
  VERIFICATION_SELECTION="$quick_selection" \
  "$CHECK" >/dev/null

expect_failure quick_compile_skipped \
  'rust-compile selected capability group concluded skipped' \
  "${quick_results[@]}" \
  VERIFICATION_SELECTION="$quick_selection" \
  VERIFICATION_RUST_COMPILE_RESULT=skipped

expect_failure quick_rust_tests_ran \
  'rust-transport unselected capability group concluded success' \
  "${quick_results[@]}" \
  VERIFICATION_SELECTION="$quick_selection" \
  VERIFICATION_RUST_TRANSPORT_RESULT=success

# Curated locks alone run Rust / transport verification without the shards.
env "${green_results[@]}" \
  VERIFICATION_SELECTION='|valid:v3|policy|rust_curated_locks|complete|' \
  VERIFICATION_RUST_SHARDS_EXPECTED=false \
  VERIFICATION_RUST_PACKAGES_RESULT=skipped \
  VERIFICATION_RUST_FEATURES_RESULT=skipped \
  "$CHECK" >/dev/null

expect_failure shards_ran_unselected \
  'rust-packages unselected capability group concluded success' \
  VERIFICATION_SELECTION='|valid:v3|policy|rust_curated_locks|complete|' \
  VERIFICATION_RUST_SHARDS_EXPECTED=false \
  VERIFICATION_RUST_FEATURES_RESULT=skipped

expect_failure missing_shards_expectation \
  'rust-packages capability expectation is missing' \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_RUST_SHARDS_EXPECTED=

expect_failure missing_compile_expectation \
  'rust-compile capability expectation is missing' \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_RUST_COMPILE_EXPECTED=

expect_failure standard_failure 'standard selected capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_STANDARD_RESULT=failure

expect_failure policy_failure 'policy selected capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_POLICY_RESULT=failure

expect_failure tooling_failure 'tooling selected capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_TOOLING_RESULT=failure

expect_failure rust_transport_cancel \
  'rust-transport selected capability group concluded cancelled' \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_RUST_TRANSPORT_RESULT=cancelled

expect_failure rust_compile_failure \
  'rust-compile selected capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_RUST_COMPILE_RESULT=failure

expect_failure rust_features_failure \
  'rust-features selected capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|rust|complete|' \
  VERIFICATION_RUST_FEATURES_RESULT=failure

expect_failure database_skip \
  'database selected capability group concluded skipped' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_DATABASE_RESULT=skipped

expect_failure services_control_skip \
  'services-control selected capability group concluded skipped' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_SERVICES_CONTROL_RESULT=skipped

expect_failure services_runtime_skip \
  'services-runtime selected capability group concluded skipped' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_SERVICES_RUNTIME_RESULT=skipped

expect_failure edge_kind_missing 'edge-kind selected capability group concluded missing' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_EDGE_KIND_RESULT=

expect_failure cw_release_assets_failure \
  'cw-release-assets selected capability group concluded failure' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_CW_RELEASE_ASSETS_RESULT=failure

expect_failure workspace_image_failure \
  'workspace-image selected capability group concluded failure' \
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

expect_failure unselected_ran \
  'policy unselected capability group concluded success' \
  VERIFICATION_SELECTION='|valid:v3|complete|' \
  VERIFICATION_POLICY_EXPECTED=false \
  VERIFICATION_POLICY_RESULT=success

expect_failure missing_expectation \
  'policy capability expectation is missing' \
  VERIFICATION_SELECTION='|valid:v3|complete|' \
  VERIFICATION_POLICY_EXPECTED=

expect_failure accepted_receipt_missing_head \
  'accepted tested-tree receipt has invalid head' \
  VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
  VERIFICATION_TESTED_TREE_RECEIPT=accepted \
  VERIFICATION_TESTED_TREE_REASON=exact-tested-tree \
  VERIFICATION_TESTED_TREE_PR=42 \
  VERIFICATION_TESTED_TREE_HEAD= \
  VERIFICATION_TESTED_TREE_RUN=501

echo 'required verification result tests: green'
