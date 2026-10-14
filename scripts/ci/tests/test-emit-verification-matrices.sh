#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/select/emit-verification-matrices.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

emit() {
  local selection="$1" receipt="$2" cw="$3" desktop="$4" workspace="$5"
  local output="$TMP/output"
  : > "$output"
  VERIFICATION_SELECTION="$selection" \
    VERIFICATION_TESTED_TREE_RECEIPT="$receipt" \
    CW_PACKAGE_SELECTED="$cw" \
    DESKTOP_PACKAGE_SELECTED="$desktop" \
    WORKSPACE_IMAGE_SELECTED="$workspace" \
    GITHUB_OUTPUT="$output" \
    "$CHECK"
  cat "$output"
}

assert_output() {
  local output="$1" group="$2" expected="$3"
  grep -Fxq "${group}_expected=${expected}" <<<"$output"
  if grep -Eq "^${group}_matrix=" <<<"$output"; then
    echo "${group}: empty-matrix transport must not be emitted" >&2
    exit 1
  fi
}

docs_output="$(emit '|valid:v3|policy|policy_shell_omittable|complete|' fallback false false false)"
assert_output "$docs_output" policy true
for group in standard tooling rust_compile rust_transport database \
    services_control services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$docs_output" "$group" false
done

shell_output="$(emit '|valid:v3|policy|policy_shell|policy_shell_omittable|complete|' fallback false false false)"
assert_output "$shell_output" policy true
assert_output "$shell_output" tooling true

legacy_policy_output="$(emit '|valid:v3|policy|complete|' fallback false false false)"
assert_output "$legacy_policy_output" policy true
assert_output "$legacy_policy_output" tooling true

receipt_output="$(emit '|valid:v3|policy|rust|kind|complete|' accepted true true true)"
for group in policy standard tooling rust_compile rust_transport database \
    services_control services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$receipt_output" "$group" false
done

selected_output="$(emit \
  '|valid:v3|policy|contracts|security|rust|database|service_idp|service_nats|kind|web|complete|' \
  fallback true false true)"
for group in policy standard tooling rust_compile rust_transport database \
    services_control services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$selected_output" "$group" true
done

desktop_output="$(emit '|valid:v3|complete|' fallback false true false)"
assert_output "$desktop_output" rust_transport true
assert_output "$desktop_output" rust_compile true

# Main and full pull-request selections compile with the Rust group, exactly
# as before the compile decision was separate.
for rust_selection in '|valid:v3|rust|complete|' '|valid:v3|rust_curated_locks|complete|' \
    '|valid:v3|transport|complete|' '|valid:v3|transport_derp_contract|complete|'; do
  rust_output="$(emit "$rust_selection" fallback false false false)"
  assert_output "$rust_output" rust_compile true
  assert_output "$rust_output" rust_transport true
done

# A hosted pull request's quick selection dispatches only what it names: the
# policy core, ShellCheck in tooling, compiling every Rust target, and Kind
# when opted in. Artifact facts that would dispatch the CW release assets,
# the container contract or the desktop package dispatch nothing.
quick_output="$(emit \
  '|valid:v3|policy|policy_shell_omittable|pr_quick|rust_compile|complete|' \
  fallback true true true)"
assert_output "$quick_output" policy true
assert_output "$quick_output" rust_compile true
for group in standard tooling rust_transport database services_control \
    services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$quick_output" "$group" false
done
quick_shell_output="$(emit \
  '|valid:v3|policy|policy_shell|policy_shell_omittable|pr_quick|complete|' \
  fallback true true true)"
assert_output "$quick_shell_output" policy true
assert_output "$quick_shell_output" tooling true
for group in standard rust_compile rust_transport database services_control \
    services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$quick_shell_output" "$group" false
done
quick_kind_output="$(emit \
  '|valid:v3|edge_kind|kind|policy|policy_shell_omittable|pr_quick|rust_compile|complete|' \
  fallback false false true)"
for group in policy rust_compile edge_kind; do
  assert_output "$quick_kind_output" "$group" true
done
for group in standard tooling rust_transport database services_control \
    services_runtime cw_release_assets workspace_image; do
  assert_output "$quick_kind_output" "$group" false
done
# The same artifact facts without pr_quick keep dispatching their groups.
full_artifact_output="$(emit '|valid:v3|policy|policy_shell_omittable|complete|' fallback true true true)"
for group in policy rust_compile rust_transport cw_release_assets workspace_image; do
  assert_output "$full_artifact_output" "$group" true
done

web_output="$(emit '|valid:v3|web|complete|' fallback false false false)"
assert_output "$web_output" standard true
assert_output "$web_output" workspace_image true

kind_web_output="$(emit '|valid:v3|web|kind|complete|' fallback false false false)"
assert_output "$kind_web_output" workspace_image false
assert_output "$kind_web_output" edge_kind true

temporal_output="$(emit '|valid:v3|service_integration|service_temporal|complete|' fallback false false false)"
assert_output "$temporal_output" services_control false
assert_output "$temporal_output" services_runtime false

billing_temporal_output="$(emit '|valid:v3|service_billing|service_integration|service_temporal|complete|' fallback false false false)"
assert_output "$billing_temporal_output" services_control true
assert_output "$billing_temporal_output" services_runtime false

orchestration_temporal_output="$(emit '|valid:v3|service_integration|service_orchestration|service_temporal|complete|' fallback false false false)"
assert_output "$orchestration_temporal_output" services_control false
assert_output "$orchestration_temporal_output" services_runtime true

apikey_output="$(emit '|valid:v3|service_apikey_smoke|complete|' fallback false false false)"
assert_output "$apikey_output" tooling true
assert_output "$apikey_output" services_control false
assert_output "$apikey_output" services_runtime false

unknown_output="$(emit '|valid:v3|future_capability|complete|' fallback false false false)"
for group in policy standard tooling rust_compile rust_transport database \
    services_control services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$unknown_output" "$group" true
done

if VERIFICATION_SELECTION='|valid:v3|complete|' \
    VERIFICATION_TESTED_TREE_RECEIPT=fallback \
    CW_PACKAGE_SELECTED=unknown \
    DESKTOP_PACKAGE_SELECTED=false \
    WORKSPACE_IMAGE_SELECTED=false \
    GITHUB_OUTPUT="$TMP/invalid" \
    "$CHECK" >/dev/null 2>&1; then
  echo 'matrix selector accepted an invalid artifact decision' >&2
  exit 1
fi

# A superseded main commit dispatches nothing, whatever it selected; the same
# selection on main's tip (or with the input unset) dispatches as before.
all_groups=(policy standard tooling rust_compile rust_transport database
  services_control services_runtime edge_kind cw_release_assets workspace_image)
everything='|valid:v3|future_capability|complete|'
superseded_emit() {
  local superseded="$1" output="$TMP/superseded-output"
  : > "$output"
  VERIFICATION_SUPERSEDED="$superseded" \
    VERIFICATION_SELECTION="$everything" \
    VERIFICATION_TESTED_TREE_RECEIPT=fallback \
    CW_PACKAGE_SELECTED=true \
    DESKTOP_PACKAGE_SELECTED=true \
    WORKSPACE_IMAGE_SELECTED=true \
    GITHUB_OUTPUT="$output" \
    "$CHECK" 2>/dev/null || return 1
  cat "$output"
}
superseded_output="$(superseded_emit true)"
for group in "${all_groups[@]}"; do
  assert_output "$superseded_output" "$group" false
done
tip_output="$(superseded_emit false)"
for group in "${all_groups[@]}"; do
  assert_output "$tip_output" "$group" true
done
[[ "$tip_output" == "$(emit "$everything" fallback true true true 2>/dev/null)" ]] || {
  echo 'an unset supersession dispatches differently from main'"'"'s tip' >&2
  exit 1
}
for invalid in yes 1 TRUE; do
  if superseded_emit "$invalid" >/dev/null; then
    echo "matrix selector accepted supersession ${invalid}" >&2
    exit 1
  fi
done

echo '[test-emit-verification-matrices] trusted capability expectation contract passed'
