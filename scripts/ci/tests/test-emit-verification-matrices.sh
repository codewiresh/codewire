#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/select/emit-verification-matrices.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

emit() {
  local selection="$1" receipt="$2" cw="$3" desktop="$4"
  local output="$TMP/output"
  : > "$output"
  VERIFICATION_SELECTION="$selection" \
    VERIFICATION_TESTED_TREE_RECEIPT="$receipt" \
    CW_PACKAGE_SELECTED="$cw" \
    DESKTOP_PACKAGE_SELECTED="$desktop" \
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

docs_output="$(emit '|valid:v3|policy|policy_shell_omittable|complete|' fallback false false)"
assert_output "$docs_output" policy true
for group in standard tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets; do
  assert_output "$docs_output" "$group" false
done

shell_output="$(emit '|valid:v3|policy|policy_shell|policy_shell_omittable|complete|' fallback false false)"
assert_output "$shell_output" policy true
assert_output "$shell_output" tooling true

legacy_policy_output="$(emit '|valid:v3|policy|complete|' fallback false false)"
assert_output "$legacy_policy_output" policy true
assert_output "$legacy_policy_output" tooling true

receipt_output="$(emit '|valid:v3|policy|rust|kind|complete|' accepted true true)"
for group in policy standard tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets; do
  assert_output "$receipt_output" "$group" false
done

selected_output="$(emit \
  '|valid:v3|policy|contracts|security|rust|database|service_idp|service_nats|kind|web|complete|' \
  fallback true false)"
for group in policy standard tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets; do
  assert_output "$selected_output" "$group" true
done

desktop_output="$(emit '|valid:v3|complete|' fallback false true)"
assert_output "$desktop_output" rust_transport true
assert_output "$desktop_output" rust_compile true
assert_output "$desktop_output" rust_shards false

# Every fast-compile selection compiles. Each other Rust job is expected only
# when its own steps have work: the shards for rust or transport, Rust /
# transport verification also for the curated locks.
for rust_case in 'rust:true:true' 'transport:true:true' 'rust_curated_locks:false:true' \
    'transport_derp_contract:false:false'; do
  IFS=: read -r rust_token shards_expected transport_expected <<<"$rust_case"
  rust_output="$(emit "|valid:v3|${rust_token}|complete|" fallback false false)"
  assert_output "$rust_output" rust_compile true
  assert_output "$rust_output" rust_shards "$shards_expected"
  assert_output "$rust_output" rust_transport "$transport_expected"
done

# Tokens that only shape a running step dispatch no job alone.
for shaping_token in contracts_proto go_tailnet go_consumer_interop security_go; do
  shaping_output="$(emit "|valid:v3|${shaping_token}|complete|" fallback false false)"
  for group in standard tooling rust_compile rust_shards rust_transport; do
    assert_output "$shaping_output" "$group" false
  done
done

# Static edge checks run in tooling; only Kind starts the Kind shards.
edge_output="$(emit '|valid:v3|edge_kind|complete|' fallback false false)"
assert_output "$edge_output" tooling true
assert_output "$edge_output" edge_kind false
kind_output="$(emit '|valid:v3|kind|complete|' fallback false false)"
assert_output "$kind_output" edge_kind true

# The retired quick pull-request marker (#3119 step 2.1) is an unknown token:
# a selection that still carries it dispatches every group rather than less.
retired_quick_output="$(emit \
  '|valid:v3|policy|policy_shell_omittable|pr_quick|rust_compile|complete|' \
  fallback true true)"
for group in policy standard tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime cw_release_assets; do
  assert_output "$retired_quick_output" "$group" true
done
# A scheduled run (owner decision 2026-10-20) dispatches the Kind shards
# alone when it selected Kind, and nothing when it did not, whatever the
# artifact facts say.
scheduled_kind_output="$(emit '|valid:v3|kind|scheduled|complete|' fallback true true)"
assert_output "$scheduled_kind_output" edge_kind true
scheduled_nothing_output="$(emit '|valid:v3|scheduled|complete|' fallback true true)"
for group in policy standard tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime cw_release_assets; do
  assert_output "$scheduled_kind_output" "$group" false
  assert_output "$scheduled_nothing_output" "$group" false
done
assert_output "$scheduled_nothing_output" edge_kind false
# The same artifact facts without scheduled keep dispatching their groups.
full_artifact_output="$(emit '|valid:v3|policy|policy_shell_omittable|complete|' fallback true true)"
for group in policy rust_compile rust_transport cw_release_assets; do
  assert_output "$full_artifact_output" "$group" true
done

web_output="$(emit '|valid:v3|web|complete|' fallback false false)"
assert_output "$web_output" standard true

# The iOS package tests run in the standard group (#3119 A12).
ios_output="$(emit '|valid:v3|ios|complete|' fallback false false)"
assert_output "$ios_output" standard true
for group in policy tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets; do
  assert_output "$ios_output" "$group" false
done

# The docs site runs in the standard group alone: no browser or
# Kind work, and docs is a known token (an unknown one dispatches everything).
docs_output="$(emit '|valid:v3|docs|complete|' fallback false false)"
assert_output "$docs_output" standard true
for group in policy tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets; do
  assert_output "$docs_output" "$group" false
done

kind_web_output="$(emit '|valid:v3|web|kind|complete|' fallback false false)"
assert_output "$kind_web_output" standard true
assert_output "$kind_web_output" edge_kind true

temporal_output="$(emit '|valid:v3|service_integration|service_temporal|complete|' fallback false false)"
assert_output "$temporal_output" services_control false
assert_output "$temporal_output" services_runtime false

billing_temporal_output="$(emit '|valid:v3|service_billing|service_integration|service_temporal|complete|' fallback false false)"
assert_output "$billing_temporal_output" services_control true
assert_output "$billing_temporal_output" services_runtime false

orchestration_temporal_output="$(emit '|valid:v3|service_integration|service_orchestration|service_temporal|complete|' fallback false false)"
assert_output "$orchestration_temporal_output" services_control false
assert_output "$orchestration_temporal_output" services_runtime true

unknown_output="$(emit '|valid:v3|future_capability|complete|' fallback false false)"
for group in policy standard tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets; do
  assert_output "$unknown_output" "$group" true
done

if VERIFICATION_SELECTION='|valid:v3|complete|' \
    VERIFICATION_TESTED_TREE_RECEIPT=fallback \
    CW_PACKAGE_SELECTED=unknown \
    DESKTOP_PACKAGE_SELECTED=false \
    GITHUB_OUTPUT="$TMP/invalid" \
    "$CHECK" >/dev/null 2>&1; then
  echo 'matrix selector accepted an invalid artifact decision' >&2
  exit 1
fi

# A superseded main commit dispatches nothing, whatever it selected; the same
# selection on main's tip (or with the input unset) dispatches as before.
all_groups=(policy standard tooling rust_compile rust_shards rust_transport database
  services_control services_runtime edge_kind cw_release_assets)
everything='|valid:v3|future_capability|complete|'
superseded_emit() {
  local superseded="$1" output="$TMP/superseded-output"
  : > "$output"
  VERIFICATION_SUPERSEDED="$superseded" \
    VERIFICATION_SELECTION="$everything" \
    VERIFICATION_TESTED_TREE_RECEIPT=fallback \
    CW_PACKAGE_SELECTED=true \
    DESKTOP_PACKAGE_SELECTED=true \
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
