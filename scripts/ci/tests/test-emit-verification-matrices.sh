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
  if [ "$expected" = true ]; then
    grep -Fxq "${group}_matrix=[\"selected\"]" <<<"$output"
  else
    grep -Fxq "${group}_matrix=[]" <<<"$output"
  fi
}

docs_output="$(emit '|valid:v3|complete|' fallback false false false)"
for group in policy standard tooling rust_transport database services_control \
    services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$docs_output" "$group" false
done

receipt_output="$(emit '|valid:v3|policy|rust|kind|complete|' accepted true true true)"
for group in policy standard tooling rust_transport database services_control \
    services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$receipt_output" "$group" false
done

selected_output="$(emit \
  '|valid:v3|policy|contracts|security|rust|database|service_idp|service_nats|kind|web|complete|' \
  fallback true false true)"
for group in policy standard tooling rust_transport database services_control \
    services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$selected_output" "$group" true
done

desktop_output="$(emit '|valid:v3|complete|' fallback false true false)"
assert_output "$desktop_output" rust_transport true

web_output="$(emit '|valid:v3|web|complete|' fallback false false false)"
assert_output "$web_output" standard true
assert_output "$web_output" workspace_image true

kind_web_output="$(emit '|valid:v3|web|kind|complete|' fallback false false false)"
assert_output "$kind_web_output" workspace_image false
assert_output "$kind_web_output" edge_kind true

unknown_output="$(emit '|valid:v3|future_capability|complete|' fallback false false false)"
for group in policy standard tooling rust_transport database services_control \
    services_runtime edge_kind cw_release_assets workspace_image; do
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

echo '[test-emit-verification-matrices] trusted empty/selected matrix contract passed'
