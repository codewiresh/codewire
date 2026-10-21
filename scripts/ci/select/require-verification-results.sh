#!/usr/bin/env bash
set -euo pipefail

selection="${VERIFICATION_SELECTION:-}"
selection_result="${VERIFICATION_SELECTION_RESULT:-missing}"
tested_tree_receipt="${VERIFICATION_TESTED_TREE_RECEIPT:-fallback}"

fail() {
  echo "::error::$*" >&2
  exit 1
}

if [ "$selection_result" != success ]; then
  fail "verification selection concluded $selection_result"
fi
if [[ "$selection" != '|valid:v3|'* ]] || [[ "$selection" != *'|complete|' ]]; then
  fail "verification selection is invalid or incomplete"
fi

require_group_result() {
  local group="$1" expected="$2" result="$3"
  case "$expected" in
    true)
      [ "$result" = success ] \
        || fail "$group selected capability group concluded ${result:-missing}"
      ;;
    false)
      [ "$result" = skipped ] \
        || fail "$group unselected capability group concluded ${result:-missing}"
      ;;
    *) fail "$group capability expectation is ${expected:-missing}" ;;
  esac
}

require_group_result policy \
  "${VERIFICATION_POLICY_EXPECTED:-missing}" \
  "${VERIFICATION_POLICY_RESULT:-missing}"
require_group_result standard \
  "${VERIFICATION_STANDARD_EXPECTED:-missing}" \
  "${VERIFICATION_STANDARD_RESULT:-missing}"
require_group_result tooling \
  "${VERIFICATION_TOOLING_EXPECTED:-missing}" \
  "${VERIFICATION_TOOLING_RESULT:-missing}"
require_group_result rust-compile \
  "${VERIFICATION_RUST_COMPILE_EXPECTED:-missing}" \
  "${VERIFICATION_RUST_COMPILE_RESULT:-missing}"
require_group_result rust-packages \
  "${VERIFICATION_RUST_SHARDS_EXPECTED:-missing}" \
  "${VERIFICATION_RUST_PACKAGES_RESULT:-missing}"
require_group_result rust-features \
  "${VERIFICATION_RUST_SHARDS_EXPECTED:-missing}" \
  "${VERIFICATION_RUST_FEATURES_RESULT:-missing}"
require_group_result rust-transport \
  "${VERIFICATION_RUST_TRANSPORT_EXPECTED:-missing}" \
  "${VERIFICATION_RUST_TRANSPORT_RESULT:-missing}"
require_group_result database \
  "${VERIFICATION_DATABASE_EXPECTED:-missing}" \
  "${VERIFICATION_DATABASE_RESULT:-missing}"
require_group_result services-control \
  "${VERIFICATION_SERVICES_CONTROL_EXPECTED:-missing}" \
  "${VERIFICATION_SERVICES_CONTROL_RESULT:-missing}"
require_group_result services-runtime \
  "${VERIFICATION_SERVICES_RUNTIME_EXPECTED:-missing}" \
  "${VERIFICATION_SERVICES_RUNTIME_RESULT:-missing}"
require_group_result edge-kind \
  "${VERIFICATION_EDGE_KIND_EXPECTED:-missing}" \
  "${VERIFICATION_EDGE_KIND_RESULT:-missing}"
require_group_result cw-release-assets \
  "${VERIFICATION_CW_RELEASE_ASSETS_EXPECTED:-missing}" \
  "${VERIFICATION_CW_RELEASE_ASSETS_RESULT:-missing}"

case "$tested_tree_receipt" in
  fallback)
    echo 'required verification: every selected capability group succeeded'
    ;;
  accepted)
    [[ "${VERIFICATION_TESTED_TREE_PR:-}" =~ ^[1-9][0-9]*$ ]] \
      || fail 'accepted tested-tree receipt has invalid PR'
    [[ "${VERIFICATION_TESTED_TREE_HEAD:-}" =~ ^[0-9a-f]{40}$ ]] \
      || fail 'accepted tested-tree receipt has invalid head'
    [[ "${VERIFICATION_TESTED_TREE_RUN:-}" =~ ^[1-9][0-9]*$ ]] \
      || fail 'accepted tested-tree receipt has invalid run'
    [ "${VERIFICATION_TESTED_TREE_REASON:-}" = exact-tested-tree ] \
      || fail 'accepted tested-tree receipt has invalid reason'
    echo "required verification: exact tested tree from PR #${VERIFICATION_TESTED_TREE_PR} run ${VERIFICATION_TESTED_TREE_RUN} accepted"
    ;;
  *)
    fail "tested-tree receipt has invalid result ${tested_tree_receipt:-missing}"
    ;;
esac
