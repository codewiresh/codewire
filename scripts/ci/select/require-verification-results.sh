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
if [[ "$selection" != '|valid:v2|'* ]] || [[ "$selection" != *'|complete|' ]]; then
  fail "verification selection is invalid or incomplete"
fi

require_group_success() {
  local group="$1" result="$2"
  if [ "$result" != success ]; then
    fail "$group capability group concluded ${result:-missing}"
  fi
}

require_group_success standard "${VERIFICATION_STANDARD_RESULT:-missing}"
require_group_success rust-transport \
  "${VERIFICATION_RUST_TRANSPORT_RESULT:-missing}"
require_group_success database-services \
  "${VERIFICATION_DATABASE_SERVICES_RESULT:-missing}"
require_group_success edge-kind "${VERIFICATION_EDGE_KIND_RESULT:-missing}"

case "$tested_tree_receipt" in
  fallback)
    echo 'required verification: selector and all capability groups succeeded'
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
