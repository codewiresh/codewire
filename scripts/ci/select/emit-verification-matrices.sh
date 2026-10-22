#!/usr/bin/env bash
set -euo pipefail

selection="${VERIFICATION_SELECTION:-}"
tested_tree_receipt="${VERIFICATION_TESTED_TREE_RECEIPT:-}"
cw_package_selected="${CW_PACKAGE_SELECTED:-}"
desktop_package_selected="${DESKTOP_PACKAGE_SELECTED:-}"
# A main push that main has moved past dispatches nothing: the newer commit's
# run, queued behind it, verifies the cumulative change.
superseded="${VERIFICATION_SUPERSEDED:-false}"

fail() {
  echo "::error::$*" >&2
  exit 1
}

if [[ "$selection" != '|valid:v3|'* ]] || [[ "$selection" != *'|complete|' ]]; then
  fail 'verification selection is invalid or incomplete'
fi
case "$tested_tree_receipt" in
  accepted|fallback) ;;
  *) fail "tested-tree receipt has invalid result ${tested_tree_receipt:-missing}" ;;
esac
for value in "$cw_package_selected" "$desktop_package_selected" "$superseded"; do
  case "$value" in
    true|false) ;;
    *) fail "artifact selection has invalid result ${value:-missing}" ;;
  esac
done

selected() {
  [[ "$selection" == *"|$1|"* ]]
}

selected_any() {
  local token
  for token in "$@"; do
    selected "$token" && return 0
  done
  return 1
}

declare -A expected=(
  [policy]=false
  [standard]=false
  [tooling]=false
  [rust_compile]=false
  [rust_shards]=false
  [rust_transport]=false
  [database]=false
  [services_control]=false
  [services_runtime]=false
  [edge_kind]=false
  [cw_release_assets]=false
)

if [ "$superseded" = true ]; then
  echo 'superseded main commit: no capability group is dispatched' >&2
elif [ "$tested_tree_receipt" = fallback ]; then
  # A scheduled run (scheduled) checks Kind alone, which the pushes to main may
  # defer; they ran the artifact groups.
  artifact_groups=true
  if selected scheduled; then
    artifact_groups=false
  fi
  # Each group is expected exactly when one of its job's verification steps
  # will run, so a dispatched heavy job always has work
  # (test-select-verification.sh proves it against the workflow's step
  # conditions). Tokens that only shape a running step, such as
  # contracts_proto, go_tailnet, security_go or transport_derp_contract,
  # dispatch nothing alone.
  desktop_package=false
  if [ "$artifact_groups" = true ] && [ "$desktop_package_selected" = true ]; then
    desktop_package=true
  fi
  selected policy && expected[policy]=true
  selected_any contracts go_support web docs sdk_go sdk_ts sdk_python ios \
    && expected[standard]=true
  selected_any \
    deploy release runtime_confidential runtime_dev_smoke security \
    policy_shell edge_kind \
    && expected[tooling]=true
  if selected policy && ! selected policy_shell_omittable; then
    expected[tooling]=true
  fi
  # Compiling every Rust target: the fast-compile token set and the desktop
  # package.
  if selected_any rust rust_curated_locks transport transport_derp_contract \
      || [ "$desktop_package" = true ]; then
    expected[rust_compile]=true
  fi
  # The packages and feature-graph shards run only selected Rust or transport.
  selected_any rust transport && expected[rust_shards]=true
  # Rust / transport verification also owns the curated locks and the desktop
  # package, which it builds separately unless the Rust selection names it.
  if selected_any rust rust_curated_locks transport \
      || { [ "$desktop_package" = true ] && ! selected rust_pkg_codewire_desktop; }; then
    expected[rust_transport]=true
  fi
  selected database && expected[database]=true
  selected_any \
    service_idp service_coordinator service_billing service_connectcore \
    && expected[services_control]=true
  selected_any service_orchestration service_nats \
    && expected[services_runtime]=true
  # The Kind shards. Edge static verification (edge_kind) runs in tooling.
  selected kind && expected[edge_kind]=true
  if [ "$artifact_groups" = true ] && [ "$cw_package_selected" = true ]; then
    expected[cw_release_assets]=true
  fi

  # A future trusted selector token must never silently create no work merely
  # because this dispatch registry has not learned it yet. Unknown tokens take
  # the conservative all-groups path until both contracts are updated.
  unknown_token=false
  IFS='|' read -r -a selection_tokens <<<"$selection"
  for token in "${selection_tokens[@]}"; do
    case "$token" in
      ''|valid:v3|complete|\
      policy|policy_shell|policy_shell_omittable|ci_script_tests|ci_script_tests_omittable|scheduled|\
      contracts|contracts_proto|go_support|go_tailnet|go_consumer_interop|\
      sdk_go|sdk_ts|sdk_python|web|docs|ios|\
      deploy|release|runtime_confidential|runtime_dev_smoke|\
      security|security_go|security_js|security_dev_smoke_auth|security_idp_kek|\
      rust|rust_workspace|rust_curated_locks|rust_pkg_*|\
      transport|transport_derp_contract|transport_pkg_*|\
      database|edge_kind|kind|kind_tools|kind_tools_omittable|\
      service_integration|service_idp|service_coordinator|\
      service_billing|service_connectcore|service_orchestration|service_nats|\
      service_temporal)
        ;;
      *)
        echo "warning: unknown verification token '$token'; dispatching all capability groups" >&2
        unknown_token=true
        ;;
    esac
  done
  if [ "$unknown_token" = true ]; then
    for group in "${!expected[@]}"; do
      expected[$group]=true
    done
  fi
fi

for group in \
    policy standard tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets; do
  value="${expected[$group]}"
  printf '%s_expected=%s\n' "$group" "$value"
done >> "${GITHUB_OUTPUT:-/dev/stdout}"
