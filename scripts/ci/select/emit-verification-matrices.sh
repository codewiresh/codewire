#!/usr/bin/env bash
set -euo pipefail

selection="${VERIFICATION_SELECTION:-}"
tested_tree_receipt="${VERIFICATION_TESTED_TREE_RECEIPT:-}"
cw_package_selected="${CW_PACKAGE_SELECTED:-}"
desktop_package_selected="${DESKTOP_PACKAGE_SELECTED:-}"
workspace_image_selected="${WORKSPACE_IMAGE_SELECTED:-}"
# A main push that main has moved past dispatches nothing: the newer commit's
# run, queued behind it, verifies the cumulative change.
superseded="${VERIFICATION_SUPERSEDED:-false}"
# Whether Kind builds the exact-source workspace (source) or runs the
# published pin (pinned). Callers that predate the choice mean source.
kind_workspace_source="${KIND_WORKSPACE_SOURCE:-source}"
# Which workflow builds and verifies the exact-source workspace image. A push to
# main leaves it to support-images, which runs the workspace contract on the
# exact image it publishes (#2892); pull requests, dispatches and callers that
# predate the choice keep CI's own build.
workspace_image_owner="${WORKSPACE_IMAGE_OWNER:-ci}"

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
for value in "$cw_package_selected" "$desktop_package_selected" \
    "$workspace_image_selected" "$superseded"; do
  case "$value" in
    true|false) ;;
    *) fail "artifact selection has invalid result ${value:-missing}" ;;
  esac
done
case "$kind_workspace_source" in
  source|pinned) ;;
  *) fail "Kind workspace source is invalid: $kind_workspace_source" ;;
esac
case "$workspace_image_owner" in
  ci|support-images) ;;
  *) fail "workspace image owner is invalid: $workspace_image_owner" ;;
esac

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
  [workspace_image]=false
)

if [ "$superseded" = true ]; then
  echo 'superseded main commit: no capability group is dispatched' >&2
elif [ "$tested_tree_receipt" = fallback ]; then
  # A hosted pull request's quick selection (pr_quick) runs only the quick
  # families it names. Artifact facts dispatch nothing there: the CW release
  # assets, container contract and desktop package run on main, or on a pull
  # request labelled ci-full.
  artifact_groups=true
  if selected pr_quick; then
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
  selected_any contracts go_support web sdk_go sdk_ts sdk_python \
    && expected[standard]=true
  selected_any \
    deploy release runtime_confidential runtime_dev_smoke security \
    service_apikey_smoke policy_shell edge_kind \
    && expected[tooling]=true
  if selected policy && ! selected policy_shell_omittable; then
    expected[tooling]=true
  fi
  # Compiling every Rust target: the fast-compile token set and the desktop
  # package, or a quick selection's rust_compile.
  if selected_any rust rust_curated_locks transport transport_derp_contract \
      || [ "$desktop_package" = true ] || selected rust_compile; then
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
  # Selected Kind builds and proves the workspace and dashboard images itself,
  # unless it runs the published workspace pin; then the selected exact-source
  # workspace still needs Container contract verification, when CI owns it.
  # Dashboard and iOS work keep the job on every event.
  if { [ "$artifact_groups" = true ] && [ "$workspace_image_owner" = ci ] \
        && [ "$workspace_image_selected" = true ] \
        && { ! selected kind || [ "$kind_workspace_source" = pinned ]; }; } \
      || selected ios \
      || { selected web && ! selected kind; }; then
    expected[workspace_image]=true
  fi

  # A future trusted selector token must never silently create no work merely
  # because this dispatch registry has not learned it yet. Unknown tokens take
  # the conservative all-groups path until both contracts are updated.
  unknown_token=false
  IFS='|' read -r -a selection_tokens <<<"$selection"
  for token in "${selection_tokens[@]}"; do
    case "$token" in
      ''|valid:v3|complete|\
      policy|policy_shell|policy_shell_omittable|pr_quick|rust_compile|\
      contracts|contracts_proto|go_support|go_tailnet|go_consumer_interop|\
      sdk_go|sdk_ts|sdk_python|web|ios|\
      deploy|release|runtime_confidential|runtime_dev_smoke|\
      security|security_go|security_js|security_dev_smoke_auth|security_idp_kek|\
      rust|rust_workspace|rust_curated_locks|rust_pkg_*|\
      transport|transport_derp_contract|transport_pkg_*|\
      database|edge_kind|kind|\
      service_integration|service_apikey_smoke|service_idp|service_coordinator|\
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
    services_control services_runtime edge_kind cw_release_assets \
    workspace_image; do
  value="${expected[$group]}"
  printf '%s_expected=%s\n' "$group" "$value"
done >> "${GITHUB_OUTPUT:-/dev/stdout}"
