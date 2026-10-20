#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/select/emit-verification-matrices.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# The owner is CI job configuration; an ambient value must not change what
# this contract observes.
unset WORKSPACE_IMAGE_OWNER

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
for group in standard tooling rust_compile rust_shards rust_transport database \
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
for group in policy standard tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$receipt_output" "$group" false
done

selected_output="$(emit \
  '|valid:v3|policy|contracts|security|rust|database|service_idp|service_nats|kind|web|complete|' \
  fallback true false true)"
for group in policy standard tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets; do
  assert_output "$selected_output" "$group" true
done
# Selected Kind builds and proves the workspace image itself.
assert_output "$selected_output" workspace_image false

desktop_output="$(emit '|valid:v3|complete|' fallback false true false)"
assert_output "$desktop_output" rust_transport true
assert_output "$desktop_output" rust_compile true
assert_output "$desktop_output" rust_shards false

# Every fast-compile selection compiles. Each other Rust job is expected only
# when its own steps have work: the shards for rust or transport, Rust /
# transport verification also for the curated locks.
for rust_case in 'rust:true:true' 'transport:true:true' 'rust_curated_locks:false:true' \
    'transport_derp_contract:false:false'; do
  IFS=: read -r rust_token shards_expected transport_expected <<<"$rust_case"
  rust_output="$(emit "|valid:v3|${rust_token}|complete|" fallback false false false)"
  assert_output "$rust_output" rust_compile true
  assert_output "$rust_output" rust_shards "$shards_expected"
  assert_output "$rust_output" rust_transport "$transport_expected"
done

# Tokens that only shape a running step dispatch no job alone.
for shaping_token in contracts_proto go_tailnet go_consumer_interop security_go; do
  shaping_output="$(emit "|valid:v3|${shaping_token}|complete|" fallback false false false)"
  for group in standard tooling rust_compile rust_shards rust_transport; do
    assert_output "$shaping_output" "$group" false
  done
done

# Static edge checks run in tooling; only Kind starts the Kind shards.
edge_output="$(emit '|valid:v3|edge_kind|complete|' fallback false false false)"
assert_output "$edge_output" tooling true
assert_output "$edge_output" edge_kind false
# An artifact-selected workspace image is Kind's to build when Kind runs.
kind_workspace_output="$(emit '|valid:v3|kind|complete|' fallback false false true)"
assert_output "$kind_workspace_output" edge_kind true
assert_output "$kind_workspace_output" workspace_image false
kind_workspace_output="$(KIND_WORKSPACE_SOURCE=source emit '|valid:v3|kind|complete|' fallback false false true)"
assert_output "$kind_workspace_output" workspace_image false
# When Kind runs the published pin instead, the selected exact-source
# workspace still gets its Container contract verification.
kind_pinned_output="$(KIND_WORKSPACE_SOURCE=pinned emit '|valid:v3|kind|complete|' fallback false false true)"
assert_output "$kind_pinned_output" edge_kind true
assert_output "$kind_pinned_output" workspace_image true
kind_pinned_output="$(KIND_WORKSPACE_SOURCE=pinned emit '|valid:v3|kind|complete|' fallback false false false)"
assert_output "$kind_pinned_output" workspace_image false
if KIND_WORKSPACE_SOURCE=cached VERIFICATION_SELECTION='|valid:v3|kind|complete|' \
    VERIFICATION_TESTED_TREE_RECEIPT=fallback CW_PACKAGE_SELECTED=false DESKTOP_PACKAGE_SELECTED=false \
    WORKSPACE_IMAGE_SELECTED=true GITHUB_OUTPUT="$TMP/unknown-source" "$CHECK" >/dev/null 2>&1; then
  echo 'an unknown Kind workspace source was accepted' >&2
  exit 1
fi

# Who owns the exact-source workspace image. CI (pull requests, dispatches,
# and callers that predate the choice) dispatches the container contract for a
# selected workspace; on a push to main support-images verifies the image it
# publishes, so the workspace alone dispatches nothing. Dashboard and iOS work
# dispatch the job under either owner, and Kind ownership is unchanged.
# OWNER|SELECTION|WORKSPACE|KIND SOURCE|WORKSPACE_IMAGE EXPECTED
while IFS='|' read -r owner tokens workspace kind_source expected_workspace; do
  owner_selection="|valid:v3|${tokens//,/|}|complete|"
  # An empty owner column means the variable is unset; empty means the same.
  if [ -n "$owner" ]; then
    owner_output="$(WORKSPACE_IMAGE_OWNER="$owner" KIND_WORKSPACE_SOURCE="$kind_source" \
      emit "$owner_selection" fallback false false "$workspace")"
  else
    owner_output="$(KIND_WORKSPACE_SOURCE="$kind_source" \
      emit "$owner_selection" fallback false false "$workspace")"
    [[ "$owner_output" == "$(WORKSPACE_IMAGE_OWNER='' KIND_WORKSPACE_SOURCE="$kind_source" \
        emit "$owner_selection" fallback false false "$workspace")" ]] || {
      echo 'an empty workspace image owner differs from an unset one' >&2
      exit 1
    }
  fi
  # Checked here, not through assert_output: errexit is off inside a function
  # called as the left side of ||.
  grep -Fxq "workspace_image_expected=${expected_workspace}" <<<"$owner_output" || {
    echo "owner=${owner:-unset} selection=${owner_selection} workspace=${workspace} kind=${kind_source}: workspace_image_expected is not ${expected_workspace}" >&2
    exit 1
  }
done <<'EOF'
|policy|true|source|true
ci|policy|true|source|true
ci|policy|false|source|false
ci|kind|true|source|false
ci|kind|true|pinned|true
support-images|policy|true|source|false
support-images|policy|true|pinned|false
support-images|kind|true|pinned|false
support-images|policy,rust|true|source|false
support-images|web|true|source|true
support-images|web,kind|true|pinned|false
support-images|ios|true|source|true
support-images|ios,kind|false|source|true
ci|web|false|source|true
ci|ios|false|source|true
EOF
# The owner moves only the workspace decision: every other group is identical.
for owner_tokens in 'policy,rust,database' 'kind,web' 'policy,ios'; do
  owner_selection="|valid:v3|${owner_tokens//,/|}|complete|"
  ci_groups="$(WORKSPACE_IMAGE_OWNER=ci emit "$owner_selection" fallback true true true | grep -v '^workspace_image_')"
  support_groups="$(WORKSPACE_IMAGE_OWNER=support-images emit "$owner_selection" fallback true true true | grep -v '^workspace_image_')"
  [[ "$ci_groups" == "$support_groups" ]] || {
    echo "the workspace owner changed another group for ${owner_selection}" >&2
    exit 1
  }
done
# A pull request's quick selection dispatches no workspace work for either owner.
for owner in ci support-images; do
  quick_owner_output="$(WORKSPACE_IMAGE_OWNER="$owner" emit \
    '|valid:v3|policy|policy_shell_omittable|pr_quick|rust_compile|complete|' fallback true true true)"
  assert_output "$quick_owner_output" workspace_image false
done
# Anything but the two owners fails closed: no decision is emitted.
for invalid_owner in support_images CI main ' ci' 'ci ' publish; do
  : > "$TMP/invalid-owner"
  if WORKSPACE_IMAGE_OWNER="$invalid_owner" VERIFICATION_SELECTION='|valid:v3|policy|complete|' \
      VERIFICATION_TESTED_TREE_RECEIPT=fallback CW_PACKAGE_SELECTED=false DESKTOP_PACKAGE_SELECTED=false \
      WORKSPACE_IMAGE_SELECTED=true GITHUB_OUTPUT="$TMP/invalid-owner" "$CHECK" >/dev/null 2>&1; then
    echo "an invalid workspace image owner was accepted: '${invalid_owner}'" >&2
    exit 1
  fi
  [[ ! -s "$TMP/invalid-owner" ]] || {
    echo "an invalid workspace image owner emitted decisions: '${invalid_owner}'" >&2
    exit 1
  }
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
for group in standard tooling rust_shards rust_transport database services_control \
    services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$quick_output" "$group" false
done
quick_shell_output="$(emit \
  '|valid:v3|policy|policy_shell|policy_shell_omittable|pr_quick|complete|' \
  fallback true true true)"
assert_output "$quick_shell_output" policy true
assert_output "$quick_shell_output" tooling true
for group in standard rust_compile rust_shards rust_transport database services_control \
    services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$quick_shell_output" "$group" false
done
quick_kind_output="$(emit \
  '|valid:v3|edge_kind|kind|policy|policy_shell_omittable|pr_quick|rust_compile|complete|' \
  fallback false false true)"
for group in policy tooling rust_compile edge_kind; do
  assert_output "$quick_kind_output" "$group" true
done
for group in standard rust_shards rust_transport database services_control \
    services_runtime cw_release_assets workspace_image; do
  assert_output "$quick_kind_output" "$group" false
done
# A scheduled run (owner decision 2026-10-20) dispatches the Kind shards
# alone when it selected Kind, and nothing when it did not, whatever the
# artifact facts and the workspace owner say.
for owner in ci support-images; do
  scheduled_kind_output="$(WORKSPACE_IMAGE_OWNER="$owner" KIND_WORKSPACE_SOURCE=pinned \
    emit '|valid:v3|kind|scheduled|complete|' fallback true true true)"
  assert_output "$scheduled_kind_output" edge_kind true
  scheduled_nothing_output="$(WORKSPACE_IMAGE_OWNER="$owner" \
    emit '|valid:v3|scheduled|complete|' fallback true true true)"
  for group in policy standard tooling rust_compile rust_shards rust_transport database \
      services_control services_runtime cw_release_assets workspace_image; do
    assert_output "$scheduled_kind_output" "$group" false
    assert_output "$scheduled_nothing_output" "$group" false
  done
  assert_output "$scheduled_nothing_output" edge_kind false
done
# The same artifact facts without pr_quick or scheduled keep dispatching their groups.
full_artifact_output="$(emit '|valid:v3|policy|policy_shell_omittable|complete|' fallback true true true)"
for group in policy rust_compile rust_transport cw_release_assets workspace_image; do
  assert_output "$full_artifact_output" "$group" true
done

web_output="$(emit '|valid:v3|web|complete|' fallback false false false)"
assert_output "$web_output" standard true
assert_output "$web_output" workspace_image true

# The docs site runs in the standard group alone: no container, browser or
# Kind work, and docs is a known token (an unknown one dispatches everything).
docs_output="$(emit '|valid:v3|docs|complete|' fallback false false false)"
assert_output "$docs_output" standard true
for group in policy tooling rust_compile rust_shards rust_transport database \
    services_control services_runtime edge_kind cw_release_assets workspace_image; do
  assert_output "$docs_output" "$group" false
done

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
for group in policy standard tooling rust_compile rust_shards rust_transport database \
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
all_groups=(policy standard tooling rust_compile rust_shards rust_transport database
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
