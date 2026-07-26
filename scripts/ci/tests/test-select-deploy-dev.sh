#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SELECTOR="$ROOT/scripts/ci/select/select-deploy-dev.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

assert_selection() {
  local name="$1" expected="$2" event="$3" worktree="$4"
  shift 4

  local changed_files="$TMP/${name}.paths"
  local output actual
  printf '%s\n' "$@" >"$changed_files"
  output="$(cd "$worktree" && env -u GITHUB_OUTPUT GITHUB_EVENT_NAME="$event" \
    "$SELECTOR" "$changed_files")"
  actual="$(sed -n 's/^deploy_dev=//p' <<<"$output")"

  if [ "$actual" != "$expected" ]; then
    printf '[test-select-deploy-dev] %s: expected %s, got %s\n' \
      "$name" "$expected" "${actual:-missing}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

# Manual diagnostics cannot change runtime or deployment behavior. Adding the
# workflow during a script-only reorganization must therefore remain deploy
# neutral.
assert_selection manual_diagnostics false push "$ROOT" \
  .gitea/workflows/manual-diagnostics.yaml

# Keep the exception narrow: the deployment workflow and product inputs still
# select the canonical dev build and rollout path.
FIXTURE_REPO="$TMP/worktree"
mkdir -p "$FIXTURE_REPO/.gitea/workflows"
git -C "$FIXTURE_REPO" init -q
git -C "$FIXTURE_REPO" config user.name 'Deploy Selector Test'
git -C "$FIXTURE_REPO" config user.email deploy-selector@example.invalid
printf '%s\n' \
  'name: Deploy Dev' \
  'run: scripts/ci/old-entrypoint.sh' \
  >"$FIXTURE_REPO/.gitea/workflows/deploy-dev.yaml"
git -C "$FIXTURE_REPO" add .gitea/workflows/deploy-dev.yaml
git -C "$FIXTURE_REPO" commit -q -m base
printf '%s\n' \
  'name: Deploy Dev' \
  'run: scripts/ci/new-entrypoint.sh' \
  >"$FIXTURE_REPO/.gitea/workflows/deploy-dev.yaml"
assert_selection deploy_workflow_reference_only false push "$FIXTURE_REPO" \
  .gitea/workflows/deploy-dev.yaml
printf '%s\n' \
  'name: Changed Deploy Dev' \
  'run: scripts/ci/old-entrypoint.sh' \
  >"$FIXTURE_REPO/.gitea/workflows/deploy-dev.yaml"
assert_selection deploy_workflow true push "$FIXTURE_REPO" \
  .gitea/workflows/deploy-dev.yaml
assert_selection product_input true push "$ROOT" Cargo.toml
assert_selection sdk_python_source false push "$ROOT" \
  libs/sdk-python/codewire/client.py
assert_selection sdk_tooling_source false push "$ROOT" \
  libs/sdk-scripts/filter-openapi.py
assert_selection sdk_ts_source false push "$ROOT" \
  libs/sdk-ts/src/types.ts
assert_selection sdk_examples_source false push "$ROOT" \
  libs/sdk-examples/run-claude/typescript/package-lock.json
assert_selection sdk_tooling_wi12_paths false push "$ROOT" \
  Makefile libs/sdk-scripts/filter-openapi.py \
  docs/plans/connect-rpc/13-rest-sunset-and-openapi-removal.md \
  libs/sdk-examples/run-claude/typescript/package-lock.json \
  libs/sdk-ts/src/types.ts
assert_selection cli_source false push "$ROOT" \
  crates/codewire-cli/src/lib.rs
assert_selection cli_bin_source false push "$ROOT" \
  crates/codewire-cli-bin/src/main.rs
assert_selection combined_cli_sources false push "$ROOT" \
  crates/codewire-cli/src/lib.rs \
  crates/codewire-cli-bin/src/main.rs
assert_selection mixed_cli_and_runtime true push "$ROOT" \
  crates/codewire-cli/src/lib.rs crates/codewire-mesh/src/server.rs
assert_selection sdk_python_runner false push "$ROOT" \
  scripts/runtime/dev/run-sdk-python-e2e.sh \
  scripts/runtime/tests/test-run-sdk-python-e2e.sh
assert_selection makefile_only false push "$ROOT" Makefile
assert_selection server_core_lifecycle_test false push "$ROOT" \
  crates/codewire-server-core/tests/org_deletion_lifecycle.rs
assert_selection mixed_sdk_and_runtime true push "$ROOT" \
  libs/sdk-python/codewire/client.py crates/codewire-server-core/src/lib.rs
assert_selection mixed_sdk_tooling_and_runtime true push "$ROOT" \
  libs/sdk-scripts/filter-openapi.py crates/codewire-server-core/src/lib.rs
assert_selection mixed_sdk_ts_and_runtime true push "$ROOT" \
  libs/sdk-ts/src/types.ts crates/codewire-server-core/src/lib.rs

# The selector's established manual-dispatch fail-safe remains unchanged.
assert_selection manual_dispatch true workflow_dispatch "$ROOT" \
  .gitea/workflows/manual-diagnostics.yaml

printf '[test-select-deploy-dev] deploy-neutral and fail-closed cases passed\n'
