#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/pre-push-worktree.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-pre-push-worktree] ERROR: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local name="$1" output="$2" expected="$3"
  if ! grep -Fq -- "$expected" <<<"$output"; then
    printf '[test-pre-push-worktree] %s missing: %s\n' "$name" "$expected" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

assert_not_contains() {
  local name="$1" output="$2" unexpected="$3"
  if grep -Fq -- "$unexpected" <<<"$output"; then
    printf '[test-pre-push-worktree] %s unexpectedly contained: %s\n' \
      "$name" "$unexpected" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

commit_all() {
  local repo="$1" message="$2"
  git -C "$repo" add -A
  git -C "$repo" -c commit.gpgsign=false commit -q -m "$message"
}

write_stub_tree() {
  local repo="$1"
  mkdir -p \
    "$repo/.githooks" \
    "$repo/.gitea/workflows" \
    "$repo/docs" \
    "$repo/libs/tailnet" \
    "$repo/scripts/checks" \
    "$repo/scripts/ci/select" \
    "$repo/scripts/ci/verify" \
    "$repo/scripts/dev"

  install -m 755 "$ROOT/.githooks/pre-push" "$repo/.githooks/pre-push"
  install -m 755 "$ROOT/scripts/dev/preflight.sh" "$repo/scripts/dev/preflight.sh"
  install -m 755 "$ROOT/scripts/dev/install-hooks.sh" "$repo/scripts/dev/install-hooks.sh"
  install -m 755 "$ROOT/scripts/ci/select/select-verification.sh" \
    "$repo/scripts/ci/select/select-verification.sh"

  cat > "$repo/scripts/ci/verify/run-product-verification.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'product %s %s\n' "$1" "${VERIFICATION_SELECTION:?}" \
  >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
EOF
  cat > "$repo/scripts/ci/verify/run-integration-verification.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'integration %s %s\n' "$1" "${VERIFICATION_SELECTION:?}" \
  >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
EOF
  cat > "$repo/scripts/ci/verify/kind-e2e.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'kind\n' >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
EOF
  cat > "$repo/scripts/checks/repo_checks.py" <<'EOF'
#!/usr/bin/env python3
import os
import sys

with open(os.environ["PREFLIGHT_TEST_TOOL_LOG"], "a", encoding="utf-8") as log:
    log.write("repo_checks " + " ".join(sys.argv[1:]) + "\n")
EOF
  chmod +x \
    "$repo/scripts/ci/verify/run-product-verification.sh" \
    "$repo/scripts/ci/verify/run-integration-verification.sh" \
    "$repo/scripts/ci/verify/kind-e2e.sh" \
    "$repo/scripts/checks/repo_checks.py"

  cat > "$repo/.gitea/workflows/ci.yaml" <<'EOF'
name: fixture
EOF
  printf 'fixture\n' > "$repo/libs/tailnet/.preflight-fixture"
}

push_branch() {
  local repo="$1" branch="$2" tool_log="$3"
  (
    cd "$repo"
    PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$tool_log" \
      git push -q origin "HEAD:refs/heads/$branch" 2>&1
  )
}

mkdir -p "$TMP/bin"
cat > "$TMP/bin/tool-stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s %s\n' "$(basename "$0")" "$*" >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
EOF
chmod +x "$TMP/bin/tool-stub"
ln -s tool-stub "$TMP/bin/bun"

repo="$TMP/checkout"
remote="$TMP/remote.git"
git init -q -b main "$repo"
git init -q --bare "$remote"
git -C "$repo" config user.name 'Preflight Fixture'
git -C "$repo" config user.email preflight-fixture@codewire.invalid
write_stub_tree "$repo"
printf 'base\n' > "$repo/docs/base.md"
commit_all "$repo" 'test: seed checkout fixture'
git -C "$repo" remote add origin "$remote"
git -C "$repo" push --no-verify -q -u origin main

install_output="$(cd "$repo" && ./scripts/dev/install-hooks.sh)"
assert_contains installer "$install_output" \
  'pre-push resolves scripts/dev/preflight.sh from the worktree invoking git push'
[ "$(git -C "$repo" config --get core.hooksPath)" = "$repo/.githooks" ] ||
  fail 'installer did not set the expected absolute shared hooksPath'

if unresolved_output="$(cd / && "$repo/.githooks/pre-push" 2>&1)"; then
  fail 'hook unexpectedly succeeded outside a worktree'
fi
assert_contains unresolved_root "$unresolved_output" \
  'pre-push: could not resolve the invoking worktree root'

git -C "$repo" switch -q -c normal-docs main
printf 'normal docs\n' > "$repo/docs/normal.md"
commit_all "$repo" 'docs: normal checkout fixture'
normal_log="$TMP/normal-tools.log"
normal_output="$(push_branch "$repo" normal-docs "$normal_log")"
assert_contains normal "$normal_output" '  docs/normal.md'
assert_contains normal "$normal_output" \
  'preflight selection: |valid:v2|policy|complete|'
assert_contains normal_tools "$(cat "$normal_log")" \
  'repo_checks rest-surface-freeze'
assert_contains normal_tools "$(cat "$normal_log")" \
  'repo_checks retired-reference-source'
assert_not_contains normal_tools "$(cat "$normal_log")" 'product '
assert_not_contains normal_tools "$(cat "$normal_log")" 'integration '
git -C "$repo" switch -q main

linked_docs="$TMP/linked-docs"
git -C "$repo" worktree add -q -b linked-docs "$linked_docs" main
printf 'linked docs\n' > "$linked_docs/docs/linked.md"
commit_all "$linked_docs" 'docs: linked worktree fixture'
linked_docs_log="$TMP/linked-docs-tools.log"
linked_docs_output="$(push_branch "$linked_docs" linked-docs "$linked_docs_log")"
assert_contains linked_docs "$linked_docs_output" '  docs/linked.md'
assert_contains linked_docs "$linked_docs_output" \
  'preflight selection: |valid:v2|policy|complete|'
assert_not_contains linked_docs_tools "$(cat "$linked_docs_log")" 'product '

linked_source="$TMP/linked-source"
git -C "$repo" worktree add -q -b linked-source "$linked_source" main
mkdir -p "$linked_source/crates/codewire-cli/src"
printf 'pub fn linked_fixture() {}\n' > \
  "$linked_source/crates/codewire-cli/src/worktree_fixture.rs"
commit_all "$linked_source" 'test: linked Rust source fixture'
source_log="$TMP/source-tools.log"
source_output="$(push_branch "$linked_source" linked-source "$source_log")"
assert_contains linked_source "$source_output" \
  '  crates/codewire-cli/src/worktree_fixture.rs'
assert_contains linked_source "$source_output" \
  'preflight selection: |valid:v2|policy|rust|rust_pkg_codewire_cli|complete|'
assert_contains source_tools "$(cat "$source_log")" 'product rust '
assert_not_contains source_tools "$(cat "$source_log")" 'product go-support '

linked_workflow="$TMP/linked-workflow"
git -C "$repo" worktree add -q -b linked-workflow "$linked_workflow" main
cat > "$linked_workflow/.gitea/workflows/ci.yaml" <<'EOF'
name: changed fixture
EOF
commit_all "$linked_workflow" 'test: linked workflow fixture'
workflow_log="$TMP/workflow-tools.log"
workflow_output="$(push_branch "$linked_workflow" linked-workflow "$workflow_log")"
assert_contains linked_workflow "$workflow_output" \
  '  .gitea/workflows/ci.yaml'
assert_contains linked_workflow "$workflow_output" \
  'preflight selection: |valid:v2|policy|rust_curated_locks|complete|'
assert_contains workflow_tools "$(cat "$workflow_log")" \
  'product rust-curated-locks '
assert_not_contains workflow_tools "$(cat "$workflow_log")" 'integration '

# Direct invocation with an empty range and a repository without a canonical
# main ref both fail closed to active product checks, never diagnostics.
empty_log="$TMP/empty-tools.log"
empty_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$empty_log" \
    "$repo/.githooks/pre-push"
} 2>&1)"
assert_contains empty "$empty_output" '  (no changed paths)'
assert_contains empty "$empty_output" '|database|'
assert_contains empty "$empty_output" '|service_integration|'
assert_not_contains empty "$empty_output" 'diagnostic_'
assert_contains empty_tools "$(cat "$empty_log")" 'integration database '
assert_contains empty_tools "$(cat "$empty_log")" 'integration services '
assert_contains empty_tools "$(cat "$empty_log")" 'kind'

unknown_repo="$TMP/unknown-checkout"
git init -q -b feature "$unknown_repo"
git -C "$unknown_repo" config user.name 'Preflight Fixture'
git -C "$unknown_repo" config user.email preflight-fixture@codewire.invalid
write_stub_tree "$unknown_repo"
printf 'unknown\n' > "$unknown_repo/docs/unknown.md"
commit_all "$unknown_repo" 'test: unknown-base fixture'
unknown_log="$TMP/unknown-tools.log"
unknown_output="$({
  cd "$unknown_repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$unknown_log" \
    "$unknown_repo/.githooks/pre-push"
} 2>&1)"
assert_contains unknown "$unknown_output" '  __unknown__'
assert_contains unknown "$unknown_output" '|rust_workspace|'
assert_not_contains unknown "$unknown_output" 'diagnostic_'
assert_contains unknown_tools "$(cat "$unknown_log")" 'product rust '
assert_contains unknown_tools "$(cat "$unknown_log")" 'product go-support '

diagnostic_paths="$TMP/diagnostic.paths"
printf 'docs/diagnostic.md\n' > "$diagnostic_paths"
diagnostic_log="$TMP/diagnostic-tools.log"
diagnostic_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$diagnostic_log" \
    PREFLIGHT_CHANGED_FILES="$diagnostic_paths" "$repo/.githooks/pre-push"
} 2>&1)"
assert_contains diagnostic "$diagnostic_output" '  docs/diagnostic.md'
assert_contains diagnostic "$diagnostic_output" \
  'preflight selection: |valid:v2|policy|complete|'
assert_not_contains diagnostic_tools "$(cat "$diagnostic_log")" 'product '

sdk_runner_paths="$TMP/sdk-runner.paths"
printf '%s\n' \
  scripts/runtime/dev/run-sdk-python-e2e.sh \
  scripts/runtime/tests/test-run-sdk-python-e2e.sh > "$sdk_runner_paths"
sdk_runner_log="$TMP/sdk-runner-tools.log"
sdk_runner_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$sdk_runner_log" \
    PREFLIGHT_CHANGED_FILES="$sdk_runner_paths" "$repo/.githooks/pre-push"
} 2>&1)"
assert_contains sdk_runner "$sdk_runner_output" \
  'preflight selection: |valid:v2|policy|sdk_python|complete|'
assert_contains sdk_runner_tools "$(cat "$sdk_runner_log")" 'product sdk-python '
assert_not_contains sdk_runner_tools "$(cat "$sdk_runner_log")" 'integration '
assert_not_contains sdk_runner_tools "$(cat "$sdk_runner_log")" 'kind'

apikey_tooling_paths="$TMP/apikey-tooling.paths"
printf '%s\n' scripts/runtime/tests/test-apikey-smoke.sh > "$apikey_tooling_paths"
apikey_tooling_log="$TMP/apikey-tooling.log"
apikey_tooling_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$apikey_tooling_log" \
    PREFLIGHT_CHANGED_FILES="$apikey_tooling_paths" "$repo/.githooks/pre-push"
} 2>&1)"
assert_contains apikey_tooling "$apikey_tooling_output" \
  'preflight selection: |valid:v2|policy|service_apikey_smoke|complete|'
assert_contains apikey_tooling_tools "$(cat "$apikey_tooling_log")" \
  'product service-apikey-smoke '
assert_not_contains apikey_tooling_tools "$(cat "$apikey_tooling_log")" 'integration '

confidential_tooling_paths="$TMP/confidential-tooling.paths"
printf '%s\n' \
  scripts/runtime/confidential/resolve-coco-support-lock.sh \
  scripts/runtime/tests/test-resolve-coco-support-lock.sh \
  > "$confidential_tooling_paths"
confidential_tooling_log="$TMP/confidential-tooling.log"
confidential_tooling_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$confidential_tooling_log" \
    PREFLIGHT_CHANGED_FILES="$confidential_tooling_paths" "$repo/.githooks/pre-push"
} 2>&1)"
assert_contains confidential_tooling "$confidential_tooling_output" \
  'preflight selection: |valid:v2|policy|runtime_confidential|complete|'
assert_contains confidential_tooling_tools "$(cat "$confidential_tooling_log")" \
  'product runtime-confidential '
assert_not_contains confidential_tooling_tools \
  "$(cat "$confidential_tooling_log")" 'product release '
assert_not_contains confidential_tooling_tools \
  "$(cat "$confidential_tooling_log")" 'integration '

sdk_tooling_paths="$TMP/sdk-tooling.paths"
printf '%s\n' \
  Makefile \
  libs/sdk-scripts/filter-openapi.py \
  docs/plans/connect-rpc/13-rest-sunset-and-openapi-removal.md > "$sdk_tooling_paths"
sdk_tooling_log="$TMP/sdk-tooling-tools.log"
sdk_tooling_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$sdk_tooling_log" \
    PREFLIGHT_CHANGED_FILES="$sdk_tooling_paths" "$repo/.githooks/pre-push"
} 2>&1)"
assert_contains sdk_tooling "$sdk_tooling_output" \
  'preflight selection: |valid:v2|go_consumer_interop|go_support|policy|sdk_go|sdk_python|sdk_ts|complete|'
assert_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'product sdk-go '
assert_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'product sdk-ts '
assert_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'product sdk-python '
assert_not_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'integration '
assert_not_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'kind'

printf '[test-pre-push-worktree] shared selection, worktree, and fail-closed cases passed\n'
