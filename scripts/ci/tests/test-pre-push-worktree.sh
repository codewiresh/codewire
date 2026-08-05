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
    "$repo/scripts/checks/source" \
    "$repo/scripts/ci/select" \
    "$repo/scripts/ci/verify" \
    "$repo/scripts/dev"

  install -m 755 "$ROOT/.githooks/pre-push" "$repo/.githooks/pre-push"
  install -m 755 "$ROOT/scripts/dev/preflight.sh" "$repo/scripts/dev/preflight.sh"
  install -m 755 "$ROOT/scripts/dev/install-hooks.sh" "$repo/scripts/dev/install-hooks.sh"
  install -m 755 "$ROOT/scripts/ci/select/select-verification.sh" \
    "$repo/scripts/ci/select/select-verification.sh"
cat > "$repo/scripts/ci/select/verify-release-tag-receipt.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${PREFLIGHT_TEST_RECEIPT_FAIL:-0}" = 1 ]; then
  exit 2
fi
printf 'receipt-ref=%s remote=%s\n' \
  "${PREFLIGHT_RELEASE_TAG_REF:-}" "${PREFLIGHT_PUSH_REMOTE_NAME:-}" \
  >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
printf 'release_tag_receipt=accepted\nrelease_tag_reason=fixture\nrelease_tag_run=1\n'
EOF

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
  cat > "$repo/scripts/checks/source/check-native-desktop-ui.py" <<'EOF'
#!/usr/bin/env python3
import os

with open(os.environ["PREFLIGHT_TEST_TOOL_LOG"], "a", encoding="utf-8") as log:
    log.write("native_desktop_ui\n")
EOF
  chmod +x \
    "$repo/scripts/ci/verify/run-product-verification.sh" \
    "$repo/scripts/ci/verify/run-integration-verification.sh" \
    "$repo/scripts/ci/verify/kind-e2e.sh" \
    "$repo/scripts/ci/select/verify-release-tag-receipt.sh" \
    "$repo/scripts/checks/repo_checks.py" \
    "$repo/scripts/checks/source/check-native-desktop-ui.py"

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

installer_worktree="$TMP/hook-installer"
git -C "$repo" worktree add -q -b hook-installer "$installer_worktree" main
install_output="$(cd "$installer_worktree" && ./scripts/dev/install-hooks.sh)"
assert_contains installer "$install_output" \
  'stable pre-push dispatcher copied into the common Git directory'
assert_contains installer "$install_output" \
  'dispatcher resolves scripts/dev/preflight.sh from the pushing worktree'
dispatcher_dir="$repo/.git/codewire-hooks"
dispatcher="$dispatcher_dir/pre-push"
[ "$(git -C "$repo" config --get core.hooksPath)" = "$dispatcher_dir" ] ||
  fail 'installer did not set the common-directory hooksPath'
[ -x "$dispatcher" ] || fail 'installer did not create an executable dispatcher'
cmp "$installer_worktree/.githooks/pre-push" "$dispatcher" ||
  fail 'installed dispatcher differs from its tracked source'

git -C "$repo" worktree remove "$installer_worktree"
[ ! -e "$installer_worktree" ] || fail 'installer worktree was not removed'
[ -x "$dispatcher" ] || fail 'dispatcher disappeared with its installing worktree'

if unresolved_output="$(cd / && "$dispatcher" 2>&1)"; then
  fail 'hook unexpectedly succeeded outside a worktree'
fi
assert_contains unresolved_root "$unresolved_output" \
  'pre-push: could not resolve the invoking worktree root'

invalid_mode_log="$TMP/invalid-mode-tools.log"
if invalid_mode_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$invalid_mode_log" \
    CODEWIRE_PREFLIGHT_MODE=explain "$dispatcher" </dev/null
} 2>&1)"; then
  fail 'pre-push accepted explain mode without verification'
fi
assert_contains invalid_mode "$invalid_mode_output" \
  'CODEWIRE_PREFLIGHT_MODE must be default, integration, kind, or full'
[ ! -s "$invalid_mode_log" ] || fail 'invalid mode ran verification tools'

multi_ref_log="$TMP/multi-ref-tools.log"
multi_ref_head="$(git -C "$repo" rev-parse main)"
zero_sha=0000000000000000000000000000000000000000
if multi_ref_output="$({
  printf '%s\n' \
    "refs/heads/one $multi_ref_head refs/heads/one $zero_sha" \
    "(delete) $zero_sha refs/heads/two $multi_ref_head" |
    {
      cd "$repo"
      PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$multi_ref_log" \
        "$dispatcher"
    }
} 2>&1)"; then
  fail 'pre-push accepted an ambiguous multi-ref push'
fi
assert_contains multi_ref "$multi_ref_output" \
  'multi-ref pushes are unsupported; push one ref at a time'
[ ! -s "$multi_ref_log" ] || fail 'multi-ref rejection ran verification tools'

delete_ref_log="$TMP/delete-ref-tools.log"
printf '%s\n' "(delete) $zero_sha refs/heads/obsolete $multi_ref_head" |
  {
    cd "$repo"
    PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$delete_ref_log" \
      "$dispatcher"
  }
[ ! -s "$delete_ref_log" ] || fail 'single-ref deletion ran verification tools'

git -C "$repo" switch -q -c normal-docs main
printf 'normal docs\n' > "$repo/docs/normal.md"
commit_all "$repo" 'docs: normal checkout fixture'
normal_log="$TMP/normal-tools.log"
normal_output="$(push_branch "$repo" normal-docs "$normal_log")"
assert_contains normal "$normal_output" '  docs/normal.md'
assert_contains normal "$normal_output" \
  'preflight selection: |valid:v3|policy|complete|'
assert_contains normal_tools "$(cat "$normal_log")" \
  'repo_checks permanent-raw-surface --self-test'
assert_contains normal_tools "$(cat "$normal_log")" \
  'repo_checks retired-reference-source'
assert_contains normal_tools "$(cat "$normal_log")" 'native_desktop_ui'
assert_not_contains normal_tools "$(cat "$normal_log")" 'product '
assert_not_contains normal_tools "$(cat "$normal_log")" 'integration '
git -C "$repo" switch -q main

git -C "$repo" tag -a -m 'release fixture' v1.2.3 main
tag_log="$TMP/tag-tools.log"
tag_output="$(
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$tag_log" \
    git push -q origin refs/tags/v1.2.3 2>&1
)"
assert_contains release_tag "$tag_output" \
  'preflight: exact-main CI receipt accepted; signed release tag verified'
assert_contains release_tag_tools "$(cat "$tag_log")" \
  'receipt-ref=refs/tags/v1.2.3 remote=origin'
assert_not_contains release_tag_tools "$(cat "$tag_log")" 'integration '
assert_not_contains release_tag_tools "$(cat "$tag_log")" 'kind'

failed_receipt_log="$TMP/failed-receipt-tools.log"
failed_receipt_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" \
    PREFLIGHT_TEST_TOOL_LOG="$failed_receipt_log" \
    PREFLIGHT_TEST_RECEIPT_FAIL=1 \
    PREFLIGHT_RELEASE_TAG_REF=refs/tags/v1.2.3 \
    PREFLIGHT_RELEASE_TAG_OBJECT_SHA="$(git rev-parse refs/tags/v1.2.3)" \
    PREFLIGHT_PUSH_REMOTE_NAME=origin \
    PREFLIGHT_HEAD_SHA="$(git rev-parse refs/tags/v1.2.3)" \
    "$repo/scripts/dev/preflight.sh"
} 2>&1)"
assert_contains failed_receipt "$failed_receipt_output" \
  'release-tag receipt: checker failed unexpectedly; full local verification required'
assert_contains failed_receipt "$failed_receipt_output" \
  'preflight: release receipt unavailable; running full fail-closed verification'
assert_contains failed_receipt_tools "$(cat "$failed_receipt_log")" \
  'integration database '
assert_contains failed_receipt_tools "$(cat "$failed_receipt_log")" 'kind'

linked_docs="$TMP/linked-docs"
git -C "$repo" worktree add -q -b linked-docs "$linked_docs" main
printf 'linked docs\n' > "$linked_docs/docs/linked.md"
commit_all "$linked_docs" 'docs: linked worktree fixture'
linked_docs_log="$TMP/linked-docs-tools.log"
linked_docs_output="$(push_branch "$linked_docs" linked-docs "$linked_docs_log")"
assert_contains linked_docs "$linked_docs_output" '  docs/linked.md'
assert_contains linked_docs "$linked_docs_output" \
  'preflight selection: |valid:v3|policy|complete|'
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
  'preflight selection: |valid:v3|policy|rust|rust_pkg_codewire_cli|complete|'
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
  'preflight selection: |valid:v3|policy|runtime_dev_smoke|rust_curated_locks|complete|'
assert_contains workflow_tools "$(cat "$workflow_log")" \
  'product rust-curated-locks '
assert_contains workflow_tools "$(cat "$workflow_log")" \
  'product runtime-dev-smoke '
assert_not_contains workflow_tools "$(cat "$workflow_log")" 'integration '

linked_database="$TMP/linked-database"
git -C "$repo" worktree add -q -b linked-database "$linked_database" main
mkdir -p "$linked_database/crates/codewire-server-core/tests"
printf 'database fixture\n' > \
  "$linked_database/crates/codewire-server-core/tests/org_deletion_lifecycle.rs"
commit_all "$linked_database" 'test: linked database fixture'
database_log="$TMP/database-tools.log"
if database_output="$(push_branch \
    "$linked_database" linked-database "$database_log")"; then
  fail 'default preflight accepted a change requiring integration mode'
fi
assert_contains linked_database "$database_output" \
  'preflight required local mode: integration'
assert_contains linked_database "$database_output" \
  'retry with CODEWIRE_PREFLIGHT_MODE=integration git push'
[ ! -s "$database_log" ] || \
  fail 'incomplete default mode ran checks before requesting escalation'
database_output="$({
  cd "$linked_database"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$database_log" \
    CODEWIRE_PREFLIGHT_MODE=integration \
    git push -q origin HEAD:refs/heads/linked-database 2>&1
})"
assert_contains linked_database_retry "$database_output" \
  'preflight required local mode: integration'
assert_contains database_tools "$(cat "$database_log")" 'integration database '
assert_not_contains database_tools "$(cat "$database_log")" 'kind'

# A clean direct invocation is truthful and lightweight.
empty_log="$TMP/empty-tools.log"
empty_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$empty_log" \
    "$repo/.githooks/pre-push"
} 2>&1)"
assert_contains empty "$empty_output" '  (no changed paths)'
assert_contains empty "$empty_output" 'preflight classification: unchanged'
assert_contains empty "$empty_output" \
  'preflight selection: |valid:v3|policy|complete|'
assert_not_contains empty "$empty_output" 'diagnostic_'
assert_not_contains empty_tools "$(cat "$empty_log")" 'integration '
assert_not_contains empty_tools "$(cat "$empty_log")" 'kind'

# A repository without a canonical baseline fails with an explanation and
# does not claim that a synthetic path was successfully classified.
unknown_repo="$TMP/unknown-checkout"
git init -q -b feature "$unknown_repo"
git -C "$unknown_repo" config user.name 'Preflight Fixture'
git -C "$unknown_repo" config user.email preflight-fixture@codewire.invalid
write_stub_tree "$unknown_repo"
printf 'unknown\n' > "$unknown_repo/docs/unknown.md"
commit_all "$unknown_repo" 'test: unknown-base fixture'
unknown_log="$TMP/unknown-tools.log"
if unknown_output="$({
  cd "$unknown_repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$unknown_log" \
    "$unknown_repo/.githooks/pre-push"
} 2>&1)"; then
  fail 'preflight accepted a repository without a canonical baseline'
fi
assert_contains unknown "$unknown_output" \
  'preflight: canonical baseline is unavailable FAILED'
[ ! -s "$unknown_log" ] || fail 'missing baseline ran verification tools'

diagnostic_paths="$TMP/diagnostic.paths"
printf 'docs/diagnostic.md\n' > "$diagnostic_paths"
diagnostic_log="$TMP/diagnostic-tools.log"
diagnostic_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$diagnostic_log" \
    PREFLIGHT_CHANGED_FILES="$diagnostic_paths" "$dispatcher"
} 2>&1)"
assert_contains diagnostic "$diagnostic_output" '  docs/diagnostic.md'
assert_contains diagnostic "$diagnostic_output" \
  'preflight selection: |valid:v3|policy|complete|'
assert_not_contains diagnostic_tools "$(cat "$diagnostic_log")" 'product '

kind_mode_paths="$TMP/kind-mode.paths"
printf 'Caddyfile\n' > "$kind_mode_paths"
kind_mode_log="$TMP/kind-mode-tools.log"
kind_mode_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$kind_mode_log" \
    PREFLIGHT_CHANGED_FILES="$kind_mode_paths" CODEWIRE_PREFLIGHT_MODE=kind \
    "$dispatcher"
} 2>&1)"
assert_contains kind_mode "$kind_mode_output" \
  'preflight required local mode: kind'
assert_contains kind_mode_tools "$(cat "$kind_mode_log")" 'product edge '
assert_contains kind_mode_tools "$(cat "$kind_mode_log")" 'kind'

full_mode_paths="$TMP/full-mode.paths"
printf 'docs/full.md\n' > "$full_mode_paths"
full_mode_log="$TMP/full-mode-tools.log"
full_mode_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$full_mode_log" \
    PREFLIGHT_CHANGED_FILES="$full_mode_paths" CODEWIRE_PREFLIGHT_MODE=full \
    "$dispatcher"
} 2>&1)"
assert_contains full_mode "$full_mode_output" 'preflight full selection: |valid:v3|'
assert_contains full_mode_tools "$(cat "$full_mode_log")" 'integration database '
assert_contains full_mode_tools "$(cat "$full_mode_log")" 'kind'

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
  'preflight selection: |valid:v3|policy|sdk_python|complete|'
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
  'preflight selection: |valid:v3|policy|service_apikey_smoke|complete|'
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
  'preflight selection: |valid:v3|policy|runtime_confidential|complete|'
assert_contains confidential_tooling_tools "$(cat "$confidential_tooling_log")" \
  'product runtime-confidential '
assert_not_contains confidential_tooling_tools \
  "$(cat "$confidential_tooling_log")" 'product release '
assert_not_contains confidential_tooling_tools \
  "$(cat "$confidential_tooling_log")" 'integration '

dev_smoke_tooling_paths="$TMP/dev-smoke-tooling.paths"
printf '%s\n' \
  scripts/runtime/dev/smoke-dev-commodity.sh \
  scripts/runtime/tests/test-smoke-dev-commodity.sh \
  > "$dev_smoke_tooling_paths"
dev_smoke_tooling_log="$TMP/dev-smoke-tooling.log"
dev_smoke_tooling_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$dev_smoke_tooling_log" \
    PREFLIGHT_CHANGED_FILES="$dev_smoke_tooling_paths" \
    "$repo/.githooks/pre-push"
} 2>&1)"
assert_contains dev_smoke_tooling "$dev_smoke_tooling_output" \
  'preflight selection: |valid:v3|policy|runtime_dev_smoke|complete|'
assert_contains dev_smoke_tooling_tools "$(cat "$dev_smoke_tooling_log")" \
  'product runtime-dev-smoke '
assert_not_contains dev_smoke_tooling_tools \
  "$(cat "$dev_smoke_tooling_log")" 'integration '

sdk_tooling_paths="$TMP/sdk-tooling.paths"
printf '%s\n' \
  Makefile \
  libs/sdk-go/client.go \
  docs/plans/connect-rpc/13-rest-sunset-and-openapi-removal.md > "$sdk_tooling_paths"
sdk_tooling_log="$TMP/sdk-tooling-tools.log"
sdk_tooling_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$sdk_tooling_log" \
    PREFLIGHT_CHANGED_FILES="$sdk_tooling_paths" "$repo/.githooks/pre-push"
} 2>&1)"
assert_contains sdk_tooling "$sdk_tooling_output" \
  'preflight selection: |valid:v3|go_consumer_interop|go_support|policy|sdk_go|complete|'
assert_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'product sdk-go '
assert_not_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'integration '
assert_not_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'kind'

printf '[test-pre-push-worktree] shared selection, worktree, and fail-closed cases passed\n'
