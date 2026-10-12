#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/pre-push-worktree.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT
# The hook reads push refs from any non-terminal stdin. Cases that push refs
# pipe them in explicitly; every other invocation must see EOF, as in CI,
# instead of blocking forever on a caller's open pipe or socket.
exec </dev/null
# The environment precheck is stubbed in the orchestration fixtures and
# exercised for real below; give every fixture an executable TMPDIR.
ORIGINAL_TMPDIR="${TMPDIR:-/tmp}"
mkdir -p "$TMP/tmpdir"
export TMPDIR="$TMP/tmpdir"

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

assert_has_line() {
  local name="$1" output="$2" line="$3"
  grep -Fxq -- "$line" <<<"$output" || {
    printf '[test-pre-push-worktree] %s has no line: %s\n' "$name" "$line" >&2
    printf '%s\n' "$output" >&2
    exit 1
  }
}

assert_lacks_line() {
  local name="$1" output="$2" line="$3"
  if grep -Fxq -- "$line" <<<"$output"; then
    printf '[test-pre-push-worktree] %s unexpectedly has line: %s\n' "$name" "$line" >&2
    exit 1
  fi
}

# A Kind run shows in the tool log as a token: the `kind` tool, a `kind-*`
# command, `--kind-browser`, or `kind` inside a `|...|` selection. A path that
# merely contains the word, such as a worktree named ci-kind-images, is not one.
assert_no_kind() {
  local name="$1" output="$2"
  if grep -Eq -- '(^|[ |])(--)?kind([ |-]|$)' <<<"$output"; then
    printf '[test-pre-push-worktree] %s unexpectedly ran Kind\n' "$name" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}
for kind_line in 'kind' 'kind-test environment' 'integration database --kind-browser' \
    'product policy |valid:v3|kind|complete|'; do
  if (assert_no_kind self-test "$kind_line") >/dev/null 2>&1; then
    fail "assert_no_kind missed a Kind run: $kind_line"
  fi
done
for path_line in 'local-rust-cache /w/ci-kind-images/.tmp/linked-source' \
    'environment --rust /home/kind/src' 'product policy |valid:v3|policy|kindred|complete|'; do
  (assert_no_kind self-test "$path_line") >/dev/null 2>&1 ||
    fail "assert_no_kind matched a line that runs no Kind: $path_line"
done

assert_policy_only() {
  local name="$1" output="$2"
  assert_contains "$name" "$output" 'product policy '
  [ "$(grep -c '^product ' <<<"$output")" -eq 1 ] || \
    fail "$name did not execute exactly one product policy family"
  assert_not_contains "$name" "$output" 'integration '
  assert_no_kind "$name" "$output"
  assert_not_contains "$name" "$output" 'bun '
  assert_not_contains "$name" "$output" 'repo_checks '
  assert_not_contains "$name" "$output" 'native_desktop_ui'
}

# The fast push check runs no verification family.
assert_push_check_only() {
  local name="$1" output="$2"
  assert_contains "$name" "$output" 'environment'
  assert_not_contains "$name" "$output" 'product '
  assert_not_contains "$name" "$output" 'integration '
  assert_no_kind "$name" "$output"
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
    "$repo/scripts/ci/receipts" \
    "$repo/scripts/ci/select" \
    "$repo/scripts/ci/tests" \
    "$repo/scripts/ci/verify" \
    "$repo/scripts/dev"

  install -m 755 "$ROOT/.githooks/pre-push" "$repo/.githooks/pre-push"
  install -m 755 "$ROOT/scripts/dev/pre-push.sh" "$repo/scripts/dev/pre-push.sh"
  install -m 755 "$ROOT/scripts/dev/preflight.sh" "$repo/scripts/dev/preflight.sh"
  install -m 755 "$ROOT/scripts/dev/preflight-push.sh" "$repo/scripts/dev/preflight-push.sh"
  install -m 755 "$ROOT/scripts/ci/receipts/local-prepush-receipt.py" \
    "$repo/scripts/ci/receipts/local-prepush-receipt.py"
  install -m 755 "$ROOT/scripts/dev/install-hooks.sh" "$repo/scripts/dev/install-hooks.sh"
  install -m 755 "$ROOT/scripts/ci/select/select-verification.sh" \
    "$repo/scripts/ci/select/select-verification.sh"
  install -m 755 "$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh" \
    "$repo/scripts/ci/verify/resolve-cargo-target-dir.sh"
  install -m 755 "$ROOT/scripts/ci/verify/shellcheck-baseline.sh" \
    "$repo/scripts/ci/verify/shellcheck-baseline.sh"
  install -m 755 "$ROOT/scripts/ci/tests/test-dashboard-image-network-probe.sh" \
    "$repo/scripts/ci/tests/test-dashboard-image-network-probe.sh"
  install -m 755 "$ROOT/scripts/ci/verify/dashboard-image.sh" \
    "$repo/scripts/ci/verify/dashboard-image.sh"
  # As in the repository, .tmp/ holds ignored local state (merge passes, logs).
  printf '.tmp/\n' > "$repo/.gitignore"
  # One workspace crate for the push check's changed-crate cases.
  mkdir -p "$repo/crates/codewire-cli/src"
  printf '[workspace]\nmembers = [\n    "crates/codewire-cli",\n]\n' > "$repo/Cargo.toml"
  printf '[package]\nname = "codewire-cli"\nversion = "0.0.0"\n' > \
    "$repo/crates/codewire-cli/Cargo.toml"
  printf '// fixture crate\n' > "$repo/crates/codewire-cli/src/lib.rs"
  mkdir -p "$repo/scripts/ci/images"
  cat > "$repo/scripts/ci/images/workspace-image-pin.py" <<'EOF'
#!/usr/bin/env python3
import os
import sys
with open(os.environ["PREFLIGHT_TEST_TOOL_LOG"], "a", encoding="utf-8") as log:
    log.write("workspace-image-pin " + " ".join(sys.argv[1:4]) + "\n")
if os.environ.get("PREFLIGHT_TEST_PIN_STALE") == "1":
    print("workspace image pin: synthetic stale pin", file=sys.stderr)
    sys.exit(1)
EOF
cat > "$repo/scripts/ci/receipts/verify-release-tag-receipt.sh" <<'EOF'
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

  # The shared compiler cache has its own fixture; here it records selection.
  cat > "$repo/scripts/ci/verify/local-rust-cache.sh" <<'EOF'
select_local_rust_cache() {
  printf 'local-rust-cache %s\n' "$1" >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
  return 1
}
EOF
  # The real precheck is exercised separately; here it records its needs.
  cat > "$repo/scripts/dev/preflight-environment.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'environment %s\n' "$*" >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
if [ "${PREFLIGHT_TEST_ENV_FAIL:-0}" = 1 ]; then
  echo '[preflight-environment] FAILED: synthetic environment failure' >&2
  exit 1
fi
EOF
  cat > "$repo/scripts/ci/verify/run-product-verification.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# This is a terminal orchestration stub, never the real policy core: the core
# itself runs this fixture through test-select-verification.sh.
printf 'product %s %s\n' "$1" "${VERIFICATION_SELECTION:?}" \
  >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
if [ "$1" = policy ] && [ "${PREFLIGHT_TEST_POLICY_FAIL:-0}" = 1 ]; then
  echo 'synthetic shared policy failure' >&2
  exit 42
fi
if [ "$1" = rust ] && [ "${PREFLIGHT_TEST_RUST_FAIL:-0}" = 1 ]; then
  echo 'synthetic optional Rust feature failure' >&2
  exit 86
fi
if [ "$1" = release ]; then
  printf 'release-bytecode %s\n' "${PYTHONDONTWRITEBYTECODE:-unset}" >> "$PREFLIGHT_TEST_TOOL_LOG"
fi
if [ "$1" = rust-compile ] && [ "${PREFLIGHT_TEST_COMPILE_FAIL:-0}" = 1 ]; then
  echo 'synthetic compile failure' >&2
  exit 87
fi
if [ "$1" = policy ] && [ -n "${PREFLIGHT_TEST_POLICY_SLEEP:-}" ]; then
  # A long policy lane observes the compile gate's failure stopping it.
  printf 'policy-started\n' >> "$PREFLIGHT_TEST_TOOL_LOG"
  sleep "$PREFLIGHT_TEST_POLICY_SLEEP"
  printf 'policy-finished\n' >> "$PREFLIGHT_TEST_TOOL_LOG"
fi
if [ "$1" = policy ]; then
  scripts/ci/tests/test-rust-owned-fixtures.sh
  scripts/ci/tests/test-dashboard-image-network-probe.sh
fi
EOF
  cat > "$repo/scripts/ci/tests/test-rust-owned-fixtures.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'rust_owned_fixtures\n' >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
if [ "${PREFLIGHT_TEST_FIXTURE_DRIFT:-0}" = 1 ]; then
  echo 'fixture checksum mismatch' >&2
  exit 1
fi
EOF
  cat > "$repo/scripts/ci/verify/run-integration-verification.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'integration %s %s port=%s\n' "$1" "${VERIFICATION_SELECTION:?}" \
  "${VERIFICATION_PORT_BASE:-default}" >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
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
    "$repo/scripts/dev/preflight-environment.sh" \
    "$repo/scripts/ci/verify/run-product-verification.sh" \
    "$repo/scripts/ci/verify/run-integration-verification.sh" \
    "$repo/scripts/ci/verify/kind-e2e.sh" \
    "$repo/scripts/ci/receipts/verify-release-tag-receipt.sh" \
    "$repo/scripts/ci/tests/test-rust-owned-fixtures.sh" \
    "$repo/scripts/checks/repo_checks.py" \
    "$repo/scripts/checks/source/check-native-desktop-ui.py"

  cat > "$repo/.gitea/workflows/ci.yaml" <<'EOF'
name: fixture
EOF
  printf 'fixture\n' > "$repo/libs/tailnet/.preflight-fixture"
}

# Merge qualification, then the push: the hook accepts the merge receipt and
# reruns nothing.
push_branch() {
  local repo="$1" branch="$2" tool_log="$3" preflight_output push_output before after
  (
    cd "$repo"
    preflight_output="$(
      PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$tool_log" \
        scripts/dev/preflight.sh --for-merge --emit-receipt 2>&1
    )"
    before="$(wc -l < "$tool_log")"
    push_output="$(
      PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$tool_log" \
        git push -q origin "HEAD:refs/heads/$branch" 2>&1
    )"
    after="$(wc -l < "$tool_log")"
    [ "$before" = "$after" ] || fail 'actual push reran verification tools'
    printf '%s\n%s\n' "$preflight_output" "$push_output"
  )
}

# A push with no receipt: the hook runs the fast push check itself.
hook_push() {
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
if [ "$(basename "$0")" = cargo ] && [ "${1:-}" = "${PREFLIGHT_TEST_CARGO_FAIL:-}" ]; then
  echo "synthetic cargo $1 failure" >&2
  exit 9
fi
EOF
chmod +x "$TMP/bin/tool-stub"
ln -s tool-stub "$TMP/bin/bun"
ln -s tool-stub "$TMP/bin/cargo"
# The toolchain identity is part of the merge pass key.
cat > "$TMP/bin/rustc" <<'EOF'
#!/usr/bin/env bash
printf 'rustc 1.93.0 (fixture %s)\nhost: x86_64-unknown-linux-gnu\n' "${PREFLIGHT_TEST_RUSTC_ID:-a}"
EOF
chmod +x "$TMP/bin/rustc"

repo="$TMP/checkout"
remote="$TMP/remote.git"
git init -q -b main "$repo"
git -C "$repo" config gc.auto 0
git -C "$repo" config maintenance.auto false
git init -q --bare "$remote"
git -C "$remote" config gc.auto 0
git -C "$remote" config maintenance.auto false
git -C "$repo" config user.name 'Preflight Fixture'
git -C "$repo" config user.email preflight-fixture@codewire.invalid
# Tags created below are synthetic pre-push inputs. Do not inherit a
# workstation's automatic GPG-tag signing policy into this hermetic fixture.
git -C "$repo" config tag.gpgSign false
write_stub_tree "$repo"
printf 'base\n' > "$repo/docs/base.md"
commit_all "$repo" 'test: seed checkout fixture'
git -C "$repo" remote add origin "$remote"
git -C "$repo" push -q -u origin main

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
  'CODEWIRE_PREFLIGHT_MODE must be default, integration, kind, full, or ci'
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

# Old behaviour, kept for older worktrees: a worktree without its own
# scripts/dev/pre-push.sh still gets the legacy receipt-only dispatcher, which
# refuses a push without a receipt and runs nothing.
legacy="$TMP/legacy-worktree"
git -C "$repo" worktree add -q -b legacy-docs "$legacy" main
git -C "$legacy" rm -q scripts/dev/pre-push.sh
printf 'legacy docs\n' > "$legacy/docs/legacy.md"
commit_all "$legacy" 'docs: legacy worktree fixture'
legacy_log="$TMP/legacy-tools.log"
if legacy_output="$(hook_push "$legacy" legacy-docs "$legacy_log")"; then
  fail 'legacy dispatcher path accepted a push without a receipt'
fi
assert_contains legacy_missing "$legacy_output" \
  'pre-push: no valid receipt (missing). Run exactly: scripts/dev/preflight.sh --for-push --emit-receipt'
[ ! -s "$legacy_log" ] || fail 'legacy receipt check ran verification tools'
# Its instruction now runs the fast push check, which the legacy path accepts.
legacy_receipt_output="$(
  cd "$legacy"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$legacy_log" \
    scripts/dev/preflight.sh --for-push --emit-receipt 2>&1
)"
assert_contains legacy_push_receipt "$legacy_receipt_output" 'scope=push'
legacy_lines="$(wc -l < "$legacy_log")"
legacy_output="$(hook_push "$legacy" legacy-docs "$legacy_log")"
assert_contains legacy_accepted "$legacy_output" \
  'pre-push: exact-tree local receipt accepted'
[ "$legacy_lines" = "$(wc -l < "$legacy_log")" ] || fail 'legacy push reran tools'
assert_push_check_only legacy_tools "$(cat "$legacy_log")"

# New behaviour: a feature push with no receipt runs the fast push check in
# the hook and records a push receipt. Docs need only the environment check.
git -C "$repo" switch -q -c normal-docs main
printf 'normal docs\n' > "$repo/docs/normal.md"
commit_all "$repo" 'docs: normal checkout fixture'
normal_hook_log="$TMP/normal-hook-tools.log"
normal_hook_output="$(hook_push "$repo" normal-docs-push "$normal_hook_log")"
assert_contains normal_hook "$normal_hook_output" \
  'pre-push: no valid receipt (missing); running the fast push check'
assert_contains normal_hook "$normal_hook_output" '[push-check] passed: environment'
assert_contains normal_hook "$normal_hook_output" \
  'pre-push: exact-tree local push receipt accepted'
assert_contains normal_hook "$normal_hook_output" \
  'pre-push: not run locally: merge-qualification; post-merge CI owns it'
assert_push_check_only normal_hook_tools "$(cat "$normal_hook_log")"
# A retried push reuses that receipt and runs nothing.
normal_hook_lines="$(wc -l < "$normal_hook_log")"
hook_push "$repo" normal-docs-push "$normal_hook_log" >/dev/null
[ "$normal_hook_lines" = "$(wc -l < "$normal_hook_log")" ] ||
  fail 'a retried push reran the push check'

# A direct canonical-main update needs merge qualification; a push receipt
# never satisfies it.
if main_output="$({
  printf '%s\n' \
    "refs/heads/normal-docs $(git -C "$repo" rev-parse HEAD) refs/heads/main $(git -C "$repo" rev-parse origin/main)" |
    {
      cd "$repo"
      PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$normal_hook_log" \
        "$dispatcher" origin
    }
} 2>&1)"; then
  fail 'direct main update accepted a push-scope receipt'
fi
assert_contains main_push "$main_output" \
  'pre-push: no valid merge receipt (missing). Run exactly: scripts/dev/preflight.sh --for-merge --emit-receipt'

# The environment precheck runs before the first family; its failure stops
# merge qualification with no family run and no receipt.
environment_failure_log="$TMP/environment-failure-tools.log"
if environment_failure_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$environment_failure_log" \
    PREFLIGHT_TEST_ENV_FAIL=1 \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"; then
  fail 'merge qualification ignored a failed environment precheck'
fi
assert_contains environment_failure "$environment_failure_output" \
  'preflight: environment precheck FAILED'
assert_not_contains environment_failure_tools "$(cat "$environment_failure_log")" 'product '
assert_not_contains environment_failure "$environment_failure_output" 'receipt_path='

# Fail only the terminal shared-policy stub: a private local checklist cannot
# qualify this tree or emit a receipt without observing the policy failure.
policy_failure_log="$TMP/policy-failure-tools.log"
if policy_failure_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$policy_failure_log" \
    PREFLIGHT_TEST_POLICY_FAIL=1 \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"; then
  fail 'local preflight accepted a failing shared-policy entrypoint'
fi
assert_contains policy_failure "$policy_failure_output" \
  'synthetic shared policy failure'
assert_contains policy_failure "$policy_failure_output" \
  'preflight: policy verification FAILED'
assert_not_contains policy_failure "$policy_failure_output" 'receipt_path='
assert_policy_only policy_failure_tools "$(grep -v '^environment' "$policy_failure_log")"
assert_not_contains policy_failure_tools "$(cat "$policy_failure_log")" \
  'rust_owned_fixtures'
assert_not_contains policy_failure "$policy_failure_output" \
  'dashboard image network probe contract: OK'
if policy_failure_receipt_output="$({
  cd "$repo"
  scripts/ci/receipts/local-prepush-receipt.py verify --accept-scope merge
} 2>&1)"; then
  fail 'failed shared policy left a usable local receipt'
fi
assert_contains policy_failure_receipt "$policy_failure_receipt_output" 'missing'

# Preserve the accepted-byte guard regression from the credential cutover:
# fixture drift must still fail via the shared policy family, before a receipt.
drift_log="$TMP/fixture-drift-tools.log"
if drift_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$drift_log" \
    PREFLIGHT_TEST_FIXTURE_DRIFT=1 \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"; then
  fail 'local preflight accepted fixture checksum drift'
fi
assert_contains fixture_drift "$drift_output" 'fixture checksum mismatch'
assert_contains fixture_drift "$drift_output" \
  'preflight: policy verification FAILED'
assert_not_contains fixture_drift "$drift_output" 'receipt_path='
assert_policy_only fixture_drift_tools "$(grep -v '^environment' "$drift_log")"
assert_not_contains fixture_drift "$drift_output" \
  'dashboard image network probe contract: OK'
if drift_receipt_output="$({
  cd "$repo"
  scripts/ci/receipts/local-prepush-receipt.py verify --accept-scope merge
} 2>&1)"; then
  fail 'failed fixture guard left a usable local receipt'
fi
assert_contains fixture_drift_receipt "$drift_receipt_output" 'missing'

normal_log="$TMP/normal-tools.log"
normal_output="$(push_branch "$repo" normal-docs "$normal_log")"
assert_contains normal "$normal_output" '  docs/normal.md'
assert_contains normal "$normal_output" \
  'preflight selection: |valid:v3|policy|policy_shell_omittable|complete|'
assert_contains normal "$normal_output" 'preflight merge mode: default'
# Family output goes to its own log, not the merged console.
assert_not_contains normal "$normal_output" \
  'dashboard image network probe contract: OK'
assert_contains normal "$normal_output" \
  'pre-push: exact-tree local merge receipt accepted'
assert_contains normal_tools "$(cat "$normal_log")" 'rust_owned_fixtures'
assert_policy_only normal_tools "$(grep -v '^environment' "$normal_log")"
# Each family keeps its own log.
normal_family_log="$(sed -n 's/^preflight family logs: //p' <<<"$normal_output")"
assert_contains normal_family_log "$(cat "$normal_family_log/policy.log")" \
  'dashboard image network probe contract: OK'
# The same exact tree reuses its passes and still records an honest receipt.
normal_rerun="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$normal_log" \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"
assert_contains normal_rerun "$normal_rerun" \
  '==> policy verification: reused the exact-tree pass'
assert_contains normal_rerun "$normal_rerun" '(ran: none; reused: policy)'
[ "$(grep -c '^product policy ' "$normal_log")" -eq 1 ] ||
  fail 'an exact-tree rerun repeated a passed family'
grep -Fxq 'reused=policy' <<<"$(
  cd "$repo" && scripts/ci/receipts/local-prepush-receipt.py verify --accept-scope merge
)" || fail 'the rerun receipt does not record its reuse'
# A different toolchain never matches.
normal_toolchain="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$normal_log" PREFLIGHT_TEST_RUSTC_ID=b \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"
assert_not_contains normal_toolchain "$normal_toolchain" 'reused the exact-tree pass'
[ "$(grep -c '^product policy ' "$normal_log")" -eq 2 ] ||
  fail 'another toolchain reused a pass'
# A tampered pass is not evidence.
for marker in "$repo"/.tmp/preflight/passed/*; do
  printf 'tampered\n' >> "$marker"
done
normal_tampered="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$normal_log" \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"
assert_not_contains normal_tampered "$normal_tampered" 'reused the exact-tree pass'
[ "$(grep -c '^product policy ' "$normal_log")" -eq 3 ] ||
  fail 'a tampered pass was reused'
# A canonical base that moved without changing this tree's change set keeps
# the same selection, so the passes still apply; only contracts, which reads
# the base, would run again (proved below).
same_tree_base="$(
  printf 'test: same tree, newer base\n' |
    git -C "$repo" commit-tree "$(git -C "$repo" rev-parse 'origin/main^{tree}')" \
      -p "$(git -C "$repo" rev-parse origin/main)"
)"
original_base="$(git -C "$repo" rev-parse origin/main)"
git -C "$repo" update-ref refs/remotes/origin/main "$same_tree_base"
normal_base="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$normal_log" \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"
git -C "$repo" update-ref refs/remotes/origin/main "$original_base"
assert_contains normal_base "$normal_base" '==> policy verification: reused the exact-tree pass'
git -C "$repo" switch -q main

git -C "$repo" switch -q -c ci-owned main
printf 'CI-owned verification\n' > "$repo/docs/ci-owned.md"
commit_all "$repo" 'docs: CI-owned verification fixture'
ci_owned_head="$(git -C "$repo" rev-parse HEAD)"
ci_owned_base="$(git -C "$repo" rev-parse refs/remotes/origin/main)"
ci_owned_log="$TMP/ci-owned-tools.log"
ci_owned_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$ci_owned_log" \
    CODEWIRE_PREFLIGHT_MODE=ci \
    git push -q origin HEAD:refs/heads/ci-owned
} 2>&1)"
assert_contains ci_owned "$ci_owned_output" \
  "pre-push: deferring exact-tree verification to required Forgejo CI head=$ci_owned_head base=$ci_owned_base"
[ ! -s "$ci_owned_log" ] || fail 'CI-owned feature push ran local verification tools'

if ci_main_output="$({
  printf '%s\n' \
    "refs/heads/ci-owned $ci_owned_head refs/heads/main $ci_owned_base" |
    {
      cd "$repo"
      PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$ci_owned_log" \
        CODEWIRE_PREFLIGHT_MODE=ci "$dispatcher" origin
    }
} 2>&1)"; then
  fail 'CI-owned verification accepted a main-branch update'
fi
assert_contains ci_main "$ci_main_output" \
  'CI-owned verification is limited to one non-main feature-branch update'

if ci_delete_output="$({
  printf '%s\n' \
    "(delete) $zero_sha refs/heads/ci-owned $ci_owned_head" |
    {
      cd "$repo"
      PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$ci_owned_log" \
        CODEWIRE_PREFLIGHT_MODE=ci "$dispatcher" origin
    }
} 2>&1)"; then
  fail 'CI-owned verification accepted a ref deletion'
fi
assert_contains ci_delete "$ci_delete_output" \
  'CI-owned verification does not authorize ref deletion'
git -C "$repo" switch -q main

git -C "$repo" switch -q -c rejected-transport main
printf 'rejected transport\n' > "$repo/docs/rejected-transport.md"
commit_all "$repo" 'test: rejected transport receipt fixture'
rejected_log="$TMP/rejected-transport-tools.log"
rejected_preflight="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$rejected_log" \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"
rejected_receipt="$(sed -n 's/^receipt_path=//p' <<<"$rejected_preflight")"
[ -f "$rejected_receipt" ] || fail 'rejected-transport receipt was not emitted'
cat > "$remote/hooks/pre-receive" <<'EOF'
#!/usr/bin/env bash
printf 'fixture rejects transport after local receipt validation\n' >&2
exit 1
EOF
chmod 0755 "$remote/hooks/pre-receive"
rejected_lines="$(wc -l < "$rejected_log")"
if rejected_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$rejected_log" \
    git push -q origin HEAD:refs/heads/rejected-transport
} 2>&1)"; then
  fail 'fixture remote unexpectedly accepted rejected transport'
fi
assert_contains rejected_transport "$rejected_output" \
  'pre-push: exact-tree local merge receipt accepted'
assert_contains rejected_transport "$rejected_output" \
  'fixture rejects transport after local receipt validation'
[ "$rejected_lines" = "$(wc -l < "$rejected_log")" ] || \
  fail 'rejected transport reran verification tools'
[ -f "$rejected_receipt" ] || fail 'rejected transport deleted a valid receipt'
rm "$remote/hooks/pre-receive"
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
assert_contains release_tag_tools "$(cat "$tag_log")" \
  'workspace-image-pin check --release --commit'

# A stale workspace image pin refuses the release before any receipt or gate.
stale_pin_log="$TMP/stale-pin-tools.log"
if stale_pin_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" \
    PREFLIGHT_TEST_TOOL_LOG="$stale_pin_log" \
    PREFLIGHT_TEST_PIN_STALE=1 \
    PREFLIGHT_RELEASE_TAG_REF=refs/tags/v1.2.3 \
    PREFLIGHT_RELEASE_TAG_OBJECT_SHA="$(git rev-parse refs/tags/v1.2.3)" \
    PREFLIGHT_PUSH_REMOTE_NAME=origin \
    PREFLIGHT_HEAD_SHA="$(git rev-parse refs/tags/v1.2.3)" \
    "$repo/scripts/dev/preflight.sh"
} 2>&1)"; then
  fail 'release preflight accepted a stale workspace image pin'
fi
assert_contains stale_pin "$stale_pin_output" \
  'release commit pins a stale workspace image; land the proposed pin before tagging'
assert_not_contains stale_pin_tools "$(cat "$stale_pin_log")" 'receipt-ref='
assert_not_contains release_tag_tools "$(cat "$tag_log")" 'integration '
assert_no_kind release_tag_tools "$(cat "$tag_log")"

# A release without the CI receipt keeps the complete fail-closed gate,
# including Kind, run in place.
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
assert_contains failed_receipt_tools "$(cat "$failed_receipt_log")" '--kind-browser'
assert_has_line failed_receipt_tools "$(cat "$failed_receipt_log")" kind

linked_docs="$TMP/linked-docs"
git -C "$repo" worktree add -q -b linked-docs "$linked_docs" main
printf 'linked docs\n' > "$linked_docs/docs/linked.md"
commit_all "$linked_docs" 'docs: linked worktree fixture'
linked_docs_log="$TMP/linked-docs-tools.log"
linked_docs_output="$(push_branch "$linked_docs" linked-docs "$linked_docs_log")"
assert_contains linked_docs "$linked_docs_output" '  docs/linked.md'
assert_contains linked_docs "$linked_docs_output" \
  'preflight selection: |valid:v3|policy|policy_shell_omittable|complete|'
assert_policy_only linked_docs_tools "$(grep -v '^environment' "$linked_docs_log")"

linked_source="$TMP/linked-source"
git -C "$repo" worktree add -q -b linked-source "$linked_source" main
printf 'pub fn linked_fixture() {}\n' > \
  "$linked_source/crates/codewire-cli/src/worktree_fixture.rs"
commit_all "$linked_source" 'test: linked Rust source fixture'

# The fast push check for one changed crate: formatting, clippy and unit
# tests for that crate only, and no verification family.
source_push_log="$TMP/source-push-tools.log"
source_push_output="$(hook_push "$linked_source" linked-source-push "$source_push_log")"
assert_contains source_push "$source_push_output" \
  '[push-check] passed: environment,rust-fmt,rust-clippy,rust-unit-tests-lib'
assert_push_check_only source_push_tools "$(cat "$source_push_log")"
assert_contains source_push_tools "$(cat "$source_push_log")" 'environment --rust'
assert_contains source_push_tools "$(cat "$source_push_log")" 'local-rust-cache '
assert_contains source_push_tools "$(cat "$source_push_log")" 'cargo fmt --all --check'
assert_contains source_push_tools "$(cat "$source_push_log")" \
  'cargo clippy --locked -p codewire-cli --all-targets -- -D warnings'
assert_contains source_push_tools "$(cat "$source_push_log")" \
  'cargo test --locked -p codewire-cli --lib'
# A failing push check refuses the push and leaves no receipt.
git -C "$linked_source" commit -q --allow-empty -m 'test: push check failure fixture'
source_push_failure_log="$TMP/source-push-failure-tools.log"
if source_push_failure="$(
  cd "$linked_source"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$source_push_failure_log" \
    PREFLIGHT_TEST_CARGO_FAIL=clippy git push -q origin HEAD:refs/heads/linked-source-push 2>&1
)"; then
  fail 'a failing push check accepted the push'
fi
assert_contains source_push_failure "$source_push_failure" 'synthetic cargo clippy failure'
assert_contains source_push_failure "$source_push_failure" \
  'preflight: push check rust-clippy FAILED'
assert_contains source_push_failure "$source_push_failure" \
  'pre-push: push check failed; fix it and push again'
assert_not_contains source_push_failure_tools "$(cat "$source_push_failure_log")" 'cargo test'
# The hook runs the check only for the commit checked out in this worktree.
if detached_push="$(
  cd "$linked_source"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$source_push_failure_log" \
    git push -q origin main:refs/heads/linked-source-main 2>&1
)"; then
  fail 'the hook qualified a commit that is not checked out'
fi
assert_contains detached_push "$detached_push" \
  'the pushed commit is not checked out here. Run exactly: scripts/dev/preflight.sh --for-push --emit-receipt'
git -C "$linked_source" reset -q --hard HEAD~1

# Compile errors fail first: the compile gate stops the slower policy lane
# beside it, and no other lane starts.
compile_failure_log="$TMP/compile-failure-tools.log"
if compile_failure_output="$({
  cd "$linked_source"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$compile_failure_log" \
    PREFLIGHT_TEST_COMPILE_FAIL=1 PREFLIGHT_TEST_POLICY_SLEEP=30 \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"; then
  fail 'merge qualification accepted a compile failure'
fi
assert_contains compile_failure "$compile_failure_output" 'synthetic compile failure'
assert_contains compile_failure "$compile_failure_output" \
  'preflight: every Rust target compiles FAILED'
assert_contains compile_failure "$compile_failure_output" \
  'preflight: lane compile failed; stopping the other lanes'
assert_contains compile_failure_tools "$(cat "$compile_failure_log")" 'policy-started'
assert_not_contains compile_failure_tools "$(cat "$compile_failure_log")" 'policy-finished'
assert_not_contains compile_failure_tools "$(cat "$compile_failure_log")" 'product rust '
assert_not_contains compile_failure "$compile_failure_output" 'receipt_path='

source_failure_log="$TMP/source-policy-failure-tools.log"
if source_failure_output="$({
  cd "$linked_source"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$source_failure_log" \
    PREFLIGHT_TEST_POLICY_FAIL=1 \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"; then
  fail 'Rust-selected preflight accepted a failing shared-policy entrypoint'
fi
assert_contains source_policy_failure "$source_failure_output" \
  '|policy|policy_shell_omittable|rust|rust_pkg_codewire_cli|complete|'
assert_contains source_policy_failure "$source_failure_output" \
  'synthetic shared policy failure'
assert_contains source_policy_failure "$source_failure_output" \
  'preflight: policy verification FAILED'
assert_contains source_policy_failure_tools "$(cat "$source_failure_log")" 'product policy '
assert_not_contains source_policy_failure "$source_failure_output" 'receipt_path='
if source_failure_receipt_output="$({
  cd "$linked_source"
  scripts/ci/receipts/local-prepush-receipt.py verify --accept-scope merge
} 2>&1)"; then
  fail 'failed Rust-selected policy left a usable local receipt'
fi
assert_contains source_policy_failure_receipt \
  "$source_failure_receipt_output" 'missing'
# An optional-feature failure propagated by the shared Rust runner must also
# stop qualification before receipt emission, after successful policy checks.
rust_failure_log="$TMP/source-rust-failure-tools.log"
if rust_failure_output="$({
  cd "$linked_source"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$rust_failure_log" \
    PREFLIGHT_TEST_RUST_FAIL=1 \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"; then
  fail 'Rust-selected preflight accepted a failing optional feature'
fi
assert_contains rust_failure "$rust_failure_output" 'synthetic optional Rust feature failure'
assert_contains rust_failure "$rust_failure_output" 'preflight: Rust verification FAILED'
assert_contains rust_failure_tools "$(cat "$rust_failure_log")" 'product rust '
assert_not_contains rust_failure "$rust_failure_output" 'receipt_path='
if rust_failure_receipt_output="$({
  cd "$linked_source"
  scripts/ci/receipts/local-prepush-receipt.py verify --accept-scope merge
} 2>&1)"; then
  fail 'failed optional Rust feature left a usable local receipt'
fi
assert_contains rust_failure_receipt "$rust_failure_receipt_output" 'missing'
# After the fix, the rerun of the same tree reuses what passed (the compile
# gate always finished before the Rust lane started; the policy lane may have
# been stopped by the failure) and repeats the failed family.
source_log="$TMP/source-tools.log"
source_output="$(push_branch "$linked_source" linked-source "$source_log")"
assert_contains linked_source "$source_output" \
  '  crates/codewire-cli/src/worktree_fixture.rs'
assert_contains linked_source "$source_output" \
  'preflight selection: |valid:v3|policy|policy_shell_omittable|rust|rust_pkg_codewire_cli|complete|'
assert_contains linked_source "$source_output" \
  '==> every Rust target compiles: reused the exact-tree pass'
assert_contains linked_source "$source_output" '==> Rust verification: passed'
assert_contains source_tools "$(cat "$source_log")" 'product rust '
assert_not_contains source_tools "$(cat "$source_log")" 'product rust-compile '
assert_not_contains source_tools "$(cat "$source_log")" 'product go-support '
assert_contains source_tools "$(cat "$source_log")" 'environment --rust'

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
  'preflight selection: |valid:v3|policy|policy_shell|policy_shell_omittable|runtime_dev_smoke|rust_curated_locks|security|security_js|complete|'
assert_contains workflow_tools "$(cat "$workflow_log")" \
  'product rust-curated-locks '
assert_contains workflow_tools "$(cat "$workflow_log")" \
  'product security '
assert_contains workflow_tools "$(cat "$workflow_log")" \
  'product runtime-dev-smoke '
assert_not_contains workflow_tools "$(cat "$workflow_log")" 'integration '
# Timing-bound JavaScript tests run alone, before policy and the compile gate.
workflow_order="$(grep -E '^product (runtime-dev-smoke|policy|rust-compile) ' "$workflow_log" | cut -d' ' -f2 | tr '\n' ' ')"
[ "$workflow_order" = 'runtime-dev-smoke policy rust-compile ' ] \
  || [ "$workflow_order" = 'runtime-dev-smoke rust-compile policy ' ] \
  || fail "the JavaScript lane overlapped policy or compile: $workflow_order"

linked_database="$TMP/linked-database"
git -C "$repo" worktree add -q -b linked-database "$linked_database" main
mkdir -p "$linked_database/crates/codewire-server-core/tests"
printf 'database fixture\n' > \
  "$linked_database/crates/codewire-server-core/tests/org_deletion_lifecycle.rs"
commit_all "$linked_database" 'test: linked database fixture'
database_log="$TMP/database-tools.log"
if database_output="$({
  cd "$linked_database"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$database_log" \
    scripts/dev/preflight.sh --default
} 2>&1)"; then
  fail 'default preflight accepted a change requiring integration mode'
fi
assert_contains linked_database "$database_output" \
  'preflight required local mode: integration'
assert_contains linked_database "$database_output" \
  'retry with scripts/dev/preflight.sh --integration'
[ ! -s "$database_log" ] || \
  fail 'incomplete default mode ran checks before requesting escalation'
database_output="$(push_branch \
  "$linked_database" linked-database "$database_log")"
assert_contains linked_database_retry "$database_output" \
  'preflight required local mode: integration'
assert_contains linked_database_retry "$database_output" \
  'preflight merge mode: integration'
# Integration lanes run beside the others on their own port range.
assert_contains database_tools "$(cat "$database_log")" 'integration database '
assert_contains database_tools "$(cat "$database_log")" 'port=62000'
assert_no_kind database_tools "$(cat "$database_log")"

# Contracts compare protos with the canonical base, so a moved base reruns
# contracts while the families that never read it are reused.
linked_proto="$TMP/linked-proto"
git -C "$repo" worktree add -q -b linked-proto "$linked_proto" main
mkdir -p "$linked_proto/proto/codewire/fixture/v1"
printf 'syntax = "proto3";\n' > "$linked_proto/proto/codewire/fixture/v1/fixture.proto"
commit_all "$linked_proto" 'test: linked proto fixture'
proto_log="$TMP/proto-tools.log"
proto_output="$(push_branch "$linked_proto" linked-proto "$proto_log")"
assert_contains linked_proto "$proto_output" '==> contract verification: passed'
proto_base="$(
  printf 'test: same tree, newer base\n' |
    git -C "$repo" commit-tree "$(git -C "$repo" rev-parse 'origin/main^{tree}')" \
      -p "$(git -C "$repo" rev-parse origin/main)"
)"
proto_original_base="$(git -C "$repo" rev-parse origin/main)"
git -C "$repo" update-ref refs/remotes/origin/main "$proto_base"
proto_rerun="$({
  cd "$linked_proto"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$proto_log" \
    scripts/dev/preflight.sh --for-merge --emit-receipt
} 2>&1)"
git -C "$repo" update-ref refs/remotes/origin/main "$proto_original_base"
assert_contains linked_proto_base "$proto_rerun" '==> contract verification: started'
assert_contains linked_proto_base "$proto_rerun" '==> policy verification: reused the exact-tree pass'
[ "$(grep -c '^product contracts ' "$proto_log")" -eq 2 ] ||
  fail 'a moved base reused the contracts pass'

# A Kind-relevant change: merge qualification never runs Kind and its
# receipt says so.
linked_kind="$TMP/linked-kind"
git -C "$repo" worktree add -q -b linked-kind "$linked_kind" main
printf 'fixture\n' > "$linked_kind/Caddyfile"
commit_all "$linked_kind" 'test: linked Kind-relevant fixture'
kind_log="$TMP/kind-tools.log"
kind_output="$(push_branch "$linked_kind" linked-kind "$kind_log")"
assert_contains linked_kind "$kind_output" 'preflight required local mode: kind'
assert_contains linked_kind "$kind_output" \
  'preflight: not run locally: kind (post-merge CI owns it; run make kind-test for platform or dashboard behaviour)'
assert_contains linked_kind "$kind_output" \
  'pre-push: not run locally: kind; post-merge CI owns it'
assert_lacks_line kind_tools "$(cat "$kind_log")" kind
assert_not_contains kind_tools "$(cat "$kind_log")" 'kind-browser'
grep -Fxq 'not_run=kind' <<<"$(
  cd "$linked_kind" && scripts/ci/receipts/local-prepush-receipt.py verify --accept-scope merge
)" || fail 'merge receipt omits that Kind did not run'

# A clean standalone push check emits the receipt; direct hook invocation
# then validates it without rerunning tools.
empty_log="$TMP/empty-tools.log"
empty_preflight="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$empty_log" \
    "$repo/scripts/dev/preflight.sh" --for-push --emit-receipt
} 2>&1)"
assert_contains empty "$empty_preflight" '  (no changed paths)'
assert_contains empty "$empty_preflight" 'preflight classification: unchanged'
assert_contains empty "$empty_preflight" \
  'preflight selection: |valid:v3|policy|policy_shell_omittable|complete|'
empty_lines="$(wc -l < "$empty_log")"
empty_output="$({ cd "$repo" && "$dispatcher"; } 2>&1)"
assert_contains empty_hook "$empty_output" \
  'pre-push: exact-tree local push receipt accepted for HEAD'
[ "$empty_lines" = "$(wc -l < "$empty_log")" ] || \
  fail 'receipt-only hook invocation reran tools'
assert_not_contains empty "$empty_preflight" 'diagnostic_'
assert_push_check_only empty_tools "$(cat "$empty_log")"

# A repository without a canonical baseline fails with an explanation and
# does not claim that a synthetic path was successfully classified.
unknown_repo="$TMP/unknown-checkout"
git init -q -b feature "$unknown_repo"
git -C "$unknown_repo" config gc.auto 0
git -C "$unknown_repo" config maintenance.auto false
git -C "$unknown_repo" config user.name 'Preflight Fixture'
git -C "$unknown_repo" config user.email preflight-fixture@codewire.invalid
write_stub_tree "$unknown_repo"
printf 'unknown\n' > "$unknown_repo/docs/unknown.md"
commit_all "$unknown_repo" 'test: unknown-base fixture'
unknown_log="$TMP/unknown-tools.log"
for scope in push merge; do
  if unknown_output="$({
    cd "$unknown_repo"
    PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$unknown_log" \
      "$unknown_repo/scripts/dev/preflight.sh" "--for-$scope" --emit-receipt
  } 2>&1)"; then
    fail "preflight --for-$scope accepted a repository without a canonical baseline"
  fi
  assert_contains unknown "$unknown_output" \
    'preflight: canonical baseline is unavailable FAILED'
done
[ ! -s "$unknown_log" ] || fail 'missing baseline ran verification tools'

diagnostic_paths="$TMP/diagnostic.paths"
printf 'docs/diagnostic.md\n' > "$diagnostic_paths"
diagnostic_log="$TMP/diagnostic-tools.log"
diagnostic_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$diagnostic_log" \
    PREFLIGHT_CHANGED_FILES="$diagnostic_paths" "$repo/scripts/dev/preflight.sh"
} 2>&1)"
assert_contains diagnostic "$diagnostic_output" '  docs/diagnostic.md'
assert_contains diagnostic "$diagnostic_output" \
  'preflight selection: |valid:v3|policy|policy_shell_omittable|complete|'
assert_policy_only diagnostic_tools "$(grep -v '^environment' "$diagnostic_log")"
for scope in push merge; do
  if diagnostic_scope_output="$({
    cd "$repo"
    PREFLIGHT_CHANGED_FILES="$diagnostic_paths" \
      "$repo/scripts/dev/preflight.sh" "--for-$scope" --emit-receipt
  } 2>&1)"; then
    fail "--for-$scope accepted a diagnostic changed-path list"
  fi
  assert_contains diagnostic_scope "$diagnostic_scope_output" \
    "preflight: --for-$scope rejects diagnostic input PREFLIGHT_CHANGED_FILES"
done

kind_mode_paths="$TMP/kind-mode.paths"
printf 'Caddyfile\n' > "$kind_mode_paths"
kind_mode_log="$TMP/kind-mode-tools.log"
kind_mode_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$kind_mode_log" \
    PREFLIGHT_CHANGED_FILES="$kind_mode_paths" CODEWIRE_PREFLIGHT_MODE=kind \
    "$repo/scripts/dev/preflight.sh"
} 2>&1)"
assert_contains kind_mode "$kind_mode_output" \
  'preflight required local mode: kind'
assert_contains kind_mode_tools "$(cat "$kind_mode_log")" 'product edge '
assert_has_line kind_mode_tools "$(cat "$kind_mode_log")" kind

full_mode_paths="$TMP/full-mode.paths"
printf 'docs/full.md\n' > "$full_mode_paths"
full_mode_log="$TMP/full-mode-tools.log"
full_mode_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$full_mode_log" \
    PREFLIGHT_CHANGED_FILES="$full_mode_paths" CODEWIRE_PREFLIGHT_MODE=full \
    "$repo/scripts/dev/preflight.sh"
} 2>&1)"
assert_contains full_mode "$full_mode_output" 'preflight full selection: |valid:v3|'
assert_contains full_mode_tools "$(cat "$full_mode_log")" 'integration database '
assert_has_line full_mode_tools "$(cat "$full_mode_log")" kind

sdk_runner_paths="$TMP/sdk-runner.paths"
printf '%s\n' \
  scripts/runtime/dev/run-sdk-python-e2e.sh \
  scripts/runtime/tests/test-run-sdk-python-e2e.sh > "$sdk_runner_paths"
sdk_runner_log="$TMP/sdk-runner-tools.log"
sdk_runner_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$sdk_runner_log" \
    PREFLIGHT_CHANGED_FILES="$sdk_runner_paths" "$repo/scripts/dev/preflight.sh"
} 2>&1)"
assert_contains sdk_runner "$sdk_runner_output" \
  'preflight selection: |valid:v3|policy|policy_shell|policy_shell_omittable|sdk_python|security|security_js|complete|'
assert_contains sdk_runner_tools "$(cat "$sdk_runner_log")" 'product sdk-python '
assert_not_contains sdk_runner_tools "$(cat "$sdk_runner_log")" 'integration '
assert_no_kind sdk_runner_tools "$(cat "$sdk_runner_log")"

apikey_tooling_paths="$TMP/apikey-tooling.paths"
printf '%s\n' scripts/runtime/tests/test-apikey-smoke.sh > "$apikey_tooling_paths"
apikey_tooling_log="$TMP/apikey-tooling.log"
apikey_tooling_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$apikey_tooling_log" \
    PREFLIGHT_CHANGED_FILES="$apikey_tooling_paths" "$repo/scripts/dev/preflight.sh"
} 2>&1)"
assert_contains apikey_tooling "$apikey_tooling_output" \
  'preflight selection: |valid:v3|policy|policy_shell|policy_shell_omittable|security|security_js|service_apikey_smoke|complete|'
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
    PREFLIGHT_CHANGED_FILES="$confidential_tooling_paths" "$repo/scripts/dev/preflight.sh"
} 2>&1)"
assert_contains confidential_tooling "$confidential_tooling_output" \
  'preflight selection: |valid:v3|policy|policy_shell|policy_shell_omittable|runtime_confidential|security|security_js|complete|'
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
    "$repo/scripts/dev/preflight.sh"
} 2>&1)"
assert_contains dev_smoke_tooling "$dev_smoke_tooling_output" \
  'preflight selection: |valid:v3|policy|policy_shell|policy_shell_omittable|runtime_dev_smoke|security|security_js|complete|'
assert_contains dev_smoke_tooling_tools "$(cat "$dev_smoke_tooling_log")" \
  'product runtime-dev-smoke '
assert_not_contains dev_smoke_tooling_tools \
  "$(cat "$dev_smoke_tooling_log")" 'integration '

# Release provenance runs with the environment of its CI step.
release_paths="$TMP/release.paths"
printf '%s\n' scripts/ci/images/build-push-image.sh > "$release_paths"
release_log="$TMP/release-tools.log"
release_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$release_log" \
    PREFLIGHT_CHANGED_FILES="$release_paths" "$repo/scripts/dev/preflight.sh"
} 2>&1)" || { printf '%s\n' "$release_output" >&2; fail 'release preflight failed'; }
assert_has_line release_tools "$(cat "$release_log")" 'release-bytecode 1'

sdk_tooling_paths="$TMP/sdk-tooling.paths"
printf '%s\n' \
  Makefile \
  libs/sdk-go/client.go \
  docs/plans/connect-rpc/13-rest-sunset-and-openapi-removal.md > "$sdk_tooling_paths"
sdk_tooling_log="$TMP/sdk-tooling-tools.log"
sdk_tooling_output="$({
  cd "$repo"
  PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$sdk_tooling_log" \
    PREFLIGHT_CHANGED_FILES="$sdk_tooling_paths" "$repo/scripts/dev/preflight.sh"
} 2>&1)"
assert_contains sdk_tooling "$sdk_tooling_output" \
  'preflight selection: |valid:v3|go_consumer_interop|go_support|policy|policy_shell_omittable|sdk_go|security|security_js|complete|'
assert_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'product sdk-go '
assert_not_contains sdk_tooling_tools "$(cat "$sdk_tooling_log")" 'integration '
assert_no_kind sdk_tooling_tools "$(cat "$sdk_tooling_log")"

printf '[test-pre-push-worktree] hook, push check, merge lanes and fail-closed cases passed\n'

# ---------------------------------------------------------------------------
# The real environment precheck, in a copy with synthetic tools. Each case is
# a workstation failure that previously surfaced only inside a late family.
environment_tree="$TMP/environment"
mkdir -p "$environment_tree/scripts/dev" "$environment_tree/scripts/ci/verify" \
  "$environment_tree/bin"
install -m 755 "$ROOT/scripts/dev/preflight-environment.sh" \
  "$environment_tree/scripts/dev/preflight-environment.sh"
install -m 644 "$ROOT/scripts/ci/verify/playwright-browser-runtime.sh" \
  "$environment_tree/scripts/ci/verify/playwright-browser-runtime.sh"
install -m 755 "$ROOT/scripts/ci/verify/check-darwin-cross.sh" \
  "$environment_tree/scripts/ci/verify/check-darwin-cross.sh"
install -m 755 "$ROOT/scripts/ci/install-pinned-playwright-chromium.sh" \
  "$environment_tree/scripts/ci/install-pinned-playwright-chromium.sh"
install -m 644 "$ROOT/rust-toolchain.toml" "$environment_tree/rust-toolchain.toml"
pinned_rust="$(sed -nE 's/^channel = "([^"]+)"/\1/p' "$ROOT/rust-toolchain.toml")"
pinned_chromium="$(sed -n "s/^readonly chromium_version='\([^']*\)'/\1/p" \
  "$ROOT/scripts/ci/install-pinned-playwright-chromium.sh")"
cat > "$environment_tree/bin/rustc" <<'EOF'
#!/usr/bin/env bash
printf 'rustc %s (fixture)\n' "${FIXTURE_RUST_VERSION:?}"
EOF
cat > "$environment_tree/bin/cargo" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  --version) printf 'cargo %s (fixture)\n' "${FIXTURE_RUST_VERSION:?}" ;;
  fmt|clippy) [ "${FIXTURE_NO_COMPONENTS:-0}" != 1 ] ;;
esac
EOF
cat > "$environment_tree/bin/cargo-zigbuild" <<'EOF'
#!/usr/bin/env bash
printf 'cargo-zigbuild %s\n' "${FIXTURE_ZIGBUILD_VERSION:?}"
EOF
cat > "$environment_tree/bin/zig" <<'EOF'
#!/usr/bin/env bash
printf '0.15.2\n'
EOF
cat > "$environment_tree/bin/chromium-fixture" <<'EOF'
#!/usr/bin/env bash
printf 'Chromium %s\n' "${FIXTURE_CHROMIUM_VERSION:?}"
EOF
chmod +x "$environment_tree"/bin/*
# A passing environment needs a short executable TMPDIR outside /tmp and
# /run; this fixture's own directory is usually too long.
environment_ok_tmp=""
for short_root in /var/tmp "${HOME:-}/.cache" "$ORIGINAL_TMPDIR"; do
  [ -n "$short_root" ] && [ -d "$short_root" ] && [ -w "$short_root" ] || continue
  candidate="$(mktemp -d "$short_root/pe.XXXXXX" 2>/dev/null)" || continue
  case "$(cd "$candidate" && pwd -P)/" in
    /tmp/*|/run/*|*/.claude/*) rm -rf -- "$candidate"; continue ;;
  esac
  if [ "${#candidate}" -le 34 ] && printf '#!/bin/sh\nexit 0\n' >"$candidate/x" \
      && chmod 0700 "$candidate/x" && "$candidate/x"; then
    rm -f -- "$candidate/x"
    environment_ok_tmp="$candidate"
    break
  fi
  rm -rf -- "$candidate"
done
cleanup_environment_tmp() {
  [ -z "$environment_ok_tmp" ] || rm -rf -- "$environment_ok_tmp"
}
trap 'cleanup_environment_tmp; chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

run_environment() {
  env -u RUSTUP_TOOLCHAIN -u PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH \
    -u CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV \
    PATH="$environment_tree/bin:$PATH" TMPDIR="$environment_ok_tmp" \
    FIXTURE_RUST_VERSION="$pinned_rust" FIXTURE_ZIGBUILD_VERSION=0.23.0 \
    FIXTURE_CHROMIUM_VERSION="$pinned_chromium" \
    "$@"
}

assert_environment_fails() {
  local name="$1" expected="$2" output
  shift 2
  if output="$(run_environment "$@" 2>&1)"; then
    fail "environment precheck accepted: $name"
  fi
  assert_contains "environment_$name" "$output" "$expected"
  assert_contains "environment_$name" "$output" 'no family ran'
}

precheck="$environment_tree/scripts/dev/preflight-environment.sh"
if [ -n "$environment_ok_tmp" ]; then
  ok_output="$(run_environment "$precheck" --rust --darwin-cross --node-modules --proto-venv \
    2>&1)" || { printf '%s\n' "$ok_output" >&2; fail 'environment precheck rejected a good environment'; }
  assert_contains environment_ok "$ok_output" "rustc and cargo ${pinned_rust}"
  assert_contains environment_ok "$ok_output" '[preflight-environment] OK'
else
  printf '[test-pre-push-worktree] note: no short executable TMPDIR here; passing-environment cases skipped\n'
  environment_ok_tmp="$TMP/env-long"
  mkdir -p "$environment_ok_tmp"
fi
long_tmp="$TMP/a-temporary-directory-name-longer-than-the-socket-budget"
mkdir -p "$long_tmp"
assert_environment_fails tmp-length 'Unix-socket tests below it need 34 or fewer' \
  env TMPDIR="$long_tmp" "$precheck"

assert_environment_fails tmp-root 'TMPDIR resolves to /tmp' env TMPDIR=/tmp "$precheck"
mkdir -p "$TMP/home/.claude/jobs"
assert_environment_fails claude-component 'the image-source policy test rejects every path with a .claude component' \
  env TMPDIR="$TMP/home/.claude/jobs" "$precheck"
if [ -d "/run/user/$(id -u)" ] && [ -w "/run/user/$(id -u)" ]; then
  assert_environment_fails run-root 'native mount tests refuse projects inside /run' \
    env TMPDIR="/run/user/$(id -u)" "$precheck"
fi
noexec_dir=""
if [ -w /dev/shm ] && findmnt -no OPTIONS /dev/shm 2>/dev/null | grep -qw noexec; then
  noexec_dir="$(mktemp -d /dev/shm/preflight-noexec.XXXXXX)"
  assert_environment_fails noexec 'does not allow executing files (noexec mount)' \
    env TMPDIR="$noexec_dir" "$precheck"
  rm -rf -- "$noexec_dir"
else
  printf '[test-pre-push-worktree] note: no writable noexec mount here; noexec probe case skipped\n'
fi
assert_environment_fails rust-version "the pinned toolchain is ${pinned_rust}" \
  env FIXTURE_RUST_VERSION=1.0.0 "$precheck" --rust
assert_environment_fails rustup-override "overrides the pinned ${pinned_rust}" \
  env RUSTUP_TOOLCHAIN=1.0.0 "$precheck" --rust
assert_environment_fails rust-components 'lacks rustfmt or clippy' \
  env FIXTURE_NO_COMPONENTS=1 "$precheck" --rust
if [ "$(uname -s)" = Linux ]; then
  assert_environment_fails zigbuild 'cargo-zigbuild 0.23.0 is required on PATH' \
    env FIXTURE_ZIGBUILD_VERSION=0.22.0 "$precheck" --darwin-cross
fi
# Rust needs are scoped to the selection: no Rust family, no Rust check.
if [ "${#environment_ok_tmp}" -le 34 ]; then
  run_environment env FIXTURE_RUST_VERSION=1.0.0 "$precheck" >/dev/null ||
    fail 'environment precheck checked Rust for a selection without Rust'
fi
assert_environment_fails chromium-version "expected pinned Chromium ${pinned_chromium}" \
  env PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$environment_tree/bin/chromium-fixture" \
    FIXTURE_CHROMIUM_VERSION=1.2.3.4 "$precheck" --browser
assert_environment_fails kind-chromium 'the Kind browser gate needs a pre-provisioned pinned Chromium' \
  env PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$TMP/absent-chromium" "$precheck" --kind-browser
# Chromium IPC paths need a TMPDIR of 48 characters or fewer, which this
# fixture's own directory may exceed; the precheck reports that too.
browser_status=0
browser_output="$(run_environment env \
  PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$environment_tree/bin/chromium-fixture" \
  "$precheck" --browser --kind-browser 2>&1)" || browser_status=$?
assert_not_contains environment_browser "$browser_output" 'expected pinned Chromium'
if [ "$browser_status" -ne 0 ]; then
  assert_contains environment_browser "$browser_output" 'temp root is too long for Chromium IPC paths'
fi
if [ "${#environment_ok_tmp}" -le 34 ]; then
  [ "$browser_status" -eq 0 ] || {
    printf '%s\n' "$browser_output" >&2
    fail 'environment precheck rejected the pinned Chromium'
  }
  assert_contains environment_browser "$browser_output" "pinned Chromium ${pinned_chromium}"
fi
mkdir -p "$TMP/elsewhere/node_modules" "$TMP/elsewhere/venv"
ln -s "$TMP/elsewhere/node_modules" "$environment_tree/node_modules"
ln -s "$TMP/elsewhere/venv" "$environment_tree/.venv-proto"
assert_environment_fails node-modules-link 'node_modules is a symlink' "$precheck" --node-modules
assert_environment_fails proto-venv-link '.venv-proto is a symlink' "$precheck" --proto-venv
if [ "${#environment_ok_tmp}" -le 34 ]; then
  run_environment "$precheck" >/dev/null ||
    fail 'environment precheck checked symlinks no selected family uses'
fi

printf '[test-pre-push-worktree] environment precheck cases passed\n'
