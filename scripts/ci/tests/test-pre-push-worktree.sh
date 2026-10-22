#!/usr/bin/env bash
# The fast pre-push hook (#3119 step 2.3): every branch push runs the push
# check, main takes changes only through pull requests, deletions need no
# check, and a release tag push checks its release receipt. Pull-request CI
# is the merge gate; nothing local records a receipt. The real environment
# precheck is exercised at the end.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/pre-push-worktree.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT
# The hook reads push refs from any non-terminal stdin. Cases that push refs
# pipe them in explicitly; every other invocation must see EOF.
exec </dev/null
ORIGINAL_TMPDIR="${TMPDIR:-/tmp}"
mkdir -p "$TMP/tmpdir"
export TMPDIR="$TMP/tmpdir"

fail() {
  printf '[test-pre-push-worktree] ERROR: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local name="$1" output="$2" expected="$3"
  grep -Fq -- "$expected" <<<"$output" || {
    printf '[test-pre-push-worktree] %s missing: %s\n%s\n' "$name" "$expected" "$output" >&2
    exit 1
  }
}

assert_not_contains() {
  local name="$1" output="$2" unexpected="$3"
  if grep -Fq -- "$unexpected" <<<"$output"; then
    printf '[test-pre-push-worktree] %s unexpectedly contained: %s\n%s\n' "$name" "$unexpected" "$output" >&2
    exit 1
  fi
}

# A fixture checkout with the real hook, preflight and push check. Tools,
# the environment precheck and the release checks are synthetic and log here.
repo="$TMP/checkout"
log="$TMP/tools.log"
git init -q -b main "$repo"
git -C "$repo" config user.name 'Preflight Fixture'
git -C "$repo" config user.email preflight-fixture@codewire.invalid
git -C "$repo" config tag.gpgSign false
mkdir -p "$repo"/{.githooks,docs,scripts/dev,scripts/ci/select,scripts/ci/verify,scripts/ci/receipts} \
  "$repo"/{scripts/ci/release,scripts/ci/images,crates/codewire-cli/src} "$TMP/bin"
for path in .githooks/pre-push scripts/dev/pre-push.sh scripts/dev/preflight.sh \
    scripts/dev/preflight-push.sh scripts/dev/install-hooks.sh \
    scripts/ci/select/select-verification.sh scripts/ci/select/main-push-switch.sh \
    scripts/ci/verify/resolve-cargo-target-dir.sh scripts/ci/verify/shellcheck-baseline.sh; do
  install -m 755 "$ROOT/$path" "$repo/$path"
done
printf '.tmp/\n' > "$repo/.gitignore"
printf '[workspace]\nmembers = ["crates/codewire-cli"]\n' > "$repo/Cargo.toml"
printf '[package]\nname = "codewire-cli"\nversion = "0.0.0"\n' > "$repo/crates/codewire-cli/Cargo.toml"
printf '// fixture crate\n' > "$repo/crates/codewire-cli/src/lib.rs"
printf 'select_local_rust_cache() { return 1; }\n' > "$repo/scripts/ci/verify/local-rust-cache.sh"
stub() { # PATH BODY: an executable that logs its name and arguments, then runs BODY
  printf '#!/usr/bin/env bash\nset -euo pipefail\nprintf "%%s %%s\\n" "%s" "$*" >> "${PREFLIGHT_TEST_TOOL_LOG:?}"\n%s\n' \
    "$(basename "$1")" "$2" > "$repo/$1"
  chmod +x "$repo/$1"
}
stub scripts/dev/preflight-environment.sh ''
stub scripts/ci/verify/run-product-verification.sh \
  '[ "$1" != policy-parts ] || { printf "policy-repo\n"; exit 0; }
[ "$1" != "${PREFLIGHT_TEST_FAIL_FAMILY:-}" ] || exit 42'
stub scripts/ci/verify/run-integration-verification.sh ''
printf 'import os, sys\nopen(os.environ["PREFLIGHT_TEST_TOOL_LOG"], "a").write("workspace-image-pin %%s\\n" %% sys.argv[1:])\n' \
  > "$repo/scripts/ci/images/workspace-image-pin.py"
stub scripts/ci/release/verify-release-support-pair.sh ''
stub scripts/ci/receipts/verify-release-tag-receipt.sh \
  'printf "release_tag_receipt=accepted\nrelease_tag_reason=fixture\nrelease_tag_run=1\n"'
cat > "$TMP/bin/tool-stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# The selector reads the crate graph; the fixture workspace has no edges.
if [ "$(basename "$0")" = cargo ] && [ "${1:-}" = metadata ]; then
  printf '{"packages":[]}\n'
  exit 0
fi
printf '%s %s\n' "$(basename "$0")" "$*" >> "${PREFLIGHT_TEST_TOOL_LOG:?}"
[ "$(basename "$0")" != cargo ] || [ "${1:-}" != "${PREFLIGHT_TEST_CARGO_FAIL:-}" ] || exit 9
EOF
chmod +x "$TMP/bin/tool-stub"
for tool in bun cargo rustc supplychain; do ln -s tool-stub "$TMP/bin/$tool"; done
export PATH="$TMP/bin:$PATH" PREFLIGHT_TEST_TOOL_LOG="$log"
printf 'base\n' > "$repo/docs/base.md"
git -C "$repo" add -A && git -C "$repo" -c commit.gpgsign=false commit -q -m 'test: seed'
git init -q --bare "$TMP/remote.git"
git -C "$repo" remote add origin "$TMP/remote.git"
git -C "$repo" push -q -u origin main
(cd "$repo" && scripts/dev/install-hooks.sh >/dev/null)
dispatcher="$repo/.git/codewire-hooks/pre-push"
cmp "$repo/.githooks/pre-push" "$dispatcher" || fail 'installed dispatcher differs from its source'

push() { # REF -> the push output; status is the push's
  : > "$log"
  (cd "$repo" && git push -q origin "$1" 2>&1)
}

# A branch push runs the push check for its changed crate, every time.
printf '// change\n' >> "$repo/crates/codewire-cli/src/lib.rs"
git -C "$repo" -c commit.gpgsign=false commit -qam 'feat: change'
output="$(push HEAD:refs/heads/feature)" || fail "a branch push failed: $output"
assert_contains branch_push "$(cat "$log")" 'cargo fmt'
assert_contains branch_push "$(cat "$log")" 'cargo clippy'
output="$(push HEAD:refs/heads/feature-again)" || fail "a repeat push failed: $output"
assert_contains repeat_push "$(cat "$log")" 'cargo fmt'
# A failing push check refuses the push.
if output="$(PREFLIGHT_TEST_CARGO_FAIL=clippy push HEAD:refs/heads/broken)"; then
  fail 'a failing push check let the push through'
fi
assert_contains failed_push "$output" 'pre-push: push check failed; fix it and push again'
# Main takes changes only through pull requests.
if output="$(push HEAD:refs/heads/main)"; then fail 'a direct push to main was accepted'; fi
assert_contains main_push "$output" 'main takes changes only through pull requests'
# Deletions need no check; several refs at once are refused.
output="$(push :refs/heads/feature)" || fail "a deletion was refused: $output"
[ ! -s "$log" ] || fail 'a deletion ran tools'
if output="$(push 'HEAD:refs/heads/one' 2>&1 && cd "$repo" && git push -q origin HEAD:refs/heads/two HEAD:refs/heads/three 2>&1)"; then
  fail 'a multi-ref push was accepted'
fi
assert_contains multi_ref "$output" 'multi-ref pushes are unsupported'
# Only the checked-out commit can be checked.
git -C "$repo" branch -q other HEAD~1
if output="$(push other:refs/heads/other)"; then fail 'a commit not checked out was pushed'; fi
assert_contains not_checked_out "$output" 'is not checked out here'
# A release tag push checks its release receipt and runs nothing else.
git -C "$repo" tag v9.9.9
output="$(push refs/tags/v9.9.9)" || fail "a release tag push failed: $output"
assert_contains tag_push "$(cat "$log")" 'verify-release-tag-receipt.sh'
grep -q '^cargo ' "$log" && fail 'a release tag push ran the push check'
# The retired merge qualification flags are gone.
for retired in --for-merge --emit-receipt; do
  if (cd "$repo" && scripts/dev/preflight.sh "$retired" >/dev/null 2>&1); then
    fail "preflight accepted the retired $retired"
  fi
done
# --all runs every selected family and stops on the first failure.
output="$(cd "$repo" && scripts/dev/preflight.sh --all 2>&1)" || fail "preflight --all failed: $output"
assert_contains all_families "$(cat "$log" 2>/dev/null; printf '%s' "$output")" 'every selected family passed'
if output="$(cd "$repo" && PREFLIGHT_TEST_FAIL_FAMILY=rust scripts/dev/preflight.sh --all 2>&1)"; then
  fail 'preflight --all passed a failing family'
fi
assert_contains all_failure "$output" 'preflight: Rust verification FAILED'
printf '[test-pre-push-worktree] hook and preflight cases passed\n'

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
# A passing environment needs a short executable TMPDIR outside /run and
# .claude; this fixture's own directory is usually too long.
environment_ok_tmp=""
for short_root in /var/tmp "${HOME:-}/.cache" "$ORIGINAL_TMPDIR"; do
  [ -n "$short_root" ] && [ -d "$short_root" ] && [ -w "$short_root" ] || continue
  candidate="$(mktemp -d "$short_root/pe.XXXXXX" 2>/dev/null)" || continue
  case "$(cd "$candidate" && pwd -P)/" in
    /run/*|*/.claude/*) rm -rf -- "$candidate"; continue ;;
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

# /tmp is judged by the execution probe, not by its path: accepted where it
# allows executing files, refused as noexec where it does not.
tmp_probe="$(mktemp /tmp/preflight-tmp-probe.XXXXXX)"
printf '#!/bin/sh\nexit 0\n' >"$tmp_probe"
chmod 0700 "$tmp_probe"
tmp_executable=false
if "$tmp_probe" 2>/dev/null; then
  tmp_executable=true
fi
rm -f -- "$tmp_probe"
if [ "$tmp_executable" = true ]; then
  tmp_output="$(run_environment env TMPDIR=/tmp "$precheck" 2>&1)" ||
    { printf '%s\n' "$tmp_output" >&2; fail 'environment precheck refused an executable /tmp'; }
  assert_contains environment_tmp_executable "$tmp_output" '[preflight-environment] OK'
else
  assert_environment_fails tmp-noexec 'TMPDIR=/tmp does not allow executing files (noexec mount)' \
    env TMPDIR=/tmp "$precheck"
fi
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
