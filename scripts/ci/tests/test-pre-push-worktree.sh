#!/usr/bin/env bash
# The fast pre-push hook (#3119 step 2.3): every branch push runs the push
# check, main takes changes only through pull requests, deletions need no
# check, and a release tag push checks only local facts: its signature, that
# it is on main, the workspace pin and the support pair. Pull-request CI is the
# merge gate; nothing local records a receipt. The real environment precheck is
# exercised at the end.
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
mkdir -p "$repo"/{.githooks,docs,scripts/dev,scripts/ci/select,scripts/ci/verify} \
  "$repo"/{scripts/ci/release,scripts/ci/images,crates/codewire-cli/src} "$TMP/bin"
for path in .githooks/pre-push scripts/dev/pre-push.sh scripts/dev/preflight.sh \
    scripts/dev/preflight-push.sh scripts/dev/install-hooks.sh scripts/dev/cpu-slice.sh \
    scripts/dev/preflight-lock.sh \
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
# The workstation CPU helper is a stub logging to its own file, and the fixture
# names the cgroup it reads, so no case moves this test's own processes.
cpu_log="$TMP/cpu.log"
cat > "$TMP/bin/codewire-cpu" <<EOF
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "$cpu_log"
exit "\${CPU_STUB_EXIT:-0}"
EOF
chmod +x "$TMP/bin/codewire-cpu"
printf '0::/user.slice/user-1000.slice/session-2.scope\n' > "$TMP/cgroup-outside"
printf '0::/cwvmtest.slice/codewire-vmtest-1-1.scope\n' > "$TMP/cgroup-inside"
export CPU_SLICE_CGROUP_FILE="$TMP/cgroup-outside"
# The workstation-wide preflight lock (#4215) lives here for the fixture, never
# at the real ~/.cache path another session's push may hold.
export PREFLIGHT_LOCK_FILE="$TMP/preflight.lock"
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
# A release tag push checks only local facts and needs no Forgejo token: just
# tag and push (#2892). Release selection reverifies the tag before publishing.
# Remote main is now two commits, so the seed is an ancestor of it.
git -C "$TMP/remote.git" fetch -q "$repo" main:main
seed="$(git -C "$repo" rev-parse HEAD~1)"
side="$(git -C "$repo" commit-tree 'HEAD^{tree}' -p HEAD -m 'side: never on main')"
signing_key() { # HOME_DIR: a throwaway OpenPGP signing key; prints its fingerprint
  mkdir -m 700 "$1"
  GNUPGHOME="$1" gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key 'Synthetic release tagger <synthetic@example.invalid>' ed25519 sign never 2>/dev/null
  GNUPGHOME="$1" gpg --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }'
}
# GnuPG sockets live in GNUPGHOME, so keep it short.
gpg_root="$(mktemp -d "$ORIGINAL_TMPDIR/ppw-gpg.XXXXXX")"
remove_signing_keys() { # stop both keys' agents, then delete their homes
  local home
  for home in release other; do
    [ ! -d "$gpg_root/$home" ] || GNUPGHOME="$gpg_root/$home" gpgconf --kill all 2>/dev/null || true
  done
  rm -rf "$gpg_root"
}
trap 'remove_signing_keys; chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT
release_key="$(signing_key "$gpg_root/release")"
other_key="$(signing_key "$gpg_root/other")"
export GNUPGHOME="$gpg_root/release"
signed_tag() { # TAG COMMIT [KEY_HOME KEY]
  GNUPGHOME="${3:-$GNUPGHOME}" git -C "$repo" -c user.signingkey="${4:-$release_key}" \
    tag -s -m "release $1" "$1" "$2"
}
assert_tag_push_passes() { # NAME TAG
  local output
  output="$(push "refs/tags/$2")" || fail "$1: a release tag push failed: $output"
  assert_contains "$1" "$output" 'preflight: signed release tag on main'
  assert_contains "$1" "$(cat "$log")" 'workspace-image-pin'
  assert_contains "$1" "$(cat "$log")" 'verify-release-support-pair.sh'
  assert_not_contains "$1" "$(cat "$log")" 'verify-release-tag-receipt'
  if grep -q '^cargo ' "$log"; then fail "$1: a release tag push ran the push check"; fi
}
assert_tag_push_refused() { # NAME TAG EXPECTED
  local output
  if output="$(push "refs/tags/$2")"; then fail "$1: a release tag push was accepted: $output"; fi
  assert_contains "$1" "$output" "$3"
  assert_not_contains "$1" "$(cat "$log")" 'verify-release-support-pair.sh'
}
# Without a token, a signed tag at main or on main pushes. Before #2892 made
# the push local, both were refused: "exact-main release receipt is unavailable".
signed_tag v9.9.9 HEAD
(unset GITEA_TOKEN GITHUB_SERVER_URL; assert_tag_push_passes tag_at_main v9.9.9)
signed_tag v9.9.8 "$seed"
(unset GITEA_TOKEN GITHUB_SERVER_URL; assert_tag_push_passes tag_on_main v9.9.8)
# A commit that is not on the remote's main is refused.
signed_tag v9.9.7 "$side"
assert_tag_push_refused tag_off_main v9.9.7 "which is not on origin's main"
# An unsigned or lightweight tag is refused.
git -C "$repo" tag -a -m 'release v9.9.6' v9.9.6 HEAD
assert_tag_push_refused unsigned_tag v9.9.6 'release tag signature does not verify'
git -C "$repo" tag v9.9.5 HEAD
assert_tag_push_refused lightweight_tag v9.9.5 'release tag is not an annotated tag'
# A tag signed by a key the pusher's keyring does not hold is refused.
signed_tag v9.9.4 HEAD "$gpg_root/other" "$other_key"
assert_tag_push_refused unknown_key_tag v9.9.4 'release tag signature does not verify'
# A signed tag whose content was altered after signing is refused.
signed_tag v9.9.3-signed HEAD
git -C "$repo" cat-file tag v9.9.3-signed | sed 's/^tag v9.9.3-signed$/tag v9.9.3/; s/^release v9.9.3-signed$/release v9.9.3 altered/' \
  > "$TMP/altered-tag"
git -C "$repo" update-ref refs/tags/v9.9.3 "$(git -C "$repo" mktag < "$TMP/altered-tag")"
assert_tag_push_refused altered_tag v9.9.3 'release tag signature does not verify'
remove_signing_keys
unset GNUPGHOME
trap 'chmod -R u+w "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT
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

# Preflight moves itself into the workstation CPU slice (#4126): from outside
# it, never when already inside, never in CI, never for --explain, and a
# failing helper leaves the run going.
on_workstation() { env -u CI -u GITHUB_ACTIONS "$@"; }
: > "$cpu_log"
output="$(cd "$repo" && on_workstation scripts/dev/preflight.sh --all 2>&1)" ||
  fail "preflight outside the slice failed: $output"
grep -Eqx 'run [0-9]+' "$cpu_log" || fail "preflight did not move itself into the slice: $(cat "$cpu_log")"
assert_contains slice_enter "$output" 'preflight: moved into cwvmtest.slice'
for case in inside ci explain; do
  : > "$cpu_log"
  case "$case" in
    inside) (cd "$repo" && CPU_SLICE_CGROUP_FILE="$TMP/cgroup-inside" on_workstation scripts/dev/preflight.sh --all >/dev/null 2>&1) ;;
    ci) (cd "$repo" && CI=true scripts/dev/preflight.sh --all >/dev/null 2>&1) ;;
    explain) (cd "$repo" && on_workstation scripts/dev/preflight.sh --explain >/dev/null 2>&1) ;;
  esac || fail "preflight ($case) failed"
  [ ! -s "$cpu_log" ] || fail "preflight ($case) called the CPU helper: $(cat "$cpu_log")"
done
output="$(cd "$repo" && CPU_STUB_EXIT=1 on_workstation scripts/dev/preflight.sh --all 2>&1)" ||
  fail "a failing CPU helper failed preflight: $output"
assert_contains slice_failure "$output" 'preflight: codewire-cpu run failed; running outside cwvmtest.slice'

# Heavy push checks queue behind another heavy preflight on the workstation
# (#4215): a push with a Rust change says whom it waits for, repeats it with
# the time waited, and at its bound runs without the lock instead of failing;
# a light push and a CI run never wait; once the holder ends, the push takes
# the lock and names itself.
if command -v flock >/dev/null 2>&1; then
  ( exec 9>>"$PREFLIGHT_LOCK_FILE"; flock 9; exec sleep 120 ) &
  lock_holder=$!
  for _ in $(seq 1 600); do flock -n "$PREFLIGHT_LOCK_FILE" true 2>/dev/null || break; sleep 0.1; done
  printf 'push check rust-clippy in /elsewhere (pid %s, since 00:00:00Z)\n' "$lock_holder" > "$PREFLIGHT_LOCK_FILE.holder"
  output="$(PREFLIGHT_LOCK_WAIT_SECONDS=2 PREFLIGHT_LOCK_REPORT_SECONDS=1 \
    on_workstation git -C "$repo" push -q origin HEAD:refs/heads/locked 2>&1)" ||
    fail "a heavy push failed when its wait for the lock ran out: $output"
  assert_contains lock_wait "$output" "is waiting for push check rust-clippy in /elsewhere (pid $lock_holder"
  assert_contains lock_wait "$output" "still waiting after 1s for push check rust-clippy in /elsewhere (pid $lock_holder"
  assert_contains lock_wait "$output" "waited 2s for push check rust-clippy in /elsewhere (pid $lock_holder"
  assert_contains lock_wait "$output" 'running without the lock'
  # One wait per push: later heavy steps run without waiting again.
  [[ "$(grep -c 'is waiting for' <<<"$output")" -eq 1 ]] ||
    fail "a push waited for the lock again after its wait ran out: $output"
  assert_contains lock_wait_holder "$(cat "$PREFLIGHT_LOCK_FILE.holder")" "(pid $lock_holder,"
  output="$(cd "$repo" && CI=true PREFLIGHT_LOCK_WAIT_SECONDS=1 git push -q origin HEAD:refs/heads/locked-ci 2>&1)" ||
    fail "a CI push waited for the workstation lock: $output"
  git -C "$repo" checkout -q -b light-only origin/main
  printf 'note\n' > "$repo/docs/light.md"
  git -C "$repo" add docs/light.md && git -C "$repo" -c commit.gpgsign=false commit -qm 'docs: light'
  output="$(PREFLIGHT_LOCK_WAIT_SECONDS=1 on_workstation git -C "$repo" push -q origin HEAD:refs/heads/light 2>&1)" ||
    fail "a light push waited for the lock: $output"
  assert_not_contains lock_light "$output" 'is waiting for'
  git -C "$repo" checkout -q -
  kill "$lock_holder" 2>/dev/null || true
  wait "$lock_holder" 2>/dev/null || true
  output="$(on_workstation git -C "$repo" push -q origin HEAD:refs/heads/unlocked 2>&1)" ||
    fail "a heavy push failed once the lock was free: $output"
  assert_contains lock_holder "$(cat "$PREFLIGHT_LOCK_FILE.holder")" 'push check rust-clippy in '
else
  printf '[test-pre-push-worktree] note: no flock here; workstation lock cases skipped\n'
fi

# The helper itself: its slice is workstation-cpu.sh's, it does nothing without
# codewire-cpu, and builder containers join the slice only from inside it.
grep -qx 'readonly SLICE=cwvmtest.slice' "$ROOT/scripts/dev/workstation-cpu.sh" ||
  fail 'workstation-cpu.sh no longer names the slice cpu-slice.sh uses'
# Preflight exports CODEWIRE_CPU_SLICE once it has joined the slice, and this
# test runs under preflight, so the probe starts without the caller's value.
slice_probe() { # CGROUP_FILE SHELL_CODE, without CI, from the real helper
  env -u CI -u GITHUB_ACTIONS -u CODEWIRE_CPU_SLICE CPU_SLICE_CGROUP_FILE="$1" \
    bash -c ". '$ROOT/scripts/dev/cpu-slice.sh'; $2" 2>&1
}
: > "$cpu_log"
output="$(PATH=/usr/bin:/bin slice_probe "$TMP/cgroup-outside" 'cpu_slice_enter probe; echo "var=${CODEWIRE_CPU_SLICE:-}"')"
[ "$output" = var= ] || fail "the helper acted without codewire-cpu: $output"
[ ! -s "$cpu_log" ] || fail 'the helper ran a codewire-cpu outside PATH'
output="$(CODEWIRE_CPU_SLICE=inherited PATH=/usr/bin:/bin slice_probe "$TMP/cgroup-outside" 'cpu_slice_enter probe; echo "var=${CODEWIRE_CPU_SLICE:-}"')"
[ "$output" = var= ] || fail "the probe read the caller's CODEWIRE_CPU_SLICE: $output"
output="$(slice_probe "$TMP/cgroup-inside" 'cpu_slice_enter probe; echo "var=${CODEWIRE_CPU_SLICE:-}"')"
[ "$output" = var=cwvmtest.slice ] || fail "inside the slice, the helper did not export it: $output"
args='cpu_slice_docker_args; echo "args=${CPU_SLICE_DOCKER_ARGS[*]-}"'
[ "$(slice_probe "$TMP/cgroup-inside" "$args")" = 'args=--cgroup-parent=cwvmtest.slice' ] ||
  fail 'a builder started inside the slice would leave it'
[ "$(slice_probe "$TMP/cgroup-outside" "$args")" = 'args=' ] ||
  fail 'a builder started outside the slice was given its cgroup parent'
[ "$(CI=true CPU_SLICE_CGROUP_FILE="$TMP/cgroup-inside" bash -c ". '$ROOT/scripts/dev/cpu-slice.sh'; $args")" = 'args=' ] ||
  fail 'a CI builder was given the workstation cgroup parent'
for builder in build-runtime-cw.sh build-runtime-guest-root.sh; do
  grep -qF 'docker run --rm --init ${CPU_SLICE_DOCKER_ARGS[@]+"${CPU_SLICE_DOCKER_ARGS[@]}"}' \
    "$ROOT/scripts/ci/release/$builder" || fail "$builder starts its container outside the slice"
done
grep -qx '  cpu_slice_enter build-local-runtime' "$ROOT/scripts/ci/release/build-local-runtime.sh" ||
  fail 'build-local-runtime.sh no longer enters the slice'
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
