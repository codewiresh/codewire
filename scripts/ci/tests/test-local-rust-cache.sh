#!/usr/bin/env bash
# Fixture proof for the workstation's shared local compiler cache: when it is
# selected, what reaches its server, and that every other caller keeps its own
# compiler. A synthetic sccache records each call; no real server starts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HELPER="$ROOT/scripts/ci/verify/local-rust-cache.sh"
readonly WRAPPER="$ROOT/scripts/ci/verify/local-rust-cache-rustc.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/local-rust-cache-test.XXXXXX")"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

fail() {
  printf '[test-local-rust-cache] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$work/fake" "$work/tools" "$work/home"
log="$work/log"
# The server starts from a cleared environment, so the fake finds its log
# path and its failure switch beside itself.
printf '%s\n' "$log" >"$work/fake/log-path"
cat >"$work/fake/sccache" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
here="$(dirname "$0")"
log="$(cat "$here/log-path")"
case "${1:-}" in
  --version) printf '%s\n' "${FAKE_SCCACHE_VERSION:-sccache 0.17.0}" ;;
  --dist-status)
    env >"$log.server-env"
    printf 'start\n' >>"$log.starts"
    [[ ! -e "$here/start-fails" ]] || exit 2
    printf '{"Disabled":"disabled"}\n'
    ;;
  *)
    printf '%s\n' "$*" >"$log.compile"
    env >"$log.compile-env"
    ;;
esac
EOF
chmod +x "$work/fake/sccache"
# A PATH with no sccache at all, whatever the host has installed.
for tool in bash env mkdir cat mv rm dirname; do
  ln -s "$(command -v "$tool")" "$work/tools/$tool"
done

# Run COMMAND through the helper's exec mode from a clean workstation
# environment plus the given assignments; write its environment to $work/env.
run_helper() {
  rm -f -- "$log".* "$work/env" "$work/stderr"
  env -u GITHUB_ACTIONS -u CI -u CODEWIRE_SCCACHE_MODE -u RUSTC_WRAPPER \
    -u CARGO_BUILD_RUSTC_WRAPPER -u CARGO_INCREMENTAL -u CARGO_BUILD_INCREMENTAL \
    -u CODEWIRE_LOCAL_RUST_CACHE -u CODEWIRE_LOCAL_SCCACHE_BASE -u XDG_CACHE_HOME \
    -u SCCACHE_DIR -u SCCACHE_SERVER_UDS -u SCCACHE_CONF \
    PATH="$work/fake:$work/tools" HOME="$work/home" \
    "$@" "$HELPER" env >"$work/env" 2>"$work/stderr"
}

env_value() {
  sed -n "s/^$1=//p" "$2"
}

assert_untouched() {
  local label="$1" wrapper="${2:-}"
  [[ "$(env_value RUSTC_WRAPPER "$work/env")" == "$wrapper" ]] ||
    fail "$label: changed the caller's compiler wrapper"
  ! grep -q '^SCCACHE_DIR=' "$work/env" || fail "$label: selected a cache"
  [[ ! -e "$log.starts" ]] || fail "$label: started a server"
}

# Selected: one disk-only server per account, started with only the cache's
# settings, and a caller's remote-cache variables gone.
run_helper SCCACHE_BUCKET=caller-bucket SCCACHE_ENDPOINT=https://caller.invalid \
  CALLER_MARKER=caller TMPDIR="$work/caller-tmp"
base="$work/home/.cache/codewire-sccache"
[[ "$(env_value RUSTC_WRAPPER "$work/env")" == "$WRAPPER" ]] || fail 'wrapper not selected'
! grep -q '^CARGO_INCREMENTAL=' "$work/env" || fail 'the cache changed incremental compilation'
[[ "$(env_value SCCACHE_DIR "$work/env")" == "$base/cache" ]] || fail 'cache directory'
[[ "$(env_value SCCACHE_SERVER_UDS "$work/env")" == "$base/server.sock" ]] || fail 'server socket'
[[ "$(env_value SCCACHE_CACHE_SIZE "$work/env")" == 50G ]] || fail 'cache size cap'
[[ "$(env_value SCCACHE_IGNORE_SERVER_IO_ERROR "$work/env")" == 1 ]] || fail 'server I/O fallback'
[[ "$(env_value CODEWIRE_LOCAL_SCCACHE_BIN "$work/env")" == "$work/fake/sccache" ]] ||
  fail 'absolute sccache path'
[[ "$(env_value CODEWIRE_LOCAL_SCCACHE_TMPDIR "$work/env")" == "$base/tmp" ]] || fail 'cache tmpdir'
[[ "$(cat "$base/sccache.conf")" == 'server_startup_timeout_ms = 60000' ]] || fail 'startup timeout'
! grep -q '^SCCACHE_BUCKET=\|^SCCACHE_ENDPOINT=' "$work/env" ||
  fail 'a remote cache selection reached the build'
[[ "$(wc -l <"$log.starts")" -eq 1 ]] || fail 'server not started exactly once'
[[ "$(env_value TMPDIR "$log.server-env")" == "$base/tmp" ]] || fail 'server tmpdir'
[[ "$(env_value SCCACHE_DIR "$log.server-env")" == "$base/cache" ]] || fail 'server cache dir'
! grep -q '^SCCACHE_BUCKET=\|^CALLER_MARKER=\|^CI=' "$log.server-env" ||
  fail 'the caller environment reached the shared server'
grep -Fxq "CODEWIRE_LOCAL_RUST_CACHE state=active dir=$base/cache size=50G" "$work/stderr" ||
  fail 'active status line'

# A nested entrypoint reuses the selection without another server start.
rm -f -- "$log".*
env -u GITHUB_ACTIONS -u CI PATH="$work/fake:$work/tools" HOME="$work/home" \
  RUSTC_WRAPPER="$WRAPPER" "$HELPER" env >/dev/null
[[ ! -e "$log.starts" ]] || fail 'nested selection restarted the server'

# The explicit base and XDG cache home are honoured.
run_helper XDG_CACHE_HOME="$work/xdg"
[[ "$(env_value SCCACHE_DIR "$work/env")" == "$work/xdg/codewire-sccache/cache" ]] ||
  fail 'XDG cache home ignored'
run_helper CODEWIRE_LOCAL_SCCACHE_BASE="$work/explicit"
[[ "$(env_value SCCACHE_DIR "$work/env")" == "$work/explicit/cache" ]] || fail 'explicit base ignored'

# CI owns its cache selection: nothing changes and nothing is printed.
for assignment in GITHUB_ACTIONS=true CI=1 CODEWIRE_SCCACHE_MODE=disabled \
    CODEWIRE_SCCACHE_MODE=r2; do
  run_helper "$assignment"
  assert_untouched "$assignment"
  [[ ! -s "$work/stderr" ]] || fail "$assignment: printed into a CI log"
done

# Every explicit caller choice is kept, with one status line saying why.
run_helper RUSTC_WRAPPER=/opt/caller-wrapper
assert_untouched 'caller wrapper' /opt/caller-wrapper
grep -Fq 'reason=caller-wrapper' "$work/stderr" || fail 'caller wrapper reason'
run_helper CARGO_BUILD_RUSTC_WRAPPER=/opt/caller-wrapper
assert_untouched 'caller config wrapper'
# sccache's client exits on forced incremental compilation; anything else is
# Cargo's choice and keeps the cache.
for assignment in CARGO_INCREMENTAL=1 CARGO_BUILD_INCREMENTAL=1; do
  run_helper "$assignment"
  assert_untouched "$assignment"
  grep -Fq 'reason=incremental-forced' "$work/stderr" || fail "$assignment reason"
done
for assignment in CARGO_INCREMENTAL=0 CARGO_BUILD_INCREMENTAL=false; do
  run_helper "$assignment"
  [[ "$(env_value RUSTC_WRAPPER "$work/env")" == "$WRAPPER" ]] || fail "$assignment disabled the cache"
  [[ "$(env_value "${assignment%%=*}" "$work/env")" == "${assignment#*=}" ]] ||
    fail "$assignment was changed"
done
run_helper CODEWIRE_LOCAL_RUST_CACHE=off
assert_untouched 'opt-out'
run_helper CODEWIRE_LOCAL_RUST_CACHE=sometimes
assert_untouched 'invalid request'
grep -Fq 'reason=invalid-request' "$work/stderr" || fail 'invalid request reason'

# Best effort: an unavailable, unreviewed or unstartable sccache compiles uncached.
run_helper PATH="$work/tools"
assert_untouched 'no sccache'
grep -Fq 'reason=sccache-unavailable' "$work/stderr" || fail 'missing sccache reason'
run_helper FAKE_SCCACHE_VERSION='sccache 0.16.0'
assert_untouched 'unreviewed version'
grep -Fq 'reason=unreviewed-sccache-version want=0.17.0' "$work/stderr" || fail 'version reason'
touch "$work/fake/start-fails"
run_helper
rm -- "$work/fake/start-fails"
[[ "$(env_value RUSTC_WRAPPER "$work/env")" == '' ]] || fail 'failed start kept the wrapper'
grep -Fq 'reason=server-unavailable' "$work/stderr" || fail 'server failure reason'
run_helper HOME=
assert_untouched 'no home'
grep -Fq 'reason=no-cache-home' "$work/stderr" || fail 'missing home reason'
run_helper CODEWIRE_LOCAL_SCCACHE_BASE=relative/cache
assert_untouched 'relative base'
grep -Fq 'reason=cache-directory-unavailable' "$work/stderr" || fail 'relative base reason'

# The rustc wrapper removes the per-worktree target directory from the cache
# key, gives sccache the cache's own tmpdir, and compiles uncached without a
# selection.
rm -f -- "$log".*
env CODEWIRE_LOCAL_SCCACHE_BIN="$work/fake/sccache" \
  CODEWIRE_LOCAL_SCCACHE_TMPDIR="$base/tmp" TMPDIR="$work/caller-tmp" \
  CARGO_TARGET_DIR="$work/target" CARGO_BUILD_TARGET_DIR="$work/target" \
  CARGO_MANIFEST_DIR=/registry/crate \
  "$WRAPPER" /toolchain/rustc --crate-name fixture
[[ "$(cat "$log.compile")" == '/toolchain/rustc --crate-name fixture' ]] ||
  fail 'wrapper changed the compiler command'
! grep -q '^CARGO_TARGET_DIR=\|^CARGO_BUILD_TARGET_DIR=' "$log.compile-env" ||
  fail 'the target directory reached the cache key'
[[ "$(env_value CARGO_MANIFEST_DIR "$log.compile-env")" == /registry/crate ]] ||
  fail 'wrapper removed a compiler input'
[[ "$(env_value TMPDIR "$log.compile-env")" == "$base/tmp" ]] || fail 'wrapper tmpdir'
direct="$(env -u CODEWIRE_LOCAL_SCCACHE_BIN CARGO_TARGET_DIR="$work/target" \
  "$WRAPPER" bash -c 'printf "%s" "${CARGO_TARGET_DIR-unset}"')"
[[ "$direct" == unset ]] || fail 'uncached fallback kept the target directory'

printf '[test-local-rust-cache] selection, CI isolation and wrapper key: OK\n'
