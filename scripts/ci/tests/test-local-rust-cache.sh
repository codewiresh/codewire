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
# Fake servers listen under a short directory: a socket path has 107 bytes.
hang=''
cleanup() {
  local pid_file pid
  [[ -z "${watch_caller:-}" ]] || kill "$watch_caller" 2>/dev/null || true
  if [[ -n "$hang" ]]; then
    # Only processes still running this test's fake server are stopped.
    for pid_file in "$hang"/*/server.sock.pid "$hang"/*/server.sock.compiler; do
      [[ -s "$pid_file" ]] || continue
      pid="$(cat -- "$pid_file")"
      if { tr '\0' ' ' <"/proc/$pid/cmdline"; } 2>/dev/null | grep -Fq -- "$hang/"; then
        kill -KILL "$pid" 2>/dev/null || true
      fi
    done
    rm -rf -- "$hang"
  fi
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
    # The server outlives its build: record any caller lock it would keep.
    for fd in /proc/$$/fd/*; do readlink "$fd"; done 2>/dev/null | grep '\.lock$' >"$log.server-locks" || true
    printf 'start\n' >>"$log.starts"
    [[ ! -e "$here/start-fails" ]] || exit 2
    printf '{"Disabled":"disabled"}\n'
    ;;
  *)
    printf '%s\n' "$*" >"$log.compile"
    env >"$log.compile-env"
    for fd in /proc/$$/fd/*; do readlink "$fd"; done 2>/dev/null | grep '\.lock$' >"$log.compile-locks" || true
    ;;
esac
EOF
chmod +x "$work/fake/sccache"
# A PATH with no sccache at all, whatever the host has installed.
for tool in bash env mkdir cat mv rm dirname readlink grep; do
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
[[ "$(env_value CODEWIRE_LOCAL_SCCACHE_RESTARTS "$work/env")" == "$base/server-restarts" ]] ||
  fail 'restart count path'
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
# A compile can start the shared server, which outlives the build: no lock
# the build holds reaches sccache, so none outlives it (#3323). Other
# descriptors, such as Cargo's jobserver, stay.
if [[ -d /proc/self/fd ]]; then
  : >"$work/held.lock"
  (
    exec {held}<>"$work/held.lock" {other}<"$work/fake/log-path"
    rm -f -- "$log".*
    env CODEWIRE_LOCAL_SCCACHE_BIN="$work/fake/sccache" CODEWIRE_LOCAL_SCCACHE_TMPDIR="$base/tmp" \
      "$WRAPPER" /toolchain/rustc --crate-name fixture
    [[ ! -s "$log.compile-locks" ]] || fail "a compile passed a held lock to sccache: $(cat "$log.compile-locks")"
    rm -f -- "$log".*
    run_helper
    [[ -e "$log.starts" ]] || fail 'the held-lock run started no server'
    [[ ! -s "$log.server-locks" ]] || fail "the server start inherited a held lock: $(cat "$log.server-locks")"
    # The caller's own descriptors stay open: closing a child's copy never
    # releases the caller's lock.
    [[ -e "/proc/$BASHPID/fd/$held" && -e "/proc/$BASHPID/fd/$other" ]] ||
      fail "the caller lost its own descriptors"
  )
fi
direct="$(env -u CODEWIRE_LOCAL_SCCACHE_BIN CARGO_TARGET_DIR="$work/target" \
  "$WRAPPER" bash -c 'printf "%s" "${CARGO_TARGET_DIR-unset}"')"
[[ "$direct" == unset ]] || fail 'uncached fallback kept the target directory'

# A compile that fails because its hung server was stopped compiles locally:
# sccache 0.17 fails a request that was still waiting for the server's first
# answer. Any other failure, and every success, is sccache's own result.
mkdir -p "$work/restart-fake"
cat >"$work/restart-fake/sccache" <<'EOF'
#!/usr/bin/env bash
if [[ -e "$(dirname "$0")/succeeds" ]]; then
  exit 0
fi
if [[ -e "$(dirname "$0")/restart" ]]; then
  read -r count <"$CODEWIRE_LOCAL_SCCACHE_RESTARTS"
  printf '%s\n' "$((count + 1))" >"$CODEWIRE_LOCAL_SCCACHE_RESTARTS"
fi
printf 'sccache: error: failed to execute compile\n' >&2
exit 2
EOF
cat >"$work/compiler" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$work/compiled"
EOF
chmod +x "$work/restart-fake/sccache" "$work/compiler"
printf '4\n' >"$work/restarts"
compile_via_wrapper() {
  rm -f -- "$work/compiled"
  env CODEWIRE_LOCAL_SCCACHE_BIN="$work/restart-fake/sccache" \
    CODEWIRE_LOCAL_SCCACHE_TMPDIR="$base/tmp" CODEWIRE_LOCAL_SCCACHE_RESTARTS="$work/restarts" \
    "$WRAPPER" "$work/compiler" --crate-name fixture 2>/dev/null
}
status=0
compile_via_wrapper || status=$?
[[ "$status" == 2 && ! -e "$work/compiled" ]] || fail 'a failed compile was retried with no restart'
touch "$work/restart-fake/restart"
compile_via_wrapper || fail 'a compile failed by a server restart did not compile locally'
[[ "$(cat "$work/compiled")" == '--crate-name fixture' ]] || fail 'the local compile changed the command'
rm -- "$work/restart-fake/restart"
touch "$work/restart-fake/succeeds"
compile_via_wrapper || fail 'a cached compile failed'
[[ ! -e "$work/compiled" ]] || fail 'a cached compile also compiled locally'

printf '[test-local-rust-cache] selection, CI isolation and wrapper key: OK\n'

# A hung server (#2753) is found from the kernel's process and socket tables,
# so this part runs on Linux, where the shared workstation and CI run.
if [[ "$(uname -s)" != Linux ]]; then
  printf '[test-local-rust-cache] hung-server check: skipped off Linux\n'
  exit 0
fi
# shellcheck source=scripts/ci/verify/local-rust-cache.sh
source "$HELPER"
local_rust_cache_server_check_supported || fail 'hang check unsupported on Linux'
hang="$(mktemp -d "${TMPDIR:-/tmp}/lrc.XXXXXX")"
(("${#hang}" < 80)) || fail "temporary directory too long for a socket: $hang"
mkdir -p "$hang/fake"

# Each fake server is a real process with clients connected to its socket, as
# the hung server had; a server that stops accepting leaves them queued. It
# ignores --stop-server or TERM when told to, and a compiling one runs a child
# as sccache runs rustc.
cat >"$work/fake-server.py" <<'EOF'
import os, signal, socket, subprocess, sys, time
path, clients, *flags = sys.argv[1:]
queued = '--queued' in flags
if '--ignore-term' in flags:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
listener = socket.socket(socket.AF_UNIX)
listener.bind(path)
listener.listen(16)
held = []
for _ in range(int(clients)):
    client = socket.socket(socket.AF_UNIX)
    client.connect(path)
    held += [client] if queued else [client, listener.accept()[0]]
if '--compiling' in flags:
    compiler = subprocess.Popen(
        [sys.executable, '-I', '-c', 'import time; time.sleep(300)', path])
    with open(path + '.compiler', 'w') as out:
        out.write(f'{compiler.pid}\n')
with open(path + '.pid', 'w') as out:
    out.write(f'{os.getpid()}\n')
while '--ignore-stop' in flags or not os.path.exists(path + '.stop'):
    time.sleep(0.05)
EOF
cat >"$hang/fake/sccache" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
here="$(dirname "$0")"
printf '%s %s\n' "$*" "${SCCACHE_SERVER_UDS:-}" >>"$here/calls"
case "${1:-}" in
  --version) printf 'sccache 0.17.0\n' ;;
  --show-stats) [[ ! -e "$here/stats-unanswered" ]] && cat "$here/stats" ;;
  --stop-server) : >"$SCCACHE_SERVER_UDS.stop" ;;
  --dist-status) printf '{"Disabled":"disabled"}\n' ;;
  *) exit 64 ;;
esac
EOF
chmod +x "$hang/fake/sccache"
fake_sccache="$hang/fake/sccache"

# Usage: start_server BASE CLIENTS [--ignore-stop] [--ignore-term] [--compiling] [--queued]
start_server() {
  # The start is not under test: the wait is a hang guard. 5 s was too short
  # for a Python start on a 4-CPU guest running the script tests side by side
  # (main run 22737).
  local base="$1" tries=1200
  shift
  mkdir -p "$base/cache"
  rm -f -- "$base/server.sock" "$base/server.sock".* "$base/server-progress"
  (python3 -I "$work/fake-server.py" "$base/server.sock" "$@" </dev/null >/dev/null 2>&1 &)
  until [[ -s "$base/server.sock.pid" ]]; do
    ((tries-- > 0)) || fail "fake server at $base did not start"
    sleep 0.05
  done
}
server_running() {
  local_rust_cache_process_start "$(cat -- "$1/server.sock.pid")" >/dev/null
}
# Statistics in sccache 0.17's layout; HITS and MISSES are finished compiles.
set_stats() {
  printf '%-34s %8s\n' 'Compile requests' 7750 'Compile requests executed' 4885 \
    'Cache hits' "$1" 'Cache hits (Rust)' "$1" 'Cache misses' "$2" \
    'Cache misses (Rust)' "$2" 'Cache hits rate' '47.02 %' 'Cache errors' 0 \
    'Compilations' "$2" 'Compilation failures' 0 'Non-cacheable calls' 31 \
    >"$hang/fake/stats"
}
# Run one check of BASE; its status lines go to $hang/stderr.
check() {
  : >"$hang/fake/calls"
  local_rust_cache_check_server "$1" "$fake_sccache" 2>"$hang/stderr"
}
# Usage: age_mark BASE STALLED_SECONDS LAST_SEEN_SECONDS_AGO
age_mark() {
  local inode progress since seen now
  IFS=' ' read -r inode progress since seen <"$1/server-progress"
  now="$(date +%s)"
  printf '%s %s %s %s\n' "$inode" "$progress" "$((now - $2))" "$((now - $3))" \
    >"$1/server-progress"
}
marked_since() {
  local inode progress since seen
  IFS=' ' read -r inode progress since seen <"$1/server-progress"
  printf '%s\n' "$since"
}
# Usage: assert_kept BASE CASE
assert_kept() {
  server_running "$1" || fail "$2: the server stopped"
  ! grep -q -- '^--stop-server ' "$hang/fake/calls" || fail "$2: --stop-server was sent"
}

set_stats 2272 2560

# Hung, as on 2026-10-14: clients wait, statistics answer, no compile finishes
# or runs, and --stop-server leaves the process running. A first observation
# only starts the clock, and four minutes is not yet a hang. After five, the
# exact server is terminated; another server on the account and the cache
# directory are left alone.
base="$hang/term"
start_server "$base" 3 --ignore-stop
start_server "$hang/other" 3 --ignore-stop
printf 'cached\n' >"$base/cache/entry"
check "$base" || fail 'a new stall failed the check'
[[ -s "$base/server-progress" ]] || fail 'the first observation was not recorded'
assert_kept "$base" 'a new stall'
age_mark "$base" 240 30
check "$base" || fail 'a short stall failed the check'
assert_kept "$base" 'a four-minute stall'
age_mark "$base" 400 30
check "$base" || fail 'a stopped hung server failed the check'
! server_running "$base" || fail 'the hung server still runs'
[[ "$(grep -c -- '^--stop-server ' "$hang/fake/calls")" == 1 ]] ||
  fail '--stop-server was not tried once first'
grep -Eq "^CODEWIRE_LOCAL_RUST_CACHE state=restarted reason=server-hung at=[0-9TZ:-]+ pid=[0-9]+ clients=3 stalled=[0-9]+s by=TERM\$" \
  "$hang/stderr" || fail "restart status: $(cat "$hang/stderr")"
server_running "$hang/other" || fail 'another server was stopped'
[[ "$(cat "$base/cache/entry")" == cached ]] || fail 'the cache directory changed'
[[ ! -e "$base/server-progress" ]] || fail 'the stopped server kept its progress mark'
[[ "$(cat "$base/server-restarts")" == 1 ]] || fail 'the restart was not counted'
grep -Fq 'state=restarted reason=server-hung' "$base/server-check.log" ||
  fail 'the restart was not logged'

# A server that ignores TERM too is killed.
base="$hang/kill"
start_server "$base" 2 --ignore-stop --ignore-term
check "$base"
age_mark "$base" 400 30
check "$base" || fail 'a killed hung server failed the check'
! server_running "$base" || fail 'the TERM-proof hung server still runs'
grep -Fq ' by=KILL' "$hang/stderr" || fail "kill status: $(cat "$hang/stderr")"

# Unresponsive: the server accepts no client and answers no statistics, as a
# stopped or deadlocked one does; five minutes of that is a hang too.
base="$hang/unresponsive"
start_server "$base" 2 --queued
touch "$hang/fake/stats-unanswered"
check "$base"
[[ -s "$base/server-progress" ]] || fail 'clients queued on an unresponsive server were not seen'
age_mark "$base" 400 30
check "$base" || fail 'a stopped unresponsive server failed the check'
rm -- "$hang/fake/stats-unanswered"
! server_running "$base" || fail 'the unresponsive server still runs'
grep -Eq ' clients=2 stalled=[0-9]+s by=stop-server$' "$hang/stderr" ||
  fail "unresponsive status: $(cat "$hang/stderr")"

# Slow but progressing: one more compile finished since the clock started.
base="$hang/slow"
start_server "$base" 2 --ignore-stop
check "$base"
age_mark "$base" 400 30
set_stats 2273 2560
check "$base"
assert_kept "$base" 'a progressing server'
(($(date +%s) - $(marked_since "$base") < 60)) || fail 'progress did not restart the clock'
set_stats 2272 2560

# A long compile: nothing finished for over five minutes, but the server runs
# a compiler, so it is working however slow that compile is.
base="$hang/compiling"
start_server "$base" 2 --ignore-stop --compiling
check "$base"
age_mark "$base" 400 30
check "$base"
assert_kept "$base" 'a server running a compiler'
(($(date +%s) - $(marked_since "$base") < 60)) || fail 'a running compiler did not restart the clock'

# Healthy: no client waits, so an old mark is dropped and nothing is stopped.
base="$hang/idle"
start_server "$base" 0 --ignore-stop
printf '1 2272 1 1\n' >"$base/server-progress"
check "$base"
assert_kept "$base" 'an idle server'
[[ ! -e "$base/server-progress" ]] || fail 'an idle server kept a progress mark'

# Observations ten minutes apart do not show clients waiting throughout.
base="$hang/gap"
start_server "$base" 2 --ignore-stop
check "$base"
age_mark "$base" 600 400
check "$base"
assert_kept "$base" 'a stall seen across a gap'
(($(date +%s) - $(marked_since "$base") < 60)) || fail 'a gap did not restart the clock'

# Before use: the selection stops a hung server that honours --stop-server,
# then starts the next one, and the caller gets the cache.
base="$hang/select"
start_server "$base" 2
check "$base"
age_mark "$base" 400 30
: >"$hang/fake/calls"
selected="$(env -u GITHUB_ACTIONS -u CI -u CODEWIRE_SCCACHE_MODE -u RUSTC_WRAPPER \
  -u CARGO_BUILD_RUSTC_WRAPPER -u CARGO_INCREMENTAL -u CARGO_BUILD_INCREMENTAL \
  -u CODEWIRE_LOCAL_RUST_CACHE PATH="$hang/fake:$PATH" \
  CODEWIRE_LOCAL_SCCACHE_BASE="$base" timeout 300 "$HELPER" printenv RUSTC_WRAPPER \
  2>"$hang/stderr")" || fail "selection over a hung server: $(cat "$hang/stderr")"
[[ "$selected" == "$WRAPPER" ]] || fail 'selection over a hung server did not select the cache'
! server_running "$base" || fail 'selection kept the hung server'
for expected in 'state=restarted reason=server-hung' ' by=stop-server' 'state=active'; do
  grep -Fq -- "$expected" "$hang/stderr" || fail "selection status: $(cat "$hang/stderr")"
done
[[ "$(sed -n 's/ .*//p' "$hang/fake/calls" | grep -v -- --show-stats | tr '\n' ' ')" == \
  '--version --stop-server --dist-status ' ]] ||
  fail "selection did not stop the hung server before starting one: $(cat "$hang/fake/calls")"

# The watcher: it runs while its caller does, holds none of the caller's
# descriptors, stops a hung server between builds, and exits with the caller.
base="$hang/watch"
start_server "$base" 2
check "$base"
age_mark "$base" 400 30
# The caller lives until the test ends it: a caller with its own lifetime
# raced the checks below, and the watcher exits with its caller (#4197).
sleep infinity &
caller=$!
watch_caller=$caller
# A separate shell starts the watcher, as an entrypoint does; its arguments
# name the watcher, which keeps that command line.
watch_mark="lrc-watch-test $HELPER $base"
bash -c 'source "$1"; CODEWIRE_LOCAL_SCCACHE_WATCH_SECONDS=1
  local_rust_cache_start_watch "$2" "$3" "$4"' lrc-watch-test "$HELPER" "$base" \
  "$fake_sccache" "$caller" >"$hang/caller-stdout" 7>"$hang/caller-fd"
holders() {
  find /proc/[0-9]*/fd -maxdepth 1 -lname "$1" 2>/dev/null | sed 's|/fd/.*||' | sort -u
}
[[ -n "$(pgrep -f -- "$watch_mark")" ]] || fail 'the watcher did not start'
[[ -z "$(holders "$hang/caller-stdout")$(holders "$hang/caller-fd")" ]] ||
  fail 'the watcher kept a caller descriptor open'
# Wait for the watcher's own record that it restarted the server, then check
# what it did. The tries are a hang guard, as in start_server: the watcher's
# 1-second period is what is under test, not how fast a loaded guest runs it.
tries=600
until grep -Fq 'state=restarted reason=server-hung' "$base/server-check.log" 2>/dev/null; do
  ((tries-- > 0)) || fail 'the watcher did not stop the hung server'
  sleep 0.1
done
! server_running "$base" || fail 'the watcher logged a restart but the hung server runs'
[[ "$(cat "$base/server-restarts")" == 1 ]] || fail 'the watcher did not count its restart'
[[ -n "$(pgrep -f -- "$watch_mark")" ]] || fail 'the watcher stopped while its caller ran'
kill "$caller"
wait "$caller" 2>/dev/null || true
watch_caller=''
tries=600
while [[ -n "$(pgrep -f -- "$watch_mark")" ]]; do
  ((tries-- > 0)) || fail 'the watcher outlived its caller'
  sleep 0.1
done

printf '[test-local-rust-cache] hung server: stopped by progress, slow and idle servers kept: OK\n'

# Sourcing selects line tables for dev and test builds, and keeps a caller's own value.
[[ "$(env -u CARGO_PROFILE_DEV_DEBUG bash -c 'source "$1"; printf %s "$CARGO_PROFILE_DEV_DEBUG"' _ "$HELPER")" == line-tables-only ]] ||
  fail 'sourcing did not select line-tables-only debuginfo'
[[ "$(CARGO_PROFILE_DEV_DEBUG=full bash -c 'source "$1"; printf %s "$CARGO_PROFILE_DEV_DEBUG"' _ "$HELPER")" == full ]] ||
  fail "sourcing overrode a caller's debuginfo setting"
printf '[test-local-rust-cache] dev debuginfo: line tables by default, caller value kept: OK\n'
