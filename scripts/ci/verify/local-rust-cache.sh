#!/usr/bin/env bash
# Select the shared local compiler cache for repository Cargo entrypoints on a
# developer or agent workstation.
#
# Source this file and call `select_local_rust_cache ROOT`, or run
#   scripts/ci/verify/local-rust-cache.sh COMMAND [ARG...]
# to run one command (for example `sccache --show-stats`) with the cache.
#
# Every worktree, package, feature set and profile on one account shares one
# disk-only sccache. Third-party crates compile from the same registry paths
# in every worktree, so one worktree's build serves the next. Two limits of
# sccache 0.17 bound that: a crate that includes generated code from its
# build-script OUT_DIR (serde_core does) is keyed by that target-directory
# path, and so is every crate above it; and workspace crates are keyed by
# their absolute worktree path. Incremental compilation stays as Cargo sets
# it: sccache passes incremental workspace units through uncached, so editing
# and rechecking a workspace crate stays as fast as without the cache.
#
# The cache is best effort, like CI's (#2520): when sccache is missing, is not
# the reviewed version, or its server does not start, Cargo compiles uncached.
# CI jobs select their own cache (scripts/ci/setup/select-untrusted-rust-cache.sh)
# and never use this one. An explicit CODEWIRE_SCCACHE_MODE, an existing
# RUSTC_WRAPPER, forced incremental compilation, or
# CODEWIRE_LOCAL_RUST_CACHE=off leaves the caller's compiler alone.
#
# A server can also hang (#2753): it keeps answering statistics but never
# finishes another compile, and every client waits on it with no timeout. On
# Linux the selection checks the server before use, and a watcher checks it
# every minute while the caller runs. A server is hung when clients have
# waited on it for five minutes in which it finished no compile and ran no
# compiler. It is then stopped (--stop-server, then TERM and KILL to its exact
# PID) and its cache is left as it is. The next compile starts a new server,
# and every compile that was waiting on the hung one compiles locally (see
# local-rust-cache-rustc.sh). Restarts are logged in server-check.log.

CODEWIRE_LOCAL_SCCACHE_VERSION='sccache 0.17.0'
# One cache serves every worktree on the account; sccache evicts least
# recently used entries beyond the cap. On 2026-10-11 /home had 293 GiB free,
# one worktree target reached 163 GiB, and this cache held 5.5 GiB after the
# check, clippy, test and Darwin builds of two dependency graphs.
CODEWIRE_LOCAL_SCCACHE_SIZE='50G'
# A compile in progress always has a compiler child, which counts as work
# however long it runs. Between compiler runs the server's own work for one
# request (compiler detection, input hashing, a cache read or write, the first
# scan of the full 50 GiB cache) takes seconds. The hang on 2026-10-14 lasted
# 30 minutes before a manual restart.
CODEWIRE_LOCAL_SCCACHE_STALL_SECONDS=300
CODEWIRE_LOCAL_SCCACHE_WATCH_SECONDS=60
# Observations further apart than this cannot show that clients waited
# throughout, so the stall is measured again from the newer one.
CODEWIRE_LOCAL_SCCACHE_OBSERVATION_GAP_SECONDS=180

# Every Cargo entrypoint that sources this file (local preflight, pull request
# CI and main CI) builds dev and test profiles with line tables only:
# backtraces keep file and line, targets shrink several-fold and link faster,
# and one setting everywhere keeps the shared compiler-cache keys identical
# (infra#1534). A caller that sets its own value keeps it.
: "${CARGO_PROFILE_DEV_DEBUG:=line-tables-only}"
export CARGO_PROFILE_DEV_DEBUG

local_rust_cache_status() {
  printf 'CODEWIRE_LOCAL_RUST_CACHE %s\n' "$*" >&2
}

# Print the server's environment: the cache settings and nothing a caller
# exported, so a caller's remote-cache selection cannot reach the shared
# server and its temporary directory outlives every caller's scratch space.
local_rust_cache_server_env() {
  local base="$1"
  printf '%s\n' \
    "HOME=$HOME" \
    "PATH=$PATH" \
    "TMPDIR=$base/tmp" \
    "SCCACHE_DIR=$base/cache" \
    "SCCACHE_CACHE_SIZE=$CODEWIRE_LOCAL_SCCACHE_SIZE" \
    "SCCACHE_SERVER_UDS=$base/server.sock" \
    "SCCACHE_CONF=$base/sccache.conf" \
    'SCCACHE_IDLE_TIMEOUT=1800' \
    'SCCACHE_DIRECT=false' \
    'AWS_EC2_METADATA_DISABLED=true'
}

# Run the reviewed sccache against the shared server at BASE.
local_rust_cache_server_command() {
  local base="$1" sccache_bin="$2" line
  local -a server_env=()
  shift 2
  while IFS= read -r line; do
    server_env+=("$line")
  done < <(local_rust_cache_server_env "$base")
  timeout 10 env -i "${server_env[@]}" "$sccache_bin" "$@"
}

# The hang check reads Linux's process and socket tables; elsewhere a running
# server is used as it is.
local_rust_cache_server_check_supported() {
  local tool
  [[ -r /proc/net/unix ]] || return 1
  for tool in awk find flock sleep timeout; do
    command -v "$tool" >/dev/null 2>&1 || return 1
  done
}

# Print the inode of the socket the server listens on and the number of
# clients connected to it, or nothing when no server listens on SOCKET.
# sccache 0.17 reports no count of waiting requests, and its request counters
# never settle for a request whose client was killed. A client the server
# accepted is listed connected (03); one it has not accepted yet, connecting
# (02).
local_rust_cache_server_socket() {
  awk -v path="$1" '
    index($0, " " path) {
      name = $0
      for (field = 1; field <= 7; field++) sub(/^[^ ]+ +/, "", name)
      if (name != path) next
      if ($4 == "00010000") inode = $7
      else if ($6 == "02" || $6 == "03") clients++
    }
    END { if (inode != "") print inode, clients + 0 }
  ' /proc/net/unix
}

# Print how many compiles the server has finished, or nothing when it does
# not answer. "Compile requests executed" counts compiles started, and a
# started compile can wait forever.
local_rust_cache_server_progress() {
  local stats
  stats="$(local_rust_cache_server_command "$1" "$2" --show-stats 2>/dev/null)" || return 0
  awk '
    { value = $NF; $NF = ""; sub(/ +$/, "") }
    $0 == "Compile requests" { answered = 1 }
    $0 == "Cache hits" || $0 == "Cache misses" || $0 == "Cache errors" ||
      $0 == "Compilations" || $0 == "Compilation failures" { finished += value }
    END { if (answered) print finished + 0 }
  ' <<<"$stats"
}

# Print PID's start time while it runs; fail once it has exited. The pair
# names one process even after its PID is reused.
local_rust_cache_process_start() {
  local stat
  local -a fields
  { IFS= read -r stat <"/proc/$1/stat"; } 2>/dev/null || return 1
  IFS=' ' read -r -a fields <<<"${stat##*) }"
  [[ "${fields[0]:-Z}" != [ZX] && -n "${fields[19]:-}" ]] || return 1
  printf '%s\n' "${fields[19]}"
}

# Print the PID holding the listening socket INODE when exactly one does.
local_rust_cache_socket_owner() {
  local link owner pid=''
  while IFS= read -r link; do
    owner="${link#/proc/}"
    owner="${owner%%/*}"
    [[ -z "$pid" || "$pid" == "$owner" ]] || return 1
    pid="$owner"
  done < <(find /proc/[0-9]*/fd -maxdepth 1 -lname "socket:\[$1\]" 2>/dev/null)
  [[ -n "$pid" ]] && printf '%s\n' "$pid"
}

# Succeed while PID runs a child: a compiler, or compiler detection. Where the
# kernel does not list children, assume one runs.
local_rust_cache_server_compiling() {
  local task child
  local -a children
  [[ -r "/proc/$1/task/$1/children" ]] || return 0
  for task in /proc/"$1"/task/*/children; do
    children=()
    { IFS=' ' read -r -a children <"$task"; } 2>/dev/null || true
    for child in "${children[@]}"; do
      local_rust_cache_process_start "$child" >/dev/null && return 0
    done
  done
  return 1
}

# Wait up to SECONDS for the process PID that started at START to exit.
local_rust_cache_wait_exit() {
  local tries=$(($3 * 5))
  while [[ "$(local_rust_cache_process_start "$1")" == "$2" ]]; do
    ((tries-- > 0)) || return 1
    sleep 0.2
  done
}

# Stop the hung server PID that started at START and print what stopped it.
# Its cache directory is not touched. Fail while it still runs.
local_rust_cache_stop_server() {
  local pid="$3" start="$4" signal
  # A hung sccache 0.17 answers this request but may never exit.
  local_rust_cache_server_command "$1" "$2" --stop-server >/dev/null 2>&1 || true
  if local_rust_cache_wait_exit "$pid" "$start" 3; then
    printf 'stop-server\n'
    return 0
  fi
  for signal in TERM KILL; do
    # Each failed wait ends on a check that PID is still that server.
    kill -s "$signal" "$pid" 2>/dev/null || true
    if local_rust_cache_wait_exit "$pid" "$start" 2; then
      printf '%s\n' "$signal"
      return 0
    fi
  done
  return 1
}

# Count one restart of the server at BASE before it is signalled, so that a
# compile its client fails because of it (local-rust-cache-rustc.sh) sees the
# count change when that client returns.
local_rust_cache_count_restart() {
  local count=''
  { IFS= read -r count <"$1/server-restarts"; } 2>/dev/null || true
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  if printf '%s\n' "$((count + 1))" >"$1/server-restarts.$$"; then
    mv -f -- "$1/server-restarts.$$" "$1/server-restarts"
  else
    rm -f -- "$1/server-restarts.$$"
  fi
}

# Report a restart to the caller and in the account's log beside the cache.
local_rust_cache_log_server() {
  local_rust_cache_status "$2"
  printf 'CODEWIRE_LOCAL_RUST_CACHE %s\n' "$2" >>"$1/server-check.log" 2>/dev/null || true
}

# One observation of the server at BASE, under the check lock. Its progress
# mark records the listening socket, the finished-compile count, when that
# count was first seen with clients waiting, and the latest observation.
# Returns 3 when a hung server could not be stopped.
local_rust_cache_observe_server() {
  local base="$1" sccache_bin="$2" mark="$1/server-progress"
  local inode='' clients='' answered progress now at pid start by
  local marked_inode='' marked_progress='' since='' seen=''
  IFS=' ' read -r inode clients <<<"$(local_rust_cache_server_socket "$base/server.sock")" || true
  if [[ -z "$inode" || "${clients:-0}" == 0 ]]; then
    rm -f -- "$mark"
    return 0
  fi
  answered="$(local_rust_cache_server_progress "$base" "$sccache_bin")" || true
  printf -v now '%(%s)T' -1
  if [[ -f "$mark" ]]; then
    IFS=' ' read -r marked_inode marked_progress since seen <"$mark" || true
  fi
  [[ "$since" =~ ^[0-9]+$ && "$seen" =~ ^[0-9]+$ ]] || marked_inode=''
  # A server that does not answer has shown no progress.
  progress="${answered:-unanswered}"
  if [[ -z "$answered" && "$marked_inode" == "$inode" ]]; then
    progress="$marked_progress"
  fi
  if [[ "$marked_inode" != "$inode" || "$marked_progress" != "$progress" ]] ||
      ((now - seen > CODEWIRE_LOCAL_SCCACHE_OBSERVATION_GAP_SECONDS)); then
    since="$now"
  fi
  if ((now - since >= CODEWIRE_LOCAL_SCCACHE_STALL_SECONDS)) &&
      pid="$(local_rust_cache_socket_owner "$inode")" &&
      start="$(local_rust_cache_process_start "$pid")"; then
    if local_rust_cache_server_compiling "$pid"; then
      since="$now"
    else
      # A compiler that has just exited is counted a moment later.
      sleep 1
      if local_rust_cache_server_compiling "$pid" ||
          [[ "$(local_rust_cache_server_progress "$base" "$sccache_bin")" != "$answered" ]]; then
        since="$now"
      else
        at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        local_rust_cache_count_restart "$base"
        if by="$(local_rust_cache_stop_server "$base" "$sccache_bin" "$pid" "$start")"; then
          rm -f -- "$mark"
          local_rust_cache_log_server "$base" "state=restarted reason=server-hung at=$at pid=$pid clients=$clients stalled=$((now - since))s by=$by"
          return 0
        fi
        local_rust_cache_log_server "$base" "state=hung reason=server-not-stopped at=$at pid=$pid clients=$clients stalled=$((now - since))s"
        return 3
      fi
    fi
  fi
  if printf '%s %s %s %s\n' "$inode" "$progress" "$since" "$now" >"$mark.$$"; then
    mv -f -- "$mark.$$" "$mark"
  else
    rm -f -- "$mark.$$"
  fi
}

# Usage: local_rust_cache_check_server BASE SCCACHE
# Observe the shared server once and stop it when it is hung. Fails only when
# a hung server still runs, so that the caller compiles uncached.
local_rust_cache_check_server() {
  local status=0
  local_rust_cache_server_check_supported || return 0
  (
    flock -w 30 9 || exit 0
    local_rust_cache_observe_server "$@"
  ) 9>>"$1/server-check.lock" || status=$?
  [[ "$status" != 3 ]]
}

# Usage: local_rust_cache_watch_server BASE SCCACHE CALLER_PID INTERVAL
# Check the server every INTERVAL seconds while CALLER_PID runs. Clients
# blocked on a hung server start no new build, so the check before use alone
# would not reach them.
local_rust_cache_watch_server() {
  local caller="$3" interval="$4" step waited=0
  step=$((interval < 5 ? interval : 5))
  while sleep "$step" && kill -0 "$caller" 2>/dev/null; do
    waited=$((waited + step))
    if ((waited >= interval)); then
      waited=0
      local_rust_cache_check_server "$1" "$2" || true
    fi
  done
}

# Start the watcher for CALLER_PID outside the caller's jobs, with none of
# the caller's descriptors, so no pipe, lock or `wait` of the caller waits on it.
local_rust_cache_start_watch() {
  local base="$1" sccache_bin="$2" caller="$3"
  local_rust_cache_server_check_supported || return 0
  (
    trap - EXIT ERR INT TERM HUP
    for fd in /proc/"$BASHPID"/fd/*; do
      fd="${fd##*/}"
      if ((fd > 2)); then
        exec {fd}>&-
      fi
    done
    cd / || exit 0
    local_rust_cache_watch_server "$base" "$sccache_bin" "$caller" \
      "$CODEWIRE_LOCAL_SCCACHE_WATCH_SECONDS" &
  ) </dev/null >/dev/null 2>&1
}

# Usage: select_local_rust_cache ROOT
# Returns 0 when the shared cache is selected, 1 when Cargo runs uncached.
select_local_rust_cache() {
  local root="$1"
  local wrapper="$root/scripts/ci/verify/local-rust-cache-rustc.sh"
  local sccache_bin version base conf line key
  local -a server_env=()

  [[ "${RUSTC_WRAPPER:-}" != "$wrapper" ]] || return 0
  case "${CODEWIRE_LOCAL_RUST_CACHE:-auto}" in
    auto) ;;
    off) return 1 ;;
    *)
      local_rust_cache_status 'state=disabled reason=invalid-request'
      return 1
      ;;
  esac
  # CI owns its compiler cache selection, including an explicit "disabled".
  [[ -z "${GITHUB_ACTIONS:-}" && -z "${CI:-}" && -z "${CODEWIRE_SCCACHE_MODE:-}" ]] ||
    return 1
  if [[ -n "${RUSTC_WRAPPER:-}" || -n "${CARGO_BUILD_RUSTC_WRAPPER:-}" ]]; then
    local_rust_cache_status 'state=disabled reason=caller-wrapper'
    return 1
  fi
  # The sccache 0.17 client exits when either variable forces incremental
  # compilation; Cargo's own default is fine.
  if [[ "${CARGO_INCREMENTAL:-}" == 1 || "${CARGO_BUILD_INCREMENTAL:-}" == 1 ]]; then
    local_rust_cache_status 'state=disabled reason=incremental-forced'
    return 1
  fi
  if ! sccache_bin="$(command -v sccache)" || [[ "$sccache_bin" != /* ]]; then
    local_rust_cache_status 'state=disabled reason=sccache-unavailable'
    return 1
  fi
  version="$("$sccache_bin" --version 2>/dev/null || true)"
  if [[ "$version" != "$CODEWIRE_LOCAL_SCCACHE_VERSION" ]]; then
    local_rust_cache_status "state=disabled reason=unreviewed-sccache-version want=${CODEWIRE_LOCAL_SCCACHE_VERSION#sccache }"
    return 1
  fi
  if [[ -n "${CODEWIRE_LOCAL_SCCACHE_BASE:-}" ]]; then
    base="$CODEWIRE_LOCAL_SCCACHE_BASE"
  elif [[ -n "${XDG_CACHE_HOME:-}" ]]; then
    base="$XDG_CACHE_HOME/codewire-sccache"
  elif [[ -n "${HOME:-}" ]]; then
    base="$HOME/.cache/codewire-sccache"
  else
    local_rust_cache_status 'state=disabled reason=no-cache-home'
    return 1
  fi
  if [[ "$base" != /* || "$base" == *$'\n'* || -z "${HOME:-}" ]] \
      || ! mkdir -p -- "$base/cache" "$base/tmp" 2>/dev/null; then
    local_rust_cache_status 'state=disabled reason=cache-directory-unavailable'
    return 1
  fi
  # The client waits 10 s for a server unless its config file says otherwise.
  conf="$base/sccache.conf"
  if [[ "$(cat -- "$conf" 2>/dev/null)" != 'server_startup_timeout_ms = 60000' ]]; then
    if ! { printf 'server_startup_timeout_ms = 60000\n' >"$conf.$$" &&
        mv -f -- "$conf.$$" "$conf"; }; then
      rm -f -- "$conf.$$"
      local_rust_cache_status 'state=disabled reason=cache-directory-unavailable'
      return 1
    fi
  fi
  while IFS= read -r line; do
    server_env+=("$line")
  done < <(local_rust_cache_server_env "$base")
  # A running server is reused unless it is hung (see above); a hung one that
  # cannot be stopped leaves this caller uncached.
  if ! local_rust_cache_check_server "$base" "$sccache_bin"; then
    local_rust_cache_status 'state=disabled reason=server-hung'
    return 1
  fi
  # Start the server here, where a failure falls back, instead of letting the
  # first compile time out. In sccache 0.17 --show-stats never starts a server
  # and --zero-stats would reset the counters every other build on the account
  # reports; --dist-status connects or starts one and changes nothing.
  if ! env -i "${server_env[@]}" "$sccache_bin" --dist-status >/dev/null 2>&1; then
    local_rust_cache_status 'state=disabled reason=server-unavailable'
    return 1
  fi

  # A caller's remote-cache variables would configure a server that a crashed
  # one is replaced by; only the local settings remain.
  for key in "${!SCCACHE_@}"; do
    unset "$key"
  done
  for line in "${server_env[@]}"; do
    key="${line%%=*}"
    case "$key" in
      SCCACHE_*) export "${line?}" ;;
    esac
  done
  export SCCACHE_IGNORE_SERVER_IO_ERROR=1
  export CODEWIRE_LOCAL_SCCACHE_BIN="$sccache_bin"
  export CODEWIRE_LOCAL_SCCACHE_TMPDIR="$base/tmp"
  export CODEWIRE_LOCAL_SCCACHE_RESTARTS="$base/server-restarts"
  export RUSTC_WRAPPER="$wrapper"
  local_rust_cache_status "state=active dir=$base/cache size=$CODEWIRE_LOCAL_SCCACHE_SIZE"
  local_rust_cache_start_watch "$base" "$sccache_bin" "${BASHPID:-$$}"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
  if [[ $# -eq 0 ]]; then
    printf 'usage: %s COMMAND [ARG...]\n' "$0" >&2
    exit 2
  fi
  select_local_rust_cache "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)" || true
  exec "$@"
fi
