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

CODEWIRE_LOCAL_SCCACHE_VERSION='sccache 0.17.0'
# One cache serves every worktree on the account; sccache evicts least
# recently used entries beyond the cap. On 2026-10-11 /home had 293 GiB free,
# one worktree target reached 163 GiB, and this cache held 5.5 GiB after the
# check, clippy, test and Darwin builds of two dependency graphs.
CODEWIRE_LOCAL_SCCACHE_SIZE='50G'

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
  # Start the server here, where a failure falls back, instead of letting the
  # first compile time out. A running server is reused as it is. In sccache
  # 0.17 --show-stats never starts a server and --zero-stats would reset the
  # counters every other build on the account reports; --dist-status connects
  # or starts one and changes nothing.
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
  export RUSTC_WRAPPER="$wrapper"
  local_rust_cache_status "state=active dir=$base/cache size=$CODEWIRE_LOCAL_SCCACHE_SIZE"
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
