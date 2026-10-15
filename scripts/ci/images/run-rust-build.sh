#!/usr/bin/env bash
# Run one Cargo build with a disabled, local, or R2-backed sccache policy.
set -euo pipefail

mode="${CODEWIRE_SCCACHE_MODE:-disabled}"
build_profile="${CODEWIRE_RUST_PROFILE:-release}"
case "$build_profile" in
  ci|release|runtime) ;;
  *)
    printf 'codewire-rust-build: invalid CODEWIRE_RUST_PROFILE: %s\n' "$build_profile" >&2
    exit 2
    ;;
esac
# Local mode is a closed disk-only boundary: sccache auto-enables S3 whenever
# remote cache variables survive, so remove every one of them.
clear_remote_cache_env() {
  unset SCCACHE_BUCKET SCCACHE_ENDPOINT SCCACHE_REGION SCCACHE_S3_USE_SSL
  unset SCCACHE_S3_KEY_PREFIX SCCACHE_MULTILEVEL_CHAIN
  unset SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY SCCACHE_IGNORE_SERVER_IO_ERROR
  unset AWS_SHARED_CREDENTIALS_FILE AWS_PROFILE
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  unset AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
  export AWS_EC2_METADATA_DISABLED=true
}

case "$mode" in
  disabled)
    # A preceding workflow selection may have exported a wrapper. Disabling
    # compiler caching must also close that inherited execution path.
    unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    ;;
  local)
    # The workflow exports the reviewed R2 endpoint and bucket before it knows
    # whether short-lived identity is available. Make local mode disk-only even
    # when the caller has remote cache configuration in scope.
    clear_remote_cache_env
    export RUSTC_WRAPPER=/usr/local/bin/sccache
    export SCCACHE_DIR="${SCCACHE_DIR:-/var/cache/sccache}"
    ;;
  r2)
    : "${SCCACHE_BUCKET:?SCCACHE_BUCKET is required in r2 mode}"
    : "${SCCACHE_ENDPOINT:?SCCACHE_ENDPOINT is required in r2 mode}"
    : "${CODEWIRE_SCCACHE_PREFIX:?CODEWIRE_SCCACHE_PREFIX is required in r2 mode}"
    case "$SCCACHE_ENDPOINT" in
      https://*) ;;
      *)
        printf 'codewire-rust-build: SCCACHE_ENDPOINT must use HTTPS\n' >&2
        exit 2
        ;;
    esac
    credentials_file="${AWS_SHARED_CREDENTIALS_FILE:-/run/secrets/aws_shared_credentials}"
    case "$credentials_file" in
      /*) ;;
      *)
        printf 'codewire-rust-build: AWS_SHARED_CREDENTIALS_FILE must be absolute\n' >&2
        exit 2
        ;;
    esac
    [ -f "$credentials_file" ] && [ -r "$credentials_file" ] && [ -s "$credentials_file" ] || {
      printf 'codewire-rust-build: private AWS shared credentials are required in r2 mode\n' >&2
      exit 2
    }
    # Pinned sccache/OpenDAL reads the standard AWS shared-credentials file;
    # it does not implement the ECS-style credential-URL provider.
    # Do not let ambient static credentials or metadata become a fallback.
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    unset AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
    export AWS_SHARED_CREDENTIALS_FILE="$credentials_file"
    export AWS_PROFILE=default
    export AWS_EC2_METADATA_DISABLED=true
    export RUSTC_WRAPPER=/usr/local/bin/sccache
    export SCCACHE_DIR="${SCCACHE_DIR:-/var/cache/sccache}"
    export SCCACHE_REGION=auto
    export SCCACHE_S3_USE_SSL=true
    export SCCACHE_S3_KEY_PREFIX="$CODEWIRE_SCCACHE_PREFIX"
    # Keep the executor-local BuildKit cache as L0 and R2 as best-effort L1.
    # A cache outage must degrade to local compilation, never fail verification.
    export SCCACHE_MULTILEVEL_CHAIN=disk,s3
    export SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY=ignore
    export SCCACHE_IGNORE_SERVER_IO_ERROR=1
    ;;
  *)
    printf 'codewire-rust-build: invalid CODEWIRE_SCCACHE_MODE: %s\n' "$mode" >&2
    exit 2
    ;;
esac

export CARGO_INCREMENTAL=0
# BuildKit may give concurrent RUN executors a shared network namespace. The
# default TCP endpoint can then connect a compiler in one executor to an
# sccache daemon whose filesystem belongs to another. Keep the daemon socket
# inside the executor while sharing only the content-addressed cache backend.
export SCCACHE_SERVER_UDS="${SCCACHE_SERVER_UDS:-/tmp/codewire-sccache.sock}"
# Rust direct mode can treat a cached compiler output as reusable before Cargo
# has materialized the matching build-script OUT_DIR in another isolated
# BuildKit executor. Hash full inputs instead; a cache hit must never leave
# Cargo pointing at an output that is absent from this executor's target tree.
export SCCACHE_DIRECT=false
started_at="$(date +%s)"
sccache_conf=''
if [ "$mode" != disabled ] && [ -z "${SCCACHE_CONF:-}" ]; then
  # The sccache client waits a fixed 10 s for its server unless the config file
  # sets server_startup_timeout_ms. With R2, server startup reads and writes a
  # check object on the bucket first, which can take longer than that.
  sccache_conf="$(mktemp "${TMPDIR:-/tmp}/codewire-sccache-conf.XXXXXX")"
  printf 'server_startup_timeout_ms = 60000\n' >"$sccache_conf"
  export SCCACHE_CONF="$sccache_conf"
fi
sccache_active=false
if [ "$mode" != disabled ]; then
  # Starting the server can time out or fail when the cache backend is slow or
  # unreachable. A cache outage must not fail the build: retry R2 as the local
  # disk cache, then compile without the wrapper.
  if sccache --zero-stats >/dev/null; then
    sccache_active=true
  elif [ "$mode" = r2 ]; then
    printf 'codewire-rust-build: warning: sccache did not start with R2; retrying with the local cache\n' >&2
    sccache --stop-server >/dev/null 2>&1 || true
    clear_remote_cache_env
    # A late R2 server may still bind the first socket; never share it.
    export SCCACHE_SERVER_UDS="$SCCACHE_SERVER_UDS.local"
    mode=local
    if sccache --zero-stats >/dev/null; then
      sccache_active=true
    fi
  fi
  if [ "$sccache_active" != true ]; then
    printf 'codewire-rust-build: warning: sccache did not start; compiling without it\n' >&2
    sccache --stop-server >/dev/null 2>&1 || true
    unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
    mode=unavailable
  fi
fi

status=0
"$@" || status=$?

if [ "$sccache_active" = true ]; then
  sccache --show-stats || printf 'codewire-rust-build: warning: sccache statistics unavailable\n' >&2
  sccache --stop-server >/dev/null 2>&1 || true
fi
[ -z "$sccache_conf" ] || rm -f -- "$sccache_conf"
printf 'CODEWIRE_CI_PHASE name=rust-compile-link mode=%s seconds=%s status=%s\n' \
  "$mode" "$(( $(date +%s) - started_at ))" "$status"
exit "$status"
