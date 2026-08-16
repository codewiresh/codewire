#!/usr/bin/env bash
# Run one Cargo build with a disabled, local, or R2-backed sccache policy.
set -euo pipefail

mode="${CODEWIRE_SCCACHE_MODE:-disabled}"
build_profile="${CODEWIRE_RUST_PROFILE:-release}"
case "$build_profile" in
  ci|release) ;;
  *)
    printf 'codewire-rust-build: invalid CODEWIRE_RUST_PROFILE: %s\n' "$build_profile" >&2
    exit 2
    ;;
esac
case "$mode" in
  disabled) ;;
  local)
    export RUSTC_WRAPPER=/usr/local/bin/sccache
    export SCCACHE_DIR="${SCCACHE_DIR:-/var/cache/sccache}"
    ;;
  r2)
    : "${SCCACHE_BUCKET:?SCCACHE_BUCKET is required in r2 mode}"
    : "${SCCACHE_ENDPOINT:?SCCACHE_ENDPOINT is required in r2 mode}"
    : "${CODEWIRE_SCCACHE_PREFIX:?CODEWIRE_SCCACHE_PREFIX is required in r2 mode}"
    if [ -z "${AWS_IAM_CREDENTIALS_URL:-}" ] && \
      [ -s /run/secrets/aws_iam_credentials_url ]; then
      AWS_IAM_CREDENTIALS_URL="$(</run/secrets/aws_iam_credentials_url)"
      export AWS_IAM_CREDENTIALS_URL
    fi
    : "${AWS_IAM_CREDENTIALS_URL:?AWS_IAM_CREDENTIALS_URL or its BuildKit secret is required in r2 mode}"
    case "$AWS_IAM_CREDENTIALS_URL" in
      https://*) ;;
      *)
        printf 'codewire-rust-build: AWS_IAM_CREDENTIALS_URL must use HTTPS\n' >&2
        exit 2
        ;;
    esac
    export RUSTC_WRAPPER=/usr/local/bin/sccache
    export SCCACHE_REGION=auto
    export SCCACHE_S3_USE_SSL=true
    export SCCACHE_S3_KEY_PREFIX="$CODEWIRE_SCCACHE_PREFIX"
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
if [ "$mode" != disabled ]; then
  sccache --zero-stats >/dev/null
fi

status=0
"$@" || status=$?

if [ "$mode" != disabled ]; then
  sccache --show-stats || printf 'codewire-rust-build: warning: sccache statistics unavailable\n' >&2
  sccache --stop-server >/dev/null 2>&1 || true
fi
printf 'CODEWIRE_CI_PHASE name=rust-compile-link mode=%s seconds=%s status=%s\n' \
  "$mode" "$(( $(date +%s) - started_at ))" "$status"
exit "$status"
