#!/usr/bin/env bash
# Adapt the job-level cache selection to a host Cargo command. The underlying
# runner owns sccache policy; this adapter exposes only the already-created
# private credential file and a disposable job-local L0 directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mode="${CODEWIRE_SCCACHE_MODE:-disabled}"

case "$mode" in
  disabled|local) ;;
  r2)
    credentials_file="${CODEWIRE_SCCACHE_CREDENTIALS_FILE:?CODEWIRE_SCCACHE_CREDENTIALS_FILE is required in r2 mode}"
    case "$credentials_file" in
      /*) ;;
      *)
        printf 'host Rust cache credentials file must be absolute\n' >&2
        exit 2
        ;;
    esac
    [[ -f "$credentials_file" && ! -L "$credentials_file" && -r "$credentials_file" && -s "$credentials_file" ]] || {
      printf 'host Rust cache credentials file must be a readable nonempty regular file\n' >&2
      exit 2
    }
    case "${CODEWIRE_SCCACHE_PREFIX:-}" in
      untrusted/codewire/*) ;;
      *)
        printf 'host Rust cache prefix must remain below untrusted/codewire/\n' >&2
        exit 2
        ;;
    esac
    export AWS_SHARED_CREDENTIALS_FILE="$credentials_file"
    ;;
  *)
    printf 'invalid CODEWIRE_SCCACHE_MODE for host Rust build: %s\n' "$mode" >&2
    exit 2
    ;;
esac

export CODEWIRE_RUST_PROFILE=ci
export SCCACHE_DIR="${SCCACHE_DIR:-${CARGO_TARGET_DIR:-$ROOT/target}/sccache-host}"
exec "$ROOT/scripts/ci/images/run-rust-build.sh" "$@"
