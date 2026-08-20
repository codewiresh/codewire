#!/usr/bin/env bash
# Select the disposable host-Rust compiler cache for one untrusted CI job.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: select-untrusted-rust-cache.sh AWS_CREDENTIALS_FILE' >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly credentials_file="$1"
readonly request="${CODEWIRE_SCCACHE_REQUEST:-auto}"
readonly fetcher="${OPENBAO_SCCACHE_FETCHER:-$ROOT/scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh}"
readonly bucket='example-ci-cache-untrusted'
readonly endpoint='https://00000000000000000000000000000000.r2.cloudflarestorage.com'
readonly prefix='untrusted/codewire/v1'

: "${GITHUB_ENV:?Forgejo job environment file is required}"
: "${GITHUB_WORKSPACE:?Forgejo job workspace is required}"
: "${RUNNER_TEMP:?Forgejo runner temporary directory is required}"

case "$credentials_file" in
  "$RUNNER_TEMP"/*) ;;
  *)
    echo 'host Rust cache credential must remain below RUNNER_TEMP' >&2
    exit 2
    ;;
esac
[[ ! -e "$credentials_file" && ! -L "$credentials_file" ]] || {
  echo 'host Rust cache credential output must be a new nonsymlink path' >&2
  exit 2
}

emit_env() {
  local key="$1" value="$2"
  [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ && "$value" != *$'\n'* ]] || {
    echo 'host Rust cache produced an invalid job environment entry' >&2
    exit 2
  }
  printf '%s=%s\n' "$key" "$value" >>"$GITHUB_ENV"
  export "$key=$value"
}

select_disabled() {
  emit_env CODEWIRE_SCCACHE_MODE disabled
  printf 'CODEWIRE_CI_CACHE state=disabled backend=none\n'
}

select_sccache() {
  local mode="$1"
  emit_env CODEWIRE_SCCACHE_MODE "$mode"
  emit_env RUSTC_WRAPPER /usr/local/bin/sccache
  emit_env CARGO_INCREMENTAL 0
  emit_env SCCACHE_DIR "$RUNNER_TEMP/codewire-sccache-host"
  emit_env SCCACHE_CACHE_SIZE 8G
  emit_env SCCACHE_BASEDIRS "$GITHUB_WORKSPACE"
  emit_env SCCACHE_SERVER_UDS "$RUNNER_TEMP/codewire-sccache.sock"
  emit_env SCCACHE_DIRECT false
  emit_env SCCACHE_IGNORE_SERVER_IO_ERROR 1
  emit_env AWS_EC2_METADATA_DISABLED true
  if [[ "$mode" == r2 ]]; then
    emit_env CODEWIRE_SCCACHE_CREDENTIALS_FILE "$credentials_file"
    emit_env AWS_SHARED_CREDENTIALS_FILE "$credentials_file"
    emit_env AWS_PROFILE default
    emit_env SCCACHE_BUCKET "$bucket"
    emit_env SCCACHE_ENDPOINT "$endpoint"
    emit_env CODEWIRE_SCCACHE_PREFIX "$prefix"
    emit_env SCCACHE_REGION auto
    emit_env SCCACHE_S3_USE_SSL true
    emit_env SCCACHE_S3_KEY_PREFIX "$prefix"
    emit_env SCCACHE_MULTILEVEL_CHAIN disk,s3
    emit_env SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY ignore
  fi
}

case "$request" in
  disabled)
    select_disabled
    ;;
  local|auto)
    if ! command -v sccache >/dev/null 2>&1 \
        || [[ "$(sccache --version 2>/dev/null)" != 'sccache 0.17.0' ]]; then
      echo '::warning::Pinned sccache is unavailable; compiling without a compiler cache'
      select_disabled
    elif [[ "$request" == local ]]; then
      select_sccache local
      printf 'CODEWIRE_CI_CACHE state=explicit backend=local\n'
    elif "$fetcher" "$credentials_file"; then
      select_sccache r2
      printf 'CODEWIRE_CI_CACHE state=remote-selected backend=r2 trust=untrusted\n'
    else
      rm -f -- "$credentials_file"
      echo '::warning::R2 sccache identity is unavailable; continuing with the job-local cache'
      select_sccache local
      printf 'CODEWIRE_CI_CACHE state=cache-unavailable fallback=local\n'
    fi
    ;;
  *)
    printf 'unsupported host Rust cache request: %s\n' "$request" >&2
    exit 2
    ;;
esac
