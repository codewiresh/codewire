#!/usr/bin/env bash
# Select the disposable host-Rust compiler cache for one source CI job.
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
# Canonical-main pushes read and write the main bucket; pull requests read it
# with a read-only token and write nothing remote. Each token covers exactly
# one bucket, so main never reads an object a pull request wrote.
trust=main-read
[[ "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}" != 'push|refs/heads/main' ]] || trust=main
readonly trust
readonly bucket='example-ci-cache-main'
readonly endpoint='https://00000000000000000000000000000000.r2.cloudflarestorage.com'
readonly prefix='main/codewire/v1'

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

remove_credential() {
  if [[ -f "$credentials_file" && ! -L "$credentials_file" ]]; then
    shred -u -- "$credentials_file"
  else
    rm -f -- "$credentials_file"
  fi
}

select_disabled() {
  emit_env CODEWIRE_SCCACHE_MODE disabled
}

# The sccache client waits a fixed 10 s for its server unless the config file
# sets server_startup_timeout_ms. With R2, server startup reads and writes a
# check object on the bucket first, which can take longer than that.
readonly sccache_conf="$RUNNER_TEMP/codewire-sccache.conf"

# One mode's job environment, as KEY=VALUE lines. Each mode has its own
# socket: a late R2 server can never capture a local fallback. The server
# lives for the whole job; the cleanup step stops it, and an idle hour ends
# one a cancelled job left behind.
sccache_env() {
  local mode="$1"
  printf '%s\n' \
    "CODEWIRE_SCCACHE_MODE=$mode" \
    'RUSTC_WRAPPER=/usr/local/bin/sccache' \
    'CARGO_INCREMENTAL=0' \
    "SCCACHE_DIR=$RUNNER_TEMP/codewire-sccache-host" \
    'SCCACHE_CACHE_SIZE=8G' \
    "SCCACHE_BASEDIRS=$GITHUB_WORKSPACE" \
    "SCCACHE_SERVER_UDS=$RUNNER_TEMP/codewire-sccache-$mode.sock" \
    'SCCACHE_DIRECT=false' \
    'SCCACHE_IGNORE_SERVER_IO_ERROR=1' \
    "SCCACHE_CONF=$sccache_conf" \
    'SCCACHE_IDLE_TIMEOUT=3600' \
    'AWS_EC2_METADATA_DISABLED=true'
  if [[ "$mode" == r2 ]]; then
    printf '%s\n' \
      "CODEWIRE_SCCACHE_CREDENTIALS_FILE=$credentials_file" \
      "AWS_SHARED_CREDENTIALS_FILE=$credentials_file" \
      'AWS_PROFILE=default' \
      "SCCACHE_BUCKET=$bucket" \
      "SCCACHE_ENDPOINT=$endpoint" \
      "CODEWIRE_SCCACHE_PREFIX=$prefix" \
      'SCCACHE_REGION=auto' \
      'SCCACHE_S3_USE_SSL=true' \
      "SCCACHE_S3_KEY_PREFIX=$prefix" \
      "CODEWIRE_R2_CACHE_TRUST=$trust" \
      'SCCACHE_MULTILEVEL_CHAIN=disk,s3' \
      'SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY=ignore'
    [[ "$trust" != main-read ]] || printf '%s\n' 'SCCACHE_S3_RW_MODE=READ_ONLY'
  fi
}

# Start the server here, where a slow or unreachable backend can fall back,
# instead of letting the first compile time out and fail the job.
sccache_starts() {
  local mode="$1" line
  (
    while IFS= read -r line; do
      export "${line?}"
    done < <(sccache_env "$mode")
    exec sccache --start-server
  ) >/dev/null 2>&1
}

select_sccache() {
  local mode="$1" line
  while IFS= read -r line; do
    emit_env "${line%%=*}" "${line#*=}"
  done < <(sccache_env "$mode")
}

# Select local mode if its server starts; otherwise compile without a cache
# and return nonzero. Each fallback reports one warning and one status line.
select_local_or_disabled() {
  if sccache_starts local; then
    select_sccache local
    return 0
  fi
  echo '::warning::The local sccache server did not start; compiling without a compiler cache'
  select_disabled
  printf 'CODEWIRE_CI_CACHE state=server-unavailable backend=local fallback=disabled\n'
  return 1
}

case "$request" in
  disabled)
    select_disabled
    printf 'CODEWIRE_CI_CACHE state=disabled backend=none\n'
    ;;
  local|auto)
    if ! command -v sccache >/dev/null 2>&1 \
        || [[ "$(sccache --version 2>/dev/null)" != 'sccache 0.17.0' ]]; then
      echo '::warning::Pinned sccache is unavailable; compiling without a compiler cache'
      select_disabled
      printf 'CODEWIRE_CI_CACHE state=disabled backend=none\n'
      exit 0
    fi
    printf 'server_startup_timeout_ms = 60000\n' >"$sccache_conf"
    if [[ "$request" == local ]]; then
      if select_local_or_disabled; then
        printf 'CODEWIRE_CI_CACHE state=explicit backend=local\n'
      fi
    elif CODEWIRE_R2_CACHE_TRUST="$trust" "$fetcher" "$credentials_file"; then
      if sccache_starts r2; then
        select_sccache r2
        printf 'CODEWIRE_CI_CACHE state=remote-selected backend=r2 trust=%s\n' "$trust"
      else
        remove_credential
        echo '::warning::The R2 sccache server did not start; continuing with the job-local cache'
        printf 'CODEWIRE_CI_CACHE state=server-unavailable backend=r2 fallback=local\n'
        select_local_or_disabled || true
      fi
    else
      remove_credential
      echo '::warning::R2 sccache identity is unavailable; continuing with the job-local cache'
      printf 'CODEWIRE_CI_CACHE state=cache-unavailable fallback=local\n'
      select_local_or_disabled || true
    fi
    ;;
  *)
    printf 'unsupported host Rust cache request: %s\n' "$request" >&2
    exit 2
    ;;
esac
