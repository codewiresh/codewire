#!/usr/bin/env bash
# One job-owned credential projection for independent workspace compiler/layer
# caches. Kind retains this file for its later product and host Rust builds.
set -euo pipefail

[[ $# == 1 ]] || { echo 'usage: select-untrusted-workspace-cache.sh AWS_CREDENTIALS_FILE' >&2; exit 2; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
credentials_file="$1"
rust_request="${CODEWIRE_SCCACHE_REQUEST:-auto}"
# Remote layer reuse is opt-in: a dispatch asks for it with layer_cache=auto.
layer_request="${CODEWIRE_BUILDKIT_CACHE_REQUEST:-local}"
fetcher="${OPENBAO_SCCACHE_FETCHER:-$ROOT/scripts/ci/setup/fetch-openbao-sccache-r2-credentials.sh}"
# Canonical-main pushes read and write the main bucket. Pull requests read it
# with a read-only token and write nothing remote.
trust=protected-read
[[ "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}" != 'push|refs/heads/main' ]] || trust=main
: "${GITHUB_ENV:?Forgejo job environment file is required}"
: "${GITHUB_WORKSPACE:?Forgejo job workspace is required}"
: "${RUNNER_TEMP:?Forgejo runner temporary directory is required}"

bucket=example-ci-cache-protected prefix=protected/codewire/v1

for request in "$rust_request" "$layer_request"; do
  case "$request" in
    auto|local|disabled) ;;
    *) echo 'workspace cache requests must be auto, local, or disabled' >&2; exit 2 ;;
  esac
done
case "$credentials_file" in
  "$RUNNER_TEMP"/*) ;;
  *) echo 'workspace cache credential must remain below RUNNER_TEMP' >&2; exit 2 ;;
esac
[[ "$credentials_file" == /* && "$credentials_file" != *','* && "$credentials_file" != *$'\n'* \
    && "$(realpath -m -- "$credentials_file")" == "$credentials_file" \
    && ! -e "$credentials_file" && ! -L "$credentials_file" ]] || {
  echo 'workspace cache credential output must be a new canonical nonsymlink path' >&2
  exit 2
}
case "$credentials_file" in
  "$(realpath -- "$GITHUB_WORKSPACE")"/*)
    echo 'workspace cache credential must remain outside the source build context' >&2; exit 2 ;;
esac
cleanup_failed_selection() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "$status" != 0 && -f "$credentials_file" && ! -L "$credentials_file" ]]; then
    shred -u -- "$credentials_file" || status=$?
  fi
  exit "$status"
}
trap cleanup_failed_selection EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

emit_env() {
  local key="$1" value="$2"
  [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ && "$value" != *$'\n'* ]] || return 2
  printf '%s=%s\n' "$key" "$value" >>"$GITHUB_ENV"
}

rust_mode="$rust_request" layer_mode="$layer_request"
[[ "$rust_mode" != auto ]] || rust_mode=local
[[ "$layer_mode" != auto ]] || layer_mode=local
if [[ "$rust_request" != disabled ]] \
    && { ! command -v sccache >/dev/null 2>&1 || [[ "$(sccache --version 2>/dev/null)" != 'sccache 0.17.0' ]]; }; then
  rust_mode=disabled
  echo '::warning::Pinned host sccache is unavailable; compiling without a compiler cache'
fi
if [[ ( "$rust_request" == auto && "$rust_mode" != disabled ) || "$layer_request" == auto ]]; then
  if CODEWIRE_R2_CACHE_TRUST="$trust" "$fetcher" "$credentials_file"; then
    # Validate the fetcher's output before exporting any job configuration.
    [[ -f "$credentials_file" && ! -L "$credentials_file" && -s "$credentials_file" \
        && -r "$credentials_file" && "$(stat -c %a -- "$credentials_file")" == 600 ]] || {
      echo 'workspace cache fetcher returned an invalid private credential file' >&2
      exit 2
    }
    [[ "$rust_request" != auto || "$rust_mode" == disabled ]] || rust_mode=r2
    [[ "$layer_request" != auto ]] || layer_mode=r2
    emit_env CODEWIRE_SCCACHE_CREDENTIALS_FILE "$credentials_file"
    emit_env CODEWIRE_R2_CACHE_TRUST "$trust"
    emit_env SCCACHE_BUCKET "$bucket"
    emit_env SCCACHE_ENDPOINT https://00000000000000000000000000000000.r2.cloudflarestorage.com
    emit_env CODEWIRE_SCCACHE_PREFIX "$prefix"
  else
    if [[ -f "$credentials_file" && ! -L "$credentials_file" ]]; then
      shred -u -- "$credentials_file"
    else
      rm -f -- "$credentials_file"
    fi
    echo "::warning::The $trust R2 cache identity is unavailable; auto modes fall back to local"
  fi
fi
emit_env CODEWIRE_SCCACHE_MODE "$rust_mode"
emit_env CODEWIRE_BUILDKIT_CACHE_MODE "$layer_mode"

# The same compiler selection serves Kind's later host builds. The workspace
# compiler itself uses the checksum-pinned sccache installed in its Dockerfile.
if [[ "$rust_mode" != disabled ]]; then
  emit_env RUSTC_WRAPPER /usr/local/bin/sccache
  emit_env CARGO_INCREMENTAL 0
  emit_env SCCACHE_DIR "$RUNNER_TEMP/codewire-sccache-host"
  emit_env SCCACHE_CACHE_SIZE 8G
  emit_env SCCACHE_BASEDIRS "$GITHUB_WORKSPACE"
  emit_env SCCACHE_SERVER_UDS "$RUNNER_TEMP/codewire-sccache.sock"
  emit_env SCCACHE_DIRECT false
  emit_env AWS_EC2_METADATA_DISABLED true
  if [[ "$rust_mode" == r2 ]]; then
    emit_env AWS_SHARED_CREDENTIALS_FILE "$credentials_file"
    emit_env AWS_PROFILE default
    emit_env SCCACHE_REGION auto
    emit_env SCCACHE_S3_USE_SSL true
    emit_env SCCACHE_S3_KEY_PREFIX "$prefix"
    [[ "$trust" != protected-read ]] || emit_env SCCACHE_S3_RW_MODE READ_ONLY
    emit_env SCCACHE_MULTILEVEL_CHAIN disk,s3
    emit_env SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY ignore
    emit_env SCCACHE_IGNORE_SERVER_IO_ERROR 1
  fi
fi
printf 'CODEWIRE_CI_CACHE scope=workspace compiler=%s layers=%s trust=%s\n' "$rust_mode" "$layer_mode" "$trust"
