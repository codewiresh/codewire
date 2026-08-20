#!/usr/bin/env bash
# Report best-effort compiler-cache evidence and remove its private credential.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'usage: finish-untrusted-rust-cache.sh AWS_CREDENTIALS_FILE' >&2
  exit 2
fi

readonly credentials_file="$1"
: "${RUNNER_TEMP:?Forgejo runner temporary directory is required}"
case "$credentials_file" in
  "$RUNNER_TEMP"/*) ;;
  *)
    echo 'host Rust cache cleanup path must remain below RUNNER_TEMP' >&2
    exit 2
    ;;
esac

case "${CODEWIRE_SCCACHE_MODE:-disabled}" in
  local|r2)
    if command -v sccache >/dev/null 2>&1; then
      sccache --show-stats \
        || echo '::warning::sccache statistics were unavailable during cleanup'
      sccache --stop-server >/dev/null 2>&1 || true
    fi
    ;;
  disabled) ;;
  *) echo '::warning::unknown sccache mode during cleanup' ;;
esac

if [[ -f "$credentials_file" && ! -L "$credentials_file" ]]; then
  shred -u -- "$credentials_file"
fi
printf 'CODEWIRE_CI_CACHE cleanup=complete mode=%s\n' \
  "${CODEWIRE_SCCACHE_MODE:-disabled}"
