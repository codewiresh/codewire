#!/usr/bin/env bash
# Resolve the exact ShellCheck used by the repository policy gate.
set -euo pipefail

readonly SHELLCHECK_VERSION=0.11.0
readonly SHELLCHECK_ARCHIVE_SHA256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
readonly SHELLCHECK_ARCHIVE="shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz"
readonly SHELLCHECK_URL="https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/${SHELLCHECK_ARCHIVE}"

shellcheck_version() {
  "$1" --version | awk '$1 == "version:" { print $2; exit }'
}

accept_exact_binary() {
  local binary="$1"

  [[ -x "$binary" ]] || return 1
  [[ "$(shellcheck_version "$binary")" == "$SHELLCHECK_VERSION" ]] || return 1
  printf '%s\n' "$binary"
}

if [[ -n "${SHELLCHECK_BIN:-}" ]]; then
  accept_exact_binary "$SHELLCHECK_BIN" || {
    printf 'SHELLCHECK_BIN must be executable ShellCheck %s: %s\n' \
      "$SHELLCHECK_VERSION" "$SHELLCHECK_BIN" >&2
    exit 1
  }
  exit 0
fi

if system_shellcheck="$(command -v shellcheck 2>/dev/null)" \
    && accept_exact_binary "$system_shellcheck"; then
  exit 0
fi

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  printf 'the pinned ShellCheck bootstrap supports Linux x86_64 only\n' >&2
  exit 1
}

cache_parent="${SHELLCHECK_CACHE_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}}"
install_dir="$cache_parent/codewire-shellcheck-v${SHELLCHECK_VERSION}-linux-x86_64"
installed_binary="$install_dir/shellcheck"
if accept_exact_binary "$installed_binary"; then
  exit 0
fi

mkdir -p "$install_dir"
archive_path="$(mktemp "$install_dir/archive.XXXXXX.tar.xz")"
cleanup() {
  rm -f -- "$archive_path"
}
trap cleanup EXIT

curl -fsSL --retry 3 --output "$archive_path" "$SHELLCHECK_URL"
printf '%s  %s\n' "$SHELLCHECK_ARCHIVE_SHA256" "$archive_path" | sha256sum -c - >&2
tar -xJf "$archive_path" --strip-components=1 -C "$install_dir"
accept_exact_binary "$installed_binary" || {
  printf 'downloaded ShellCheck did not report version %s\n' "$SHELLCHECK_VERSION" >&2
  exit 1
}
