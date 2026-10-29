#!/usr/bin/env bash
# Shared Chromium version and browser-backing preflight. Source this file.

prepare_playwright_browser_runtime() {
  local chromium="$1" root="$2"
  local expected_version actual_version temp_path temp_real
  local dev_shm_available_kib temp_available_kib

  expected_version="$(sed -n "s/^readonly chromium_version='\([^']*\)'/\1/p" \
    "$root/scripts/ci/install-pinned-playwright-chromium.sh")"
  actual_version="$(
    "$chromium" --version 2>/dev/null \
      | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
      | head -n 1 \
      || true
  )"
  if [ -z "$expected_version" ] || [ "$actual_version" != "$expected_version" ]; then
    echo "::error::dashboard browser version is ${actual_version:-unreadable}; expected pinned Chromium ${expected_version:-unreadable}. Set PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH to scripts/ci/install-pinned-playwright-chromium.sh output"
    return 1
  fi

  temp_path="${TMPDIR:-/tmp}"
  if [ ! -d "$temp_path" ] || [ ! -w "$temp_path" ]; then
    echo "::error::dashboard browser temp root is not a writable directory: ${temp_path}"
    return 1
  fi
  temp_real="$(realpath -e "$temp_path")"
  if [ "${#temp_real}" -gt 48 ]; then
    echo "::error::dashboard browser temp root is too long for Chromium IPC paths (${#temp_real} > 48): ${temp_real}"
    return 1
  fi

  dev_shm_available_kib=""
  if [ -d /dev/shm ] && [ -w /dev/shm ]; then
    dev_shm_available_kib="$(df -Pk /dev/shm | awk 'END { print $4 }')"
  fi
  if [[ "$dev_shm_available_kib" =~ ^[0-9]+$ ]] \
      && [ "$dev_shm_available_kib" -ge 1048576 ]; then
    export CODEWIRE_PLAYWRIGHT_USE_DEV_SHM=1
    printf '[playwright-browser] runtime: Chromium %s, backing=/dev/shm, available_kib=%s\n' \
      "$actual_version" "$dev_shm_available_kib"
    return 0
  fi

  temp_available_kib="$(df -Pk "$temp_real" | awk 'END { print $4 }')"
  if ! [[ "$temp_available_kib" =~ ^[0-9]+$ ]]; then
    echo "::error::unable to read available browser backing capacity at ${temp_real}"
    return 1
  fi
  if [ "$temp_available_kib" -lt 1048576 ]; then
    echo "::error::browser backing filesystem ${temp_real} has ${temp_available_kib} KiB available; at least 1048576 KiB is required"
    return 1
  fi

  export CODEWIRE_PLAYWRIGHT_USE_DEV_SHM=0
  printf '[playwright-browser] runtime: Chromium %s, backing=%s, available_kib=%s\n' \
    "$actual_version" "$temp_real" "$temp_available_kib"
}

# Print the Chromium a browser gate runs: an explicit
# PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH, else the pinned build already unpacked
# in this checkout's .tmp/, else the pinned archive verified and unpacked there
# by scripts/ci/install-pinned-playwright-chromium.sh. The verified archive is
# kept in a per-user cache, so another checkout unpacks it without
# downloading; the installer checks its digest on every use. The browser
# itself always runs from inside the checkout, where the workstation's
# loopback firewall rules expect it.
resolve_pinned_playwright_chromium() {
  local root="$1" installer expected candidate cache archive chromium
  if [ -n "${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}" ]; then
    printf '%s\n' "$PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"
    return 0
  fi
  installer="$root/scripts/ci/install-pinned-playwright-chromium.sh"
  expected="$(sed -n "s/^readonly chromium_version='\([^']*\)'/\1/p" "$installer")"
  [ -n "$expected" ] || return 1
  for candidate in "$root"/.tmp/playwright-chromium.*/chrome-linux64/chrome; do
    if [ -x "$candidate" ] && "$candidate" --version 2>/dev/null | grep -Fq " $expected"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  cache="${CODEWIRE_CHROMIUM_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/codewire/chrome-for-testing}/${expected}"
  archive="$cache/chrome-linux64.zip"
  if [ -f "$archive" ] \
      && chromium="$(CODEWIRE_CHROMIUM_ARCHIVE="$archive" "$installer")"; then
    printf '%s\n' "$chromium"
    return 0
  fi
  chromium="$("$installer")" || return $?
  # Caching is an optimization; a failure here leaves the next run to download.
  if mkdir -p "$cache" \
      && cp "${chromium%/chrome-linux64/chrome}/chrome-linux64.zip" "$archive.$$"; then
    mv -f "$archive.$$" "$archive" || rm -f "$archive.$$"
  fi
  printf '%s\n' "$chromium"
}
