#!/usr/bin/env bash
# Shared Chromium version and renderer-backing preflight. Source this file.

playwright_snapshot_os_release() {
  if [ ! -r /etc/os-release ]; then
    return 1
  fi

  (
    # shellcheck disable=SC1091
    source /etc/os-release
    printf '%s-%s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}"
  )
}

playwright_snapshot_package_version() {
  dpkg-query -W -f='${Version}' "$1" 2>/dev/null
}

playwright_snapshot_fonts_config_sha256() {
  sha256sum /etc/fonts/fonts.conf 2>/dev/null | awk '{ print $1 }'
}

playwright_snapshot_font_files_sha256() {
  fc-list --format '%{file}\n' 2>/dev/null \
    | LC_ALL=C sort -u \
    | while IFS= read -r font_file; do
        [ -n "$font_file" ] && sha256sum "$font_file"
      done \
    | sha256sum \
    | awk '{ print $1 }'
}

verify_playwright_snapshot_runtime() {
  local snapshot_environment="${CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV:-}"
  local actual_os actual_version actual_fonts_config actual_font_files
  local package expected_version

  case "$snapshot_environment" in
    '')
      printf '[playwright-browser] snapshot_env=platform-auto\n'
      return 0
      ;;
    ubuntu24-cft145)
      ;;
    *)
      echo "::error::unsupported explicit Playwright snapshot environment: ${snapshot_environment}"
      return 1
      ;;
  esac

  actual_os="$(playwright_snapshot_os_release || true)"
  if [ "$actual_os" != ubuntu-24.04 ]; then
    echo "::error::Playwright snapshot environment ubuntu24-cft145 requires Ubuntu 24.04; found ${actual_os:-unreadable}"
    return 1
  fi

  while IFS='=' read -r package expected_version; do
    actual_version="$(playwright_snapshot_package_version "$package" || true)"
    if [ "$actual_version" != "$expected_version" ]; then
      echo "::error::Playwright snapshot environment ubuntu24-cft145 requires ${package}=${expected_version}; found ${actual_version:-unreadable}"
      return 1
    fi
  done <<'EOF'
fontconfig=2.15.0-1.1ubuntu2
libfontconfig1=2.15.0-1.1ubuntu2
libfreetype6=2.13.2+dfsg-1ubuntu0.1
EOF

  actual_fonts_config="$(playwright_snapshot_fonts_config_sha256 || true)"
  if [ "$actual_fonts_config" != 93a23ba073996edb8b42d6c89ebc2ec5fd2101ce82cb65ba0db358dabf55ca22 ]; then
    echo "::error::Playwright snapshot environment ubuntu24-cft145 has an unexpected Fontconfig configuration"
    return 1
  fi

  actual_font_files="$(playwright_snapshot_font_files_sha256 || true)"
  if [ "$actual_font_files" != 1b870a4e39c927334f6efc08fdd849094ac4f1eeb47209636c43e6c89feb6084 ]; then
    echo "::error::Playwright snapshot environment ubuntu24-cft145 has an unexpected font inventory"
    return 1
  fi

  printf '[playwright-browser] snapshot_env=ubuntu24-cft145, renderer=ubuntu-24.04-fonts-v1\n'
}

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

  verify_playwright_snapshot_runtime || return 1

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
