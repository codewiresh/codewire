#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

readonly chromium_version='145.0.7632.6'
readonly chromium_sha256='b5e3195041af345a668d110f5daf5581961fa3608626ea588c97dd0fe81c4e38'
readonly chromium_url="https://storage.googleapis.com/chrome-for-testing-public/${chromium_version}/linux64/chrome-linux64.zip"

mkdir -p "$ROOT/.tmp"
install_dir="$(mktemp -d "$ROOT/.tmp/playwright-chromium.XXXXXX")"
archive="${CODEWIRE_CHROMIUM_ARCHIVE:-$install_dir/chrome-linux64.zip}"

if [[ -z "${CODEWIRE_CHROMIUM_ARCHIVE:-}" ]]; then
  curl --fail --silent --show-error --location --retry 3 \
    --output "$archive" "$chromium_url"
fi

printf '%s  %s\n' "$chromium_sha256" "$archive" | sha256sum --check --status
unzip -q "$archive" -d "$install_dir"

chromium="$install_dir/chrome-linux64/chrome"
if [[ ! -x "$chromium" ]]; then
  echo "verified Chromium archive did not contain the expected executable" >&2
  exit 1
fi

missing_libraries="$(ldd "$chromium" | awk '/not found/ {print $1}' | LC_ALL=C sort -u)"
if [[ -n "$missing_libraries" ]]; then
  printf 'pinned Chromium cannot run with the immutable CI image; missing libraries:\n%s\n' \
    "$missing_libraries" >&2
  exit 1
fi

printf '%s\n' "$chromium"
