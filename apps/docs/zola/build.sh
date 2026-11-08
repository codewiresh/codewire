#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

site_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
output="$(realpath -m "$1")"
case "$output" in
  /|"$site_root"|"$site_root/content"|"$site_root/templates"|"$site_root/sass"|"$site_root/static"|"$site_root/tests")
    echo "refusing unsafe Zola output directory: $output" >&2
    exit 1
    ;;
esac

zola_bin="${ZOLA_BIN:-zola}"
if [[ "$($zola_bin --version)" != "zola 0.22.1" ]]; then
  echo "Zola 0.22.1 is required" >&2
  exit 1
fi

export CODEWIRE_BUILD_TIMESTAMP="${CODEWIRE_BUILD_TIMESTAMP:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

(
  cd "$site_root"
  "$zola_bin" build --force --output-dir "$output"
)
python3 "$site_root/tests/normalize_output.py" "$output"
python3 "$site_root/export_markdown.py" --site-root "$site_root" "$output"
