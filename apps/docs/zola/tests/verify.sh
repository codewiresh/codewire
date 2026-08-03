#!/usr/bin/env bash
set -euo pipefail

site_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
zola_bin="${ZOLA_BIN:-zola}"
if [[ "$($zola_bin --version)" != "zola 0.22.1" ]]; then
  echo "Zola 0.22.1 is required" >&2
  exit 1
fi

output_a="$(mktemp -d /tmp/codewire-zola-output-a.XXXXXX)"
output_b="$(mktemp -d /tmp/codewire-zola-output-b.XXXXXX)"
cleanup() {
  rm -rf -- "$output_a" "$output_b"
}
trap cleanup EXIT

(
  cd "$site_root"
  "$zola_bin" check --skip-external-links
)
ZOLA_BIN="$zola_bin" "$site_root/build.sh" "$output_a"
ZOLA_BIN="$zola_bin" "$site_root/build.sh" "$output_b"

manifest_a="$output_a.sha256"
manifest_b="$output_b.sha256"
(
  cd "$output_a"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) >"$manifest_a"
(
  cd "$output_b"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) >"$manifest_b"
trap 'rm -rf -- "$output_a" "$output_b"; rm -f -- "$manifest_a" "$manifest_b"' EXIT
diff -u "$manifest_a" "$manifest_b"

python3 "$site_root/tests/verify_site.py" --site-root "$site_root" --output "$output_a"
