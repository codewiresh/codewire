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
output_c="$(mktemp -d /tmp/codewire-zola-output-c.XXXXXX)"
manifest_a="$output_a.sha256"
manifest_b="$output_b.sha256"
cleanup() {
  rm -rf -- "$output_a" "$output_b" "$output_c"
  rm -f -- "$manifest_a" "$manifest_b"
}
trap cleanup EXIT

export CODEWIRE_BUILD_TIMESTAMP="2026-11-08T00:00:00Z"
export CODEWIRE_OPENSSF_OFFLINE=1
(
  cd "$site_root"
  "$zola_bin" check --skip-external-links
)
ZOLA_BIN="$zola_bin" "$site_root/build.sh" "$output_a"
ZOLA_BIN="$zola_bin" "$site_root/build.sh" "$output_b"

(
  cd "$output_a"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) >"$manifest_a"
(
  cd "$output_b"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) >"$manifest_b"
diff -u "$manifest_a" "$manifest_b"

python3 "$site_root/tests/verify_site.py" --site-root "$site_root" --output "$output_a"

(
  export CODEWIRE_OPENSSF_OFFLINE=0
  export CODEWIRE_OPENSSF_SCORECARD_PATH="tests/fixtures/scorecard.json"
  export CODEWIRE_OPENSSF_BEST_PRACTICES_PATH="tests/fixtures/best-practices.json"
  ZOLA_BIN="$zola_bin" "$site_root/build.sh" "$output_c"
)
python3 "$site_root/tests/verify_site.py" --site-root "$site_root" --output "$output_c"
python3 "$site_root/tests/verify_security_posture.py" --unavailable "$output_a" --populated "$output_c"
