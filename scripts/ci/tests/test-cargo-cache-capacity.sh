#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/setup/assert-cargo-cache-capacity.sh"
fixture_parent="${CARGO_TARGET_DIR:-$ROOT/target}"
mkdir -p "$fixture_parent"
fixture="$(mktemp -d "$fixture_parent/codewire-cargo-cache-capacity-test.XXXXXX")"
cleanup() {
  rm -rf -- "$fixture"
}
trap cleanup EXIT

make_df_fixture() {
  local path="$1" available_kib="$2" available_inodes="$3"
  sed \
    -e "s/__AVAILABLE_KIB__/$available_kib/" \
    -e "s/__AVAILABLE_INODES__/$available_inodes/" \
    "$ROOT/scripts/ci/tests/fixtures/cargo-cache-df.sh" >"$path"
  chmod +x "$path"
}

make_df_fixture "$fixture/ample-df" 4194304 20000
"$CHECK" \
  --minimum-kib 2097152 \
  --minimum-inodes 10000 \
  --df-bin "$fixture/ample-df" \
  "$fixture/cargo-home" >"$fixture/ample.log"
grep -Fq '[cargo-cache] capacity: OK' "$fixture/ample.log"

make_df_fixture "$fixture/unknown-inodes-df" 4194304 0
"$CHECK" \
  --minimum-kib 2097152 \
  --minimum-inodes 10000 \
  --df-bin "$fixture/unknown-inodes-df" \
  "$fixture/cargo-home" >"$fixture/unknown-inodes.log"
grep -Fq 'inode accounting unavailable' "$fixture/unknown-inodes.log"

make_df_fixture "$fixture/low-space-df" 1048576 20000
if "$CHECK" \
  --minimum-kib 2097152 \
  --minimum-inodes 10000 \
  --df-bin "$fixture/low-space-df" \
  "$fixture/cargo-home" >"$fixture/low-space.log" 2>&1; then
  printf 'Cargo cache capacity guard accepted insufficient space\n' >&2
  exit 1
fi
grep -Fq '[cargo-cache] ERROR: Cargo cache filesystem' "$fixture/low-space.log"
grep -Fq '1048576 KiB available; at least 2097152 KiB is required' "$fixture/low-space.log"

make_df_fixture "$fixture/low-inodes-df" 4194304 5000
if "$CHECK" \
  --minimum-kib 2097152 \
  --minimum-inodes 10000 \
  --df-bin "$fixture/low-inodes-df" \
  "$fixture/cargo-home" >"$fixture/low-inodes.log" 2>&1; then
  printf 'Cargo cache capacity guard accepted insufficient inodes\n' >&2
  exit 1
fi
grep -Fq '[cargo-cache] ERROR: Cargo cache filesystem' "$fixture/low-inodes.log"
grep -Fq '5000 inodes available; at least 10000 are required' "$fixture/low-inodes.log"

make_df_fixture "$fixture/malformed-df" unavailable unavailable
if "$CHECK" \
  --minimum-kib 2097152 \
  --minimum-inodes 10000 \
  --df-bin "$fixture/malformed-df" \
  "$fixture/cargo-home" >"$fixture/malformed.log" 2>&1; then
  printf 'Cargo cache capacity guard accepted malformed df output\n' >&2
  exit 1
fi
grep -Fq '[cargo-cache] ERROR: unable to read available KiB' "$fixture/malformed.log"

if "$CHECK" >"$fixture/usage.log" 2>&1; then
  printf 'Cargo cache capacity guard accepted a missing cache path\n' >&2
  exit 1
fi
grep -Fq 'usage: assert-cargo-cache-capacity.sh' "$fixture/usage.log"

printf 'Cargo cache capacity fixtures: OK\n'
