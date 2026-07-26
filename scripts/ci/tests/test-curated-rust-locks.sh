#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GUARD="$ROOT/scripts/ci/verify/check-curated-rust-locks.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/codewire-test-curated-rust-locks.XXXXXX")"

cleanup() {
  rm -rf -- "$TMP"
}
trap cleanup EXIT

pass_log="$TMP/pass.log"
"$GUARD" >"$pass_log"
grep -qF '[curated-rust-locks] gateway: OK' "$pass_log"
grep -qF '[curated-rust-locks] derp: OK' "$pass_log"

fixture_dir="$TMP/fixture"
mkdir -p "$fixture_dir"
cp "$ROOT"/deployments/docker/*.Cargo.toml "$fixture_dir/"
cp "$ROOT"/deployments/docker/*.Cargo.lock "$fixture_dir/"

stale_lock="$fixture_dir/gateway.Cargo.lock"
sed '/^name = "codewire-gateway"$/,/^]$/ {
  /^ "uuid",$/d
}' "$ROOT/deployments/docker/gateway.Cargo.lock" >"$stale_lock"

stale_log="$TMP/stale.log"
if CURATED_RUST_MANIFEST_DIR="$fixture_dir" "$GUARD" >"$stale_log" 2>&1; then
  echo 'curated Rust lock guard accepted a stale gateway lock' >&2
  exit 1
fi
grep -qF 'curated Rust workspace gateway has manifest/lock drift' "$stale_log"
grep -qF 'cannot update the lock file' "$stale_log"
grep -qF -- '--locked was passed' "$stale_log"

printf 'curated Rust workspace lock fixtures: stale gateway rejected; current derp/gateway green\n'
