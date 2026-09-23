#!/usr/bin/env bash
# Derive every curated image Rust workspace from the root workspace: give each
# shared dependency the root's version requirement, then prune the root
# Cargo.lock to the curated dependency graph. The curated images therefore
# never select a package version that the root lock does not already select.
# Run after changing root Rust dependencies; the curated-lock guard fails on
# any drift.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CARGO_BIN="${CARGO_BIN:-cargo}"
MANIFEST_DIR="${CURATED_RUST_MANIFEST_DIR:-$ROOT/deployments/docker}"
HELPER="$ROOT/scripts/ci/verify/curated_rust_locks.py"
STAGING_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/codewire-sync-curated-rust-locks.XXXXXX")"
trap 'rm -rf -- "$STAGING_ROOT"' EXIT

shopt -s nullglob
manifests=("$MANIFEST_DIR"/*.Cargo.toml)
[ "${#manifests[@]}" -gt 0 ] || {
  printf 'no curated Rust workspace manifests found under %s\n' "$MANIFEST_DIR" >&2
  exit 1
}

python3 "$HELPER" sync-manifests "$ROOT/Cargo.toml" "${manifests[@]}"

for manifest in "${manifests[@]}"; do
  filename="${manifest##*/}"
  name="${filename%.Cargo.toml}"
  stage="$STAGING_ROOT/$name"
  mkdir -p "$stage"
  cp "$manifest" "$stage/Cargo.toml"
  # Seed with the root lock; Cargo keeps its versions and prunes the rest.
  cp "$ROOT/Cargo.lock" "$stage/Cargo.lock"
  ln -s "$ROOT/crates" "$stage/crates"
  ln -s "$ROOT/proto" "$stage/proto"
  ln -s "$ROOT/libs" "$stage/libs"
  "$CARGO_BIN" metadata --format-version 1 --manifest-path "$stage/Cargo.toml" >/dev/null
  cp "$stage/Cargo.lock" "$MANIFEST_DIR/$name.Cargo.lock"
  printf '[curated-rust-locks] %s: derived from the root lock\n' "$name"
done

"$ROOT/scripts/ci/verify/check-curated-rust-locks.sh"
