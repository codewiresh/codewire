#!/usr/bin/env bash
# Keep the Rust tailnet port on Tailscale's wire formats: the Go golden proves
# the checked-in vectors still match the pinned tailscale.com, and the Rust
# tests prove the port matches the vectors.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/ci/verify/local-rust-cache.sh
source "$ROOT/scripts/ci/verify/local-rust-cache.sh"
select_local_rust_cache "$ROOT" || true

echo "::group::Tailscale wire-format golden (tailscale.com)"
(
  cd tests/contract
  GOWORK=off go test ./tailscalegolden/ -count=1
)
echo "::endgroup::"

echo "::group::Rust tailnet golden, parity, checksum, and MTU gates"
cargo test -p codewire-tailnet -- --nocapture
echo "::endgroup::"
