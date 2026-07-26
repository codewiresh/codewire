#!/usr/bin/env bash
# Keep Go tailnet behavior and the Rust tailnet port in lockstep.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

echo "::group::Go tailnet parity fixture"
(
  cd libs/tailnet
  GOWORK=off go test ./... -run TestTailnetParityFixture -count=1
)
echo "::endgroup::"

echo "::group::Rust tailnet parity, checksum, and MTU gates"
cargo test -p codewire-tailnet -- --nocapture
echo "::endgroup::"
