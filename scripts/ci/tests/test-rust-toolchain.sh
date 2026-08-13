#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/verify/check-rust-toolchain.sh"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/codewire-rust-toolchain-test.XXXXXX")"
cleanup() {
  rm -rf -- "$fixture"
}
trap cleanup EXIT

"$CHECK"
while IFS= read -r input; do
  mkdir -p "$fixture/$(dirname "$input")"
  cp "$ROOT/$input" "$fixture/$input"
done < <("$CHECK" --list-inputs)

sed -i '0,/name: Verify sealed Rust toolchain/s//name: Set up mutable Rust toolchain/' \
  "$fixture/.gitea/workflows/ci.yaml"
if "$CHECK" --root "$fixture" >"$fixture/workflow-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted primary workflow drift\n' >&2
  exit 1
fi
grep -Fq '.gitea/workflows/ci.yaml sealed toolchain drift' \
  "$fixture/workflow-drift.log"
sed -i '0,/name: Set up mutable Rust toolchain/s//name: Verify sealed Rust toolchain/' \
  "$fixture/.gitea/workflows/ci.yaml"

sed -i '/^      CARGO_HOME: \${{ github\.workspace }}\/target\/ci-rust-cargo-home$/d' \
  "$fixture/.gitea/workflows/ci.yaml"
if "$CHECK" --root "$fixture" >"$fixture/cargo-home-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted a shared CI Cargo home\n' >&2
  exit 1
fi
grep -Fq 'primary Rust CI job must isolate CARGO_HOME on the job workspace' \
  "$fixture/cargo-home-drift.log"
cp "$ROOT/.gitea/workflows/ci.yaml" "$fixture/.gitea/workflows/ci.yaml"

# Match the workflow shell variable literally.
# shellcheck disable=SC2016
sed -i '/run: scripts\/ci\/setup\/assert-cargo-cache-capacity\.sh "$CARGO_HOME"/d' \
  "$fixture/.gitea/workflows/ci.yaml"
if "$CHECK" --root "$fixture" >"$fixture/capacity-check-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted a missing CI cache-capacity check\n' >&2
  exit 1
fi
grep -Fq 'primary Rust CI job must verify Cargo cache capacity before Cargo verification' \
  "$fixture/capacity-check-drift.log"
cp "$ROOT/.gitea/workflows/ci.yaml" "$fixture/.gitea/workflows/ci.yaml"

sed -i '0,/rust:1.91.1-bookworm/s//rust:1.91-bookworm/' \
  "$fixture/deployments/docker/services.Dockerfile"
if "$CHECK" --root "$fixture" >"$fixture/builder-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted shipped-builder drift\n' >&2
  exit 1
fi
grep -Fq 'deployments/docker/services.Dockerfile does not declare exactly one rust:1.91.1-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 builder input' \
  "$fixture/builder-drift.log"
sed -i '0,/rust:1.91-bookworm/s//rust:1.91.1-bookworm/' \
  "$fixture/deployments/docker/services.Dockerfile"

sed -i '0,/rust-version = "1.91.1"/s//rust-version = "1.91.0"/' \
  "$fixture/crates/codewire-desktop/Cargo.toml"
if "$CHECK" --root "$fixture" >"$fixture/msrv-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted detached-package MSRV drift\n' >&2
  exit 1
fi
grep -Fq 'crates/codewire-desktop/Cargo.toml must declare exact Rust 1.91.1' \
  "$fixture/msrv-drift.log"
sed -i '0,/rust-version = "1.91.0"/s//rust-version = "1.91.1"/' \
  "$fixture/crates/codewire-desktop/Cargo.toml"

sed -i '0,/\/usr\/local\/rustup\/ \/home\/codewire\/\.rustup\//s//\/usr\/local\/rustup\/ \/home\/codewire\/\.rustup-stable\//' \
  "$fixture/images/workspace/Dockerfile"
if "$CHECK" --root "$fixture" >"$fixture/workspace-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted workspace-user drift\n' >&2
  exit 1
fi
grep -Fq 'workspace user Rustup home does not come from the exact 1.91.1 build stage' \
  "$fixture/workspace-drift.log"

cp "$ROOT/images/workspace/Dockerfile" "$fixture/images/workspace/Dockerfile"
printf '\nRUN curl -fsSL https://sh.rustup.rs | sh\n' >>"$fixture/images/workspace/Dockerfile"
if "$CHECK" --root "$fixture" >"$fixture/workspace-installer.log" 2>&1; then
  printf 'Rust toolchain guard accepted the mutable workspace Rustup installer\n' >&2
  exit 1
fi
grep -Fq 'workspace user toolchain must not use the mutable Rustup network installer' \
  "$fixture/workspace-installer.log"

printf 'Rust toolchain drift fixtures: OK\n'
