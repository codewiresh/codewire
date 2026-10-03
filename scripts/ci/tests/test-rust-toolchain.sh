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

sed -i "s/^readonly rust_version=.*/readonly rust_version='stable'/" \
  "$fixture/scripts/ci/setup/assert-ci-runner-image.sh"
if "$CHECK" --root "$fixture" >"$fixture/runner-toolchain-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted sealed runner compiler drift\n' >&2
  exit 1
fi
grep -Fq 'sealed CI runner compiler differs from' "$fixture/runner-toolchain-drift.log"
cp "$ROOT/scripts/ci/setup/assert-ci-runner-image.sh" \
  "$fixture/scripts/ci/setup/assert-ci-runner-image.sh"

sed -i "s/^readonly REQUIRED_RUST=.*/readonly REQUIRED_RUST='stable'/" \
  "$fixture/scripts/ci/verify/build-local-vmm-initramfs.sh"
if "$CHECK" --root "$fixture" >"$fixture/guest-toolchain-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted local VMM guest compiler drift\n' >&2
  exit 1
fi
grep -Fq 'local VMM guest builder compiler differs from' "$fixture/guest-toolchain-drift.log"
cp "$ROOT/scripts/ci/verify/build-local-vmm-initramfs.sh" \
  "$fixture/scripts/ci/verify/build-local-vmm-initramfs.sh"

sed -i 's/4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' \
  "$fixture/.gitea/workflows/rust-latest-canary.yaml"
if "$CHECK" --root "$fixture" >"$fixture/canary-rustup-digest.log" 2>&1; then
  printf 'Rust toolchain guard accepted canary rustup digest drift\n' >&2
  exit 1
fi
grep -Fq 'latest-stable canary rustup digest drift' \
  "$fixture/canary-rustup-digest.log"
cp "$ROOT/.gitea/workflows/rust-latest-canary.yaml" \
  "$fixture/.gitea/workflows/rust-latest-canary.yaml"

sed -i 's/--default-toolchain stable/--default-toolchain 1.93.0/' \
  "$fixture/.gitea/workflows/rust-latest-canary.yaml"
if "$CHECK" --root "$fixture" >"$fixture/canary-moving-stable.log" 2>&1; then
  printf 'Rust toolchain guard accepted a pinned canary toolchain\n' >&2
  exit 1
fi
grep -Fq 'latest-stable canary must be the single moving toolchain consumer' \
  "$fixture/canary-moving-stable.log"
cp "$ROOT/.gitea/workflows/rust-latest-canary.yaml" \
  "$fixture/.gitea/workflows/rust-latest-canary.yaml"

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

sed -i '0,/rust:1.93.0-bookworm/s//rust:1.93-bookworm/' \
  "$fixture/deployments/docker/rust-base.Dockerfile"
if "$CHECK" --root "$fixture" >"$fixture/builder-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted shipped-builder drift\n' >&2
  exit 1
fi
grep -Fq 'deployments/docker/rust-base.Dockerfile does not declare exactly one reviewed rust:1.93.0-bookworm@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382 input' \
  "$fixture/builder-drift.log"
sed -i '0,/rust:1.93-bookworm/s//rust:1.93.0-bookworm/' \
  "$fixture/deployments/docker/rust-base.Dockerfile"

sed -i 's/^ARG RUST_IMAGE=.*/ARG RUST_IMAGE=rust:stable-bookworm/' \
  "$fixture/apps/dashboard/Dockerfile"
if "$CHECK" --root "$fixture" >"$fixture/docs-builder-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted dashboard docs builder drift\n' >&2
  exit 1
fi
grep -Fq 'dashboard docs builder does not select the reviewed' "$fixture/docs-builder-drift.log"
cp "$ROOT/apps/dashboard/Dockerfile" "$fixture/apps/dashboard/Dockerfile"

sed -i "s/^readonly rust_build_digest=.*/readonly rust_build_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'/" \
  "$fixture/scripts/checks/security/audit-runtime-images.sh"
if "$CHECK" --root "$fixture" >"$fixture/runtime-audit-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted runtime audit foundation drift\n' >&2
  exit 1
fi
grep -Fq 'runtime image audit Rust build digest differs from' "$fixture/runtime-audit-drift.log"
cp "$ROOT/scripts/checks/security/audit-runtime-images.sh" \
  "$fixture/scripts/checks/security/audit-runtime-images.sh"

sed -i 's/@sha256:[0-9a-f]\{64\} AS cw-toolchain$/@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS cw-toolchain/' \
  "$fixture/images/workspace/Dockerfile"
if "$CHECK" --root "$fixture" >"$fixture/workspace-digest-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted an unreviewed workspace compiler digest\n' >&2
  exit 1
fi
grep -Fq 'workspace build-stage compiler differs from' "$fixture/workspace-digest-drift.log"
cp "$ROOT/images/workspace/Dockerfile" "$fixture/images/workspace/Dockerfile"

sed -i '0,/rust-version = "1.93.0"/s//rust-version = "1.92.0"/' \
  "$fixture/crates/codewire-desktop/Cargo.toml"
if "$CHECK" --root "$fixture" >"$fixture/msrv-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted detached-package MSRV drift\n' >&2
  exit 1
fi
grep -Fq 'crates/codewire-desktop/Cargo.toml must declare exact Rust 1.93.0' \
  "$fixture/msrv-drift.log"
sed -i '0,/rust-version = "1.92.0"/s//rust-version = "1.93.0"/' \
  "$fixture/crates/codewire-desktop/Cargo.toml"

sed -i '0,/\/usr\/local\/rustup\/ \/home\/codewire\/\.rustup\//s//\/usr\/local\/rustup\/ \/home\/codewire\/\.rustup-stable\//' \
  "$fixture/images/workspace/Dockerfile"
if "$CHECK" --root "$fixture" >"$fixture/workspace-drift.log" 2>&1; then
  printf 'Rust toolchain guard accepted workspace-user drift\n' >&2
  exit 1
fi
grep -Fq 'workspace user Rustup home does not come from the exact 1.93.0 build stage' \
  "$fixture/workspace-drift.log"

cp "$ROOT/images/workspace/Dockerfile" "$fixture/images/workspace/Dockerfile"
printf '\nRUN curl -fsSL https://sh.rustup.rs | sh\n' >>"$fixture/images/workspace/Dockerfile"
if "$CHECK" --root "$fixture" >"$fixture/workspace-installer.log" 2>&1; then
  printf 'Rust toolchain guard accepted the mutable workspace Rustup installer\n' >&2
  exit 1
fi
grep -Fq 'workspace user toolchain must not use the mutable Rustup network installer' \
  "$fixture/workspace-installer.log"

cp "$ROOT/images/workspace/Dockerfile" "$fixture/images/workspace/Dockerfile"
sed -i '/RUN rustup component add --toolchain 1.93.0 rustfmt clippy/d' \
  "$fixture/images/workspace/Dockerfile"
if "$CHECK" --root "$fixture" >"$fixture/workspace-components.log" 2>&1; then
  printf 'Rust toolchain guard accepted missing workspace components\n' >&2
  exit 1
fi
grep -Fq 'workspace build stage does not select exact 1.93.0 rustfmt and clippy components' \
  "$fixture/workspace-components.log"

printf 'Rust toolchain drift fixtures: OK\n'
