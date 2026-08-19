#!/usr/bin/env bash
# Keep the supported compiler, package MSRV, primary CI, and shipped builders aligned.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LIST_INPUTS=false

usage() {
  printf 'usage: check-rust-toolchain.sh [--root PATH] [--list-inputs]\n' >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 ]] || {
        usage
        exit 2
      }
      ROOT="$2"
      shift 2
      ;;
    --list-inputs)
      LIST_INPUTS=true
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done
ROOT="$(cd "$ROOT" && pwd)"

readonly SEALED_TOOLCHAIN_STEP='name: Verify sealed Rust toolchain'
readonly CANARY_RUSTUP_VERSION='1.29.0'
readonly CANARY_RUSTUP_SHA256='4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10'
# These are matched literally against Gitea workflow syntax.
# shellcheck disable=SC2016
readonly CI_RUST_CARGO_HOME='${{ github.workspace }}/target/ci-rust-cargo-home'
# shellcheck disable=SC2016
readonly CI_CARGO_CAPACITY_CHECK='scripts/ci/setup/assert-cargo-cache-capacity.sh "$CARGO_HOME"'
readonly -a PINNED_WORKFLOWS=(
  '.gitea/workflows/ci.yaml:8'
  '.gitea/workflows/cli-release.yaml:1'
  '.gitea/workflows/connect-apikey-smoke.yaml:1'
  '.gitea/workflows/deploy-dev.yaml:1'
  '.gitea/workflows/manual-diagnostics.yaml:1'
  '.gitea/workflows/support-images.yaml:1'
)
readonly CANARY_WORKFLOW='.gitea/workflows/rust-latest-canary.yaml'
readonly -a SHIPPED_RUST_DOCKERFILES=(
  'apps/dashboard/Dockerfile'
  'deployments/docker/derp.Dockerfile'
  'deployments/docker/gateway.Dockerfile'
  'deployments/docker/mesh.Dockerfile'
  'deployments/docker/services.Dockerfile'
)
readonly RUST_BUILD_BASE_DOCKERFILE='deployments/docker/rust-base.Dockerfile'
readonly RUST_BUILD_WRAPPER='scripts/ci/images/run-rust-build.sh'
readonly BAKE_FILE='docker-bake.hcl'
readonly WORKSPACE_DOCKERFILE='images/workspace/Dockerfile'
readonly -a CURATED_MANIFESTS=(
  'deployments/docker/derp.Cargo.toml'
  'deployments/docker/gateway.Cargo.toml'
)
readonly -a DETACHED_MANIFESTS=(
  'crates/codewire-desktop/Cargo.toml'
  'crates/codewire-platform-native/Cargo.toml'
  'crates/codewire-ui/Cargo.toml'
)

die() {
  printf '[rust-toolchain] ERROR: %s\n' "$*" >&2
  exit 1
}

is_detached_manifest() {
  local candidate="$1"
  local detached
  for detached in "${DETACHED_MANIFESTS[@]}"; do
    [[ "$candidate" == "$detached" ]] && return 0
  done
  return 1
}

list_inputs() {
  local entry

  printf '%s\n' rust-toolchain.toml Cargo.toml
  for entry in "${PINNED_WORKFLOWS[@]}"; do
    printf '%s\n' "${entry%:*}"
  done
  printf '%s\n' "$CANARY_WORKFLOW" "$WORKSPACE_DOCKERFILE" \
    "$RUST_BUILD_BASE_DOCKERFILE" "$RUST_BUILD_WRAPPER" "$BAKE_FILE"
  printf '%s\n' "${SHIPPED_RUST_DOCKERFILES[@]}" "${CURATED_MANIFESTS[@]}"
  find "$ROOT/crates" -mindepth 2 -maxdepth 2 -name Cargo.toml -printf '%P\n' \
    | sed 's#^#crates/#'
}

if [[ "$LIST_INPUTS" == true ]]; then
  list_inputs | LC_ALL=C sort -u
  exit 0
fi

while IFS= read -r input; do
  [[ -f "$ROOT/$input" ]] || die "missing required input: $input"
done < <(list_inputs)

channel="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' \
  "$ROOT/rust-toolchain.toml")"
[[ "$channel" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "rust-toolchain.toml channel must be one exact release, got: ${channel:-missing}"
[[ "$(grep -Fxc 'components = ["clippy", "rustfmt"]' "$ROOT/rust-toolchain.toml" || true)" -eq 1 ]] ||
  die 'rust-toolchain.toml must install the clippy and rustfmt baseline components'
[[ "$(grep -Fxc 'profile = "minimal"' "$ROOT/rust-toolchain.toml" || true)" -eq 1 ]] ||
  die 'rust-toolchain.toml must use the minimal profile'

workspace_pin="rust-version = \"$channel\""
[[ "$(grep -Fxc "$workspace_pin" "$ROOT/Cargo.toml" || true)" -eq 1 ]] ||
  die "root workspace Rust version differs from $channel"

while IFS= read -r manifest; do
  if is_detached_manifest "$manifest"; then
    [[ "$(grep -Fxc "$workspace_pin" "$ROOT/$manifest" || true)" -eq 1 ]] ||
      die "$manifest must declare exact Rust $channel"
    [[ "$(grep -Fxc 'rust-version.workspace = true' "$ROOT/$manifest" || true)" -eq 0 ]] ||
      die "$manifest must not inherit from the excluded root workspace"
  else
    [[ "$(grep -Fxc 'rust-version.workspace = true' "$ROOT/$manifest" || true)" -eq 1 ]] ||
      die "$manifest must inherit the workspace Rust version"
    [[ "$(grep -Fxc "$workspace_pin" "$ROOT/$manifest" || true)" -eq 0 ]] ||
      die "$manifest duplicates the workspace Rust version"
  fi
done < <(find "$ROOT/crates" -mindepth 2 -maxdepth 2 -name Cargo.toml -printf '%P\n' \
  | sed 's#^#crates/#' | LC_ALL=C sort)

for manifest in "${CURATED_MANIFESTS[@]}"; do
  [[ "$(grep -Fxc "$workspace_pin" "$ROOT/$manifest" || true)" -eq 1 ]] ||
    die "$manifest Rust version differs from $channel"
done

for entry in "${PINNED_WORKFLOWS[@]}"; do
  workflow="${entry%:*}"
  expected_count="${entry##*:}"
  assertion_count="$(grep -Fc "$SEALED_TOOLCHAIN_STEP" "$ROOT/$workflow" || true)"
  action_count="$(grep -Fc 'rust-toolchain@' "$ROOT/$workflow" || true)"
  [[ "$assertion_count" -eq "$expected_count" && "$action_count" -eq 0 ]] ||
    die "$workflow sealed toolchain drift (assertions=$assertion_count actions=$action_count expected=$expected_count)"
done

rust_transport_block="$(sed -n '/^  rust-transport:/,/^  database:/p' \
  "$ROOT/.gitea/workflows/ci.yaml")"
[[ "$(grep -Fxc "      CARGO_HOME: $CI_RUST_CARGO_HOME" <<<"$rust_transport_block" || true)" -eq 1 ]] ||
  die 'primary Rust CI job must isolate CARGO_HOME on the job workspace'
[[ "$(grep -Fxc "        run: $CI_CARGO_CAPACITY_CHECK" <<<"$rust_transport_block" || true)" -eq 1 ]] ||
  die 'primary Rust CI job must verify Cargo cache capacity before Cargo verification'

[[ "$(grep -Fxc "  RUSTUP_VERSION: $CANARY_RUSTUP_VERSION" "$ROOT/$CANARY_WORKFLOW" || true)" -eq 1 ]] ||
  die 'latest-stable canary rustup version drift'
[[ "$(grep -Fxc "  RUSTUP_INIT_SHA256: $CANARY_RUSTUP_SHA256" "$ROOT/$CANARY_WORKFLOW" || true)" -eq 1 ]] ||
  die 'latest-stable canary rustup digest drift'
# Match the workflow shell variable literally.
# shellcheck disable=SC2016
[[ "$(grep -Fc 'rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init' "$ROOT/$CANARY_WORKFLOW" || true)" -eq 1 ]] ||
  die 'latest-stable canary must download only the reviewed rustup-init archive'
[[ "$(grep -Fc 'sha256sum --check --strict' "$ROOT/$CANARY_WORKFLOW" || true)" -eq 1 ]] ||
  die 'latest-stable canary must verify rustup-init before execution'
[[ "$(grep -Fc -- '--default-toolchain stable --no-modify-path' "$ROOT/$CANARY_WORKFLOW" || true)" -eq 1 ]] ||
  die 'latest-stable canary must be the single moving toolchain consumer'
[[ "$(grep -Fc 'rust-toolchain@' "$ROOT/$CANARY_WORKFLOW" || true)" -eq 0 ]] ||
  die 'latest-stable canary must not ask the sealed runner action to mutate Rust'
grep -Fq 'continue-on-error: true' "$ROOT/$CANARY_WORKFLOW" ||
  die 'latest-stable canary must remain non-authoritative'
grep -Fq 'runs-on: ci-heavy' "$ROOT/$CANARY_WORKFLOW" ||
  die 'latest-stable canary must use the credential-free heavy profile'
grep -Fq 'cargo +stable check --locked --workspace --all-targets' "$ROOT/$CANARY_WORKFLOW" ||
  die 'latest-stable canary must override the repository toolchain file explicitly'
if grep -Fq 'pull_request:' "$ROOT/$CANARY_WORKFLOW"; then
  die 'latest-stable canary must not become a pull-request gate'
fi

while IFS= read -r workflow; do
  relative="${workflow#"$ROOT/"}"
  [[ "$relative" == "$CANARY_WORKFLOW" ]] ||
    die "moving stable toolchain escaped the canary: $relative"
done < <(grep -Rl --include='*.yaml' --include='*.yml' \
  -E -- '--default-toolchain[[:space:]]+stable' "$ROOT/.gitea/workflows" || true)

rust_build_image="rust:${channel}-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33"
[[ "$(grep -Fxc "ARG RUST_IMAGE=$rust_build_image" "$ROOT/$RUST_BUILD_BASE_DOCKERFILE" || true)" -eq 1 ]] ||
  die "$RUST_BUILD_BASE_DOCKERFILE does not declare exactly one reviewed $rust_build_image input"
grep -Fq "test \"\$(rustc --version)\" = 'rustc ${channel} " \
  "$ROOT/$RUST_BUILD_BASE_DOCKERFILE" ||
  die "$RUST_BUILD_BASE_DOCKERFILE does not verify exact Rust $channel"
grep -Fq 'ADD --checksum=sha256:67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006' \
  "$ROOT/$RUST_BUILD_BASE_DOCKERFILE" ||
  die "$RUST_BUILD_BASE_DOCKERFILE does not checksum-pin reviewed sccache 0.17.0"
grep -Fq "test \"\$(sccache --version)\" = 'sccache 0.17.0'" \
  "$ROOT/$RUST_BUILD_BASE_DOCKERFILE" ||
  die "$RUST_BUILD_BASE_DOCKERFILE does not verify reviewed sccache 0.17.0"
grep -Fq 'export CARGO_INCREMENTAL=0' "$ROOT/$RUST_BUILD_WRAPPER" ||
  die "$RUST_BUILD_WRAPPER must disable incremental compilation for sccache"
grep -Fq 'default = "disabled"' "$ROOT/$BAKE_FILE" ||
  die "$BAKE_FILE must default remote compiler caching to disabled"
for dockerfile in "${SHIPPED_RUST_DOCKERFILES[@]}"; do
  [[ "$(grep -Ec '^FROM codewire-rust-base AS (builder|rust-builder|cw-builder)$' "$ROOT/$dockerfile" || true)" -ge 1 ]] ||
    die "$dockerfile does not build from the shared reviewed Rust build base"
  if grep -Eq 'cargo[ -]chef|recipe\.json' "$ROOT/$dockerfile"; then
    die "$dockerfile must not add cargo-chef ahead of the measured sccache experiment"
  fi
done
[[ "$(grep -Fc "FROM rust:${channel}-slim-bookworm@sha256:" "$ROOT/$WORKSPACE_DOCKERFILE" || true)" -eq 1 ]] ||
  die "workspace build-stage compiler differs from $channel"
[[ "$(grep -Fxc "RUN rustup component add --toolchain ${channel}-x86_64-unknown-linux-gnu rustfmt clippy" "$ROOT/$WORKSPACE_DOCKERFILE" || true)" -eq 1 ]] ||
  die "workspace build stage does not select exact $channel rustfmt and clippy components"
[[ "$(grep -Fxc 'COPY --from=cw-builder --chown=codewire:codewire /usr/local/cargo/ /home/codewire/.cargo/' "$ROOT/$WORKSPACE_DOCKERFILE" || true)" -eq 1 ]] ||
  die "workspace user Cargo home does not come from the exact $channel build stage"
[[ "$(grep -Fxc 'COPY --from=cw-builder --chown=codewire:codewire /usr/local/rustup/ /home/codewire/.rustup/' "$ROOT/$WORKSPACE_DOCKERFILE" || true)" -eq 1 ]] ||
  die "workspace user Rustup home does not come from the exact $channel build stage"
if grep -Fq 'https://sh.rustup.rs' "$ROOT/$WORKSPACE_DOCKERFILE"; then
  die 'workspace user toolchain must not use the mutable Rustup network installer'
fi

printf '[rust-toolchain] exact Rust %s baseline: OK (%s crate manifests, %s sealed runner assertions, %s shipped builders)\n' \
  "$channel" \
  "$(find "$ROOT/crates" -mindepth 2 -maxdepth 2 -name Cargo.toml | wc -l)" \
  "$(printf '%s\n' "${PINNED_WORKFLOWS[@]}" | awk -F: '{ total += $NF } END { print total + 0 }')" \
  "$((${#SHIPPED_RUST_DOCKERFILES[@]} + 2))"
