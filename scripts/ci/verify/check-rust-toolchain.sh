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

readonly TOOLCHAIN_ACTION='https://forgejo.example.invalid/noel/rust-toolchain@b3b07ba8b418998c39fb20f53e8b695cdcc8de1b'
readonly SEALED_TOOLCHAIN_STEP='name: Verify sealed Rust toolchain'
# These are matched literally against Gitea workflow syntax.
# shellcheck disable=SC2016
readonly CI_RUST_CARGO_HOME='${{ github.workspace }}/target/ci-rust-cargo-home'
# shellcheck disable=SC2016
readonly CI_CARGO_CAPACITY_CHECK='scripts/ci/setup/assert-cargo-cache-capacity.sh "$CARGO_HOME"'
readonly -a PINNED_WORKFLOWS=(
  '.gitea/workflows/ci.yaml:6'
  '.gitea/workflows/claude-e2e.yaml:1'
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
  printf '%s\n' "$CANARY_WORKFLOW" "$WORKSPACE_DOCKERFILE"
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

rust_transport_block="$(sed -n '/^  rust-transport:/,/^  database-services:/p' \
  "$ROOT/.gitea/workflows/ci.yaml")"
[[ "$(grep -Fxc "      CARGO_HOME: $CI_RUST_CARGO_HOME" <<<"$rust_transport_block" || true)" -eq 1 ]] ||
  die 'primary Rust CI job must isolate CARGO_HOME on the job workspace'
[[ "$(grep -Fxc "        run: $CI_CARGO_CAPACITY_CHECK" <<<"$rust_transport_block" || true)" -eq 1 ]] ||
  die 'primary Rust CI job must verify Cargo cache capacity before Cargo verification'

[[ "$(grep -Fc "uses: $TOOLCHAIN_ACTION" "$ROOT/$CANARY_WORKFLOW" || true)" -eq 1 ]] ||
  die 'latest-stable canary action pin drift'
[[ "$(grep -Ec '^[[:space:]]+toolchain:[[:space:]]+stable$' "$ROOT/$CANARY_WORKFLOW" || true)" -eq 1 ]] ||
  die 'latest-stable canary must be the single moving toolchain consumer'
grep -Fq 'continue-on-error: true' "$ROOT/$CANARY_WORKFLOW" ||
  die 'latest-stable canary must remain non-authoritative'
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
  -E 'toolchain:[[:space:]]+stable' "$ROOT/.gitea/workflows" || true)

rust_image="rust:${channel}-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33"
for dockerfile in "${SHIPPED_RUST_DOCKERFILES[@]}"; do
  [[ "$(grep -Fxc "ARG RUST_IMAGE=$rust_image" "$ROOT/$dockerfile" || true)" -eq 1 ]] ||
    die "$dockerfile does not declare exactly one $rust_image builder input"
  # The Dockerfile variable reference is intentionally matched literally.
  # shellcheck disable=SC2016
  [[ "$(grep -Fc 'FROM ${RUST_IMAGE}' "$ROOT/$dockerfile" || true)" -ge 1 ]] ||
    die "$dockerfile does not consume its reviewed Rust image"
done
[[ "$(grep -Fc "FROM rust:${channel}-slim-bookworm@sha256:" "$ROOT/$WORKSPACE_DOCKERFILE" || true)" -eq 1 ]] ||
  die "workspace build-stage compiler differs from $channel"
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
  "$((${#SHIPPED_RUST_DOCKERFILES[@]} + 1))"
