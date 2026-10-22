#!/usr/bin/env bash
set -euo pipefail

platform_create_uses_canonical_workspace() {
  grep -Fq 'request.project_spec.image = CANONICAL_WORKSPACE_IMAGE.to_string();' "$1" \
    2>/dev/null
}

if [[ "${1:-}" == '--self-test' ]]; then
  fixture_root="$(mktemp -d)"
  trap 'rm -rf -- "$fixture_root"' EXIT
  canonical="$fixture_root/canonical.rs"
  legacy="$fixture_root/legacy.rs"
  printf '%s\n' \
    'request.project_spec.image = CANONICAL_WORKSPACE_IMAGE.to_string();' >"$canonical"
  printf '%s\n' \
    'request.image = CANONICAL_WORKSPACE_IMAGE.to_string();' >"$legacy"
  platform_create_uses_canonical_workspace "$canonical"
  if platform_create_uses_canonical_workspace "$legacy"; then
    echo 'runtime image audit self-test: legacy source was accepted' >&2
    exit 1
  fi
  if platform_create_uses_canonical_workspace "$fixture_root/missing.rs"; then
    echo 'runtime image audit self-test: missing source was accepted' >&2
    exit 1
  fi
  echo 'runtime image audit self-test: canonical project source accepted; legacy source rejected'
  exit 0
fi
if (( $# != 0 )); then
  echo 'usage: audit-runtime-images.sh [--self-test]' >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

# The workspace digest is the published pin (crates/codewire-workspace-image).
# Orchestration appends it to the repository a deployment configures
# (CODEWIRE_WORKSPACE_IMAGE_REPOSITORY); the CLI's and the dashboard's default
# is the same digest at the public GHCR mirror.
readonly runtime_defaults='crates/codewire-server-core/src/runtime_images.rs'
if ! python3 scripts/ci/images/workspace-image-pin.py show >/dev/null; then
  echo "runtime image audit: the published workspace pin is not well formed" >&2
  exit 1
fi
readonly dind_image='docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c'
rust_channel="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' \
  rust-toolchain.toml)"
if [[ ! "$rust_channel" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "runtime image audit: rust-toolchain.toml must declare one exact release" >&2
  exit 1
fi
readonly rust_channel
readonly rust_build_digest='114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6'
readonly rust_build_image="rust:${rust_channel}-bookworm@sha256:${rust_build_digest}"
readonly debian_runtime_image='debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818'
readonly dashboard_runtime='gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e'
readonly dashboard_dockerfile='apps/dashboard/Dockerfile'
readonly rust_base_dockerfile='deployments/docker/rust-base.Dockerfile'
readonly -a runtime_dockerfiles=(
  "$dashboard_dockerfile"
  'deployments/docker/daemon.Dockerfile'
  'deployments/docker/derp.Dockerfile'
  'deployments/docker/services.Dockerfile'
  'deployments/docker/mesh.Dockerfile'
)

fail=0

# CI tests intentionally model rejected and publication-destination references.
# They are not shipped runtime callers, so keep their fixtures outside these
# repository-wide moving-reference guards.
readonly -a runtime_reference_paths=(
  ':!docs/**'
  ':!scripts/ci/tests/**'
  ':!scripts/checks/security/audit-runtime-images.sh'
)

# A deployment's own workspace repository is configuration, and orchestration
# refuses one with a tag (docs/CONFIGURATION.md).
if moving_workspace="$(git grep -nF -e 'ghcr.io/codewiresh/workspace:latest' -- \
    "${runtime_reference_paths[@]}" || true)" \
  && [[ -n "$moving_workspace" ]]; then
  echo "runtime image audit: moving canonical workspace references are forbidden" >&2
  echo "$moving_workspace" >&2
  fail=1
fi
if moving_dind="$(git grep -nF 'docker:dind' -- \
    "${runtime_reference_paths[@]}" || true)" \
  && [[ -n "$moving_dind" ]]; then
  echo "runtime image audit: upstream moving DinD references are forbidden" >&2
  echo "$moving_dind" >&2
  fail=1
fi
if retired_dind="$(git grep -nF 'ghcr.io/codewiresh/dind' -- \
    "${runtime_reference_paths[@]}" || true)" \
  && [[ -n "$retired_dind" ]]; then
  echo "runtime image audit: retired custom DinD references are forbidden" >&2
  echo "$retired_dind" >&2
  fail=1
fi

for assertion in \
  "crates/codewire-orchestration/src/sandbox/mod.rs:runtime_images::configured().workspace_image()" \
  "crates/codewire-orchestration/src/sandbox/runtime_images.rs:workspace_image::image_at(workspace_repository)" \
  "$runtime_defaults:pub const PUBLIC_WORKSPACE_IMAGE: &str = codewire_workspace_image::PUBLIC_IMAGE;" \
  "crates/codewire-cli/src/commands/collaboration.rs:codewire_workspace_image::PUBLIC_IMAGE" \
  "crates/codewire-orchestration/src/sandbox/template/mod.rs:$dind_image"; do
  path="${assertion%%:*}"
  expected="${assertion#*:}"
  if ! grep -Fq "$expected" "$path"; then
    echo "runtime image audit: canonical runtime default is missing from $path" >&2
    fail=1
  fi
done

if ! platform_create_uses_canonical_workspace \
    crates/codewire-cli/src/commands/environment.rs; then
  echo "runtime image audit: platform create no longer consumes the canonical workspace default" >&2
  fail=1
fi

if ! grep -Fxq "ARG RUST_IMAGE=$rust_build_image" "$rust_base_dockerfile"; then
  echo "runtime image audit: reviewed Rust foundation is missing from $rust_base_dockerfile" >&2
  fail=1
fi
if ! grep -Fq 'ADD --checksum=sha256:67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006' \
    "$rust_base_dockerfile"; then
  echo "runtime image audit: reviewed sccache checksum is missing from $rust_base_dockerfile" >&2
  fail=1
fi

for dockerfile in "${runtime_dockerfiles[@]}"; do
  while IFS= read -r declaration; do
    [[ -z "$declaration" ]] && continue
    value="${declaration#*=}"
    if [[ ! "$value" =~ @sha256:[0-9a-f]{64}$ ]]; then
      echo "runtime image audit: build image is not digest-pinned in $dockerfile: $declaration" >&2
      fail=1
    fi
  done < <(sed -nE '/^ARG [A-Z_]+_IMAGE=/p' "$dockerfile")

  if ! grep -Fq 'FROM codewire-rust-base AS ' "$dockerfile"; then
    echo "runtime image audit: shared reviewed Rust foundation is missing from $dockerfile" >&2
    fail=1
  fi
  if ! grep -Fxq "ARG DEBIAN_IMAGE=$debian_runtime_image" "$dockerfile"; then
    echo "runtime image audit: reviewed Debian foundation is missing from $dockerfile" >&2
    fail=1
  fi
  if grep -En '^FROM (rust|debian):' "$dockerfile" >&2; then
    echo "runtime image audit: mutable literal foundation remains in $dockerfile" >&2
    fail=1
  fi
done

if ! grep -Fq "ARG RUNTIME_IMAGE=$dashboard_runtime" "$dashboard_dockerfile"; then
  echo "runtime image audit: dashboard runtime digest drifted from the accepted inventory" >&2
  fail=1
fi
if ! grep -Fq 'cargo metadata --locked --offline --no-deps --format-version 1' \
    "$dashboard_dockerfile"; then
  echo "runtime image audit: dashboard metadata collection must stay locked, offline, and dependency-free" >&2
  fail=1
fi
# Dashboard verification builds the canonical Bake target with --pull --load
# under the verification tag (scripts/ci/verify/build-dashboard-image.sh, which
# also chooses the compiler cache), then inspects that image. The Make and
# shell expressions must be matched literally.
# shellcheck disable=SC2016
if ! grep -Fxq $'\tscripts/ci/verify/build-dashboard-image.sh "$(DASHBOARD_VERIFY_IMAGE)"' Makefile \
    || ! grep -Fxq $'\tscripts/ci/verify/dashboard-image.sh "$(DASHBOARD_VERIFY_IMAGE)"' Makefile \
    || ! grep -Fq 'flags=(--set "dashboard.tags=$tag"' scripts/ci/verify/build-dashboard-image.sh \
    || ! grep -Fq 'docker buildx bake --file docker-bake.hcl --pull --load "${flags[@]}" dashboard' \
      scripts/ci/verify/build-dashboard-image.sh; then
  echo "runtime image audit: dashboard verification must load the canonical Bake result before inspection" >&2
  fail=1
fi
for inventory in \
    'usr/share/codewire/Cargo.lock' \
    'usr/share/codewire/rust-workspace-metadata.json' \
    'usr/share/codewire/runtime-files.sha256'; do
  if ! grep -Fq "$inventory" scripts/ci/verify/dashboard-image.sh; then
    echo "runtime image audit: final-image verifier does not require $inventory" >&2
    fail=1
  fi
done
if ! jq -e --arg runtime "$dashboard_runtime" '
  .schema_version == 1 and
  .runtime.base == $runtime and
  .runtime.uid == 65532 and
  .runtime.gid == 65532 and
  (.forbidden | index("node") != null) and
  (.forbidden | index("shell") != null) and
  (.forbidden | index("zola") != null)
' apps/dashboard/runtime-inventory.json >/dev/null; then
  echo "runtime image audit: invalid dashboard runtime inventory" >&2
  fail=1
fi

if ! grep -Eq 'newTag: main-[0-9a-f]{7,40}-[0-9]+' deployments/k8s/overlays/dev/kustomization.yaml; then
  echo "runtime image audit: dev dashboard source is not an immutable source tag" >&2
  fail=1
fi
if ! awk '
  /name: git\.example\.com\/codewire\/dashboard/ { dashboard = 1; next }
  dashboard && /digest: sha256:[0-9a-f]{64}/ { found = 1; exit }
  dashboard && /name: / { exit }
  END { exit found ? 0 : 1 }
' deployments/k8s/overlays/production/kustomization.yaml; then
  echo "runtime image audit: production dashboard render input lacks an exact digest" >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "runtime image audit: OK"
