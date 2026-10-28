#!/usr/bin/env bash
set -euo pipefail

# The tools each rendered container runs, which its pinned image must provide
# on its own PATH (crates/codewire-orchestration/src/sandbox/template/
# workspace.rs). The DinD bootstrap mounts the Docker data image and starts
# Docker with busybox (dind_bootstrap_script). The support image's Debian base
# runs the Docker data init (docker_data_image_prepare_script) and the daemon
# copy (#3208).
readonly -a dind_tools=(sh mkdir awk mount dockerd)
readonly -a support_tools=(sh dirname mkdir chown chmod rm cp mv truncate stat awk
  mkfs.ext4 e2fsck resize2fs dumpe2fs)

# Print `tool path` for each TOOL found on IMAGE's PATH, as the container's
# shell resolves it. With CODEWIRE_RUNTIME_TOOL_LISTINGS set, print the
# listing named LABEL in that directory instead (the self-test's fixtures).
list_image_tools() {
  local label="$1" image="$2"
  shift 2
  if [[ -n "${CODEWIRE_RUNTIME_TOOL_LISTINGS:-}" ]]; then
    cat -- "$CODEWIRE_RUNTIME_TOOL_LISTINGS/$label"
    return
  fi
  # The tool names expand inside the container, not here.
  # shellcheck disable=SC2016
  docker run --rm --network none --entrypoint sh "$image" -c \
    'for tool do path="$(command -v "$tool")" && printf "%s %s\n" "$tool" "$path"; done; exit 0' \
    sh "$@"
}

# Fail, naming each, when a TOOL is not at an absolute path in IMAGE's listing.
require_image_tools() {
  local label="$1" image="$2" listing tool
  shift 2
  local -a missing=()
  if ! listing="$(list_image_tools "$label" "$image" "$@")"; then
    echo "runtime image audit: could not list the tools of $image" >&2
    return 1
  fi
  for tool in "$@"; do
    if ! awk -v tool="$tool" '$1 == tool && $2 ~ /^\// { found = 1 } END { exit found ? 0 : 1 }' \
        <<<"$listing"; then
      missing+=("$tool")
    fi
  done
  if (( ${#missing[@]} != 0 )); then
    echo "runtime image audit: $image ($label) lacks ${missing[*]}" >&2
    return 1
  fi
}

# The tool listings of the self-test: the Docker 29.9.2 DinD image and the
# support image's Debian base as the probe printed them, and each without a
# tool its container runs.
write_tool_fixtures() {
  local root="$1"
  printf '%s\n' 'sh /bin/sh' 'mkdir /bin/mkdir' 'awk /usr/bin/awk' 'mount /bin/mount' \
    'dockerd /usr/local/bin/dockerd' 'chown /bin/chown' 'chmod /bin/chmod' \
    'dirname /usr/bin/dirname' 'rm /bin/rm' 'cp /bin/cp' 'mv /bin/mv' \
    'truncate /usr/bin/truncate' 'stat /bin/stat' >"$root/dind-29.9.2"
  grep -v '^mount ' "$root/dind-29.9.2" >"$root/dind-without-mount"
  printf '%s\n' 'sh /usr/bin/sh' 'dirname /usr/bin/dirname' 'mkdir /usr/bin/mkdir' \
    'chown /usr/bin/chown' 'chmod /usr/bin/chmod' 'rm /usr/bin/rm' 'cp /usr/bin/cp' \
    'mv /usr/bin/mv' 'truncate /usr/bin/truncate' 'stat /usr/bin/stat' 'awk /usr/bin/awk' \
    'mkfs.ext4 /usr/sbin/mkfs.ext4' 'e2fsck /usr/sbin/e2fsck' \
    'resize2fs /usr/sbin/resize2fs' 'dumpe2fs /usr/sbin/dumpe2fs' >"$root/support-base"
  grep -Ev '^(mkfs[.]ext4|e2fsck|resize2fs|dumpe2fs) ' "$root/support-base" \
    >"$root/support-without-e2fsprogs"
  # A tool name with no path is a shell builtin or alias, not an executable.
  sed 's|^dockerd .*|dockerd dockerd|' "$root/dind-29.9.2" >"$root/dind-relative-dockerd"
}

tool_fixture_self_test() {
  local root="$1"
  write_tool_fixtures "$root"
  export CODEWIRE_RUNTIME_TOOL_LISTINGS="$root"
  require_image_tools dind-29.9.2 fixture-dind "${dind_tools[@]}"
  require_image_tools support-base fixture-support "${support_tools[@]}"
  local case
  for case in \
      'dind-without-mount:dind' \
      'dind-relative-dockerd:dind' \
      'support-without-e2fsprogs:support' \
      'dind-29.9.2:support'; do
    local listing="${case%%:*}" role="${case#*:}"
    local -a tools=("${dind_tools[@]}")
    [[ "$role" == support ]] && tools=("${support_tools[@]}")
    if require_image_tools "$listing" "fixture-$role" "${tools[@]}" 2>"$root/$listing.err"; then
      echo "runtime image audit self-test: $listing passed as a $role image" >&2
      return 1
    fi
  done
  grep -Fxq 'runtime image audit: fixture-dind (dind-without-mount) lacks mount' \
    "$root/dind-without-mount.err"
  grep -Fxq 'runtime image audit: fixture-support (support-without-e2fsprogs) lacks mkfs.ext4 e2fsck resize2fs dumpe2fs' \
    "$root/support-without-e2fsprogs.err"
  unset CODEWIRE_RUNTIME_TOOL_LISTINGS
}

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
  tool_fixture_self_test "$fixture_root"
  echo 'runtime image audit self-test: canonical project source accepted; legacy source rejected'
  echo 'runtime image audit self-test: the 29.9.2 DinD and Debian support listings pass; DinD without mount, support without e2fsprogs and DinD as the support image fail'
  exit 0
fi
# --probe-images runs each pinned image with Docker and checks the tools its
# rendered containers call. It pulls the public images, so it is invoked by
# hand rather than in CI, where the self-test checks the same logic on
# recorded listings.
probe_images=false
if [[ "${1:-}" == '--probe-images' ]]; then
  probe_images=true
  shift
fi
if (( $# != 0 )); then
  echo 'usage: audit-runtime-images.sh [--self-test | --probe-images]' >&2
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
readonly dind_image='docker.io/library/docker:29.9.2-dind@sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977'
rust_channel="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' \
  rust-toolchain.toml)"
if [[ ! "$rust_channel" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "runtime image audit: rust-toolchain.toml must declare one exact release" >&2
  exit 1
fi
readonly rust_channel
readonly rust_build_digest='114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6'
readonly rust_build_image="rust:${rust_channel}-bookworm@sha256:${rust_build_digest}"
readonly debian_runtime_image='debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587'
if [[ "$probe_images" == true ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo 'runtime image audit: --probe-images requires Docker' >&2
    exit 1
  fi
  probe_fail=0
  require_image_tools dind "$dind_image" "${dind_tools[@]}" || probe_fail=1
  require_image_tools support "$debian_runtime_image" "${support_tools[@]}" || probe_fail=1
  if [[ "$probe_fail" -ne 0 ]]; then
    exit 1
  fi
  echo "runtime image audit: $dind_image and $debian_runtime_image provide every tool their containers run"
  exit 0
fi
readonly dashboard_runtime='gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f'
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

# The hosted Dev and Production image pins live in codewire/deploy, whose
# release record owns the exact digests.

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "runtime image audit: OK"
