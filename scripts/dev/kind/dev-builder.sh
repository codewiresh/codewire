# shellcheck shell=bash
# The kind-dev BuildKit builder and per-worktree target, shared by service
# deploys (deploy-service.sh) and the retained suites' smoke build
# (build-smokes.sh). Both must use the same builder: its cache mounts hold each
# worktree's Cargo target and the shared compiler cache, so a smoke build after
# a deploy only links what the deploy already compiled.

# BuildKit's default GC policy prunes cache mounts past 488 MiB and empties the
# store to 9 GiB whenever the disk has under 20 percent free, which evicted every
# worktree's target, the compiler cache and the registry between deploys: each
# deploy was cold. Keep up to 80 GB of them instead, at least 40 GB unless the
# disk falls under 40 GB free, and anything unused for two weeks goes. The
# builder name carries the policy's digest, so a changed policy gets a builder
# that runs it rather than reusing one created with another.
KIND_DEV_BUILDKIT_CONFIG='[worker.oci]
  gc = true
  [[worker.oci.gcpolicy]]
    filters = ["type==source.local", "type==source.git.checkout"]
    keepDuration = "48h"
    maxUsedSpace = "512MB"
  [[worker.oci.gcpolicy]]
    keepDuration = "336h"
    reservedSpace = "40GB"
    maxUsedSpace = "80GB"
    minFreeSpace = "40GB"
  [[worker.oci.gcpolicy]]
    all = true
    reservedSpace = "40GB"
    maxUsedSpace = "80GB"
    minFreeSpace = "40GB"'

# kind_dev_builder BASE STATE_DIR prints the builder's name, creating it once.
kind_dev_builder() {
  local name
  name="${1}-$(printf '%s\n' "$KIND_DEV_BUILDKIT_CONFIG" | sha256sum | cut -c1-8)"
  if ! docker buildx inspect "$name" >/dev/null 2>&1; then
    printf '%s\n' "$KIND_DEV_BUILDKIT_CONFIG" >"$2/buildkitd.toml"
    docker buildx create --name "$name" --driver docker-container \
      --buildkitd-config "$2/buildkitd.toml" >/dev/null || return 1
  fi
  printf '%s\n' "$name"
}

# One Cargo target per worktree: crates built from another worktree's source
# must never be reused (Cargo judges freshness by modification time).
kind_dev_tree() {
  printf '%s' "$1" | sha256sum | cut -c1-16
}
