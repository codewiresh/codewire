#!/usr/bin/env bash
# Select the metal guest's warm Rust cache for one main push or pull request
# job (infra#1534).
#
# A main guest on the bare-metal host mounts its own persistent cache at
# /ci-cache, a 110 GB ext4 image that outlives every guest; each guest runs one
# job at a time. On a push to main or a pull request this links the job's shared target
# directories (target/ci-cache: host-debug, host-ci and desktop-release, one per
# profile, shared by every family that builds that profile) and its Cargo home
# (target/ci-rust-cargo-home: the registry index, downloaded crates and git
# checkouts) into the cache, so the job starts from the last build on its
# guest. Main and pull requests share it (owner, 2026-10-21: the cache risk
# is accepted). Anywhere else (another event, a cloud runner, a job that ships
# an artifact) it changes nothing and the job builds in its own workspace.
#
# Bounds, applied before linking:
# - a new ISO week, or a new CODEWIRE_WARM_CACHE_EPOCH (a repository variable
#   an operator raises to force a clean build), wipes the whole cache;
# - the target directories stay under 90 GB, removing whole profile
#   directories, least recently used first;
# - the Cargo home stays under 12 GB, wiped whole when it is over.
# CI never runs `cargo login`, so no registry credential is ever written to the
# persistent Cargo home.
set -euo pipefail

readonly root="${WARM_CACHE_ROOT:-/ci-cache}"
readonly cache="$root/v1"
# Caps in KiB: 90 GB of target directories and 12 GB of Cargo home, inside the
# 110 GB image. Tests override them.
readonly target_cap_kib="${WARM_CACHE_TARGET_CAP_KIB:-87890625}"
readonly cargo_home_cap_kib="${WARM_CACHE_CARGO_HOME_CAP_KIB:-11718750}"
# Artifacts that ship or are published build from a clean target.
readonly shipping_jobs=' cw-release-assets workspace-image '

: "${GITHUB_WORKSPACE:?Forgejo job workspace is required}"
: "${GITHUB_JOB:?Forgejo job id is required}"

skip() {
  printf '[warm-rust-cache] not used: %s\n' "$*"
  exit 0
}

case "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}" in
  'push|refs/heads/main' | pull_request\|*) ;;
  *) skip 'not a push to main or a pull request' ;;
esac
[[ "$shipping_jobs" != *" $GITHUB_JOB "* ]] || skip "$GITHUB_JOB ships an artifact and builds clean"
if [[ -z "${WARM_CACHE_ROOT:-}" ]]; then
  [[ "$(stat -f -c %T "$root" 2>/dev/null)" == ext2/ext3 ]] || skip 'no warm cache is mounted on this runner'
fi

week="$(date -u +%G-W%V)"
key="$week/${CODEWIRE_WARM_CACHE_EPOCH:-0}"
if [[ -d "$cache" && "$(cat "$cache/.key" 2>/dev/null || true)" != "$key" ]]; then
  printf '[warm-rust-cache] clean build: the cache key moved to %s\n' "$key"
  rm -rf -- "$cache"
fi
mkdir -p "$cache/ci-cache" "$cache/cargo-home"
printf '%s\n' "$key" > "$cache/.key"

usage_kib() {
  du -sk "$1" 2>/dev/null | awk '{print $1}'
}

# Least recently used profile directories go first, whole.
while :; do
  total=0
  oldest=''
  oldest_time=''
  for dir in "$cache"/ci-cache/*/; do
    [[ -d "$dir" ]] || continue
    dir="${dir%/}"
    total=$(( total + $(usage_kib "$dir") ))
    used="$(stat -c %Y "$dir/.last-used" 2>/dev/null || echo 0)"
    if [[ -z "$oldest_time" || "$used" -lt "$oldest_time" ]]; then
      oldest="$dir"
      oldest_time="$used"
    fi
  done
  [[ "$total" -gt "$target_cap_kib" && -n "$oldest" ]] || break
  printf '[warm-rust-cache] over the target cap: removing %s\n' "${oldest##*/}"
  rm -rf -- "$oldest"
done
if [[ "$(usage_kib "$cache/cargo-home")" -gt "$cargo_home_cap_kib" ]]; then
  printf '[warm-rust-cache] over the Cargo home cap: wiping it\n'
  rm -rf -- "$cache/cargo-home"
  mkdir -p "$cache/cargo-home"
fi

# The job's own paths become links into the cache. Nothing has built yet, so
# whatever a checkout left there is replaced.
mkdir -p "$GITHUB_WORKSPACE/target"
for link in ci-cache:ci-cache ci-rust-cargo-home:cargo-home; do
  path="$GITHUB_WORKSPACE/target/${link%%:*}"
  rm -rf -- "$path"
  ln -s "$cache/${link#*:}" "$path"
done
date -u +%s > "$cache/.job-started"
printf '[warm-rust-cache] using %s (key %s)\n' "$cache" "$key"
