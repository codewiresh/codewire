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
# is accepted). Anywhere else (another event, a cloud runner) it changes
# nothing and the job builds in its own workspace. CI ships no artifact: the
# release and delivery workflows build those, never from this cache.
#
# Bounds, applied before linking:
# - a new ISO week, or a new CODEWIRE_WARM_CACHE_EPOCH (a repository variable
#   an operator raises to force a clean build), wipes the whole cache;
# - the target directories stay under 70 GB, removing whole profile
#   directories, least recently used first;
# - the Cargo home stays under 12 GB, wiped whole when it is over;
# - the cache filesystem keeps a free-space floor for the job's own build: a
#   quarter of the filesystem, and never less than the 2 GiB Cargo's capacity
#   check requires. Below it, whole profile directories go, least recently
#   used first, then the Cargo home; each removal is logged. Only when nothing
#   is left to remove and the filesystem is still under 2 GiB free does the
#   step fail (main run 19967: a week's growth filled a smaller guest cache).
# CI never runs `cargo login`, so no registry credential is ever written to the
# persistent Cargo home.
set -euo pipefail

readonly root="${WARM_CACHE_ROOT:-/ci-cache}"
readonly cache="$root/v1"
# Caps in KiB: 70 GB of target directories and 12 GB of Cargo home, inside the
# 110 GB image (107.7 GB usable). Together they start a job at 76%, leaving the
# job's own build room; at 90 GB a job could start at 95% and run out (infra#1534).
# Tests override them.
readonly target_cap_kib="${WARM_CACHE_TARGET_CAP_KIB:-68359375}"
readonly cargo_home_cap_kib="${WARM_CACHE_CARGO_HOME_CAP_KIB:-11718750}"
# The free-space floor; the hard minimum is assert-cargo-cache-capacity.sh's.
readonly hard_minimum_free_kib=2097152
# Tests point this at a fake df.
readonly df_bin="${WARM_CACHE_DF:-df}"

: "${GITHUB_WORKSPACE:?Forgejo job workspace is required}"

skip() {
  printf '[warm-rust-cache] not used: %s\n' "$*"
  exit 0
}

case "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}" in
  'push|refs/heads/main' | pull_request\|*) ;;
  *) skip 'not a push to main or a pull request' ;;
esac
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

# The cache filesystem's free and total KiB, from df -P.
filesystem_kib() {
  local field="$1" value
  value="$("$df_bin" -Pk "$cache" | awk -v field="$field" 'END { print $field }')"
  [[ "$value" =~ ^[0-9]+$ ]] || {
    printf '[warm-rust-cache] ERROR: unable to read the cache filesystem\n' >&2
    exit 1
  }
  printf '%s\n' "$value"
}
size_kib="$(filesystem_kib 2)"
minimum_free_kib="${WARM_CACHE_MIN_FREE_KIB:-$(( size_kib / 4 ))}"
(( minimum_free_kib >= hard_minimum_free_kib )) || minimum_free_kib="$hard_minimum_free_kib"

# Least recently used profile directories go first, whole (ties by name), while
# the targets are over their cap or the filesystem is under its floor.
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
  [[ -n "$oldest" ]] || break
  if (( total > target_cap_kib )); then
    reason='over the target cap'
  elif (( $(filesystem_kib 4) < minimum_free_kib )); then
    reason="under ${minimum_free_kib} KiB free"
  else
    break
  fi
  printf '[warm-rust-cache] %s: removing %s (%s KiB)\n' "$reason" "${oldest##*/}" "$(usage_kib "$oldest")"
  rm -rf -- "$oldest"
done
if [[ "$(usage_kib "$cache/cargo-home")" -gt "$cargo_home_cap_kib" ]]; then
  printf '[warm-rust-cache] over the Cargo home cap: wiping it\n'
  rm -rf -- "$cache/cargo-home"
  mkdir -p "$cache/cargo-home"
elif (( $(filesystem_kib 4) < minimum_free_kib )); then
  printf '[warm-rust-cache] under %s KiB free with no target left: wiping the Cargo home (%s KiB)\n' \
    "$minimum_free_kib" "$(usage_kib "$cache/cargo-home")"
  rm -rf -- "$cache/cargo-home"
  mkdir -p "$cache/cargo-home"
fi
free_kib="$(filesystem_kib 4)"
if (( free_kib < hard_minimum_free_kib )); then
  printf '[warm-rust-cache] ERROR: the cache filesystem has %s KiB free with nothing left to remove; at least %s KiB is required\n' \
    "$free_kib" "$hard_minimum_free_kib" >&2
  exit 1
fi
printf '[warm-rust-cache] %s KiB free of %s (floor %s)\n' "$free_kib" "$size_kib" "$minimum_free_kib"

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
