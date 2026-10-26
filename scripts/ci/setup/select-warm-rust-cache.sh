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
# guest. Go's module and build caches live there too (go/mod and go/build,
# exported as GOMODCACHE and GOCACHE): without them every job that runs Go
# downloaded its modules cold (main run 23934: 112 modules, about 70 s, in
# Contracts alone). Go verifies each module it downloads against go.sum or the
# checksum database, and keys its build cache by the build's inputs. GOFLAGS
# adds -count=1, so a warm cache never stands in for a test run, and
# -modcacherw, so the module cache can be removed. Main and pull requests
# share the cache (owner, 2026-10-21: the cache risk is accepted). Anywhere
# else (another event, a cloud runner) it changes nothing and the job builds
# in its own workspace. CI ships no artifact: the release and delivery
# workflows build those, never from this cache.
#
# Bounds, applied before linking:
# - a new ISO week, or a new CODEWIRE_WARM_CACHE_EPOCH (a repository variable
#   an operator raises to force a clean build), wipes the whole cache;
# - the target directories stay under 70 GB, removing whole profile
#   directories, least recently used first;
# - the Cargo home stays under 12 GB, wiped whole when it is over;
# - the Go caches stay under 3 GiB together, wiped whole when they are over
#   (about 0.5 GiB after Contracts, Go support and the Go SDK), and first,
#   before any profile directory, under the free-space floor;
# - the cache filesystem keeps a free-space floor for the job's own build: a
#   quarter of the filesystem, and never less than the 2 GiB Cargo's capacity
#   check requires. Below it, whole profile directories go, least recently
#   used first, then the Cargo home; each removal is logged. Only when nothing
#   is left to remove and the filesystem is still under 2 GiB free does the
#   step fail (main run 19967: a week's growth filled a smaller guest cache).
# CI never runs `cargo login`, so no registry credential is ever written to the
# persistent Cargo home.
#
# Main's warm VM (infra#1534, step 1 of the warm-VM design) runs several jobs
# at once on one persistent filesystem, which its runner names in
# CODEWIRE_CI_WARM_SEATS. There each job takes a seat: a cache directory named
# after the job (GITHUB_JOB-1, then -2 while -1 is busy), so Rust checks always
# starts from the last Rust checks build. The seat's lock is held for the
# job's whole life by a detached process in the job container, which dies with
# it, so no two running jobs ever share a seat. The later steps find the seat
# through WARM_CACHE_ROOT in GITHUB_ENV. Seats nobody used for
# WARM_CACHE_SEAT_MAX_IDLE_DAYS (3) are removed when free.
set -euo pipefail

: "${GITHUB_WORKSPACE:?Forgejo job workspace is required}"

skip() {
  printf '[warm-rust-cache] not used: %s\n' "$*"
  exit 0
}

case "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}" in
  'push|refs/heads/main' | pull_request\|*) ;;
  *) skip 'not a push to main or a pull request' ;;
esac

# take_seat SEATS: print the seat this job holds, taking the first free one.
take_seat() {
  local seats="$1" job="${GITHUB_JOB:-job}" n seat
  [[ "$job" =~ ^[A-Za-z0-9_-]{1,100}$ ]] || {
    printf '[warm-rust-cache] ERROR: invalid job id %q\n' "$job" >&2
    exit 1
  }
  for n in 1 2 3 4; do
    seat="$seats/$job-$n"
    mkdir -p "$seat"
    # fd 9 stays open in a detached child after this script exits, so the
    # lock lasts until the job container is removed.
    exec 9>"$seat.lock"
    if flock -n 9; then
      setsid sleep infinity </dev/null >/dev/null 2>&1 &
      echo "$!" > "$seat.holder"
      exec 9>&-
      touch "$seat"
      printf '%s\n' "$seat"
      return 0
    fi
    exec 9>&-
  done
  printf '[warm-rust-cache] ERROR: every seat of %s is busy\n' "$job" >&2
  exit 1
}

# remove_idle_seats SEATS: seats unused for WARM_CACHE_SEAT_MAX_IDLE_DAYS go,
# but only when no job holds them.
remove_idle_seats() {
  local seats="$1" seat days="${WARM_CACHE_SEAT_MAX_IDLE_DAYS:-3}"
  [[ "$days" =~ ^[1-9][0-9]*$ ]] || days=3
  while IFS= read -r seat; do
    [[ -d "$seat" && ! -L "$seat" ]] || continue
    if flock -n "$seat.lock" rm -rf -- "$seat"; then
      rm -f -- "$seat.lock" "$seat.holder"
      printf '[warm-rust-cache] removed the seat %s, unused for %s days\n' "${seat##*/}" "$days"
    fi
  done < <(find "$seats" -mindepth 1 -maxdepth 1 -type d -mtime +"$(( days - 1 ))" 2>/dev/null)
}

if [[ -n "${CODEWIRE_CI_WARM_SEATS:-}" && -z "${WARM_CACHE_ROOT:-}" ]]; then
  # Tests hold their seats on a temporary directory.
  [[ "$(stat -f -c %T "$CODEWIRE_CI_WARM_SEATS" 2>/dev/null)" == ext2/ext3 || -n "${WARM_CACHE_SEATS_ANY_FS:-}" ]] ||
    skip "the warm VM's seats ($CODEWIRE_CI_WARM_SEATS) are not mounted"
  remove_idle_seats "$CODEWIRE_CI_WARM_SEATS"
  WARM_CACHE_ROOT="$(take_seat "$CODEWIRE_CI_WARM_SEATS")"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "WARM_CACHE_ROOT=$WARM_CACHE_ROOT" >> "$GITHUB_ENV"
  fi
  printf '[warm-rust-cache] seat %s\n' "${WARM_CACHE_ROOT##*/}"
fi

readonly root="${WARM_CACHE_ROOT:-/ci-cache}"
readonly cache="$root/v1"
# Caps in KiB: 70 GB of target directories and 12 GB of Cargo home, inside the
# 110 GB image (107.7 GB usable). Together they start a job at 76%, leaving the
# job's own build room; at 90 GB a job could start at 95% and run out (infra#1534).
# Tests override them.
readonly target_cap_kib="${WARM_CACHE_TARGET_CAP_KIB:-68359375}"
readonly cargo_home_cap_kib="${WARM_CACHE_CARGO_HOME_CAP_KIB:-11718750}"
readonly go_cap_kib="${WARM_CACHE_GO_CAP_KIB:-3145728}"
# The free-space floor; the hard minimum is assert-cargo-cache-capacity.sh's.
readonly hard_minimum_free_kib=2097152
# Tests point this at a fake df.
readonly df_bin="${WARM_CACHE_DF:-df}"

if [[ -z "${WARM_CACHE_ROOT:-}" ]]; then
  [[ "$(stat -f -c %T "$root" 2>/dev/null)" == ext2/ext3 ]] || skip 'no warm cache is mounted on this runner'
fi

week="$(date -u +%G-W%V)"
key="$week/${CODEWIRE_WARM_CACHE_EPOCH:-0}"
# Go makes its module cache read-only; make it removable first.
remove_tree() {
  chmod -R u+w -- "$1" 2>/dev/null || true
  rm -rf -- "$1"
}

if [[ -d "$cache" && "$(cat "$cache/.key" 2>/dev/null || true)" != "$key" ]]; then
  printf '[warm-rust-cache] clean build: the cache key moved to %s\n' "$key"
  remove_tree "$cache"
fi
mkdir -p "$cache/ci-cache" "$cache/cargo-home" "$cache/go"
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

# Under the floor, the Go caches go before any Rust profile: refilling them
# costs about a minute, a Rust profile several. So keeping Go warm never makes
# a Rust build colder (a medium guest's 19 GB cache held host-debug 70 MB above
# its floor in PR run 24302).
if (( $(filesystem_kib 4) < minimum_free_kib )) && [[ -n "$(find "$cache/go" -mindepth 2 -print -quit 2>/dev/null)" ]]; then
  printf '[warm-rust-cache] under %s KiB free: wiping the Go caches (%s KiB) before any Rust profile\n' \
    "$minimum_free_kib" "$(usage_kib "$cache/go")"
  remove_tree "$cache/go"
  mkdir -p "$cache/go"
fi
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
  printf '[warm-rust-cache] under %s KiB free with no target left: wiping the Cargo home (%s KiB) and the Go caches (%s KiB)\n' \
    "$minimum_free_kib" "$(usage_kib "$cache/cargo-home")" "$(usage_kib "$cache/go")"
  rm -rf -- "$cache/cargo-home"
  remove_tree "$cache/go"
  mkdir -p "$cache/cargo-home" "$cache/go"
fi
if [[ "$(usage_kib "$cache/go")" -gt "$go_cap_kib" ]]; then
  printf '[warm-rust-cache] over the Go cache cap: wiping it\n'
  remove_tree "$cache/go"
  mkdir -p "$cache/go"
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
mkdir -p "$cache/go/mod" "$cache/go/build"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    printf 'GOMODCACHE=%s\n' "$cache/go/mod"
    printf 'GOCACHE=%s\n' "$cache/go/build"
    printf 'GOFLAGS=%s\n' "${GOFLAGS:+$GOFLAGS }-modcacherw -count=1"
  } >> "$GITHUB_ENV"
fi
date -u +%s > "$cache/.job-started"
printf '[warm-rust-cache] using %s (key %s)\n' "$cache" "$key"
