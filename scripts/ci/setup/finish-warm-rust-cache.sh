#!/usr/bin/env bash
# Record what one job did with the metal guest's warm Rust cache
# (infra#1534): mark each profile directory it built as recently used, and
# report every directory's size and the job's peak memory, so the caps and the
# cargo job bound can be set from measurements. Best effort; never fails a job.
set -uo pipefail

readonly root="${WARM_CACHE_ROOT:-/ci-cache}"
readonly cache="$root/v1"

[[ -f "$cache/.job-started" && -L "${GITHUB_WORKSPACE:-/nonexistent}/target/ci-cache" ]] || {
  printf '[warm-rust-cache] not used by this job\n'
  exit 0
}
started="$(cat "$cache/.job-started" 2>/dev/null || echo 0)"
for dir in "$cache"/ci-cache/*/; do
  [[ -d "$dir" ]] || continue
  dir="${dir%/}"
  # A directory this job built in has a file newer than the job's start.
  if [[ -n "$(find "$dir" -mindepth 1 ! -name .last-used -newermt "@$started" -print -quit 2>/dev/null)" ]]; then
    touch "$dir/.last-used"
  fi
done
for dir in "$cache"/ci-cache/*/ "$cache/cargo-home/"; do
  [[ -d "$dir" ]] || continue
  printf '[warm-rust-cache] size %s %s KiB\n' "$(basename "$dir")" "$(du -sk "$dir" 2>/dev/null | awk '{print $1}')"
done
used='' size=''
read -r used size < <(df -Pk "$root" 2>/dev/null | awk 'END {print $3, $2}')
printf '[warm-rust-cache] filesystem %s KiB used of %s\n' "${used:-?}" "${size:-?}"
# Over 85% after a job, the next job may run out of space in the cache: the
# only in-guest signal, shown on the run page (infra#1534).
if [[ "$used" =~ ^[0-9]+$ && "$size" =~ ^[1-9][0-9]*$ ]] && (( used * 100 > size * 85 )); then
  printf '::warning::the warm Rust cache disk is %s%% full after this job; the next job may run out of space\n' \
    "$(( used * 100 / size ))"
fi
if [[ -r /sys/fs/cgroup/memory.peak ]]; then
  printf '[warm-rust-cache] job memory.peak %s bytes\n' "$(cat /sys/fs/cgroup/memory.peak)"
fi
exit 0
