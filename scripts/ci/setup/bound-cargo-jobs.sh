#!/usr/bin/env bash
# Bound cargo's parallel rustc processes by the runner this job landed on
# (infra#1534). A sized Heavy job runs on a metal guest (about 17 GiB, CPU
# bursting to the host's 60 threads) or, when every guest is busy, on a cloud
# overflow worker (8 vCPU, about 13 GiB). One rustc per visible CPU would
# exceed either's memory, and a fixed count suits only one of them, so the
# bound is computed here, at job start: the visible CPUs, but no more than one
# job per CODEWIRE_CARGO_JOB_MEMORY_MIB (1536 MiB) of available memory, and at
# least one. It is written to GITHUB_ENV for every later step.
set -euo pipefail

: "${GITHUB_ENV:?Forgejo job environment file is required}"
readonly per_job_mib="${CODEWIRE_CARGO_JOB_MEMORY_MIB:-1536}"
# Tests point these at fixtures.
readonly meminfo="${CODEWIRE_BOUND_MEMINFO:-/proc/meminfo}"
readonly cgroup="${CODEWIRE_BOUND_CGROUP:-/sys/fs/cgroup}"
cpus="${CODEWIRE_BOUND_NPROC:-$(nproc)}"

[[ "$per_job_mib" =~ ^[1-9][0-9]*$ ]] || {
  printf '[bound-cargo-jobs] CODEWIRE_CARGO_JOB_MEMORY_MIB must be a positive integer\n' >&2
  exit 1
}
available_kib="$(awk '$1 == "MemAvailable:" {print $2}' "$meminfo")"
[[ "$available_kib" =~ ^[0-9]+$ ]] || {
  printf '[bound-cargo-jobs] %s has no MemAvailable\n' "$meminfo" >&2
  exit 1
}
# A memory limit on this container's own cgroup bounds it further.
limit="$(cat "$cgroup/memory.max" 2>/dev/null || echo max)"
if [[ "$limit" =~ ^[0-9]+$ ]]; then
  used="$(cat "$cgroup/memory.current" 2>/dev/null || echo 0)"
  [[ "$used" =~ ^[0-9]+$ ]] || used=0
  headroom_kib=$(((limit - used) / 1024))
  ((headroom_kib < available_kib)) && available_kib="$headroom_kib"
fi

jobs=$((available_kib / (per_job_mib * 1024)))
((jobs > cpus)) && jobs="$cpus"
((jobs < 1)) && jobs=1
printf 'CARGO_BUILD_JOBS=%s\n' "$jobs" >>"$GITHUB_ENV"
printf '[bound-cargo-jobs] CARGO_BUILD_JOBS=%s (%s CPUs, %s MiB available, %s MiB per job)\n' \
  "$jobs" "$cpus" "$((available_kib / 1024))" "$per_job_mib"
