#!/usr/bin/env bash
# bound-cargo-jobs.sh: the visible CPUs, bounded by available memory at one
# job per 1.5 GiB and by the container's own cgroup limit, at least one; and
# every sized Heavy job sets it before building instead of a fixed count.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly SCRIPT="$ROOT/scripts/ci/setup/bound-cargo-jobs.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  printf '[test-bound-cargo-jobs] FAIL: %s\n' "$*" >&2
  exit 1
}

# bound CPUS AVAILABLE_MIB [CGROUP_LIMIT_BYTES CGROUP_USED_BYTES]
bound() {
  local cpus="$1" available_mib="$2"
  rm -rf "$work/cgroup" "$work/env"
  mkdir -p "$work/cgroup"
  printf 'MemTotal:       99999999 kB\nMemAvailable:   %s kB\n' "$((available_mib * 1024))" >"$work/meminfo"
  if (($# > 2)); then
    printf '%s\n' "$3" >"$work/cgroup/memory.max"
    printf '%s\n' "$4" >"$work/cgroup/memory.current"
  fi
  env -i PATH="$PATH" GITHUB_ENV="$work/env" CODEWIRE_BOUND_NPROC="$cpus" \
    CODEWIRE_BOUND_MEMINFO="$work/meminfo" CODEWIRE_BOUND_CGROUP="$work/cgroup" \
    ${SHARE+CODEWIRE_CI_CPU_SHARE="$SHARE"} "$SCRIPT" >/dev/null 2>"$work/stderr"
  sed -n 's/^CARGO_BUILD_JOBS=//p' "$work/env"
}

# A metal guest: 61 CPUs, about 16.5 GiB free.
[[ "$(bound 61 16896)" == 11 ]] || fail 'a metal guest is not bounded by memory'
# A cloud overflow worker: 8 vCPU, about 13 GiB free, bounded by its CPUs.
[[ "$(bound 8 13312)" == 8 ]] || fail 'a cloud worker is not bounded by its CPUs'
# A cgroup limit below available memory wins: 6 GiB headroom gives 4.
[[ "$(bound 61 16896 $((8 * 1024 * 1024 * 1024)) $((2 * 1024 * 1024 * 1024)))" == 4 ]] ||
  fail 'the container cgroup limit was ignored'
# An unlimited cgroup changes nothing.
[[ "$(bound 61 16896 max 123)" == 11 ]] || fail 'an unlimited cgroup changed the bound'
# Never below one.
[[ "$(bound 4 512)" == 1 ]] || fail 'the bound fell below one'
# A metal guest's CPU share (CODEWIRE_CI_CPU_SHARE) caps the CPUs and sizes
# every later step's test threads; without it nothing sets test threads.
[[ "$(SHARE=12 bound 61 65536)" == 12 ]] || fail 'the CPU share did not cap the CPUs'
grep -qx 'RUST_TEST_THREADS=12' "$work/env" || fail 'the CPU share did not set RUST_TEST_THREADS'
grep -qx 'NEXTEST_TEST_THREADS=12' "$work/env" || fail 'the CPU share did not set NEXTEST_TEST_THREADS'
# Memory still wins when it is the tighter bound.
[[ "$(SHARE=12 bound 61 6144)" == 4 ]] || fail 'the CPU share overrode the memory bound'
# A share above the visible CPUs changes nothing.
[[ "$(SHARE=64 bound 8 13312)" == 8 ]] || fail 'a share above the CPUs raised the bound'
[[ "$(bound 61 16896)" == 11 ]] || fail 'the bound without a CPU share changed'
if grep -q 'TEST_THREADS' "$work/env"; then fail 'test threads were set without a CPU share'; fi
# A malformed share is ignored with a warning, never read as a smaller bound.
[[ "$(SHARE=12cores bound 61 16896)" == 11 ]] || fail 'a malformed CPU share changed the bound'
if grep -q 'TEST_THREADS' "$work/env"; then fail 'a malformed CPU share set test threads'; fi
grep -q 'ignoring CODEWIRE_CI_CPU_SHARE' "$work/stderr" || fail 'a malformed CPU share gave no warning'
[[ "$(SHARE=0 bound 61 16896)" == 11 ]] || fail 'a zero CPU share changed the bound'
# A broken input fails the step rather than guessing.
printf 'MemTotal: 1 kB\n' >"$work/meminfo"
if env -i PATH="$PATH" GITHUB_ENV="$work/env" CODEWIRE_BOUND_MEMINFO="$work/meminfo" \
  CODEWIRE_BOUND_CGROUP="$work/cgroup" "$SCRIPT" >/dev/null 2>&1; then
  fail 'missing MemAvailable did not fail'
fi

# Every sized metal job bounds cargo in a step, after its checkout and before
# any later step, and none keeps a fixed job-level count.
python3 -I - "$ROOT/.gitea/workflows/ci.yaml" <<'WIRING'
import sys
import yaml

jobs = yaml.safe_load(open(sys.argv[1]))["jobs"]
# The sized metal runners are the CODEWIRE_CI_RUNNER_*_HEAVY and *_MEDIUM
# variables (infra#1534): Database on heavy, eight groups on medium.
sized = {name for name, job in jobs.items()
         if "_HEAVY ||" in str(job.get("runs-on", "")) or "_MEDIUM ||" in str(job.get("runs-on", ""))}
assert len(sized) == 10, sorted(sized)
for name in sized:
    job = jobs[name]
    assert "CARGO_BUILD_JOBS" not in (job.get("env") or {}), name
    steps = job.get("steps") or []
    names = [step.get("name") for step in steps]
    assert names.count("Bound cargo jobs by memory") == 1, name
    index = names.index("Bound cargo jobs by memory")
    step = steps[index]
    assert step["run"] == "scripts/ci/setup/bound-cargo-jobs.sh", name
    checkout = next(i for i, s in enumerate(steps)
                    if str(s.get("uses", "")).startswith("noel/actions-checkout@"))
    assert checkout < index, name
    gate = steps[checkout].get("if")
    if "BUILD_ONCE" in (job.get("env") or {}):
        gate = gate[:-len(" }}")] + " && env.BUILD_ONCE != 'true' }}"
    assert step.get("if") == gate, name
    # Only the checkout and the warm cache selection come before it.
    for earlier in steps[checkout + 1:index]:
        assert earlier.get("name") == "Select the warm Rust cache", (name, earlier.get("name"))
for name, job in jobs.items():
    if name not in sized:
        assert "Bound cargo jobs by memory" not in [s.get("name") for s in job.get("steps") or []], name
WIRING

printf '[test-bound-cargo-jobs] CPUs bounded by memory and cgroup, at least one, wired into every sized job: OK\n'
