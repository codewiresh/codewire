# shellcheck shell=bash disable=SC2034 # CPU_SLICE_DOCKER_ARGS is read by the sourcing builder.
# Keep the dev loop's heavy work inside the workstation CPU slice (#4126).
#
# On the owner's Linux workstation, scripts/dev/workstation-cpu.sh (installed
# as codewire-cpu) gives preflight runs and local-VM runs one slice with a CPU
# ceiling. A run that forgets `codewire-cpu run $$` lands in user.slice, whose
# higher weight then starves the runs that did use the slice. Sourced by
# preflight.sh and the local runtime builders; in CI, on macOS and on a machine
# without codewire-cpu, both functions do nothing.

# The slice workstation-cpu.sh moves processes into; a test pins the match.
CPU_SLICE=cwvmtest.slice
# Where this shell's cgroup is read from; tests point it at a fixture.
CPU_SLICE_CGROUP_FILE="${CPU_SLICE_CGROUP_FILE:-/proc/self/cgroup}"

cpu_slice_off() {
  [ -n "${CI:-}${GITHUB_ACTIONS:-}" ]
}

cpu_slice_inside() {
  grep -q "/$CPU_SLICE/" "$CPU_SLICE_CGROUP_FILE" 2>/dev/null
}

# cpu_slice_enter LABEL: move this shell, and every child it starts later, into
# the slice unless it already runs there, and export CODEWIRE_CPU_SLICE as
# codewire/root bin/heavy does, so image builders take their ceiling too
# (buildx-builder.sh). Never fails the caller.
cpu_slice_enter() {
  ! cpu_slice_off || return 0
  if cpu_slice_inside; then
    export CODEWIRE_CPU_SLICE="$CPU_SLICE"
    return 0
  fi
  command -v codewire-cpu >/dev/null 2>&1 || return 0
  if codewire-cpu run "$$" >/dev/null 2>&1; then
    export CODEWIRE_CPU_SLICE="$CPU_SLICE"
    printf '%s: moved into %s\n' "$1" "$CPU_SLICE" >&2
  else
    printf '%s: codewire-cpu run failed; running outside %s\n' "$1" "$CPU_SLICE" >&2
  fi
}

# cpu_slice_docker_args: set CPU_SLICE_DOCKER_ARGS to the docker run arguments
# that keep a container in the slice when this shell runs there. Docker starts
# containers in system.slice otherwise, outside the slice's ceiling.
cpu_slice_docker_args() {
  CPU_SLICE_DOCKER_ARGS=()
  if ! cpu_slice_off && cpu_slice_inside; then
    CPU_SLICE_DOCKER_ARGS=(--cgroup-parent="$CPU_SLICE")
  fi
}
