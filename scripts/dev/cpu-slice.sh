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
# LOCAL_RUNTIME_CPUS, a whole number of cores, also caps each builder container
# with --cpus, in CI too: Dev delivery's pod-runtime build (#5602) sets it so
# build scripts and linkers, which ignore Cargo's job count, stay within it.
cpu_slice_docker_args() {
  CPU_SLICE_DOCKER_ARGS=()
  if ! cpu_slice_off && cpu_slice_inside; then
    CPU_SLICE_DOCKER_ARGS=(--cgroup-parent="$CPU_SLICE")
  fi
  if [[ "${LOCAL_RUNTIME_CPUS:-}" =~ ^[1-9][0-9]?$ ]]; then
    CPU_SLICE_DOCKER_ARGS+=(--cpus "$LOCAL_RUNTIME_CPUS")
  elif [ -n "${LOCAL_RUNTIME_CPUS:-}" ]; then
    printf 'cpu-slice: LOCAL_RUNTIME_CPUS must be a whole number of cores from 1 to 99; ignored\n' >&2
  fi
}

# cpu_slot_prefix: set CPU_SLOT_PREFIX to the words that make a heavy command
# wait for one of the workstation's build slots and run in the slice
# (`codewire-cpu build --`), or to nothing: in CI, from inside a slot, and
# where codewire-cpu is missing or installed from before `build`. The slice
# caps the cores heavy work takes; the slots cap how many jobs share them.
cpu_slot_prefix() {
  local usage
  CPU_SLOT_PREFIX=()
  ! cpu_slice_off || return 0
  [ -z "${CODEWIRE_CPU_SLOT:-}" ] || return 0
  command -v codewire-cpu >/dev/null 2>&1 || return 0
  usage="$(codewire-cpu 2>&1 || true)"
  case "$usage" in
    *'build -- COMMAND'*) CPU_SLOT_PREFIX=(codewire-cpu build --) ;;
  esac
}
