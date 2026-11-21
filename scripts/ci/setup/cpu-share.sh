#!/usr/bin/env bash
# Sourced by the CI build and test scripts.
#
# ci_cpu_share: the cores this job may assume, from CODEWIRE_CI_CPU_SHARE,
# which the metal runner dispatcher sets per guest class (infra#1632). A Kata
# guest sees every host thread as a vCPU (61 on the CI host), but it shares
# the host with the other guests, so sizing thread pools from nproc
# oversubscribes the host: a database lane took 250 s in one run and 555 s in
# another. Prints nothing when the variable is unset, so a runner without it
# (a cloud runner, a workstation) keeps sizing from its own CPUs; a malformed
# value is ignored with a warning, never read as 1.
ci_cpu_share() {
  local share="${CODEWIRE_CI_CPU_SHARE:-}"
  [ -n "$share" ] || return 0
  if [[ "$share" =~ ^[1-9][0-9]{0,3}$ ]]; then
    printf '%s\n' "$share"
  else
    printf 'warning: ignoring CODEWIRE_CI_CPU_SHARE=%q; it is not a positive integer\n' "$share" >&2
  fi
}

# ci_cpu_cap_list MULTIPLE: the first MULTIPLE x share CPUs this process may
# run on, as a taskset list (0,1,...), or nothing when the share is unset or
# the process already runs on no more than that. A job whose commands start
# their own processes uses more than its share however its pools are sized;
# pinning it bounds every process it starts, since a Kata guest's vCPUs are
# host threads (infra#1534 step G).
ci_cpu_cap_list() {
  local share
  share="$(ci_cpu_share)"
  [[ -n "$share" && "${1:-}" =~ ^[1-9]$ ]] || return 0
  python3 -I -c 'import os, sys
cpus = sorted(os.sched_getaffinity(0))
cap = int(sys.argv[1])
if len(cpus) > cap:
    print(",".join(map(str, cpus[:cap])))' "$((share * $1))"
}
