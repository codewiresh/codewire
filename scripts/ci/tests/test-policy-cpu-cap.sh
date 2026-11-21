#!/usr/bin/env bash
# Policy is pinned to twice its CPU share in CI (infra#1534 step G):
# ci_cpu_cap_list names the first MULTIPLE x share CPUs this process may run
# on, nothing without a share or when it already runs on no more, and
# run-product-verification.sh re-executes policy-core under taskset once.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
fail() { echo "test-policy-cpu-cap: $*" >&2; exit 1; }
command -v taskset >/dev/null || fail 'taskset is missing'
(($(nproc) >= 4)) || fail 'needs at least 4 CPUs'

cap() { # SHARE MULTIPLE CPUS: ci_cpu_cap_list on CPUS, with SHARE
  taskset -c "$3" env -u CODEWIRE_CI_CPU_SHARE ${1:+CODEWIRE_CI_CPU_SHARE="$1"} bash -c \
    'source "$0/scripts/ci/setup/cpu-share.sh"; ci_cpu_cap_list "$1"' "$ROOT" "$2"
}
[ -z "$(cap '' 2 0-3)" ] || fail 'a runner without a share was pinned'
[ "$(cap 1 2 0-3)" = 0,1 ] || fail "a share of 1 on CPUs 0-3 is not CPUs 0,1: $(cap 1 2 0-3)"
[ "$(cap 1 2 1,3)" = '' ] || fail 'a process already on two CPUs was pinned again'
[ "$(cap 8 2 0-3)" = '' ] || fail 'a cap above the allowed CPUs was applied'
[ "$(cap 1 2 1-3)" = 1,2 ] || fail "the cap does not follow the allowed CPUs: $(cap 1 2 1-3)"
[ -z "$(cap nonsense 2 0-3 2>/dev/null)" ] || fail 'a malformed share was read'

# The pin comes before the family runs, only for policy-core, and once: the
# re-executed run carries CODEWIRE_POLICY_CPU_CAP, so it never pins again.
script="$ROOT/scripts/ci/verify/run-product-verification.sh"
pin="$(grep -n 'exec taskset -c "$policy_cpus"' "$script" | cut -d: -f1)"
dispatch="$(grep -n '^  policy-core) run_policy_core ;;$' "$script" | tail -1 | cut -d: -f1)"
[[ -n "$pin" && -n "$dispatch" && "$pin" -lt "$dispatch" ]] || fail 'Policy is not pinned before it runs'
grep -q '^if \[\[ "$FAMILY" == policy-core && -z "${CODEWIRE_POLICY_CPU_CAP:-}" \]\]; then$' "$script" ||
  fail 'the pin is not limited to policy-core, once'
grep -q 'CODEWIRE_POLICY_CPU_CAP="$policy_cpus" exec taskset' "$script" || fail 'the re-executed run is not marked'

echo 'test-policy-cpu-cap: twice the share, of the allowed CPUs, for policy-core once, none without a share'
