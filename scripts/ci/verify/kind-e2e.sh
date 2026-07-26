#!/usr/bin/env bash
# Stable dispatcher for the Rust product Kind gate and retained-cluster suites.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [ "${KIND_CLUSTER_NAME+x}" = x ]; then
  KIND_CLUSTER_NAME_EXPLICIT=1
else
  KIND_CLUSTER_NAME_EXPLICIT=0
fi

# shellcheck source=scripts/ci/verify/kind/common.sh
source "$ROOT/scripts/ci/verify/kind/common.sh"
# shellcheck source=scripts/ci/verify/kind/suites/integrated.sh
source "$ROOT/scripts/ci/verify/kind/suites/integrated.sh"
# shellcheck source=scripts/ci/verify/kind/suites/final-fencing.sh
source "$ROOT/scripts/ci/verify/kind/suites/final-fencing.sh"
# shellcheck source=scripts/ci/verify/kind/suites/environment-session.sh
source "$ROOT/scripts/ci/verify/kind/suites/environment-session.sh"

kind_e2e_usage() {
  cat >&2 <<'EOF'
usage:
  scripts/ci/verify/kind-e2e.sh
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite final-fencing
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite environment-session
EOF
}

dispatch_kind_e2e() {
  if [ "$#" -eq 0 ]; then
    run_integrated_kind_suite
    return
  fi
  if [ "${1:-}" != "suite" ]; then
    echo "::error::unknown Kind e2e command: ${1:-missing}"
    kind_e2e_usage
    return 2
  fi
  if [ "$#" -ne 2 ]; then
    echo "::error::the Kind e2e suite command requires exactly one suite name"
    kind_e2e_usage
    return 2
  fi

  case "$2" in
    environment-session)
      run_retained_environment_session_suite
      ;;
    final-fencing)
      run_retained_final_fencing_suite
      ;;
    *)
      echo "::error::unknown Kind e2e suite: $2"
      kind_e2e_usage
      return 2
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  dispatch_kind_e2e "$@"
fi
