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
# shellcheck source=scripts/ci/verify/kind/suites/dashboard-browser.sh
source "$ROOT/scripts/ci/verify/kind/suites/dashboard-browser.sh"
# shellcheck source=scripts/ci/verify/kind/suites/final-fencing.sh
source "$ROOT/scripts/ci/verify/kind/suites/final-fencing.sh"
# shellcheck source=scripts/ci/verify/kind/suites/environment-session.sh
source "$ROOT/scripts/ci/verify/kind/suites/environment-session.sh"
# shellcheck source=scripts/ci/verify/kind/suites/sandbox-supply-chain.sh
source "$ROOT/scripts/ci/verify/kind/suites/sandbox-supply-chain.sh"
# shellcheck source=scripts/ci/verify/kind/suites/runtime-acceptance.sh
source "$ROOT/scripts/ci/verify/kind/suites/runtime-acceptance.sh"
# shellcheck source=scripts/ci/verify/kind/credential-mode.sh
source "$ROOT/scripts/ci/verify/kind/credential-mode.sh"
# shellcheck source=scripts/ci/verify/kind/suites/up.sh
source "$ROOT/scripts/ci/verify/kind/suites/up.sh"
# shellcheck source=scripts/ci/verify/kind/suites/edge-contract.sh
source "$ROOT/scripts/ci/verify/kind/suites/edge-contract.sh"
# shellcheck source=scripts/ci/verify/kind/suites/credential-journey.sh
source "$ROOT/scripts/ci/verify/kind/suites/credential-journey.sh"
# shellcheck source=scripts/ci/verify/kind/suites/workspace-services.sh
source "$ROOT/scripts/ci/verify/kind/suites/workspace-services.sh"

kind_e2e_usage() {
  cat >&2 <<'EOF'
usage:
  scripts/ci/verify/kind-e2e.sh
  KIND_CLUSTER_NAME=<new-cluster> scripts/ci/verify/kind-e2e.sh up
  KIND_CLUSTER_NAME=<new-cluster> scripts/ci/verify/kind-e2e.sh shard <suite> [<suite>...]
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite edge-contract
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite integrated
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite credentials
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite workspace-services
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite dashboard-browser
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite final-fencing
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite environment-session
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite sandbox-supply-chain
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite runtime-acceptance
  KIND_CLUSTER_NAME=<retained-cluster> KIND_PUBLIC_ORIGIN=<origin> scripts/ci/verify/kind-e2e.sh credentials real
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh credentials fake
EOF
}

dispatch_kind_e2e() {
  if [ "$#" -eq 0 ]; then
    run_integrated_kind_suite
    return
  fi
  # Call every suite and `up` as a plain statement. Bash ignores errexit in a
  # function called from ||, so `run_x || return $?` would let an unchecked
  # failing step fall through to green; require_kind_errexit refuses that.
  if [ "${1:-}" = "up" ] && [ "$#" -eq 1 ]; then
    run_kind_up
    log "cluster ${KIND_CLUSTER_NAME} is up; no test suites ran"
    return
  fi
  # A shard brings its cluster up and runs every mapped suite in this one
  # process: the remote DinD network attachment and loopback forwarders are
  # process state, so separate up/suite invocations would strand the cluster.
  if [ "${1:-}" = "shard" ]; then
    if [ "$#" -lt 2 ]; then
      echo "::error::the Kind shard command requires at least one suite name"
      kind_e2e_usage
      return 2
    fi
    run_kind_up
    log "cluster ${KIND_CLUSTER_NAME} is up; running shard suites: ${*:2}"
    shift
    local suite
    for suite in "$@"; do
      dispatch_kind_e2e suite "$suite"
    done
    log "Kind shard suites green: $*"
    return
  fi
  if [ "${1:-}" = "credentials" ]; then
    case "$#:${2:-}" in
      2:real | 2:fake)
        run_retained_credential_mode "$2"
        return
        ;;
    esac
    echo "::error::the Kind credentials command takes exactly one mode: real or fake"
    kind_e2e_usage
    return 2
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
    edge-contract)
      run_retained_edge_contract_suite
      ;;
    integrated)
      run_retained_integrated_suite
      ;;
    credentials)
      run_retained_credentials_suite
      ;;
    workspace-services)
      run_retained_workspace_services_suite
      ;;
    dashboard-browser)
      run_retained_dashboard_browser_suite
      ;;
    environment-session)
      run_retained_environment_session_suite
      ;;
    final-fencing)
      run_retained_final_fencing_suite
      ;;
    sandbox-supply-chain)
      run_retained_sandbox_supply_chain_suite
      ;;
    runtime-acceptance)
      run_retained_runtime_acceptance_suite
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
