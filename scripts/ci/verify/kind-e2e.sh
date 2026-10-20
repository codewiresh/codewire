#!/usr/bin/env bash
# ShellCheck follows the whole Kind suite tree from here. Its data-flow pass
# needs over 10 GiB, more than a CI worker has, and reports nothing at the
# policy's warning severity, so this file uses the ordinary analysis.
# shellcheck extended-analysis=false
# Stable dispatcher for the Rust product Kind gate and retained-cluster suites.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [ "${KIND_CLUSTER_NAME+x}" = x ] || [ -n "${CLUSTER:-}" ]; then
  KIND_CLUSTER_NAME_EXPLICIT=1
else
  KIND_CLUSTER_NAME_EXPLICIT=0
fi

# Only create entrypoints allocate a saved profile. Read/test/remove commands
# require an existing profile and cannot claim a cluster merely by its name.
if [[ "${BASH_SOURCE[0]}" == "$0" ]] && [ -n "${CLUSTER:-}" ] \
    && { [ "$#" -eq 0 ] || [ "${1:-}" = up ] || [ "${1:-}" = shard ]; }; then
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = prebuilt-release ]; then
    echo '::error::named Kind profiles currently require the synthetic CI product image contract' >&2
    exit 2
  fi
  profile_args=(--cluster "$CLUSTER")
  [ -z "${KIND_PUBLIC_ORIGIN:-}" ] || profile_args+=(--public-origin "$KIND_PUBLIC_ORIGIN")
  [ -z "${KIND_BROWSER_API_ORIGIN:-}" ] || profile_args+=(--browser-api-origin "$KIND_BROWSER_API_ORIGIN")
  python3 "$ROOT/scripts/dev/kind/cluster-profile.py" ensure "${profile_args[@]}" >/dev/null
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
# shellcheck source=scripts/ci/verify/kind/suites/cw-runtime.sh
source "$ROOT/scripts/ci/verify/kind/suites/cw-runtime.sh"
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
# shellcheck source=scripts/ci/verify/kind/suites/warm-pools.sh
source "$ROOT/scripts/ci/verify/kind/suites/warm-pools.sh"

kind_e2e_usage() {
  cat >&2 <<'EOF'
usage:
  scripts/ci/verify/kind-e2e.sh
  CLUSTER=<new-profile> scripts/ci/verify/kind-e2e.sh up
  CLUSTER=<new-profile> scripts/ci/verify/kind-e2e.sh shard <suite> [<suite>...]
  CLUSTER=<profile> scripts/ci/verify/kind-e2e.sh down
  KIND_CLUSTER_NAME=<new-cluster> scripts/ci/verify/kind-e2e.sh up
  KIND_CLUSTER_NAME=<new-cluster> scripts/ci/verify/kind-e2e.sh shard <suite> [<suite>...]
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite edge-contract
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite integrated
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite credentials
  KIND_CLUSTER_NAME=<retained-cluster> KIND_CREDENTIAL_STAGES="<stage>..." scripts/ci/verify/kind-e2e.sh suite credentials
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite workspace-services
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite dashboard-browser
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite final-fencing
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite environment-session
  CLUSTER=<profile> scripts/ci/verify/kind-e2e.sh suite cw-runtime
  CLUSTER=<profile> scripts/ci/verify/kind-e2e.sh suite cw-managed-agents
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite sandbox-supply-chain
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite runtime-acceptance
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh suite warm-pools
  KIND_CLUSTER_NAME=<retained-cluster> KIND_PUBLIC_ORIGIN=<origin> scripts/ci/verify/kind-e2e.sh credentials real
  KIND_CLUSTER_NAME=<retained-cluster> scripts/ci/verify/kind-e2e.sh credentials fake
EOF
}

dispatch_kind_e2e() {
  # A credentials stage subset reruns one stage on a retained cluster. The
  # gate, its shards and every other command run whole suites, so they refuse
  # it rather than ignore it.
  if [ -n "${KIND_CREDENTIAL_STAGES:-}" ] && { [ "$#" -ne 2 ] || [ "$1" != suite ] \
      || [ "$2" != credentials ] || [ "${KIND_SHARD_TRANSACTION:-0}" = 1 ]; }; then
    echo "::error::KIND_CREDENTIAL_STAGES selects stages of the retained credentials suite only (suite credentials); unset it for this command"
    return 2
  fi
  # Part of the dashboard browser suite, likewise only for a retained run.
  if [ -n "${KIND_DASHBOARD_SELECTION:-}" ] && { [ "$#" -ne 2 ] || [ "$1" != suite ] \
      || [ "$2" != dashboard-browser ] || [ "${KIND_SHARD_TRANSACTION:-0}" = 1 ]; }; then
    echo "::error::KIND_DASHBOARD_SELECTION selects tests of the retained dashboard-browser suite only (suite dashboard-browser); unset it for this command"
    return 2
  fi
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
    KIND_SHARD_TRANSACTION=1
    KIND_SHARD_SUITE_NAMES=("${@:2}")
    run_kind_up
    log "cluster ${KIND_CLUSTER_NAME} is up; running shard suites: ${*:2}"
    shift
    local suite original_kubeconfig="${KUBECONFIG-}" kubeconfig_was_set="${KUBECONFIG+x}"
    for suite in "$@"; do
      dispatch_kind_e2e suite "$suite"
      # A suite replaces the EXIT trap and pins a temporary kubeconfig. Keep
      # the creating process's network state and dispose only that suite's
      # context before the next one. Failure uses the chained owner cleanup.
      if [ -n "$RETAINED_KUBECONFIG" ]; then
        rm -f "$RETAINED_KUBECONFIG" || return $?
        RETAINED_KUBECONFIG=""
      fi
      if [ "$kubeconfig_was_set" = x ]; then
        export KUBECONFIG="$original_kubeconfig"
      else
        unset KUBECONFIG
      fi
      trap cleanup EXIT
    done
    log "Kind shard suites green: $*"
    return
  fi
  if [ "${1:-}" = down ] && [ "$#" -eq 1 ]; then
    run_kind_down
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
    cw-runtime)
      run_retained_cw_runtime_suite
      ;;
    cw-managed-agents)
      run_retained_cw_managed_agents_suite
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
    warm-pools)
      run_retained_warm_pools_suite
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
