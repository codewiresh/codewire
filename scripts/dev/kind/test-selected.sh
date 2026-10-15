#!/usr/bin/env bash
# Observe a change on the kept Kind cluster: rebuild and deploy the services
# it changes, then run only the retained suites that cover it.
#
#   KIND_CLUSTER_NAME=<cluster> scripts/dev/kind/test-selected.sh
#   KIND_TEST_SUITES="credentials dashboard-browser" ...   # explicit suites
#   PREFLIGHT_BASE_SHA=<parent> ...                        # stacked branches
#
# The repository's one path classifier (scripts/dev/preflight.sh --explain)
# selects capability tokens; the table below maps them to suites and the run
# prints each suite with the tokens that chose it. Before any suite runs, every
# service the cluster does not record as running this tree's source
# (scripts/dev/kind/service-sources.py) is rebuilt incrementally and deployed
# (deploy-service.sh): what the change feeds, and anything another tree or an
# older main left there.
#
# Exit status: 0 when every selected suite passed or the change has nothing a
# retained Kind cluster observes; 3 when only the full CI Kind gate covers the
# change (nothing was deployed or run); anything else is a failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/dev/kind/profile.sh
source "$ROOT/scripts/dev/kind/profile.sh"
kind_profile_load "$ROOT" || exit $?
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
# cw-runtime, cw-managed-agents and warm-pools run only when named
# (KIND_TEST_SUITES). cw-runtime needs admitted release A/B and support
# producers on a named profile; on a retained cluster cw-managed-agents runs
# the managed-agent journey alone against the deployed daemon (#2672), and
# takes long enough that every orchestration or CLI change should not pay
# for it. warm-pools needs the C0 agent-sandbox controller and the canonical
# image (make kind-runtime-images).
ORDER=(edge-contract credentials workspace-services dashboard-browser final-fencing runtime-acceptance integrated cw-runtime cw-managed-agents warm-pools)
# deploy-service.sh services, in deploy order.
SERVICES=(idp orchestration credential-service billing coordinator mesh dashboard daemon)

log() { printf '[kind-test] %s\n' "$*" >&2; }
die() { printf '[kind-test] error: %s\n' "$*" >&2; exit 1; }

declare -A wanted=() why=()
full_reasons=()
unobserved=()

want() {
  local reason="$1" suite
  shift
  for suite in "$@"; do
    wanted["$suite"]=1
    why["$suite"]="${why[$suite]:+${why[$suite]}, }${reason}"
  done
}
full() { full_reasons+=("$1: $2"); }
unobserved() { unobserved+=("$1 ($2)"); }

# Every crate's token has its own row; a crate without one asks for the full
# gate, so a new crate is mapped deliberately (test-kind-e2e-suites.sh).
map_token() {
  local token="$1"
  case "$token" in
    # Credential authority, brokerage, bridge and protected storage: the
    # synthetic credential journey (enroll, profile, native Codex, Claude).
    rust_pkg_codewire_credential_service | rust_pkg_codewire_credential_broker | \
      rust_pkg_codewire_credential_bridge | rust_pkg_codewire_platform_credentials | \
      rust_pkg_codewire_local_credentials | rust_pkg_codewire_protected_store)
      want "$token" credentials ;;
    # Grant policy decides both credential delivery and workspace SSH access.
    rust_pkg_codewire_access) want "$token" credentials workspace-services ;;
    # The CLI also writes the managed SSH block the user SSH journey runs.
    rust_pkg_codewire_cli | rust_pkg_codewire_cli_bin) want "$token" credentials workspace-services ;;
    rust_pkg_codewire_workspace_access) want "$token" workspace-services ;;
    # The sandbox daemon serves exec, files and sessions and carries the
    # in-sandbox credential bridge.
    rust_pkg_codewire_daemon | transport_pkg_codewire_daemon)
      want "$token" workspace-services credentials ;;
    rust_pkg_codewire_daemon_bridge) want "$token" workspace-services ;;
    rust_pkg_codewire_dashboard_web | web) want "$token" dashboard-browser ;;
    # The IdP and its OIDC library sign every browser in and own edge routes;
    # it sends the verification and two-factor email.
    rust_pkg_codewire_idp | rust_pkg_codewire_oidc) want "$token" dashboard-browser edge-contract ;;
    rust_pkg_codewire_email) want "$token" dashboard-browser ;;
    rust_pkg_codewire_orchestration)
      want "$token" edge-contract workspace-services final-fencing runtime-acceptance credentials ;;
    # The client's examples are the session, run and coordinator ingress smokes.
    rust_pkg_codewire_client) want "$token" edge-contract workspace-services integrated ;;
    # Project documents drive environment setup and create-time detection.
    rust_pkg_codewire_project | rust_pkg_codewire_project_proto)
      want "$token" edge-contract workspace-services ;;
    # Billing and admin Connect routes, then the billing wire contract.
    rust_pkg_codewire_billing | rust_pkg_codewire_admin_proto) want "$token" edge-contract integrated ;;
    # Internal service TLS: orchestration roots, credential-service, Mesh.
    rust_pkg_codewire_tls) want "$token" edge-contract credentials integrated ;;
    # The coordinator runtime smokes include the Mesh ownership probe.
    transport_pkg_codewire_coordinator | transport_pkg_codewire_mesh) want "$token" integrated ;;
    # Coordinator and Mesh data plane, also linked into the sandbox daemon.
    transport_pkg_codewire_tailnet | transport_pkg_codewire_netstack)
      want "$token" integrated workspace-services ;;
    rust_pkg_codewire_server_core | rust_pkg_codewire_proto | rust_pkg_codewire_daemon_proto | \
      rust_pkg_codewire_workload_secrets)
      full "$token" 'every service compiles it; only the full gate rebuilds them all' ;;
    rust_workspace) full "$token" 'the workspace manifest or lockfile rebuilds every service' ;;
    contracts_proto) full "$token" 'protobuf contracts change every service and client' ;;
    rust_pkg_codewire_local_vmm | transport_pkg_codewire_local_vmm | \
      transport_pkg_codewire_vmm_guest_probe | rust_pkg_codewire_egress_broker | \
      rust_pkg_codewire_egress_policy)
      unobserved "$token" 'local microVM runtime; Kind runs none' ;;
    transport_pkg_codewire_derp | transport_pkg_codewire_udp_relay)
      unobserved "$token" 'not deployed in Kind' ;;
    rust_pkg_codewire_workspace_image)
      unobserved "$token" 'a workspace image pin is observed on Dev' ;;
    rust_pkg_codewire_desktop | rust_pkg_codewire_types) unobserved "$token" 'desktop only' ;;
    rust_pkg_codewire_cw_release)
      unobserved "$token" 'cw release store: SUITES=cw-runtime on a named profile' ;;
    rust_pkg_* | transport_pkg_*) full "$token" 'no retained suite is mapped to this crate yet' ;;
    # Kind relevance alone is decided after every token is mapped. Base
    # manifests select `deploy`, and the Kind cluster renders them too.
    edge_kind | kind | deploy) ;;
    # Families with no in-cluster behavior of their own. `database` names a
    # check family, not changed schema; changed migrations are found below.
    *) ;;
  esac
}

base="${PREFLIGHT_BASE_SHA:-}"
if [ -z "$base" ]; then
  for candidate in gitea/main origin/main main; do
    if git -C "$ROOT" rev-parse --verify --quiet "${candidate}^{commit}" >/dev/null; then
      base="$candidate"
      break
    fi
  done
fi
[ -n "$base" ] || die 'no base branch to compare against; set PREFLIGHT_BASE_SHA'
changes="$(python3 -B "$ROOT/scripts/dev/kind/service-sources.py" changes --base "$base")" \
  || die 'could not determine which services this change feeds'
changed_crates=" $(sed -n 's/^crate //p' <<<"$changes" | tr '\n' ' ')"
mapfile -t changed_services < <(sed -n 's/^service //p' <<<"$changes")
while read -r migration; do
  [ -n "$migration" ] || continue
  full "$migration" "deploying would apply it to this cluster's shared database"
done < <(sed -n 's/^migration //p' <<<"$changes")

if [ -n "${KIND_TEST_SUITES:-}" ]; then
  read -r -a requested <<<"$KIND_TEST_SUITES"
  want requested "${requested[@]}"
else
  explain="$("$ROOT/scripts/dev/preflight.sh" --explain 2>&1)" \
    || { printf '%s\n' "$explain" >&2; die "preflight could not classify the change"; }
  classification="$(sed -n 's/^preflight classification: //p' <<<"$explain")"
  required_mode="$(sed -n 's/^preflight required local mode: //p' <<<"$explain")"
  selection="$(sed -n 's/^preflight selection: //p' <<<"$explain")"
  [ -n "$selection" ] || die "preflight printed no selection"
  if [ "$classification" = unclassified ]; then
    full unclassified 'preflight cannot classify every changed path'
  fi
  IFS='|' read -r -a tokens <<<"$selection"
  # A workspace image change also selects the crates that compile the pin.
  # Unless those crates changed too, the pin is all that changed.
  if [[ "|${selection}|" == *'|rust_pkg_codewire_workspace_image|'* ]]; then
    kept=()
    for token in "${tokens[@]}"; do
      case "$token" in
        rust_pkg_codewire_server_core | rust_pkg_codewire_orchestration | \
          rust_pkg_codewire_dashboard_web | rust_pkg_codewire_cli)
          crate="${token#rust_pkg_}"
          [[ "$changed_crates" == *" ${crate//_/-} "* ]] || continue
          ;;
      esac
      kept+=("$token")
    done
    tokens=("${kept[@]}")
  fi
  # The selector marks a Kind-relevant path (harness, ingress, Kind overlay) by
  # requiring the Kind mode; the printed selection omits its Kind tokens.
  kind_relevant=false
  [ "$required_mode" != kind ] || kind_relevant=true
  for token in "${tokens[@]}"; do
    [ -n "$token" ] || continue
    case "$token" in edge_kind | kind | deploy) kind_relevant=true ;; esac
    map_token "$token"
  done
  if [ "$kind_relevant" = true ] && [ "${#wanted[@]}" -eq 0 ] && [ "${#full_reasons[@]}" -eq 0 ]; then
    full kind 'a Kind-relevant change with no narrower suite'
  fi
fi

for suite in "${!wanted[@]}"; do
  printf '%s\n' "${ORDER[@]}" | grep -Fxq "$suite" || die "unknown suite: ${suite}"
done
selected=()
for suite in "${ORDER[@]}"; do
  [ -n "${wanted[$suite]:-}" ] && selected+=("$suite")
done
log "change since ${base}"
for item in "${unobserved[@]}"; do
  log "  not observable in Kind: ${item}"
done
if [ "${#full_reasons[@]}" -gt 0 ]; then
  log 'only the full CI Kind gate covers this change; nothing was deployed or run:'
  for reason in "${full_reasons[@]}"; do
    log "  ${reason}"
  done
  log 'push it for CI (CODEWIRE_PREFLIGHT_MODE=ci git push), or name suites with SUITES=... to observe part of it'
  exit 3
fi
if [ "${#selected[@]}" -eq 0 ]; then
  log 'no Kind-observable change; nothing to run'
  exit 0
fi
for suite in "${selected[@]}"; do
  log "  suite ${suite}: ${why[$suite]}"
done
log "  services this change feeds: ${changed_services[*]:-none}"

if [ "$KIND_PROFILE" = 1 ]; then
  kind_profile_lock "$ROOT" || exit $?
  kind_profile_verify_node "$ROOT" || exit $?
  kind_profile_verify_artifacts "$ROOT" || exit $?
  if [ -n "${CARGO_CI_DIR:-}" ] && [ "$CARGO_CI_DIR" != "$KIND_PROFILE_SMOKE_DIR" ]; then
    die 'CARGO_CI_DIR conflicts with the saved immutable smoke artifact'
  fi
  export CARGO_CI_DIR="$KIND_PROFILE_SMOKE_DIR"
else
  # The default kubeconfig's port for a kept cluster goes stale when its node
  # restarts; ask kind for the current one, as each retained suite does.
  mkdir -p "$ROOT/.tmp"
  kubeconfig="$(mktemp "$ROOT/.tmp/kind-test-kubeconfig.XXXXXX")"
  trap 'rm -f "$kubeconfig"' EXIT
  kind get kubeconfig --name "$KIND_CLUSTER_NAME" >"$kubeconfig" \
    || die "cannot read the kubeconfig of ${KIND_CLUSTER_NAME}"
  export KUBECONFIG="$kubeconfig"
  # A kept cluster can publish shifted host ports. Address the ones its node
  # publishes (the node ports of tests/e2e/kind/kind-config.yaml), never the
  # defaults, which may belong to another cluster.
  for binding in KIND_INGRESS_HOST_PORT:80 KIND_INGRESS_TLS_HOST_PORT:443 \
      KIND_TEMPORAL_HOST_PORT:30733 KIND_ORCHESTRATION_HOST_PORT:30084 \
      KIND_COORDINATOR_DIRECT_HOST_PORT:30090 KIND_POSTGRES_HOST_PORT:30432; do
    variable="${binding%%:*}"
    published="$(docker port "${KIND_CLUSTER_NAME}-control-plane" "${binding#*:}/tcp" 2>/dev/null \
      | sed -n 's/^0\.0\.0\.0:\([0-9][0-9]*\)$/\1/p' | head -n 1)" || true
    [ -n "$published" ] || die "${KIND_CLUSTER_NAME} publishes no host port for node port ${binding#*:}"
    if [ -n "${!variable:-}" ] && [ "${!variable}" != "$published" ]; then
      die "${variable}=${!variable} is not the port ${KIND_CLUSTER_NAME} publishes (${published})"
    fi
    export "${variable}=${published}"
  done
fi

# Suites name their test environments kind-*. One still live, and not being
# destroyed, was left by a failed run or belongs to a suite running now: its
# Sandbox keeps authenticating to the credential bridge, which breaks the next
# credentials run's evidence, so start only from a clean cluster.
leftovers="$(kubectl --context "kind-${KIND_CLUSTER_NAME}" -n codewire-e2e exec deploy/postgres -- \
  psql -U codewire -d codewire -v ON_ERROR_STOP=1 -AtF ' ' -c \
  "SELECT id, name, state FROM environments WHERE name LIKE 'kind-%' AND desired_state <> 'destroyed' ORDER BY created_at")" \
  || die "cannot list the cluster's environments"
if [ -n "$leftovers" ]; then
  log 'refusing to start: kind-* environments from an earlier or still running suite are live:'
  while read -r leftover; do
    log "  ${leftover}"
  done <<<"$leftovers"
  log 'if no suite is running, remove each with the product CLI as the suites do (env --platform rm ID), then its kind-* profiles and credentials'
  exit 1
fi

# The browser suite browses the ingress origin. `make kind-watch` points the
# cluster at the review origin instead, where its sign-in, Origin and device
# flows fail; say so rather than run it into those failures.
if [[ " ${selected[*]} " == *" dashboard-browser "* ]]; then
  ingress="${KIND_INGRESS_URL:-http://127.0.0.1:${KIND_INGRESS_HOST_PORT:-8090}}"
  frontend="$(kubectl --context "kind-${KIND_CLUSTER_NAME}" -n codewire-e2e get configmap codewire-config \
    -o 'jsonpath={.data.FRONTEND_URL}')" || die "cannot read the cluster's browser origin"
  if [ "$frontend" != "$ingress" ]; then
    log "refusing to start: dashboard-browser browses ${ingress}, but ${KIND_CLUSTER_NAME} serves ${frontend:-no origin}"
    log 'run make kind-credentials-fake to restore the ingress origin (restart make kind-watch afterwards to review again)'
    exit 1
  fi
fi

# The browser suite drives the dashboard's frozen Playwright install (its
# pinned Chromium it installs itself); provide it as CI does, once per checkout.
if [[ " ${selected[*]} " == *" dashboard-browser "* ]] \
    && [ ! -x "$ROOT/apps/dashboard/node_modules/.bin/playwright" ]; then
  log 'installing the frozen dashboard dependencies for the browser suite'
  (cd "$ROOT" && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 bun install --frozen-lockfile --ignore-scripts) \
    || die 'the frozen dashboard dependency install failed'
fi

started=$SECONDS
for service in "${SERVICES[@]}"; do
  KIND_CLUSTER_NAME="$KIND_CLUSTER_NAME" KIND_DEPLOY_SKIP_CURRENT=1 \
    "$ROOT/scripts/dev/kind/deploy-service.sh" "$service" || die "deploying ${service} failed"
done
# The synthetic trust roots renew at 72 hours. A deploy republishes them; do
# it here too, for a run that deploys nothing.
"$ROOT/scripts/dev/kind/trust-roots.sh" || die 'republishing the synthetic trust roots failed'
timings=("deploy $((SECONDS - started))s")
for suite in "${selected[@]}"; do
  started=$SECONDS
  # Test the current source against the cluster as deployed, not only an
  # unchanged tree that matches the image receipt.
  KIND_CLUSTER_NAME="$KIND_CLUSTER_NAME" KIND_RETAINED_USE_CLUSTER_WORKSPACE=1 \
    "$ROOT/scripts/ci/verify/kind-e2e.sh" suite "$suite" || die "suite ${suite} failed after $((SECONDS - started))s"
  timings+=("${suite} $((SECONDS - started))s")
  log "suite ${suite} green in $((SECONDS - started))s"
done
log "all selected suites green: ${timings[*]}"
