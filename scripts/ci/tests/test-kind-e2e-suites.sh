#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/verify/kind-e2e.sh"
COMMON="$ROOT/scripts/ci/verify/kind/common.sh"
INTEGRATED="$ROOT/scripts/ci/verify/kind/suites/integrated.sh"
FINAL_FENCING="$ROOT/scripts/ci/verify/kind/suites/final-fencing.sh"
ENVIRONMENT_SESSION="$ROOT/scripts/ci/verify/kind/suites/environment-session.sh"
mkdir -p "$ROOT/.tmp"
FIXTURE="$(mktemp -d "$ROOT/.tmp/kind-e2e-suites.XXXXXX")"
CALLS="$FIXTURE/calls"

cleanup_fixture() {
  rm -rf "$FIXTURE"
}
trap cleanup_fixture EXIT

fail() {
  printf '[test-kind-e2e-suites] ERROR: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$FIXTURE/${label}.out" 2>&1; then
    fail "$label unexpectedly succeeded"
  fi
}

record() {
  printf '%s\n' "$1" >>"$CALLS"
}

bash -n "$SCRIPT" "$COMMON" "$INTEGRATED" "$FINAL_FENCING" \
  "$ENVIRONMENT_SESSION" "$0"
grep -Fq 'CRD_SMOKE_GATEWAY_TOKEN="$daemon_token"' "$COMMON" ||
  fail 'local gateway and workspace daemon do not share the derived credential'
grep -Fq 'CRD_SMOKE_GATEWAY_TOKEN is required with CRD_SMOKE_LOCAL_GATEWAY=1' \
  "$ROOT/crates/codewire-orchestration/src/bin/crd-smoke.rs" ||
  fail 'local CRD smoke permits an unrelated literal gateway credential'

# Sourcing the dispatcher defines every suite without executing one.
# shellcheck source=scripts/ci/verify/kind-e2e.sh
source "$SCRIPT"

# No arguments retain the complete integrated gate; the retained suite requires
# the exact two-token command and unknown input fails closed.
: >"$CALLS"
run_integrated_kind_suite() { record integrated; }
run_retained_final_fencing_suite() { record final-fencing; }
run_retained_environment_session_suite() { record environment-session; }
dispatch_kind_e2e
printf '%s\n' integrated | cmp -s - "$CALLS" || fail 'no-argument dispatch changed'

: >"$CALLS"
dispatch_kind_e2e suite final-fencing
printf '%s\n' final-fencing | cmp -s - "$CALLS" || fail 'final-fencing dispatch changed'

: >"$CALLS"
dispatch_kind_e2e suite environment-session
printf '%s\n' environment-session | cmp -s - "$CALLS" ||
  fail 'environment-session dispatch changed'

expect_failure missing-suite dispatch_kind_e2e suite
grep -Fq 'requires exactly one suite name' "$FIXTURE/missing-suite.out" ||
  fail 'missing suite did not explain its failure'
expect_failure unknown-suite dispatch_kind_e2e suite unknown
grep -Fq 'unknown Kind e2e suite: unknown' "$FIXTURE/unknown-suite.out" ||
  fail 'unknown suite did not explain its failure'
expect_failure unknown-command dispatch_kind_e2e retained
grep -Fq 'unknown Kind e2e command: retained' "$FIXTURE/unknown-command.out" ||
  fail 'unknown command did not explain its failure'

# Restore the production suite functions replaced by the dispatcher spies.
# shellcheck source=scripts/ci/verify/kind/suites/integrated.sh
source "$INTEGRATED"
# shellcheck source=scripts/ci/verify/kind/suites/final-fencing.sh
source "$FINAL_FENCING"
# shellcheck source=scripts/ci/verify/kind/suites/environment-session.sh
source "$ENVIRONMENT_SESSION"

# The integrated suite retains the exact existing order. Stub every expensive
# action so this fixture proves dispatch and order without creating a cluster.
: >"$CALLS"
require_tool() { :; }
reclaim_cancelled_ci_clusters() { record reclaim; }
# shellcheck disable=SC2329 # Invoked indirectly by the integrated EXIT trap.
cleanup() { :; }
ingress_path_drift_check() { record ingress-drift; }
create_cluster() { record create-cluster; }
build_images_and_smokes() { record build; }
load_images_into_kind() { record load; }
deploy_overlay() { record deploy; }
host_key_authorization_smoke() { record host-key-authz; }
edge_routing_probes() { record edge; }
connect_edge_probes() { record connect-edge; }
internal_connect_listener_probes() { record internal-connect; }
mesh_product_connect_ownership_smoke() { record mesh-product-connect-ownership; }
coordinator_ingress_smoke() { record coordinator; }
gateway_selector_smoke() { record gateway-selector; }
billing_contract_through_ingress() { record billing; }
deploy_agent_sandbox_and_smoke() { record sandbox-temporal; }
rust_reconciler_ttl_e2e() { record ttl; }
log() { record "log:$*"; }
run_integrated_kind_suite
trap - EXIT
trap cleanup_fixture EXIT
cat >"$FIXTURE/want-order" <<'EOF'
reclaim
ingress-drift
create-cluster
build
load
deploy
host-key-authz
edge
connect-edge
internal-connect
mesh-product-connect-ownership
coordinator
gateway-selector
billing
sandbox-temporal
ttl
log:green
EOF
cmp -s "$FIXTURE/want-order" "$CALLS" || {
  diff -u "$FIXTURE/want-order" "$CALLS" >&2 || true
  fail 'integrated suite order changed'
}

# Restore shared production functions replaced by the integrated-order spies.
# shellcheck source=scripts/ci/verify/kind/common.sh
source "$COMMON"

# A cluster becomes rerunnable only after controller, workspace/file, and
# ordinary Temporal prerequisites pass, immediately before final fencing.
: >"$CALLS"
deploy_agent_sandbox() { record deploy-agent; }
workspace_service_smokes() { record workspace-services; }
temporal_workflow_smoke() { record temporal-workflow; }
mark_retained_cluster_prepared() { record prepared-marker; }
temporal_fencing_smoke() { record temporal-fencing; }
deploy_agent_sandbox_and_smoke
cat >"$FIXTURE/want-prepared-order" <<'EOF'
deploy-agent
workspace-services
temporal-workflow
prepared-marker
temporal-fencing
EOF
cmp -s "$FIXTURE/want-prepared-order" "$CALLS" ||
  fail 'prepared marker does not guard the final-fencing boundary'

# Retained validation rejects implicit naming, missing clusters, the wrong
# current context, missing markers, and incompatible marker versions.
KIND_CLUSTER_NAME=retained-fixture
KIND_CLUSTER_NAME_EXPLICIT=0
expect_failure implicit-cluster validate_retained_cluster
grep -Fq 'explicit non-empty KIND_CLUSTER_NAME' "$FIXTURE/implicit-cluster.out" ||
  fail 'implicit cluster rejection was not decisive'

FAKE_CLUSTERS=other-cluster
FAKE_CONTEXT=kind-retained-fixture
FAKE_MARKER_VERSION="$KIND_E2E_COMPATIBILITY_VERSION"
FAKE_MARKER_CLUSTER="$KIND_CLUSTER_NAME"
FAKE_MARKER_MISSING=0
kind() {
  case "$*" in
    'get clusters') printf '%s\n' "$FAKE_CLUSTERS" ;;
    'get kubeconfig --name retained-fixture')
      printf 'apiVersion: v1\ncurrent-context: kind-retained-fixture\n'
      ;;
    *) fail "unexpected fake kind invocation: $*" ;;
  esac
}
kubectl() {
  case "$*" in
    'config current-context') printf '%s\n' "$FAKE_CONTEXT" ;;
    *'cluster-info'*) return 0 ;;
    *"configmap/${KIND_E2E_PREPARED_CONFIGMAP}"*"compatibility_version"*)
      if [ "$FAKE_MARKER_MISSING" = 1 ]; then
        printf 'NotFound\n' >&2
        return 1
      fi
      printf '%s' "$FAKE_MARKER_VERSION"
      ;;
    *"configmap/${KIND_E2E_PREPARED_CONFIGMAP}"*"cluster-name"*)
      printf '%s' "$FAKE_MARKER_CLUSTER"
      ;;
    *'get deployment/'*) printf '1' ;;
    *'get crd/sandboxclaims.extensions.agents.x-k8s.io'*) return 0 ;;
    *) fail "unexpected fake kubectl invocation: $*" ;;
  esac
}

KIND_CLUSTER_NAME_EXPLICIT=1
expect_failure missing-cluster validate_retained_cluster
grep -Fq 'does not exist' "$FIXTURE/missing-cluster.out" ||
  fail 'missing cluster rejection was not decisive'

FAKE_CLUSTERS=$KIND_CLUSTER_NAME
FAKE_CONTEXT=codewire-dev
expect_failure wrong-context validate_retained_cluster
grep -Fq 'does not match retained Kind context' "$FIXTURE/wrong-context.out" ||
  fail 'wrong context rejection was not decisive'

FAKE_CONTEXT=kind-retained-fixture
FAKE_MARKER_MISSING=1
expect_failure missing-marker validate_retained_cluster
grep -Fq 'is unprepared' "$FIXTURE/missing-marker.out" || {
  sed -n '1,80p' "$FIXTURE/missing-marker.out" >&2
  fail 'missing marker rejection was not decisive'
}

FAKE_MARKER_MISSING=0
FAKE_MARKER_VERSION=0
expect_failure incompatible-marker validate_retained_cluster
grep -Fq 'marker is incompatible' "$FIXTURE/incompatible-marker.out" ||
  fail 'incompatible marker rejection was not decisive'

mkdir -p "$FIXTURE/bin"
printf '#!/usr/bin/env bash\nexit 0\n' >"$FIXTURE/bin/temporal-fencing-smoke"
chmod +x "$FIXTURE/bin/temporal-fencing-smoke"
CARGO_CI_DIR="$FIXTURE/bin"
FAKE_MARKER_VERSION="$KIND_E2E_COMPATIBILITY_VERSION"
validate_retained_cluster >"$FIXTURE/accepted.out"
grep -Fq 'accepted at compatibility version' "$FIXTURE/accepted.out" ||
  fail 'compatible retained cluster was not accepted'

# A retained-suite failure dumps state but never deletes its cluster, even when
# KEEP_KIND_CLUSTER is unset or zero.
: >"$CALLS"
validate_retained_cluster() { :; }
temporal_fencing_smoke() { return 42; }
stop_gateway_port_forward() { :; }
dump_cluster_state() { record dump; }
log() { record "log:$*"; }
kind() { record "kind:$*"; }
KEEP_KIND_CLUSTER=0
RETAINED_KUBECONFIG=""
if (run_retained_final_fencing_suite); then
  fail 'failing retained final-fencing suite unexpectedly succeeded'
fi
grep -Fxq dump "$CALLS" || fail 'retained failure did not dump cluster state'
if grep -Fq 'delete cluster' "$CALLS"; then
  fail 'retained suite tried to delete its cluster'
fi

printf '[test-kind-e2e-suites] dispatcher, order, prerequisites, and cleanup passed\n'
