#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/verify/kind-e2e.sh"
COMMON="$ROOT/scripts/ci/verify/kind/common.sh"
INTEGRATED="$ROOT/scripts/ci/verify/kind/suites/integrated.sh"
DASHBOARD_BROWSER="$ROOT/scripts/ci/verify/kind/suites/dashboard-browser.sh"
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

bash -n "$SCRIPT" "$COMMON" "$INTEGRATED" "$DASHBOARD_BROWSER" "$FINAL_FENCING" \
  "$ENVIRONMENT_SESSION" "$0"
grep -Fq 'CRD_SMOKE_GATEWAY_TOKEN="$daemon_token"' "$COMMON" ||
  fail 'local gateway and workspace daemon do not share the derived credential'
grep -Fq 'CRD_SMOKE_GATEWAY_TOKEN is required with CRD_SMOKE_LOCAL_GATEWAY=1' \
  "$ROOT/crates/codewire-orchestration/src/bin/crd-smoke.rs" ||
  fail 'local CRD smoke permits an unrelated literal gateway credential'
grep -Fq 'KIND_POSTGRES_HOST_PORT="${KIND_POSTGRES_HOST_PORT:-25432}"' "$COMMON" ||
  fail 'Kind Postgres host port is not configurable with the accepted default'
grep -Fq 'sed "s/hostPort: 25432/hostPort: ${KIND_POSTGRES_HOST_PORT}/"' "$COMMON" ||
  fail 'Kind cluster creation does not render the configured Postgres host port'
grep -Fq 'configure_remote_dind_kind_network' "$COMMON" ||
  fail 'Kind cluster creation does not adapt the remote DinD network boundary'
if grep -Fq '127.0.0.1:25432/codewire' "$COMMON"; then
  fail 'Kind smoke callers bypass the configurable Postgres URL'
fi

# Sourcing the dispatcher defines every suite without executing one.
# shellcheck source=scripts/ci/verify/kind-e2e.sh
source "$SCRIPT"

missing_tool=codewire-deliberately-missing-kind-tool
if (require_tool "$missing_tool") >"$FIXTURE/missing-tool.out" 2>&1; then
  fail 'missing Kind prerequisite unexpectedly succeeded'
fi
grep -Fq "missing required tool: $missing_tool" "$FIXTURE/missing-tool.out" ||
  fail 'missing Kind prerequisite did not explain its failure'

# No arguments retain the complete integrated gate; the retained suite requires
# the exact two-token command and unknown input fails closed.
: >"$CALLS"
run_integrated_kind_suite() { record integrated; }
run_retained_dashboard_browser_suite() { record dashboard-browser-retained; }
run_retained_final_fencing_suite() { record final-fencing; }
run_retained_environment_session_suite() { record environment-session; }
dispatch_kind_e2e
printf '%s\n' integrated | cmp -s - "$CALLS" || fail 'no-argument dispatch changed'

: >"$CALLS"
dispatch_kind_e2e suite dashboard-browser
printf '%s\n' dashboard-browser-retained | cmp -s - "$CALLS" ||
  fail 'dashboard-browser dispatch changed'

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
# shellcheck source=scripts/ci/verify/kind/suites/dashboard-browser.sh
source "$DASHBOARD_BROWSER"
# shellcheck source=scripts/ci/verify/kind/suites/final-fencing.sh
source "$FINAL_FENCING"
# shellcheck source=scripts/ci/verify/kind/suites/environment-session.sh
source "$ENVIRONMENT_SESSION"

# The integrated suite builds before starting its disposable control plane and
# proves API readiness after image import. Stub every expensive action so this
# fixture proves dispatch and order without creating a cluster.
: >"$CALLS"
require_tool() { record "require:$1"; }
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
billing_contract_through_ingress() { record billing; }
deploy_agent_sandbox_and_smoke() { record sandbox-temporal; }
dashboard_browser_e2e() { record dashboard-browser; }
assert_sandbox_supply_chain() { record sandbox-supply-chain; }
rust_reconciler_ttl_e2e() { record ttl; }
log() { record "log:$*"; }
run_integrated_kind_suite
trap - EXIT
trap cleanup_fixture EXIT
cat >"$FIXTURE/want-order" <<'EOF'
require:curl
require:base64
require:docker
require:jq
require:kind
require:kubectl
require:openssl
require:psql
require:python3
require:ssh-keygen
require:ssh-keyscan
reclaim
ingress-drift
build
create-cluster
load
deploy
host-key-authz
edge
connect-edge
internal-connect
mesh-product-connect-ownership
coordinator
billing
sandbox-temporal
dashboard-browser
sandbox-supply-chain
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

# Every large image import is separated by an API recovery gate. This keeps a
# temporarily starved control plane from accumulating four back-to-back imports.
: >"$CALLS"
kind() { record "kind:$*"; }
wait_for_kind_api_after_image_load() { record wait-api; }
log() { :; }
load_images_into_kind
cat >"$FIXTURE/want-image-load-order" <<EOF
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-dashboard:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-services:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-mesh:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-gateway:e2e
wait-api
EOF
cmp -s "$FIXTURE/want-image-load-order" "$CALLS" || {
  diff -u "$FIXTURE/want-image-load-order" "$CALLS" >&2 || true
  fail 'Kind image imports are not separated by API recovery gates'
}

# Forgejo CI names only the two approved Nexus platform manifests. They must
# already exist in the private DinD store, are side-loaded after product
# images, and replace every pinned public reference in a disposable render.
: >"$CALLS"
env \
  KIND_INGRESS_CONTROLLER_IMAGE='nexus-system-cluster.example.invalid/oci-approved/ingress-nginx/controller@sha256:5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180' \
  KIND_INGRESS_CERTGEN_IMAGE='nexus-system-cluster.example.invalid/oci-approved/ingress-nginx/kube-webhook-certgen@sha256:334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053' \
  ROOT="$ROOT" COMMON="$COMMON" CALLS="$CALLS" bash -seu <<'BASH'
  fail() { printf "[sealed-kind-test] ERROR: %s\n" "$*" >&2; exit 1; }
  record() { printf "%s\n" "$1" >>"$CALLS"; }
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$COMMON"
  docker() {
    [ "${1:-} ${2:-}" = 'image inspect' ] || fail "unexpected sealed Docker invocation: $*"
    record "docker:$*"
  }
  kind() { record "kind:$*"; }
  wait_for_kind_api_after_image_load() { record wait-api; }
  log() { :; }
  load_images_into_kind
  rendered="$(render_ingress_manifest)"
  [ "$(grep -Fc "$KIND_INGRESS_CONTROLLER_IMAGE" "$rendered")" -eq 1 ] ||
    fail 'sealed ingress render does not contain the exact controller once'
  [ "$(grep -Fc "$KIND_INGRESS_CERTGEN_IMAGE" "$rendered")" -eq 2 ] ||
    fail 'sealed ingress render does not contain the exact certgen twice'
  if grep -Fq 'registry.k8s.io/ingress-nginx/' "$rendered"; then
    fail 'sealed ingress render retained a public registry image'
  fi
BASH
grep -Fq "docker:image inspect nexus-system-cluster.example.invalid/oci-approved/ingress-nginx/controller@sha256:5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180" "$CALLS" ||
  fail 'sealed controller was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image inspect nexus-system-cluster.example.invalid/oci-approved/ingress-nginx/kube-webhook-certgen@sha256:334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053" "$CALLS" ||
  fail 'sealed certgen was not proven in the runner-preloaded Docker store'

grep -Fq 'KIND_INGRESS_CONTROLLER_IMAGE: nexus-system-cluster.example.invalid/oci-approved/ingress-nginx/controller@sha256:5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180' \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved ingress controller'
grep -Fq 'KIND_INGRESS_CERTGEN_IMAGE: nexus-system-cluster.example.invalid/oci-approved/ingress-nginx/kube-webhook-certgen@sha256:334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053' \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved ingress cert generator'

# Restore the production API recovery implementation after the load-order spy.
# shellcheck source=scripts/ci/verify/kind/common.sh
source "$COMMON"

# A remote DinD job joins the exact Kind network, receives an internal
# kubeconfig, and starts loopback-only forwarding for the existing host-port
# contracts. A local Docker caller remains untouched.
: >"$CALLS"
(
  HOSTNAME=remote-job
  HOME="$FIXTURE/remote-home"
  KUBECONFIG="$FIXTURE/remote-kubeconfig"
  docker() {
    # shellcheck disable=SC2016 # Match the literal Go-template CLI argument.
    case "$*" in
      'container inspect remote-job') return 0 ;;
      "inspect --format {{range \$name, \$_ := .NetworkSettings.Networks}}{{println \$name}}{{end}} ${KIND_CLUSTER_NAME}-control-plane")
        printf 'kind\n'
        ;;
      'network connect kind remote-job') record 'network-connect:kind:remote-job' ;;
      *) fail "unexpected remote Docker invocation: $*" ;;
    esac
  }
  kind() {
    if [ "$*" != "get kubeconfig --internal --name $KIND_CLUSTER_NAME" ]; then
      fail "unexpected remote Kind invocation: $*"
    fi
    printf 'apiVersion: v1\ncurrent-context: kind-%s\n' "$KIND_CLUSTER_NAME"
  }
  start_remote_dind_kind_forwarding() { record "forward:$1"; }
  log() { record "log:$*"; }
  configure_remote_dind_kind_network
  grep -Fqx "current-context: kind-${KIND_CLUSTER_NAME}" "$KUBECONFIG" ||
    fail 'remote DinD kubeconfig did not use the internal Kind rendering'
)
cat >"$FIXTURE/want-remote-dind" <<EOF
network-connect:kind:remote-job
forward:${KIND_CLUSTER_NAME}-control-plane
log:remote DinD Kind API and host-port topology configured
EOF
cmp -s "$FIXTURE/want-remote-dind" "$CALLS" || {
  diff -u "$FIXTURE/want-remote-dind" "$CALLS" >&2 || true
  fail 'remote DinD Kind network adaptation changed'
}

: >"$CALLS"
(
  HOSTNAME=local-host
  docker() {
    record "docker:$*"
    return 1
  }
  log() { record "log:$*"; }
  configure_remote_dind_kind_network
)
cat >"$FIXTURE/want-local-docker" <<'EOF'
docker:container inspect local-host
log:local Docker topology detected; retaining Kind host-port kubeconfig
EOF
cmp -s "$FIXTURE/want-local-docker" "$CALLS" ||
  fail 'local Docker topology no longer bypasses remote DinD adaptation'

# A transient API refusal after image import is retried, but a control plane
# that never recovers fails closed at the fixed 60-second boundary.
: >"$CALLS"
(
  attempts=0
  kubectl() {
    attempts=$((attempts + 1))
    record "probe:${attempts}:$*"
    [ "$attempts" -ge 3 ]
  }
  sleep() { record "sleep:$1"; }
  log() { record "log:$*"; }
  wait_for_kind_api_after_image_load
)
cat >"$FIXTURE/want-api-recovery" <<EOF
log:checking Kind API after image import
probe:1:--context kind-${KIND_CLUSTER_NAME} --request-timeout=1s get --raw=/readyz
sleep:1
probe:2:--context kind-${KIND_CLUSTER_NAME} --request-timeout=1s get --raw=/readyz
sleep:1
probe:3:--context kind-${KIND_CLUSTER_NAME} --request-timeout=1s get --raw=/readyz
log:Kind API ready after image import
EOF
cmp -s "$FIXTURE/want-api-recovery" "$CALLS" || {
  diff -u "$FIXTURE/want-api-recovery" "$CALLS" >&2 || true
  fail 'Kind API recovery did not retain its bounded retry contract'
}

: >"$CALLS"
if (
  kubectl() { record probe; return 1; }
  sleep() { :; }
  capture_kind_control_plane_state() { record diagnostic; }
  wait_for_kind_api_after_image_load
) >"$FIXTURE/api-unavailable.out" 2>&1; then
  fail 'permanently unavailable Kind API unexpectedly succeeded'
fi
[ "$(grep -c '^probe$' "$CALLS")" -eq 60 ] ||
  fail 'Kind API failure did not exhaust the fixed retry boundary'
[ "$(grep -c '^diagnostic$' "$CALLS")" -eq 1 ] ||
  fail 'Kind API failure did not capture one value-blind diagnostic'
grep -Fq 'did not become ready within 60 seconds after image import' \
  "$FIXTURE/api-unavailable.out" ||
  fail 'Kind API failure did not explain the bounded recovery failure'

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
