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
readonly SEALED_CONTROLLER_IMAGE='nexus.example.invalid/oci-approved/ingress-nginx/controller@sha256:5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180'
readonly SEALED_CERTGEN_IMAGE='nexus.example.invalid/oci-approved/ingress-nginx/kube-webhook-certgen@sha256:334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053'
readonly SEALED_AGENT_IMAGE='nexus.example.invalid/oci-approved/codewire/agent-sandbox-controller@sha256:6081ae66b4134ebc6b170d965741b8dae09442ec74563b6c1ac999c366dac125'
readonly SEALED_WORKSPACE_IMAGE='nexus.example.invalid/oci-approved/codewire/workspace@sha256:cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510'
readonly SEALED_DIND_IMAGE='nexus.example.invalid/oci-approved/docker/dind@sha256:66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e'

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
grep -Fq 'std::env::var("CRD_SMOKE_WORKSPACE_IMAGE")' \
  "$ROOT/crates/codewire-orchestration/src/bin/crd-smoke.rs" ||
  fail 'CRD smoke cannot consume the sealed workspace alias'
grep -Fq 'std::env::var("SMOKE_WORKSPACE_IMAGE")' \
  "$ROOT/crates/codewire-orchestration/src/bin/temporal-fencing-smoke.rs" ||
  fail 'Temporal fencing smoke cannot consume the sealed workspace alias'
[[ "$(grep -Fc 'SMOKE_WORKSPACE_IMAGE="$(kind_workspace_runtime_image)"' "$COMMON")" -eq 4 ]] ||
  fail 'Kind smoke callers do not consistently select the sealed workspace alias'
grep -Fq 'PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE="$(kind_workspace_runtime_image)"' "$COMMON" ||
  fail 'dashboard lifecycle does not select the sealed workspace alias'
grep -Fq 'process.env.PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE || workspaceImage' \
  "$ROOT/apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts" ||
  fail 'dashboard lifecycle preset cannot consume the sealed workspace alias'
grep -Fq '(${presetId}, ${workspaceRuntimeImage},' \
  "$ROOT/apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts" ||
  fail 'dashboard lifecycle preset ignores its selected runtime workspace image'
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

# Protected delivery may supply exact locally materialized release candidates.
# The suite accepts them only when every product alias carries the same exact
# source identity and release/promotable labels; ordinary PR Kind still builds
# the non-promotable CI profile itself.
docker() {
  if [ "${1:-} ${2:-} ${3:-}" = 'image inspect --format' ]; then
    case "${4:-}" in
      *dev.codewire.build.profile*) printf '%s\n' release ;;
      *dev.codewire.promotable*) printf '%s\n' true ;;
      *org.opencontainers.image.revision*) printf '%s\n' 0123456789abcdef0123456789abcdef01234567 ;;
      *) fail "unexpected protected image assertion: $*" ;;
    esac
    return
  fi
  [ "${1:-} ${2:-}" = 'image inspect' ] || fail "unexpected protected image command: $*"
}
CODEWIRE_KIND_EXPECTED_SOURCE_SHA=0123456789abcdef0123456789abcdef01234567
assert_prebuilt_release_product_images
CODEWIRE_KIND_EXPECTED_SOURCE_SHA=not-a-sha
expect_failure malformed-prebuilt-source assert_prebuilt_release_product_images
grep -Fq 'prebuilt release images require one exact expected source SHA' \
  "$FIXTURE/malformed-prebuilt-source.out" ||
  fail 'prebuilt release image mode accepted a malformed source identity'
unset -f docker
unset CODEWIRE_KIND_EXPECTED_SOURCE_SHA

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
acquire_kind_host_lock() { record acquire-lock; }
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
require:flock
require:jq
require:kind
require:kubectl
require:openssl
require:psql
require:python3
require:ssh-keygen
require:ssh-keyscan
acquire-lock
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

# The integrated transaction lock is host-wide rather than worktree-local and
# is bounded, so concurrent local suites wait instead of deleting each other.
: >"$CALLS"
KIND_HOST_LOCK_FILE="$FIXTURE/kind-host.lock"
KIND_HOST_LOCK_TIMEOUT_SECONDS=37
flock() { record "flock:$*"; }
log() { :; }
acquire_kind_host_lock
[ -f "$KIND_HOST_LOCK_FILE" ] || fail 'Kind host lock file was not created'
grep -Eq '^flock:-w 37 [0-9]+$' "$CALLS" ||
  fail 'Kind host lock is not acquired with the configured bound'

# Cancelled-run cleanup owns run-ID-suffixed CI clusters, but it must preserve
# the unsuffixed local default and every unrelated local Kind cluster.
: >"$CALLS"
cat >"$FIXTURE/kind-config.yaml" <<'EOF'
hostPort: 8090
EOF
kind() {
  case "${1:-} ${2:-}" in
    'get clusters')
      if grep -q '^kind:delete ' "$CALLS"; then
        printf '%s\n' agent-sandbox codewire e2e-test
      else
        printf '%s\n' codewire-e2e-ci codewire-e2e-ci-873 agent-sandbox codewire e2e-test
      fi
      ;;
    'delete cluster') record "kind:delete ${4:-}" ;;
    *) fail "unexpected Kind cleanup invocation: $*" ;;
  esac
}
docker() {
  [ "${1:-}" = ps ] || fail "unexpected Docker cleanup invocation: $*"
}
log() { :; }
reclaim_cancelled_ci_clusters "$FIXTURE/kind-config.yaml"
cat >"$FIXTURE/want-cancelled-cleanup" <<'EOF'
kind:delete codewire-e2e-ci-873
EOF
cmp -s "$FIXTURE/want-cancelled-cleanup" "$CALLS" || {
  diff -u "$FIXTURE/want-cancelled-cleanup" "$CALLS" >&2 || true
  fail 'cancelled-run cleanup did not preserve the exact CI ownership boundary'
}

# Every large image import is separated by an API recovery gate. This keeps a
# temporarily starved control plane from accumulating four back-to-back imports.
: >"$CALLS"
docker() {
  case "${1:-} ${2:-}" in
    'image inspect'|'image tag') ;;
    *) fail "unexpected Docker invocation: $*" ;;
  esac
}
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
if [ -n "${KIND_INGRESS_CONTROLLER_IMAGE:-}" ] \
    && [ -n "${KIND_INGRESS_CERTGEN_IMAGE:-}" ] \
    && [ -n "${KIND_AGENT_SANDBOX_IMAGE:-}" ] \
    && [ -n "${KIND_WORKSPACE_IMAGE:-}" ] \
    && [ -n "${KIND_DIND_IMAGE:-}" ]; then
  cat >>"$FIXTURE/want-image-load-order" <<EOF
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_INGRESS_CONTROLLER_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_INGRESS_CERTGEN_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_AGENT_SANDBOX_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_WORKSPACE_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_DIND_LOCAL_IMAGE}
wait-api
EOF
fi
cmp -s "$FIXTURE/want-image-load-order" "$CALLS" || {
  diff -u "$FIXTURE/want-image-load-order" "$CALLS" >&2 || true
  fail 'Kind image imports are not separated by API recovery gates'
}

# Forgejo CI names only the five approved Nexus manifests. They must
# already exist in the private DinD store, are side-loaded after product
# images, and replace every pinned public reference in a disposable render.
: >"$CALLS"
env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  ROOT="$ROOT" COMMON="$COMMON" CALLS="$CALLS" bash -seu <<'BASH'
  fail() { printf "[sealed-kind-test] ERROR: %s\n" "$*" >&2; exit 1; }
  record() { printf "%s\n" "$1" >>"$CALLS"; }
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$COMMON"
  [ "$(kind_workspace_runtime_image)" = "$KIND_WORKSPACE_LOCAL_IMAGE" ] ||
    fail 'sealed workspace input did not resolve to its local alias'
  [ "$(kind_dind_runtime_image)" = "$KIND_DIND_LOCAL_IMAGE" ] ||
    fail 'sealed DinD input did not resolve to its local alias'
  docker() {
    case "${1:-} ${2:-}" in
      'image inspect'|'image tag') ;;
      *) fail "unexpected sealed Docker invocation: $*" ;;
    esac
    record "docker:$*"
  }
  kind() { record "kind:$*"; }
  wait_for_kind_api_after_image_load() { record wait-api; }
  log() { :; }
  load_images_into_kind
  rendered="$(render_ingress_manifest)"
  agent_rendered="$(render_agent_sandbox_manifest)"
  kind_rendered="$(render_kind_overlay_manifest)"
  [ "$(grep -Fc "$KIND_INGRESS_CONTROLLER_LOCAL_IMAGE" "$rendered")" -eq 1 ] ||
    fail 'sealed ingress render does not contain the local controller once'
  [ "$(grep -Fc "$KIND_INGRESS_CERTGEN_LOCAL_IMAGE" "$rendered")" -eq 2 ] ||
    fail 'sealed ingress render does not contain the local certgen twice'
  [ "$(grep -Fc 'imagePullPolicy: Never' "$rendered")" -eq 3 ] ||
    fail 'sealed ingress render does not prohibit registry pulls'
  if grep -Fq 'nexus.example.invalid/oci-approved/ingress-nginx/' "$rendered"; then
    fail 'sealed ingress render retained a private registry reference'
  fi
  if grep -Fq 'registry.k8s.io/ingress-nginx/' "$rendered"; then
    fail 'sealed ingress render retained a public registry image'
  fi
  [ "$(grep -Fc "$KIND_AGENT_SANDBOX_LOCAL_IMAGE" "$agent_rendered")" -eq 1 ] ||
    fail 'sealed agent-sandbox render does not contain the local controller once'
  [ "$(grep -Fc 'imagePullPolicy: Never' "$agent_rendered")" -eq 1 ] ||
    fail 'sealed agent-sandbox render does not prohibit registry pulls'
  if grep -Fq 'nexus.example.invalid/oci-approved/codewire/' "$agent_rendered"; then
    fail 'sealed agent-sandbox render retained a private registry reference'
  fi
  if grep -Fq 'ghcr.io/noeljackson/agent-sandbox-controller' "$agent_rendered"; then
    fail 'sealed agent-sandbox render retained the public registry image'
  fi
  [ "$(grep -Fc "$KIND_DIND_LOCAL_IMAGE" "$kind_rendered")" -eq 1 ] ||
    fail 'sealed Kind overlay does not contain the local DinD alias once'
  [ "$(grep -Fc "$KIND_WORKSPACE_LOCAL_IMAGE" "$kind_rendered")" -eq 1 ] ||
    fail 'sealed Kind overlay does not contain the local warm-pool workspace alias once'
  if grep -Fq 'docker.io/library/docker:29.7.1-dind' "$kind_rendered"; then
    fail 'sealed Kind overlay retained the public DinD image'
  fi
  if grep -Fq 'ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467' "$kind_rendered"; then
    fail 'sealed Kind overlay retained the public warm-pool workspace image'
  fi
BASH

grep -E '^kind:load docker-image|^wait-api$' "$CALLS" \
  >"$FIXTURE/sealed-image-load-order"
cat >"$FIXTURE/want-sealed-image-load-order" <<EOF
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-dashboard:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-services:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-mesh:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-gateway:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_INGRESS_CONTROLLER_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_INGRESS_CERTGEN_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_AGENT_SANDBOX_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_WORKSPACE_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_DIND_LOCAL_IMAGE}
wait-api
EOF
cmp -s "$FIXTURE/want-sealed-image-load-order" "$FIXTURE/sealed-image-load-order" || {
  diff -u "$FIXTURE/want-sealed-image-load-order" \
    "$FIXTURE/sealed-image-load-order" >&2 || true
  fail 'sealed Kind image imports are not separated by API recovery gates'
}

# Runtime observation accepts only the local aliases in sealed mode, requires
# the workspace in rendered templates, validates the configured optional DinD
# input, and rejects pull failures without an unrelated-service allowlist.
env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  ROOT="$ROOT" COMMON="$COMMON" bash -seu <<'BASH'
  fail() { printf "[sealed-supply-chain-test] ERROR: %s\n" "$*" >&2; exit 1; }
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$COMMON"
  service_account_json='{"automountServiceAccountToken":false}'
  pods_json="$(jq -cn \
    --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{initContainers:[],containers:[{image:$workspace},{image:$dind},{image:"postgres:17-alpine"}]}}]}')"
  templates_json="$(jq -cn \
    --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{podTemplate:{spec:{containers:[{image:$workspace},{image:$dind}]}}}}]}')"
  events_json='{"items":[]}'
  configured_dind="$KIND_DIND_LOCAL_IMAGE"
  kubectl() {
    case "$*" in
      '-n dev-sandboxes get serviceaccount/codewire-sandbox -o json')
        printf '%s\n' "$service_account_json"
        ;;
      '-n codewire-e2e get configmap/codewire-config -o jsonpath={.data.SANDBOX_DIND_IMAGE}')
        printf '%s' "$configured_dind"
        ;;
      'get pods -A -o json') printf '%s\n' "$pods_json" ;;
      'get sandboxtemplates -A -o json') printf '%s\n' "$templates_json" ;;
      'get events -A -o json') printf '%s\n' "$events_json" ;;
      *) fail "unexpected kubectl invocation: $*" ;;
    esac
  }
  log() { :; }

  assert_sandbox_supply_chain

  pods_json="$(jq -cn \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{containers:[{image:"ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467"},{image:$dind}]}}]}')"
  if assert_sandbox_supply_chain >/dev/null 2>&1; then
    fail 'sealed runtime accepted a public workspace reference'
  fi

  pods_json="$(jq -cn \
    --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{containers:[{image:$workspace},{image:$dind}]}}]}')"
  templates_json="$(jq -cn --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    '{items:[{spec:{image:$workspace}}]}')"
  assert_sandbox_supply_chain ||
    fail 'sealed runtime rejected a template where optional DinD is inactive'

  configured_dind='docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c'
  if assert_sandbox_supply_chain >/dev/null 2>&1; then
    fail 'sealed runtime accepted a substituted configured DinD input'
  fi
  configured_dind="$KIND_DIND_LOCAL_IMAGE"

  templates_json="$(jq -cn \
    --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{images:[$workspace,$dind]}}]}')"
  events_json="$(jq -cn --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{reason:"ImagePullBackOff",message:("failed to pull " + $dind),metadata:{namespace:"dev-sandboxes"},involvedObject:{name:"workspace"}}]}')"
  if assert_sandbox_supply_chain >/dev/null 2>&1; then
    fail 'sealed runtime ignored a DinD pull failure'
  fi
BASH

# A partial or substituted sealed-image tuple must fail before any nested
# cluster action. The public source remains pinned by its multi-arch index,
# while the approved runner input is the independently verified amd64 child.
expect_failure partial-platform-images env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE='' \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Nexus digests' \
  "$FIXTURE/partial-platform-images.out" ||
  fail 'partial sealed platform tuple did not explain its rejection'

expect_failure partial-workspace-only env \
  KIND_INGRESS_CONTROLLER_IMAGE='' \
  KIND_INGRESS_CERTGEN_IMAGE='' \
  KIND_AGENT_SANDBOX_IMAGE='' \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Nexus digests' \
  "$FIXTURE/partial-workspace-only.out" ||
  fail 'workspace-only sealed tuple did not explain its rejection'

expect_failure substituted-agent-image env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE='nexus.example.invalid/oci-approved/codewire/agent-sandbox-controller@sha256:555146af2337dd5d8baf0844d7f5de9a3cd8fc7b032b85756ae244bc2583fb41' \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Nexus digests' \
  "$FIXTURE/substituted-agent-image.out" ||
  fail 'agent-sandbox index substitution did not explain its rejection'

expect_failure substituted-workspace-image env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
  KIND_WORKSPACE_IMAGE='nexus.example.invalid/oci-approved/codewire/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Nexus digests' \
  "$FIXTURE/substituted-workspace-image.out" ||
  fail 'workspace digest substitution did not explain its rejection'

expect_failure substituted-dind-image env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE='nexus.example.invalid/oci-approved/docker/dind@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Nexus digests' \
  "$FIXTURE/substituted-dind-image.out" ||
  fail 'DinD digest substitution did not explain its rejection'

grep -Fq "docker:image inspect $SEALED_CONTROLLER_IMAGE" "$CALLS" ||
  fail 'sealed controller was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image inspect $SEALED_CERTGEN_IMAGE" "$CALLS" ||
  fail 'sealed certgen was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image tag $SEALED_CONTROLLER_IMAGE localhost/codewire-ci/ingress-nginx-controller:verified-5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180" "$CALLS" ||
  fail 'sealed controller was not assigned its disposable Kind reference'
grep -Fq "docker:image tag $SEALED_CERTGEN_IMAGE localhost/codewire-ci/ingress-kube-webhook-certgen:verified-334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053" "$CALLS" ||
  fail 'sealed certgen was not assigned its disposable Kind reference'
grep -Fq "docker:image inspect $SEALED_AGENT_IMAGE" "$CALLS" ||
  fail 'sealed agent-sandbox controller was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image tag $SEALED_AGENT_IMAGE localhost/codewire-ci/agent-sandbox-controller:verified-6081ae66b4134ebc6b170d965741b8dae09442ec74563b6c1ac999c366dac125" "$CALLS" ||
  fail 'sealed agent-sandbox controller was not assigned its disposable Kind reference'
grep -Fq "docker:image inspect $SEALED_WORKSPACE_IMAGE" "$CALLS" ||
  fail 'sealed workspace was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image tag $SEALED_WORKSPACE_IMAGE localhost/codewire-ci/workspace:verified-cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510" "$CALLS" ||
  fail 'sealed workspace was not assigned its disposable Kind reference'
grep -Fq "docker:image inspect $SEALED_DIND_IMAGE" "$CALLS" ||
  fail 'sealed DinD was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image tag $SEALED_DIND_IMAGE localhost/codewire-ci/docker-dind:verified-66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e" "$CALLS" ||
  fail 'sealed DinD was not assigned its disposable Kind reference'

grep -Fq "KIND_INGRESS_CONTROLLER_IMAGE: $SEALED_CONTROLLER_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved ingress controller'
grep -Fq "KIND_INGRESS_CERTGEN_IMAGE: $SEALED_CERTGEN_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved ingress cert generator'
grep -Fq "KIND_AGENT_SANDBOX_IMAGE: $SEALED_AGENT_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved agent-sandbox controller'
grep -Fq "KIND_WORKSPACE_IMAGE: $SEALED_WORKSPACE_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the Forgejo-proven workspace image'
grep -Fq "KIND_DIND_IMAGE: $SEALED_DIND_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved Docker DinD image'
if grep -Fq 'nexus-system-cluster.example.invalid/oci-approved/' \
    "$ROOT/.gitea/workflows/ci.yaml"; then
  fail 'Forgejo CI still uses the Nexus recovery alias for an approved Kind input'
fi

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
