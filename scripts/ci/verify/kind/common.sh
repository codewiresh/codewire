#!/usr/bin/env bash
# Shared mechanics for the Rust product Kind suites. Source this file; invoke
# scripts/ci/verify/kind-e2e.sh as the stable entrypoint.
set -euo pipefail

export KIND_E2E_COMMON_LOADED=1
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)}"
# shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
source "$ROOT/scripts/ci/verify/playwright-browser-runtime.sh"
# shellcheck source=scripts/ci/verify/kind-host-runtime.sh
source "$ROOT/scripts/ci/verify/kind-host-runtime.sh"
CARGO_TARGET_DIR="$(
  "$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh" "$ROOT"
)"
export CARGO_TARGET_DIR
CARGO_CI_DIR="$CARGO_TARGET_DIR/ci"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
KIND_CONFIG="${KIND_CONFIG:-$ROOT/tests/e2e/kind/kind-config.yaml}"
RUN_DIR="${RUN_DIR:-$ROOT/.tmp/codewire-kind-e2e-${KIND_CLUSTER_NAME}}"
mkdir -p "$RUN_DIR"
# Use the hostless HTTP server for the edge and transitional REST probes. The
# coordinator TLS ingress intentionally owns Host/SNI localhost below.
KIND_INGRESS_URL="${KIND_INGRESS_URL:-http://127.0.0.1:8090}"
KIND_INGRESS_TLS_URL="${KIND_INGRESS_TLS_URL:-https://localhost:10443}"
KIND_POSTGRES_HOST_PORT="${KIND_POSTGRES_HOST_PORT:-25432}"
if ! [[ "$KIND_POSTGRES_HOST_PORT" =~ ^[0-9]+$ ]] \
    || [ "$KIND_POSTGRES_HOST_PORT" -lt 1024 ] \
    || [ "$KIND_POSTGRES_HOST_PORT" -gt 65535 ]; then
  echo "::error::KIND_POSTGRES_HOST_PORT must be an unprivileged TCP port"
  exit 2
fi
KIND_DATABASE_URL="postgres://codewire:codewire@127.0.0.1:${KIND_POSTGRES_HOST_PORT}/codewire"
KEEP_KIND_CLUSTER="${KEEP_KIND_CLUSTER:-0}"
KIND_HOST_LOCK_TIMEOUT_SECONDS="${KIND_HOST_LOCK_TIMEOUT_SECONDS:-1200}"
if ! [[ "$KIND_HOST_LOCK_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
    || [ "$KIND_HOST_LOCK_TIMEOUT_SECONDS" -lt 1 ]; then
  echo "::error::KIND_HOST_LOCK_TIMEOUT_SECONDS must be a positive integer"
  exit 2
fi
KIND_HOST_LOCK_FILE="${KIND_HOST_LOCK_FILE:-${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/codewire-kind-e2e-${UID}.lock}"
KIND_HOST_LOCK_FD=""
NS=codewire-e2e
SANDBOX_NS=dev-sandboxes
# shellcheck source=scripts/ci/verify/kind/credentials.sh
source "$ROOT/scripts/ci/verify/kind/credentials.sh"
AUTHZ_TMPDIR=""
GATEWAY_SMOKE_TMPDIR=""
GATEWAY_PORT_FORWARD_PID=""
GATEWAY_PORT_FORWARD_PORT=""
GATEWAY_PUBLIC_FINGERPRINT=""
KIND_E2E_COMPATIBILITY_VERSION=1
KIND_E2E_PREPARED_CONFIGMAP=codewire-kind-e2e-prepared
RETAINED_KUBECONFIG=""
REMOTE_DIND_JOB_CONTAINER=""
REMOTE_DIND_KIND_NETWORK=""
REMOTE_DIND_FORWARDER_PID=""
if [ -z "${DEFAULT_KIND_WORKSPACE_IMAGE+x}" ]; then
  DEFAULT_KIND_WORKSPACE_IMAGE='ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467'
fi
if [ -z "${DEFAULT_KIND_DIND_IMAGE+x}" ]; then
  DEFAULT_KIND_DIND_IMAGE='docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c'
fi
if [ -z "${KIND_WORKSPACE_IMAGE+x}" ]; then
  KIND_WORKSPACE_IMAGE="$DEFAULT_KIND_WORKSPACE_IMAGE"
fi
if [ -z "${KIND_DIND_IMAGE+x}" ]; then
  KIND_DIND_IMAGE="$DEFAULT_KIND_DIND_IMAGE"
fi
if [ -z "${KIND_POSTGRES_IMAGE+x}" ]; then
  KIND_POSTGRES_IMAGE='docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee'
fi
if [ -z "${KIND_TEMPORAL_IMAGE+x}" ]; then
  KIND_TEMPORAL_IMAGE='docker.io/temporalio/auto-setup:1.29.0@sha256:6605395ec22aa6a1993bb0bfd35002b011603e21d11c4a71ee646038c59e8909'
fi
if [ -z "${KIND_INGRESS_CONTROLLER_IMAGE+x}" ]; then
  KIND_INGRESS_CONTROLLER_IMAGE=''
fi
if [ -z "${KIND_INGRESS_CERTGEN_IMAGE+x}" ]; then
  KIND_INGRESS_CERTGEN_IMAGE=''
fi
if [ -z "${KIND_AGENT_SANDBOX_IMAGE+x}" ]; then
  KIND_AGENT_SANDBOX_IMAGE=''
fi
if [ -z "${APPROVED_KIND_INGRESS_CONTROLLER_IMAGE+x}" ]; then
  APPROVED_KIND_INGRESS_CONTROLLER_IMAGE='nexus.example.invalid/oci-approved/ingress-nginx/controller@sha256:5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180'
fi
if [ -z "${APPROVED_KIND_INGRESS_CERTGEN_IMAGE+x}" ]; then
  APPROVED_KIND_INGRESS_CERTGEN_IMAGE='nexus.example.invalid/oci-approved/ingress-nginx/kube-webhook-certgen@sha256:334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053'
fi
if [ -z "${APPROVED_KIND_AGENT_SANDBOX_IMAGE+x}" ]; then
  APPROVED_KIND_AGENT_SANDBOX_IMAGE='nexus.example.invalid/oci-approved/codewire/agent-sandbox-controller@sha256:6081ae66b4134ebc6b170d965741b8dae09442ec74563b6c1ac999c366dac125'
fi
if [ -z "${APPROVED_KIND_WORKSPACE_IMAGE+x}" ]; then
  APPROVED_KIND_WORKSPACE_IMAGE='nexus.example.invalid/oci-approved/codewire/workspace@sha256:cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510'
fi
if [ -z "${APPROVED_KIND_DIND_IMAGE+x}" ]; then
  APPROVED_KIND_DIND_IMAGE='nexus.example.invalid/oci-approved/docker/dind@sha256:66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e'
fi
if [ -z "${KIND_INGRESS_CONTROLLER_LOCAL_IMAGE+x}" ]; then
  KIND_INGRESS_CONTROLLER_LOCAL_IMAGE='localhost/codewire-ci/ingress-nginx-controller:verified-5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180'
fi
if [ -z "${KIND_INGRESS_CERTGEN_LOCAL_IMAGE+x}" ]; then
  KIND_INGRESS_CERTGEN_LOCAL_IMAGE='localhost/codewire-ci/ingress-kube-webhook-certgen:verified-334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053'
fi
if [ -z "${KIND_AGENT_SANDBOX_LOCAL_IMAGE+x}" ]; then
  KIND_AGENT_SANDBOX_LOCAL_IMAGE='localhost/codewire-ci/agent-sandbox-controller:verified-6081ae66b4134ebc6b170d965741b8dae09442ec74563b6c1ac999c366dac125'
fi
if [ -z "${KIND_WORKSPACE_LOCAL_IMAGE+x}" ]; then
  KIND_WORKSPACE_LOCAL_IMAGE='localhost/codewire-ci/workspace:verified-cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510'
fi
if [ -z "${KIND_DIND_LOCAL_IMAGE+x}" ]; then
  KIND_DIND_LOCAL_IMAGE='localhost/codewire-ci/docker-dind:verified-66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e'
fi
if [ -z "${KIND_POSTGRES_LOCAL_IMAGE+x}" ]; then
  KIND_POSTGRES_LOCAL_IMAGE='localhost/codewire-ci/postgres:verified-7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee'
fi
if [ -z "${KIND_TEMPORAL_LOCAL_IMAGE+x}" ]; then
  KIND_TEMPORAL_LOCAL_IMAGE='localhost/codewire-ci/temporal:verified-6605395ec22aa6a1993bb0bfd35002b011603e21d11c4a71ee646038c59e8909'
fi
readonly DEFAULT_KIND_WORKSPACE_IMAGE DEFAULT_KIND_DIND_IMAGE \
  KIND_WORKSPACE_IMAGE KIND_DIND_IMAGE KIND_POSTGRES_IMAGE KIND_TEMPORAL_IMAGE \
  KIND_INGRESS_CONTROLLER_IMAGE KIND_INGRESS_CERTGEN_IMAGE KIND_AGENT_SANDBOX_IMAGE \
  APPROVED_KIND_INGRESS_CONTROLLER_IMAGE APPROVED_KIND_INGRESS_CERTGEN_IMAGE \
  APPROVED_KIND_AGENT_SANDBOX_IMAGE APPROVED_KIND_WORKSPACE_IMAGE \
  APPROVED_KIND_DIND_IMAGE KIND_INGRESS_CONTROLLER_LOCAL_IMAGE \
  KIND_INGRESS_CERTGEN_LOCAL_IMAGE KIND_AGENT_SANDBOX_LOCAL_IMAGE \
  KIND_WORKSPACE_LOCAL_IMAGE KIND_DIND_LOCAL_IMAGE KIND_POSTGRES_LOCAL_IMAGE \
  KIND_TEMPORAL_LOCAL_IMAGE

log() {
  printf '[kind-e2e] %s\n' "$*"
}

acquire_kind_host_lock() {
  mkdir -p "$(dirname "$KIND_HOST_LOCK_FILE")"
  exec {KIND_HOST_LOCK_FD}>"$KIND_HOST_LOCK_FILE"
  log "waiting for exclusive local Kind transaction lock"
  if ! flock -w "$KIND_HOST_LOCK_TIMEOUT_SECONDS" "$KIND_HOST_LOCK_FD"; then
    echo "::error::timed out waiting for the local Kind transaction lock"
    return 1
  fi
  log "acquired exclusive local Kind transaction lock"
}

dump_cluster_state() {
  local context="kind-${KIND_CLUSTER_NAME}"
  if ! kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME"; then
    log "kind cluster ${KIND_CLUSTER_NAME} does not exist; skipping kubectl state dump"
    return
  fi
  if ! kubectl --context "$context" cluster-info --request-timeout=10s >/dev/null 2>&1; then
    log "kind cluster ${KIND_CLUSTER_NAME} is not reachable; skipping kubectl state dump"
    return
  fi

  kubectl --context "$context" get pods -A || true
  kubectl --context "$context" -n "$NS" describe deploy/codewire-billing || true
  kubectl --context "$context" -n "$NS" describe deploy/codewire-dashboard || true
  kubectl --context "$context" -n "$NS" describe deploy/codewire-idp || true
  kubectl --context "$context" -n "$NS" describe deploy/codewire-orchestration || true
  kubectl --context "$context" -n "$NS" describe deploy/codewire-coordinator || true
  kubectl --context "$context" -n "$NS" logs deploy/codewire-billing --tail=100 || true
  kubectl --context "$context" -n "$NS" logs deploy/codewire-dashboard --tail=160 || true
  kubectl --context "$context" -n "$NS" logs deploy/codewire-idp --tail=160 || true
  kubectl --context "$context" -n "$NS" logs deploy/codewire-orchestration --tail=160 || true
  kubectl --context "$context" -n "$NS" logs deploy/codewire-coordinator --tail=160 || true
  kubectl --context "$context" -n "$NS" get svc/codewire-coordinator-nodeport -o wide || true
  kubectl --context "$context" -n "$NS" logs deploy/temporal --tail=80 || true
  kubectl --context "$context" -n "$SANDBOX_NS" get sandboxclaim,sandbox,sandboxtemplate,sandboxwarmpool,pvc,pv -o wide || true
  kubectl --context "$context" -n "$SANDBOX_NS" describe sandboxclaim,sandbox,sandboxtemplate,sandboxwarmpool || true
  kubectl --context "$context" -n "$SANDBOX_NS" get events --sort-by=.lastTimestamp || true
  kubectl --context "$context" -n "$NS" get events --sort-by=.lastTimestamp || true
  kubectl --context "$context" -n ingress-nginx describe pods || true
  kubectl --context "$context" -n ingress-nginx get events --sort-by=.lastTimestamp || true
  kubectl --context "$context" -n ingress-nginx logs deploy/ingress-nginx-controller --tail=80 || true
  kubectl --context "$context" -n agent-sandbox-system logs -l app=agent-sandbox-controller --tail=160 --all-containers || true
}

cleanup() {
  local status=$?
  stop_gateway_port_forward
  if [ "$status" -ne 0 ]; then
    dump_cluster_state
  fi
  stop_remote_dind_kind_forwarding
  if [ "$KEEP_KIND_CLUSTER" != "1" ]; then
    kind delete cluster --name "$KIND_CLUSTER_NAME" >/dev/null 2>&1 || true
  fi
  if [ -n "$AUTHZ_TMPDIR" ]; then
    rm -rf "$AUTHZ_TMPDIR"
  fi
  if [ -n "$GATEWAY_SMOKE_TMPDIR" ]; then
    rm -rf "$GATEWAY_SMOKE_TMPDIR"
  fi
  exit "$status"
}

assert_kind_idp_topology() {
  local issuer ingress_paths

  issuer="$(kubectl -n "$NS" get configmap codewire-config \
    -o jsonpath='{.data.PUBLIC_OIDC_ISSUER_URL}')"
  if [ "$issuer" != "$KIND_INGRESS_URL" ]; then
    echo "::error::Kind IdP issuer must match the host ingress: expected ${KIND_INGRESS_URL}, got ${issuer:-missing}"
    return 1
  fi

  kubectl -n "$NS" get deployment/codewire-idp >/dev/null
  kubectl -n "$NS" get service/codewire-idp >/dev/null
  ingress_paths="$(kubectl -n "$NS" get ingress codewire-idp-e2e \
    -o jsonpath='{range .spec.rules[*].http.paths[*]}{.path}{"\n"}{end}')"
  for required_path in \
      /api/oauth /api/auth/sign-up /api/auth/sign-in /api/oidc \
      /.well-known/openid-configuration /.well-known/jwks.json; do
    if ! grep -Fqx "$required_path" <<<"$ingress_paths"; then
      echo "::error::Kind IdP ingress is missing permanent raw path ${required_path}"
      return 1
    fi
  done
}

retained_suite_cleanup() {
  local status=$?
  stop_gateway_port_forward
  if [ "$status" -ne 0 ]; then
    dump_cluster_state
  fi
  if [ -n "$AUTHZ_TMPDIR" ]; then
    rm -rf "$AUTHZ_TMPDIR"
  fi
  if [ -n "$GATEWAY_SMOKE_TMPDIR" ]; then
    rm -rf "$GATEWAY_SMOKE_TMPDIR"
  fi
  if [ -n "$RETAINED_KUBECONFIG" ]; then
    rm -f "$RETAINED_KUBECONFIG"
  fi
  log "retained suite left Kind cluster ${KIND_CLUSTER_NAME} intact"
  exit "$status"
}

stop_gateway_port_forward() {
  if [ -n "$GATEWAY_PORT_FORWARD_PID" ]; then
    kill "$GATEWAY_PORT_FORWARD_PID" >/dev/null 2>&1 || true
    wait "$GATEWAY_PORT_FORWARD_PID" >/dev/null 2>&1 || true
    GATEWAY_PORT_FORWARD_PID=""
    GATEWAY_PORT_FORWARD_PORT=""
  fi
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "::error::missing required tool: $tool"
    exit 1
  fi
}

require_available_deployment() {
  local namespace="$1" name="$2" available
  if ! available="$(kubectl --request-timeout=10s -n "$namespace" get \
      "deployment/${name}" -o jsonpath='{.status.availableReplicas}' 2>&1)"; then
    echo "::error::retained Kind cluster is missing Deployment/${name} in ${namespace}: ${available}"
    return 1
  fi
  if ! [[ "$available" =~ ^[1-9][0-9]*$ ]]; then
    echo "::error::retained Kind Deployment/${name} in ${namespace} has ${available:-0} available replicas, want at least 1"
    return 1
  fi
}

validate_retained_cluster_identity() {
  local expected_context current_context clusters
  local -a kubeconfig_args=()

  if [ "${KIND_CLUSTER_NAME_EXPLICIT:-0}" != "1" ] || [ -z "$KIND_CLUSTER_NAME" ]; then
    echo "::error::retained suites require an explicit non-empty KIND_CLUSTER_NAME"
    return 1
  fi
  expected_context="kind-${KIND_CLUSTER_NAME}"

  if ! clusters="$(kind get clusters 2>&1)"; then
    echo "::error::failed to enumerate Kind clusters for retained suite: ${clusters}"
    return 1
  fi
  if ! grep -Fxq "$KIND_CLUSTER_NAME" <<<"$clusters"; then
    echo "::error::retained Kind cluster ${KIND_CLUSTER_NAME} does not exist; available clusters: ${clusters:-none}"
    return 1
  fi

  if ! current_context="$(kubectl config current-context 2>&1)"; then
    echo "::error::cannot determine kubectl context for retained Kind cluster ${KIND_CLUSTER_NAME}: ${current_context}"
    return 1
  fi
  if [ "$current_context" != "$expected_context" ]; then
    echo "::error::kubectl context ${current_context} does not match retained Kind context ${expected_context}"
    return 1
  fi

  # A retained suite can invoke a narrower read-only suite. Each invocation
  # owns its file so child cleanup cannot remove the parent's pinned context.
  # Keep the API endpoint in the caller's existing topology. Remote DinD's
  # published loopback endpoint belongs to the daemon, not the job container.
  # This only chooses the export; it must not reconnect or start forwarding.
  if is_remote_dind_kind_job; then
    kubeconfig_args+=(--internal)
  fi
  RETAINED_KUBECONFIG="$(mktemp "$RUN_DIR/retained-kubeconfig.XXXXXX")" || return $?
  if ! kind get kubeconfig "${kubeconfig_args[@]}" --name "$KIND_CLUSTER_NAME" \
      >"$RETAINED_KUBECONFIG"; then
    echo "::error::failed to pin kubeconfig for retained Kind cluster ${KIND_CLUSTER_NAME}"
    return 1
  fi
  export KUBECONFIG="$RETAINED_KUBECONFIG"
  if ! kubectl --context "$expected_context" cluster-info --request-timeout=10s >/dev/null 2>&1; then
    echo "::error::retained Kind context ${expected_context} is not reachable"
    return 1
  fi

  require_available_deployment "$NS" postgres
  require_available_deployment "$NS" temporal
  require_available_deployment "$NS" codewire-billing
  require_available_deployment "$NS" codewire-orchestration
  require_available_deployment "$NS" codewire-coordinator
  require_available_deployment agent-sandbox-system agent-sandbox-controller
  if ! kubectl --request-timeout=10s get \
      crd/sandboxclaims.extensions.agents.x-k8s.io >/dev/null 2>&1; then
    echo "::error::retained Kind cluster is missing the SandboxClaim CRD"
    return 1
  fi
  log "retained Kind cluster ${KIND_CLUSTER_NAME} identity and runtime prerequisites accepted"
}

validate_retained_cluster() {
  local prepared_version prepared_cluster prepared_workspace expected_workspace

  validate_retained_cluster_identity || return $?
  if ! prepared_version="$(kubectl --request-timeout=10s -n "$NS" get \
      "configmap/${KIND_E2E_PREPARED_CONFIGMAP}" \
      -o jsonpath='{.data.compatibility_version}' 2>&1)"; then
    echo "::error::retained Kind cluster ${KIND_CLUSTER_NAME} is unprepared: ${prepared_version}"
    return 1
  fi
  prepared_cluster="$(kubectl --request-timeout=10s -n "$NS" get \
    "configmap/${KIND_E2E_PREPARED_CONFIGMAP}" -o jsonpath='{.data.cluster-name}')"
  if [ "$prepared_version" != "$KIND_E2E_COMPATIBILITY_VERSION" ] \
      || [ "$prepared_cluster" != "$KIND_CLUSTER_NAME" ]; then
    echo "::error::retained Kind cluster marker is incompatible: version=${prepared_version:-missing} cluster=${prepared_cluster:-missing}; want version=${KIND_E2E_COMPATIBILITY_VERSION} cluster=${KIND_CLUSTER_NAME}"
    return 1
  fi

  prepared_workspace="$(kubectl --request-timeout=10s -n "$NS" get \
    "configmap/${KIND_E2E_PREPARED_CONFIGMAP}" -o jsonpath='{.data.workspace-image}')" || return $?
  expected_workspace="$(kind_workspace_runtime_image)" || return $?
  if [ "$prepared_workspace" != "$expected_workspace" ]; then
    echo '::error::retained Kind workspace image does not match its verified source' >&2
    return 1
  fi

  log "retained Kind cluster ${KIND_CLUSTER_NAME} accepted at compatibility version ${KIND_E2E_COMPATIBILITY_VERSION}"
}

mark_retained_cluster_prepared() {
  local workspace_image
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  log "marking Kind cluster ${KIND_CLUSTER_NAME} prepared for retained suites"
  kubectl -n "$NS" create configmap "$KIND_E2E_PREPARED_CONFIGMAP" \
    --from-literal="compatibility_version=${KIND_E2E_COMPATIBILITY_VERSION}" \
    --from-literal="cluster-name=${KIND_CLUSTER_NAME}" \
    --from-literal="workspace-image=$workspace_image" \
    --dry-run=client -o yaml | kubectl_apply -f -
}

reclaim_cancelled_ci_clusters() {
  local kind_config="$1"
  local ci_cluster_prefix='codewire-e2e-ci-'
  local clusters cluster remaining running_containers ports port owners

  if ! clusters="$(kind get clusters 2>&1)"; then
    echo "::error::failed to enumerate Kind clusters before e2e startup: ${clusters}"
    return 1
  fi

  while IFS= read -r cluster; do
    case "$cluster" in
      "${ci_cluster_prefix}"*)
        log "reclaiming cancelled-run kind cluster ${cluster}"
        if ! kind delete cluster --name "$cluster"; then
          echo "::error::failed to reclaim cancelled-run kind cluster ${cluster}"
          return 1
        fi
        ;;
    esac
  done <<< "$clusters"

  if ! remaining="$(kind get clusters 2>&1)"; then
    echo "::error::failed to verify Kind cluster cleanup: ${remaining}"
    return 1
  fi
  while IFS= read -r cluster; do
    case "$cluster" in
      "${ci_cluster_prefix}"*)
        echo "::error::cancelled-run kind cluster ${cluster} survived cleanup"
        return 1
        ;;
    esac
  done <<< "$remaining"

  if ! ports="$(
    awk '
      $1 == "hostPort:" {
        if ($2 !~ /^[0-9]+$/) exit 2
        if (!seen[$2]++) print $2
      }
    ' "$kind_config"
  )" || [ -z "$ports" ]; then
    echo "::error::could not determine fixed host ports from ${kind_config}"
    return 1
  fi

  if ! running_containers="$(docker ps --format '{{.ID}}\t{{.Names}}\t{{.Ports}}' 2>&1)"; then
    echo "::error::failed to inspect Docker port ownership before Kind startup: ${running_containers}"
    return 1
  fi
  while IFS= read -r port; do
    owners="$(
      awk -F '\t' -v port="$port" '
        index($3, ":" port "->") { print }
      ' <<< "$running_containers"
    )"
    if [ -n "$owners" ]; then
      echo "::error::fixed Kind host port ${port} remains occupied after cancelled-run cleanup: ${owners}"
      return 1
    fi
  done <<< "$ports"
}

http_code() {
  curl -s -o /dev/null -w '%{http_code}' "$@" || echo 000
}

# 503 through ingress-nginx means "this location has no synced endpoints
# yet" — per-location backend sync settles independently after a controller
# reload, so one path for a service can answer while a sibling still 503s
# (cycle-2 and cycle-7 failures were this same eventual-consistency class
# through different doors). Every edge probe therefore treats 503 as
# infrastructure-not-settled and retries within a bounded window; the WANT
# assertion runs against the settled response, so a real no-backend
# condition (503 persisting past the bound) still fails the probe.
http_code_settled() {
  local code i
  for i in $(seq 1 15); do
    code="$(http_code "$@")"
    if [ "$code" != "503" ]; then
      printf '%s\n' "$code"
      return 0
    fi
    echo "edge probe got 503; waiting for ingress location sync (${i}/15)" >&2
    sleep 2
  done
  printf '%s\n' "$code"
}

require_get_code() {
  local path="$1" want="$2" label="$3" code
  code="$(http_code_settled "${KIND_INGRESS_URL}${path}")"
  if [ "$code" != "$want" ]; then
    echo "::error::${label} returned ${code}, want ${want}"
    exit 1
  fi
}

require_post_code() {
  local path="$1" want="$2" label="$3" code
  code="$(http_code_settled -X POST "${KIND_INGRESS_URL}${path}")"
  if [ "$code" != "$want" ]; then
    echo "::error::${label} returned ${code}, want ${want}"
    exit 1
  fi
}

# curl with the same 503-settling policy for probes that need headers/body:
# writes headers to $PROBE_HEADERS, body to stdout, settled status code to
# $PROBE_CODE.
curl_settled() {
  local i
  PROBE_HEADERS="$(mktemp)"
  for i in $(seq 1 15); do
    PROBE_BODY="$(curl -s -D "$PROBE_HEADERS" "$@")"
    PROBE_CODE="$(awk 'NR==1{print $2}' "$PROBE_HEADERS")"
    if [ "$PROBE_CODE" != "503" ]; then
      return 0
    fi
    echo "edge probe got 503; waiting for ingress location sync (${i}/15)" >&2
    sleep 2
  done
  return 0
}

auth_token_for_environment_scope() {
  local environment_id="$1" scope="$2" secret payload encoded_payload signature
  case "$scope" in
    coordinate | daemon) ;;
    *)
      echo "::error::unsupported environment auth token scope: $scope" >&2
      return 1
      ;;
  esac
  secret="$(
    kubectl -n "$NS" get secret codewire-secrets \
      -o jsonpath='{.data.SESSION_SECRET}' | base64 --decode
  )"
  payload="$(printf '{"environment_id":"%s","scope":"%s"}' "$environment_id" "$scope")"
  encoded_payload="$(
    printf '%s' "$payload" | openssl base64 -A | tr '+/' '-_' | tr -d '='
  )"
  signature="$(
    printf '%s' "$encoded_payload" \
      | openssl dgst -sha256 -hmac "$secret" -binary \
      | openssl base64 -A | tr '+/' '-_' | tr -d '='
  )"
  printf '%s.%s' "$encoded_payload" "$signature"
}

gateway_auth_token_for_environment() {
  auth_token_for_environment_scope "$1" coordinate
}

daemon_auth_token_for_environment() {
  auth_token_for_environment_scope "$1" daemon
}

kubectl_apply() {
  timeout "${KUBECTL_APPLY_TIMEOUT:-180s}" \
    kubectl --request-timeout="${KUBECTL_REQUEST_TIMEOUT:-30s}" apply "$@"
}

ingress_path_drift_check() {
  log "checking kind/base ingress routing drift"
  local billing_paths=(
    '/api/webhooks/stripe'
    '/codewire\.console\.v1\.BillingService/'
  )
  local files=(
    tests/e2e/kind/ingress.yaml
    deployments/k8s/base/ingress.yaml
    deployments/k8s/overlays/local-kind/ingress.yaml
    deployments/k8s/overlays/local-kind-static/ingress.yaml
  )
  local path file
  for path in "${billing_paths[@]}"; do
    for file in "${files[@]}"; do
      grep -qF "path: ${path}" "$ROOT/$file" || {
        echo "::error file=$file::billing route ${path} missing"
        exit 1
      }
    done
  done

  for file in "${files[@]}"; do
    grep -qF 'path: /api' "$ROOT/$file" || {
      echo "::error file=$file::broad /api orchestration route missing"
      exit 1
    }
  done

  grep -qF 'host: "*.cwpreview.sh"' "$ROOT/deployments/k8s/base/ingress.yaml" || {
    echo "::error file=deployments/k8s/base/ingress.yaml::preview wildcard host missing"
    exit 1
  }
  for file in \
    tests/e2e/kind/ingress.yaml \
    deployments/k8s/overlays/local-kind/ingress.yaml \
    deployments/k8s/overlays/local-kind-static/ingress.yaml; do
    grep -qF 'host: "*.codewire-dev.local"' "$ROOT/$file" || {
      echo "::error file=$file::local preview wildcard host missing"
      exit 1
    }
  done
}

build_images_and_smokes() {
  case "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" in
    build-ci)
      log "verifying the canonical source workspace image once for Kind"
      "$ROOT/scripts/ci/verify/rehearse-build-local-image.sh"
      "$ROOT/scripts/ci/verify/verify-workspace-image.sh"
      log "building exact candidate product images once through the CI Bake profile"
      CODEWIRE_BAKE_METADATA_FILE="$RUN_DIR/kind-image-build-metadata.json" \
        "$ROOT/scripts/ci/images/build-kind-images.sh"
      ;;
    prebuilt-release)
      log "using exact prebuilt protected release images without rebuilding"
      assert_prebuilt_release_product_images
      ;;
    *)
      echo "::error::CODEWIRE_KIND_PRODUCT_IMAGE_MODE must be build-ci or prebuilt-release"
      return 2
      ;;
  esac

  log "verifying the exact dashboard candidate runtime contract"
  "$ROOT/scripts/ci/verify/dashboard-image.sh" "codewire-dashboard:e2e"

  prepare_kind_support_images

  log "building Rust kind smoke binaries"
  local smoke_started_at
  smoke_started_at="$(date +%s)"
  (
    cd "$ROOT"
    "$ROOT/scripts/ci/verify/run-host-rust-build.sh" bash -ceu '
      cargo build --profile ci -p codewire-orchestration --bin crd-smoke --bin environment-setup-smoke --bin exec-smoke --bin exec-stream-smoke --bin file-service-smoke --bin prepare-stream-smoke --bin log-stream-smoke --bin temporal-smoke --bin temporal-fencing-smoke --bin reconciler-ttl-smoke --bin sidecar-smoke --features kind-e2e
      cargo build --profile ci -p codewire-client --example platform-run-smoke --example environment-session-smoke
      cargo build --profile ci -p codewire-client --example coordinator-ingress-smoke --features kind-e2e
      cargo build --locked --profile ci -p codewire-cli-bin --bin cw
      cargo test --locked --profile ci -p codewire-orchestration --lib --no-run --message-format=json >"$1"
    ' -- "$RUN_DIR/credential-bootstrap-build.jsonl"
  )
  printf 'CODEWIRE_CI_PHASE name=kind-smoke-binary-build seconds=%s\n' \
    "$(( $(date +%s) - smoke_started_at ))"
}

assert_prebuilt_release_product_images() {
  local expected_sha="${CODEWIRE_KIND_EXPECTED_SOURCE_SHA:-}"
  local image image_ref profile promotable revision

  if ! [[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "::error::prebuilt release images require one exact expected source SHA"
    return 2
  fi
  for image in dashboard services mesh gateway; do
    image_ref="codewire-${image}:e2e"
    docker image inspect "$image_ref" >/dev/null || {
      echo "::error::prebuilt release image is missing: ${image_ref}"
      return 1
    }
    profile="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.build.profile" }}' "$image_ref")"
    promotable="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.promotable" }}' "$image_ref")"
    revision="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image_ref")"
    if [ "$profile" != release ] || [ "$promotable" != true ] \
        || [ "$revision" != "$expected_sha" ]; then
      echo "::error::prebuilt release image identity mismatch: ${image_ref}"
      return 1
    fi
  done
}

create_cluster() {
  local kind_config rendered_kind_config
  if kind get clusters | grep -qx "$KIND_CLUSTER_NAME"; then
    log "deleting existing kind cluster ${KIND_CLUSTER_NAME}"
    kind delete cluster --name "$KIND_CLUSTER_NAME"
  fi

  log "checking Docker runtime for kind"
  docker version
  docker info --format 'Server={{.ServerVersion}} Driver={{.Driver}} CgroupDriver={{.CgroupDriver}} SecurityOptions={{json .SecurityOptions}}' || docker info || true

  log "creating kind cluster ${KIND_CLUSTER_NAME}"
  kind_config="$KIND_CONFIG"
  rendered_kind_config="$RUN_DIR/kind-config.yaml"
  if [ "$(grep -Fc 'hostPort: 25432' "$kind_config")" -ne 1 ]; then
    echo "::error::Kind config must contain exactly one default Postgres host-port mapping"
    exit 1
  fi
  sed "s/hostPort: 25432/hostPort: ${KIND_POSTGRES_HOST_PORT}/" \
    "$kind_config" >"$rendered_kind_config"
  if ! kind create cluster --name "$KIND_CLUSTER_NAME" --config "$rendered_kind_config" --wait 120s; then
    echo "::error::kind cluster creation failed. This gate needs a runner with a real privileged Docker runtime capable of starting kind node containers; rootless Podman/netavark runners are not sufficient."
    exit 1
  fi
  configure_remote_dind_kind_network
}

stop_remote_dind_kind_forwarding() {
  if [ -n "$REMOTE_DIND_FORWARDER_PID" ]; then
    kill "$REMOTE_DIND_FORWARDER_PID" >/dev/null 2>&1 || true
    wait "$REMOTE_DIND_FORWARDER_PID" >/dev/null 2>&1 || true
    REMOTE_DIND_FORWARDER_PID=""
  fi
  if [ -n "$REMOTE_DIND_JOB_CONTAINER" ] && [ -n "$REMOTE_DIND_KIND_NETWORK" ]; then
    docker network disconnect "$REMOTE_DIND_KIND_NETWORK" \
      "$REMOTE_DIND_JOB_CONTAINER" >/dev/null 2>&1 || true
  fi
  REMOTE_DIND_JOB_CONTAINER=""
  REMOTE_DIND_KIND_NETWORK=""
}

start_remote_dind_kind_forwarding() {
  local node="$1" attempt
  local forwarder_log="$RUN_DIR/remote-dind-kind-forwarder.log"

  python3 -u "$ROOT/scripts/ci/verify/kind/forward-remote-dind-ports.py" \
    --target "$node" \
    --forward 8090:80 \
    --forward 10443:443 \
    --forward 7233:30733 \
    --forward 8084:30084 \
    --forward 18092:30090 \
    --forward "${KIND_POSTGRES_HOST_PORT}:30432" \
    >"$forwarder_log" 2>&1 &
  REMOTE_DIND_FORWARDER_PID=$!

  for ((attempt = 1; attempt <= 50; attempt++)); do
    if grep -Fqx 'remote DinD Kind loopback forwarder ready' "$forwarder_log"; then
      log "remote DinD Kind loopback forwarding ready"
      return 0
    fi
    if ! kill -0 "$REMOTE_DIND_FORWARDER_PID" >/dev/null 2>&1; then
      echo "::error::remote DinD Kind loopback forwarder exited before readiness"
      return 1
    fi
    sleep 0.1
  done

  echo "::error::remote DinD Kind loopback forwarder did not become ready"
  return 1
}

is_remote_dind_kind_job() {
  [ -n "${HOSTNAME:-}" ] \
    && docker container inspect "$HOSTNAME" >/dev/null 2>&1
}

configure_remote_dind_kind_network() {
  local self_container="${HOSTNAME:-}"
  local node="${KIND_CLUSTER_NAME}-control-plane"
  local kubeconfig_path kubeconfig_tmp
  local -a node_networks=()

  # A local Docker daemon publishes Kind's mapped ports directly in this
  # process namespace. Forgejo's hardened workers instead give the job a
  # socket for a sibling DinD daemon, making that daemon's 127.0.0.1 foreign.
  # The job hostname is a container in the latter topology and absent in the
  # former, which lets this adaptation remain a no-op for local preflight.
  if ! is_remote_dind_kind_job; then
    log "local Docker topology detected; retaining Kind host-port kubeconfig"
    return 0
  fi
  if [[ "$self_container" =~ [^A-Za-z0-9_.-] ]]; then
    echo "::error::remote DinD job container identity is malformed"
    return 1
  fi

  mapfile -t node_networks < <(
    docker inspect --format \
      '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' \
      "$node" | sed '/^$/d'
  )
  if [ "${#node_networks[@]}" -ne 1 ] \
      || [[ "${node_networks[0]:-}" =~ [^A-Za-z0-9_.-] ]]; then
    echo "::error::Kind control-plane must have exactly one bounded Docker network"
    return 1
  fi

  REMOTE_DIND_JOB_CONTAINER="$self_container"
  REMOTE_DIND_KIND_NETWORK="${node_networks[0]}"
  docker network connect "$REMOTE_DIND_KIND_NETWORK" \
    "$REMOTE_DIND_JOB_CONTAINER"

  kubeconfig_path="${KUBECONFIG:-$HOME/.kube/config}"
  if [[ "$kubeconfig_path" == *:* ]]; then
    echo "::error::remote DinD Kind requires one explicit kubeconfig path"
    return 1
  fi
  mkdir -p "$(dirname "$kubeconfig_path")"
  kubeconfig_tmp="$(mktemp "${kubeconfig_path}.internal.XXXXXX")"
  chmod 600 "$kubeconfig_tmp"
  if ! kind get kubeconfig --internal --name "$KIND_CLUSTER_NAME" \
      >"$kubeconfig_tmp"; then
    shred -u "$kubeconfig_tmp"
    echo "::error::failed to render internal Kind kubeconfig for remote DinD"
    return 1
  fi
  install -m 600 "$kubeconfig_tmp" "$kubeconfig_path"
  shred -u "$kubeconfig_tmp"

  start_remote_dind_kind_forwarding "$node"
  log "remote DinD Kind API and host-port topology configured"
}

validate_sealed_kind_images() {
  if [ -z "$KIND_INGRESS_CONTROLLER_IMAGE" ] \
      && [ -z "$KIND_INGRESS_CERTGEN_IMAGE" ] \
      && [ -z "$KIND_AGENT_SANDBOX_IMAGE" ] \
      && [ "$KIND_WORKSPACE_IMAGE" = "$DEFAULT_KIND_WORKSPACE_IMAGE" ] \
      && [ "$KIND_DIND_IMAGE" = "$DEFAULT_KIND_DIND_IMAGE" ]; then
    return 1
  fi
  if [ "$KIND_INGRESS_CONTROLLER_IMAGE" != "$APPROVED_KIND_INGRESS_CONTROLLER_IMAGE" ] \
      || [ "$KIND_INGRESS_CERTGEN_IMAGE" != "$APPROVED_KIND_INGRESS_CERTGEN_IMAGE" ] \
      || [ "$KIND_AGENT_SANDBOX_IMAGE" != "$APPROVED_KIND_AGENT_SANDBOX_IMAGE" ] \
      || [ "$KIND_WORKSPACE_IMAGE" != "$APPROVED_KIND_WORKSPACE_IMAGE" ] \
      || [ "$KIND_DIND_IMAGE" != "$APPROVED_KIND_DIND_IMAGE" ]; then
    echo "::error::sealed Kind inputs must match the five approved Nexus digests"
    return 2
  fi
}

kind_workspace_runtime_image() {
  local sealed_status=0
  validate_sealed_kind_images || sealed_status=$?
  [ "$sealed_status" -le 1 ] || return "$sealed_status"
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = build-ci ]; then
    python3 "$ROOT/scripts/ci/verify/workspace-image-artifact.py" reuse "$ROOT" \
      "$ROOT/.tmp/codewire-workspace-image-verification.json"
    return $?
  fi
  if [ "$sealed_status" -eq 0 ]; then
    printf '%s\n' "$KIND_WORKSPACE_LOCAL_IMAGE"
  else
    printf '%s\n' "$KIND_WORKSPACE_IMAGE"
  fi
}

kind_dind_runtime_image() {
  if validate_sealed_kind_images; then
    printf '%s\n' "$KIND_DIND_LOCAL_IMAGE"
  else
    local status=$?
    [ "$status" -eq 1 ] || return "$status"
    printf '%s\n' "$KIND_DIND_IMAGE"
  fi
}

prepare_kind_support_images() {
  local source alias

  # Resolve the two cluster-local service dependencies before creating Kind.
  # Pulling by an exact linux/amd64 manifest digest makes upstream mutation a
  # hard failure. Side-loading local aliases keeps registry availability and
  # credentials out of the nested cluster's rollout path.
  for source in "$KIND_POSTGRES_IMAGE" "$KIND_TEMPORAL_IMAGE"; do
    if ! [[ "$source" =~ @sha256:[0-9a-f]{64}$ ]]; then
      echo "::error::Kind support image is not digest-pinned: ${source}"
      return 2
    fi
    if ! docker image inspect "$source" >/dev/null 2>&1; then
      log "pulling exact Kind support image ${source}"
      docker pull "$source"
    fi
  done
  for source in \
      "$KIND_POSTGRES_IMAGE|$KIND_POSTGRES_LOCAL_IMAGE" \
      "$KIND_TEMPORAL_IMAGE|$KIND_TEMPORAL_LOCAL_IMAGE"; do
    alias="${source#*|}"
    source="${source%%|*}"
    docker image tag "$source" "$alias"
  done
  prepare_kind_credential_support_images
}

load_images_into_kind() {
  local image sealed source alias

  # Importing several release images back-to-back can make the nested
  # kube-apiserver temporarily unavailable while containerd commits layers.
  # Admit one image at a time and require the control plane to recover before
  # adding the next source of I/O pressure.
  for image in \
      codewire-dashboard:e2e \
      codewire-services:e2e \
      codewire-mesh:e2e \
      codewire-gateway:e2e \
      "$KIND_POSTGRES_LOCAL_IMAGE" \
      "$KIND_TEMPORAL_LOCAL_IMAGE"; do
    log "loading ${image} into kind"
    kind load docker-image --name "$KIND_CLUSTER_NAME" "$image"
    wait_for_kind_api_after_image_load
  done

  load_kind_credential_support_images

  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = build-ci ]; then
    image="$(kind_workspace_runtime_image)" || return $?
    log "loading the exact verified source workspace image into Kind"
    kind load docker-image --name "$KIND_CLUSTER_NAME" "$image"
    wait_for_kind_api_after_image_load
  fi

  if validate_sealed_kind_images; then
    # The trusted runner boundary pulls these images from Nexus before any
    # repository-controlled workflow starts. This process receives neither a
    # registry credential nor public-registry egress; it can only prove and
    # side-load the five exact local references into the disposable Kind node.
    for sealed in \
        "$KIND_INGRESS_CONTROLLER_IMAGE|$KIND_INGRESS_CONTROLLER_LOCAL_IMAGE" \
        "$KIND_INGRESS_CERTGEN_IMAGE|$KIND_INGRESS_CERTGEN_LOCAL_IMAGE" \
        "$KIND_AGENT_SANDBOX_IMAGE|$KIND_AGENT_SANDBOX_LOCAL_IMAGE" \
        "$KIND_WORKSPACE_IMAGE|$KIND_WORKSPACE_LOCAL_IMAGE" \
        "$KIND_DIND_IMAGE|$KIND_DIND_LOCAL_IMAGE"; do
      source="${sealed%%|*}"
      alias="${sealed#*|}"
      if ! docker image inspect "$source" >/dev/null 2>&1; then
        echo "::error::approved Kind platform image was not preloaded by the runner boundary: ${source}"
        return 1
      fi
      # A digest-only Docker image has no RepoTag in the archive consumed by
      # `kind load docker-image`. Give the content a deterministic disposable
      # name after proving the exact approved digest, then render only that
      # side-loaded name with imagePullPolicy Never. No registry credential is
      # copied into the nested cluster.
      docker image tag "$source" "$alias"
      log "loading approved platform image into kind"
      kind load docker-image --name "$KIND_CLUSTER_NAME" "$alias"
      wait_for_kind_api_after_image_load
    done
  else
    local sealed_status=$?
    [ "$sealed_status" -eq 1 ] || return "$sealed_status"
  fi
}

render_ingress_manifest() {
  local source="$ROOT/tests/e2e/kind/vendor/ingress-nginx-deploy.yaml"
  local rendered="$RUN_DIR/ingress-nginx-deploy.yaml"

  if validate_sealed_kind_images; then
    python3 - "$source" "$rendered" \
      "$KIND_INGRESS_CONTROLLER_LOCAL_IMAGE" "$KIND_INGRESS_CERTGEN_LOCAL_IMAGE" <<'PY'
from pathlib import Path
import sys

source, rendered, controller, certgen = sys.argv[1:]
text = Path(source).read_text()
replacements = {
    "registry.k8s.io/ingress-nginx/controller:v1.12.1@sha256:d2fbc4ec70d8aa2050dd91a91506e998765e86c96f32cffb56c503c9c34eed5b": (controller, 1),
    "registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.5.2@sha256:e8825994b7a2c7497375a9b945f386506ca6a3eda80b89b74ef2db743f66a5ea": (certgen, 2),
}
for old, (new, expected_count) in replacements.items():
    old_block = f"image: {old}\n        imagePullPolicy: IfNotPresent"
    actual_count = text.count(old_block)
    if actual_count != expected_count:
        raise SystemExit(
            f"vendored ingress image occurrence mismatch: expected {expected_count}, got {actual_count}"
        )
    new_block = f"image: {new}\n        imagePullPolicy: Never"
    text = text.replace(old_block, new_block)
Path(rendered).write_text(text)
PY
    printf '%s\n' "$rendered"
  else
    local sealed_status=$?
    [ "$sealed_status" -eq 1 ] || return "$sealed_status"
    printf '%s\n' "$source"
  fi
}

render_agent_sandbox_manifest() {
  local source="$ROOT/deployments/k8s/agent-sandbox/base"
  local rendered="$RUN_DIR/agent-sandbox-deploy.yaml"

  kubectl kustomize "$source" >"$rendered"
  if validate_sealed_kind_images; then
    python3 - "$rendered" "$KIND_AGENT_SANDBOX_LOCAL_IMAGE" <<'PY'
from pathlib import Path
import re
import sys

rendered, local_image = sys.argv[1:]
path = Path(rendered)
text = path.read_text()
public_image = "ghcr.io/noeljackson/agent-sandbox-controller@sha256:555146af2337dd5d8baf0844d7f5de9a3cd8fc7b032b85756ae244bc2583fb41"
pattern = re.compile(rf"(?m)^(?P<indent>[ ]*)image: {re.escape(public_image)}$")

def replace(match: re.Match[str]) -> str:
    indent = match.group("indent")
    return f"{indent}image: {local_image}\n{indent}imagePullPolicy: Never"

text, count = pattern.subn(replace, text)
if count != 1:
    raise SystemExit(
        f"agent-sandbox image occurrence mismatch: expected 1, got {count}"
    )
path.write_text(text)
PY
  else
    local sealed_status=$?
    [ "$sealed_status" -eq 1 ] || return "$sealed_status"
  fi
  printf '%s\n' "$rendered"
}

render_kind_overlay_manifest() {
  local source="$ROOT/tests/e2e/kind"
  local rendered="$RUN_DIR/codewire-kind-overlay.yaml"

  kubectl kustomize "$source" >"$rendered"
  python3 - "$rendered" "$KIND_POSTGRES_LOCAL_IMAGE" "$KIND_TEMPORAL_LOCAL_IMAGE" <<'PY'
from pathlib import Path
import re
import sys

rendered, postgres, temporal = sys.argv[1:]
path = Path(rendered)
text = path.read_text()
replacements = {
    "postgres:17-alpine": (postgres, 2),
    "temporalio/auto-setup:1.29.0": (temporal, 1),
}
for public, (local, expected) in replacements.items():
    pattern = re.compile(rf"(?m)^(?P<indent>[ ]*)image: {re.escape(public)}$")
    text, count = pattern.subn(
        lambda match: (
            f'{match.group("indent")}image: {local}\n'
            f'{match.group("indent")}imagePullPolicy: Never'
        ),
        text,
    )
    if count != expected:
        raise SystemExit(
            f"Kind support image occurrence mismatch for {public}: expected {expected}, got {count}"
        )
path.write_text(text)
PY
  if validate_sealed_kind_images; then
    python3 - "$rendered" "$KIND_DIND_LOCAL_IMAGE" <<'PY'
from pathlib import Path
import sys

rendered, local_dind = sys.argv[1:]
path = Path(rendered)
text = path.read_text()
public_dind = "docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c"
old = f"  SANDBOX_DIND_IMAGE: {public_dind}\n"
if text.count(old) != 1:
    raise SystemExit("Kind overlay Dind image occurrence mismatch")
text = text.replace(old, f"  SANDBOX_DIND_IMAGE: {local_dind}\n")
path.write_text(text)
PY
  else
    local sealed_status=$?
    [ "$sealed_status" -eq 1 ] || return "$sealed_status"
  fi
  printf '%s\n' "$rendered"
}

capture_kind_control_plane_state() {
  local node="${KIND_CLUSTER_NAME}-control-plane"

  # Keep failure evidence value-blind. Do not dump the node configuration,
  # environment, Kubernetes objects, or component logs here: those may carry
  # credentials. These fields distinguish a dead/OOM-killed node container
  # from a live node whose static control-plane containers are unhealthy.
  log "capturing value-blind Kind control-plane state"
  docker inspect --format \
    'kind-node status={{.State.Status}} running={{.State.Running}} oom_killed={{.State.OOMKilled}} exit_code={{.State.ExitCode}} restart_count={{.RestartCount}} error_present={{if .State.Error}}true{{else}}false{{end}}' \
    "$node" || true
  docker stats --no-stream --format \
    'kind-node name={{.Name}} cpu={{.CPUPerc}} memory={{.MemUsage}} pids={{.PIDs}}' \
    "$node" || true
  docker exec "$node" systemctl is-active kubelet || true
  docker exec "$node" crictl ps -a --name kube-apiserver || true
  docker exec "$node" crictl ps -a --name etcd || true
}

wait_for_kind_api_after_image_load() {
  local context="kind-${KIND_CLUSTER_NAME}" attempt

  log "checking Kind API after image import"
  for ((attempt = 1; attempt <= 60; attempt++)); do
    if kubectl --context "$context" --request-timeout=1s \
        get --raw=/readyz >/dev/null 2>&1; then
      log "Kind API ready after image import"
      return 0
    fi
    if [ "$attempt" -lt 60 ]; then
      sleep 1
    fi
  done

  capture_kind_control_plane_state
  echo "::error::Kind API did not become ready within 60 seconds after image import"
  return 1
}


deploy_overlay() {
  local ingress_manifest kind_overlay
  ingress_manifest="$(render_ingress_manifest)"
  log "deploying vendored ingress-nginx"
  kubectl_apply --validate=false -f "$ingress_manifest"
  kubectl wait --namespace ingress-nginx \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/component=controller \
    --timeout=180s

  deploy_kind_credential_cert_manager

  log "ensuring isolated kind sandbox namespace"
  kubectl create namespace "$SANDBOX_NS" --dry-run=client -o yaml |
    kubectl_apply -f -
  kubectl label namespace "$SANDBOX_NS" \
    app.kubernetes.io/managed-by=codewire \
    codewire.sh/resource-type=sandbox \
    codewire.sh/runtime-scope=shared \
    --overwrite

  log "deploying kind e2e overlay"
  kubectl -n "$NS" delete job codewire-db-migrate --ignore-not-found --wait=true
  kind_overlay="$(render_kind_overlay_manifest)"
  local applied=0
  for i in $(seq 1 12); do
    if [ -n "$kind_overlay" ]; then
      if kubectl_apply --validate=false -f "$kind_overlay"; then
        applied=1
        break
      fi
    fi
    echo "kubectl apply failed; retry ${i}/12 in 5s"
    sleep 5
  done
  if [ "$applied" != "1" ]; then
    echo "::error::rendered Kind overlay did not apply"
    exit 1
  fi
  assert_kind_idp_topology
  deploy_kind_credential_issuers
  # Staged rollout: the services fail fast (correctly) when Postgres or
  # Temporal is unreachable, so park them at zero replicas until their
  # dependencies are Ready — otherwise a slow runner leaves them in
  # CrashLoopBackOff and the readiness window below races ever-growing
  # backoff delays (cycle-5 failure mode: temporal still
  # ContainerCreating while services crash-looped on "Connection
  # refused"). Scaling 0 -> 1 afterwards yields fresh pods with no
  # backoff history (and, like the old rollout restart, fresh image
  # pulls of the side-loaded tags).
  kubectl -n "$NS" scale \
    deploy/codewire-billing \
    deploy/codewire-idp \
    deploy/codewire-mesh \
    deploy/codewire-orchestration \
    deploy/codewire-coordinator \
    --replicas=0

  log "waiting for postgres and temporal (service dependencies)"
  kubectl -n "$NS" rollout status deploy/postgres --timeout=300s
  kubectl -n "$NS" rollout status deploy/temporal --timeout=600s

  log "waiting for the standard SQLx application baseline"
  if ! kubectl -n "$NS" wait --for=condition=complete \
      job/codewire-db-migrate --timeout=300s; then
    kubectl -n "$NS" logs job/codewire-db-migrate --all-containers=true || true
    return 1
  fi
  kubectl -n "$NS" logs job/codewire-db-migrate --all-containers=true
  local expected_migration_rows migration_rows
  expected_migration_rows="$(find "$ROOT/crates/codewire-server-core/migrations" \
    -maxdepth 1 -type f -name '*.sql' -print | wc -l | tr -d '[:space:]')"
  migration_rows="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire -tAc \
      'SELECT count(*) FILTER (WHERE success = true), count(*) FROM _sqlx_migrations')"
  if [ "$migration_rows" != "${expected_migration_rows}|${expected_migration_rows}" ]; then
    echo "::error::expected ${expected_migration_rows} successful SQLx migration rows and no other ledger rows, got ${migration_rows}"
    return 1
  fi

  log "loading billing and coordinator contract fixtures"
  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 < "$ROOT/tests/fixtures/billing/seed.sql"
  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 < "$ROOT/tests/e2e/kind/coordinator-seed.sql"

  start_kind_credential_fixture

  log "starting billing, IdP, primary authorization, Mesh, and coordinator (dependencies ready)"
  kubectl -n "$NS" scale \
    deploy/codewire-billing \
    deploy/codewire-idp \
    deploy/codewire-mesh \
    deploy/codewire-orchestration \
    deploy/codewire-coordinator \
    --replicas=1
  kubectl -n "$NS" rollout status deploy/codewire-billing --timeout=300s
  kubectl -n "$NS" rollout status deploy/codewire-dashboard --timeout=300s
  kubectl -n "$NS" rollout status deploy/codewire-idp --timeout=300s
  kubectl -n "$NS" rollout status deploy/codewire-orchestration --timeout=300s
  kubectl -n "$NS" rollout status deploy/codewire-mesh --timeout=300s
  kubectl -n "$NS" rollout status deploy/codewire-coordinator --timeout=300s
}

dashboard_browser_e2e() {
  local playwright chromium workspace_image
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  playwright="$ROOT/apps/dashboard/node_modules/.bin/playwright"
  if [ ! -x "$playwright" ]; then
    echo "::error::dashboard Playwright dependencies are missing; run PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 bun install --frozen-lockfile --ignore-scripts"
    return 1
  fi

  chromium="${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}"
  if [ -z "$chromium" ]; then
    chromium="$(command -v chromium || command -v google-chrome || command -v google-chrome-stable || true)"
  fi
  if [ -z "$chromium" ] || [ ! -x "$chromium" ]; then
    echo "::error::the Kind browser gate requires a pre-provisioned Chromium executable; set PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"
    return 1
  fi

  prepare_playwright_browser_runtime "$chromium" "$ROOT" || return $?

  log "running full Rust dashboard Playwright suite through Kind ingress"
  require_get_code /healthz 204 "dashboard health"
  require_get_code /login 200 "dashboard login page"
  DATABASE_URL="${KIND_DATABASE_URL}?sslmode=disable" \
    SERVER_URL="$KIND_INGRESS_URL" \
    PLAYWRIGHT_BASE_URL="$KIND_INGRESS_URL" \
    PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE="$workspace_image" \
    PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chromium" \
    CODEWIRE_PLAYWRIGHT_USE_DEV_SHM="$CODEWIRE_PLAYWRIGHT_USE_DEV_SHM" \
    KUBE_CONTEXT="kind-${KIND_CLUSTER_NAME}" \
    PLAYWRIGHT_KUBE_CONTEXT="kind-${KIND_CLUSTER_NAME}" \
    PLAYWRIGHT_SANDBOX_NAMESPACE="$SANDBOX_NS" \
    "$playwright" test --config "$ROOT/apps/dashboard/playwright.config.ts"
}

mesh_product_connect_ownership_smoke() {
  log "proving Mesh generated Connect ownership and private HMAC authorization"
  local api_key='cw_c0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de'
  local network_id='mesh-kind-owned'
  local session_network_id='mesh-kind-session'
  local invite_network_id='mesh-kind-invite'

  # The Mesh product surface is Connect-only. A plain HTTP request reaches the
  # generated service and is rejected by Connect's protocol validation. That
  # proves ingress selected the generated service before the authenticated
  # product probes below run.
  wait_edge_upstream mesh-connect "/codewire.v1.MeshNetworkService/ListMeshNetworks" 400

  curl_settled -X POST \
    -H "authorization: Bearer ${api_key}" \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"networkId\":\"${network_id}\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNetworkService/CreateMeshNetwork"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e --arg network_id "$network_id" \
      '.network.id == $network_id and .network.orgId == "org_contract_1"' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh Connect API-key create failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: mesh' "$PROBE_HEADERS"; then
    echo "::error::Mesh Connect network create did not reach the Mesh workload"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  # A browser cookie crosses the private HMAC authorization receiver; Mesh has
  # no independent cookie/session middleware.
  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"networkId\":\"${session_network_id}\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNetworkService/CreateMeshNetwork"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e --arg network_id "$session_network_id" \
      '.network.id == $network_id and .network.orgId == "org_contract_1"' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh Connect session-cookie create failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  # Invitation administration remains owner-only. Create the invitation
  # target as the organization owner, then redeem its capability as the
  # ordinary member through the machine credential below.
  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"networkId\":\"${invite_network_id}\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNetworkService/CreateMeshNetwork"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e --arg network_id "$invite_network_id" \
      '.network.id == $network_id and .network.orgId == "org_contract_1"' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh Connect owner-session create failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  curl_settled -X POST \
    -H "authorization: Bearer ${api_key}" \
    -H 'content-type: application/json' \
    -d '{"orgId":"org_contract_1"}' \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNetworkService/ListMeshNetworks"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e --arg network_id "$network_id" \
      'any(.networks[]; .id == $network_id and .orgId == "org_contract_1" and
       (.nodeCount // 0) == 0 and (.inviteCount // 0) == 0)' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh Connect API-key list did not return the exact owned network: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  curl_settled -X POST \
    -H "authorization: Bearer ${api_key}" \
    -H 'content-type: application/json' \
    -d '{"orgId":"org_contract_2"}' \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNetworkService/ListMeshNetworks"
  if [ "$PROBE_CODE" != "403" ] || ! jq -e \
      '.code == "permission_denied"' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::exact-organization API key crossed the Mesh ownership boundary: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  # The OAuth bearer belongs to the same ordinary product user as the API key.
  # Exact network membership exposes only that user's two networks; the
  # administrator's invite network remains hidden despite the shared org.
  curl_settled -X POST \
    -H 'authorization: Bearer at_kind_connect_oidc_codewire_api' \
    -H 'content-type: application/json' \
    -d '{"orgId":"org_contract_1"}' \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNetworkService/ListMeshNetworks"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e \
      --arg api_key_network "$network_id" \
      --arg session_network "$session_network_id" \
      --arg invite_network "$invite_network_id" \
      '(.networks | length) == 2 and
       any(.networks[]; .id == $api_key_network and .orgId == "org_contract_1") and
       any(.networks[]; .id == $session_network and .orgId == "org_contract_1") and
       (any(.networks[]; .id == $invite_network) | not)' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh Connect OAuth list crossed the exact network-membership boundary: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  local rejected_credential='Bearer rejected-bridge-credential'
  curl_settled -X POST \
    -H "authorization: ${rejected_credential}" \
    -H 'content-type: application/json' \
    -d '{"orgId":"org_contract_1"}' \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNetworkService/ListMeshNetworks"
  if [ "$PROBE_CODE" != "401" ] || ! jq -e \
      '.code == "unauthenticated"' <<<"$PROBE_BODY" >/dev/null \
    || [[ "$PROBE_BODY" == *"${rejected_credential}"* ]]; then
    echo "::error::Mesh Connect receiver leaked or accepted a rejected primary credential: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  local stored_owner
  stored_owner="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT organization_id FROM networks WHERE network_id = '${network_id}'")"
  if [ "$stored_owner" != "org_contract_1" ]; then
    echo "::error::Mesh network owner was not written atomically: got ${stored_owner:-empty}"
    exit 1
  fi

  # Same-org administration does not bypass exact network ownership.
  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"networkId\":\"${network_id}\",\"nodeName\":\"mesh-kind-node\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNodeService/CreateMeshNodeEnrollment"
  if [ "$PROBE_CODE" != "403" ] || ! jq -e \
      '.code == "permission_denied"' <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::same-org Mesh nonmember created an enrollment: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  # Enrollment redemption is a generated, unauthenticated one-use capability
  # exchange. It returns registration metadata only and never mints or stores a
  # steady-state node bearer.
  curl_settled -X POST \
    -H "authorization: Bearer ${api_key}" \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"networkId\":\"${network_id}\",\"nodeName\":\"mesh-kind-node\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNodeService/CreateMeshNodeEnrollment"
  local enrollment_id enrollment_code
  if [ "$PROBE_CODE" != "200" ] || ! jq -e \
      --arg network_id "$network_id" \
      '.enrollment.orgId == "org_contract_1" and
       .enrollment.networkId == $network_id and
       .enrollment.nodeName == "mesh-kind-node" and
       (.enrollment.id | type == "string" and length > 0) and
       (.enrollmentCode | type == "string" and startswith("cw_enr_"))' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh generated enrollment create failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: mesh' "$PROBE_HEADERS"; then
    echo "::error::MeshNodeService enrollment create did not reach the Mesh workload"
    cat "$PROBE_HEADERS"
    exit 1
  fi
  enrollment_id="$(jq -er '.enrollment.id' <<<"$PROBE_BODY")"
  enrollment_code="$(jq -er '.enrollmentCode' <<<"$PROBE_BODY")"

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -d "{\"enrollmentCode\":\"${enrollment_code}\",\"nodeName\":\"mesh-kind-node\",\"peerUrl\":\"https://mesh-kind-node.test/peer\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNodeService/RedeemMeshNodeEnrollment"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e \
      --arg network_id "$network_id" \
      --arg enrollment_id "$enrollment_id" \
      '.node.orgId == "org_contract_1" and
       .node.networkId == $network_id and
       .node.name == "mesh-kind-node" and
       .node.peerUrl == "https://mesh-kind-node.test/peer" and
       .enrollment.id == $enrollment_id and
       .enrollment.orgId == "org_contract_1" and
       .enrollment.networkId == $network_id and
       .enrollment.ownerUserId == "usr_contract_user" and
       .enrollment.issuedByUserId == "usr_contract_user" and
       (.enrollment.redeemedAt | type == "string" and length > 0) and
       ([.. | objects |
          has("nodeToken") or has("credential") or has("token") or
          has("enrollmentCode")] | any | not)' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh generated enrollment redemption returned invalid or credential-shaped metadata: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: mesh' "$PROBE_HEADERS"; then
    echo "::error::MeshNodeService redemption did not reach the Mesh workload"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -d "{\"enrollmentCode\":\"${enrollment_code}\",\"nodeName\":\"mesh-kind-node\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNodeService/RedeemMeshNodeEnrollment"
  if [ "$PROBE_CODE" != "403" ] || ! jq -e \
      '.code == "permission_denied"' <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh enrollment capability was not exactly one-use: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  while read -r retired_method retired_path; do
    curl_settled -X "$retired_method" \
      -H 'content-type: application/json' \
      -d '{}' \
      "${KIND_INGRESS_URL}${retired_path}"
    if [ "$PROBE_CODE" != "404" ]; then
      echo "::error::retired Mesh coordinate/auth route ${retired_path} returned ${PROBE_CODE}, want 404"
      exit 1
    fi
  done <<'EOF'
POST /api/v1/node-enrollments/redeem
POST /api/v1/networks
GET /api/v1/networks
POST /api/v1/network-auth/runtime/node
GET /api/v1/network-auth/bundle
POST /api/v1/network-auth/delegation/node
POST /api/v1/network-auth/runtime/client
GET /api/v1/tailnet/coordinate
EOF

  local node_registration legacy_relations legacy_columns migration_004
  local migration_005 migration_006 network_auth_rows
  node_registration="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tA -F '|' -c \
      "SELECT network_id, name, owner_subject, authorized_by, enrollment_id, peer_url FROM nodes WHERE network_id = '${network_id}' AND name = 'mesh-kind-node'")"
  legacy_relations="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relname IN ('users', 'sessions', 'oauth_state', 'oidc_users', 'oidc_sessions', 'oidc_device_flows', 'device_codes', 'github_app')")"
  legacy_columns="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND ((table_name = 'nodes' AND column_name = 'token') OR (table_name = 'oidc_device_flows' AND column_name = 'node_token'))")"
  migration_004="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tA -F '|' -c \
      "SELECT description, success FROM _sqlx_migrations WHERE version = 4")"
  migration_005="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tA -F '|' -c \
      "SELECT description, success FROM _sqlx_migrations WHERE version = 5")"
  migration_006="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tA -F '|' -c \
      "SELECT description, success FROM _sqlx_migrations WHERE version = 6")"
  network_auth_rows="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT count(*) FROM kv WHERE namespace = 'mesh.networkauth'")"
  if [ "$node_registration" != "${network_id}|mesh-kind-node|usr_contract_user|usr_contract_user|${enrollment_id}|https://mesh-kind-node.test/peer" ] \
    || [ "$legacy_relations" != "0" ] \
    || [ "$legacy_columns" != "0" ] \
    || [ "$migration_004" != "retire persistent node bearer|t" ] \
    || [ "$migration_005" != "retire network auth issuer|t" ] \
    || [ "$migration_006" != "retire raw auth session device state|t" ] \
    || [ "$network_auth_rows" != "0" ]; then
    echo "::error::Mesh raw-auth retirement persistence proof failed: node=${node_registration:-missing} legacy_relations=${legacy_relations:-missing} legacy_columns=${legacy_columns:-missing} migration_004=${migration_004:-missing} migration_005=${migration_005:-missing} migration_006=${migration_006:-missing} network_auth_rows=${network_auth_rows:-missing}"
    exit 1
  fi

  # The generated primary-origin path must reach Mesh, forward the presented
  # product credential through the same private HMAC receiver, and expose the
  # one-use capability only in the create response.
  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"networkId\":\"${invite_network_id}\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshInviteService/CreateMeshInvite"
  local invite_id invite_code
  if [ "$PROBE_CODE" != "200" ] || ! jq -e \
      '(.invite.id | type == "string" and length > 0) and
       (.inviteCode | type == "string" and startswith("cw_inv_"))' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh Connect invite create returned no clean one-use capability: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  invite_id="$(jq -er '.invite.id' <<<"$PROBE_BODY")"
  invite_code="$(jq -er '.inviteCode' <<<"$PROBE_BODY")"
  if [ "$invite_id" = "$invite_code" ] \
    || jq -e '.invite | has("inviteCode") or has("inviteToken") or has("codeHash") or has("usesRemaining")' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh Connect invite create violated the clean contract: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: mesh' "$PROBE_HEADERS"; then
    echo "::error::MeshInviteService did not reach the Mesh workload"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"networkId\":\"${invite_network_id}\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshInviteService/ListMeshInvites"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e --arg invite_id "$invite_id" \
      '(.invites | length) == 1 and .invites[0].id == $invite_id and
       ((.invites[0] | has("inviteCode") or has("inviteToken") or has("codeHash") or has("usesRemaining")) | not)' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh Connect/REST invitation state diverged: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  local persisted_invite forbidden_columns
  persisted_invite="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tA -F '|' -c \
      "SELECT id, organization_id, created_by_user_id, code_hash FROM invites WHERE id = '${invite_id}'")"
  forbidden_columns="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'invites' AND column_name IN ('token', 'created_by', 'uses_remaining')")"
  if [[ "$persisted_invite" != "${invite_id}|org_contract_1|usr_contract_admin|"* ]] \
    || [[ "$persisted_invite" == *"${invite_code}"* ]] \
    || [ "$forbidden_columns" != "0" ]; then
    echo "::error::Mesh invitation persistence is not opaque-ID/hash-only: row=${persisted_invite:-missing} forbidden_columns=${forbidden_columns:-missing}"
    exit 1
  fi

  curl_settled -X POST \
    -H "authorization: Bearer ${api_key}" \
    -H 'content-type: application/json' \
    -d "{\"inviteCode\":\"${invite_code}\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.MeshNetworkService/JoinMeshNetwork"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e --arg network_id "$invite_network_id" \
      '.network.id == $network_id and .network.orgId == "org_contract_1"' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh Connect one-use invitation redemption failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  local invite_rows invite_provenance
  invite_rows="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT count(*) FROM invites WHERE id = '${invite_id}'")"
  invite_provenance="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT created_by FROM network_members WHERE network_id = '${invite_network_id}' AND subject = 'usr_contract_user'")"
  if [ "$invite_rows" != "0" ] || [ "$invite_provenance" != "invite:${invite_id}" ] \
    || [[ "$invite_provenance" == *"${invite_code}"* ]]; then
    echo "::error::Mesh invitation consumption/provenance is not one-use and non-secret: rows=${invite_rows:-missing} provenance=${invite_provenance:-missing}"
    exit 1
  fi
  log "Mesh Connect/HMAC/exact-org/invitation/enrollment proof OK"
}

# Polls a path through the ingress until the expected status arrives —
# absorbs the endpoint-propagation window after `kubectl rollout status`
# (pods Ready != ingress-nginx upstreams synced; a matched location with no
# ready endpoints answers 503). Every unretried edge probe below depends on
# the upstream it targets having passed through here first.
wait_edge_upstream() {
  local label="$1" path="$2" want="$3"
  local code i
  for i in $(seq 1 45); do
    code="$(http_code "${KIND_INGRESS_URL}${path}")"
    if [ "$code" = "$want" ]; then
      log "${label} upstream ready (${path} -> ${want} after ${i} poll(s))"
      return 0
    fi
    echo "${label} returned ${code}; waiting for ingress endpoint sync (${i}/45)"
    sleep 2
  done
  echo "::error::${label} upstream never became ready at ${path} (last code ${code})"
  exit 1
}

edge_routing_probes() {
  log "running ingress edge routing probes"

  # The retained orchestration browser transport must be reachable through the
  # ingress before unretried probes run; this absorbs endpoint propagation.
  wait_edge_upstream orchestration /api/v1/organizations/org_contract_1/environments/env_contract_1/ssh-proxy 401
  local code path

  for path in \
    /api/v1/billing/plans/sandbox \
    /api/v1/organizations/org_contract_1/billing/invoices \
    /api/v1/organizations/org_contract_1/billing \
    /api/v1/organizations/org_contract_1/environments/usage \
    /api/v1/admin/billing/catalog/plans; do
    require_get_code "$path" 404 "retired billing REST path $path"
  done

  for path in billing/checkout billing/portal billing/setup; do
    require_post_code "/api/v1/organizations/org_contract_1/${path}" 404 "retired billing REST POST $path"
  done

  curl_settled -X POST --data '{}' "${KIND_INGRESS_URL}/api/webhooks/stripe"
  if [ "$PROBE_CODE" != "400" ] || ! echo "$PROBE_BODY" | grep -q "invalid signature"; then
    echo "::error::webhook path did not reach configured Stripe signature guard: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  require_get_code /api/v1/billing/checkout 404 "nonexistent unscoped billing checkout"

  for path in \
    /api/v1/admin/billing/catalog/plans \
    /api/v1/admin/billing/catalog/prices \
    /api/v1/admin/billing/catalog/settings/trial_days \
    /api/v1/admin/billing/catalog/subscription-migrations; do
    require_get_code "$path" 404 "retired catalog REST path $path"
  done

  require_get_code /api/v1/organizations/org_contract_1/environments 404 "retired environments REST path"

  for path in \
    /api/v1/organizations/org_contract_1 \
    /api/v1/admin/organizations \
    /api/v1/admin/audit-logs \
    /api/v1/admin/environments/env_contract_1/lifecycle-journal \
    /api/v1/admin/environments/startup-summary \
    /api/v1/admin/environments/env_contract_1/startup-timings \
    /api/v1/organizations/org_contract_1/environments/env_contract_1 \
    /api/v1/organizations/org_contract_1/presets \
    /api/v1/organizations/org_contract_1/repo-configs \
    /api/v1/organizations/org_contract_1/api-keys \
    /api/v1/environment-create/detect; do
    require_get_code "$path" 404 "retired orchestration REST path $path"
  done

  require_post_code /api/v1/organizations/org_contract_1/environments/env_contract_1/exec 404 "retired exec REST path"
  require_post_code /api/v1/terminal/ticket 404 "retired terminal-ticket REST path"
  require_get_code /api/v1/organizations/org_contract_1/environments/env_contract_1/ssh-proxy 401 "permanent ssh-proxy websocket path"
  require_get_code /api/v1/organizations/org_contract_1/environments/env_contract_1/ssh-proxy/check 401 "permanent ssh-proxy check path"

  curl_settled -H 'Host: web.codewire-dev.local' "${KIND_INGRESS_URL}/"
  if [ "$PROBE_CODE" != "400" ]; then
    echo "::error::preview wildcard route returned ${PROBE_CODE}, want 400"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: codewire-orchestration' "$PROBE_HEADERS"; then
    echo "::error::preview wildcard route did not reach codewire-orchestration"
    cat "$PROBE_HEADERS"
    exit 1
  fi
}

# Connect-RPC edge proofs (docs/plans/connect-rpc/03, WI-4 / D5):
#   - a billing-owned Connect regex beats the /codewire\. orchestration
#     fallback (the probe's PublicPing rule -> codewire-billing),
#   - the fallback delivers every other Connect path to orchestration with
#     Connect-shaped answers (never dashboard HTML),
#   - a server-streaming response crosses ingress-nginx incrementally
#     (proxy-buffering off on the connect Ingress).
# The probe is mounted because the e2e kustomization sets
# CONNECT_TESTING_SURFACE=1 on both deployments (D8).
connect_edge_probes() {
  log "running Connect edge routing probes"
  local base="${KIND_INGRESS_URL}/codewire.testing.v1.PingService"
  local ok i

  # 1. Billing-owned regex wins over the fallback: PublicPing -> billing.
  ok=0
  for i in $(seq 1 30); do
    curl_settled -X POST -H 'content-type: application/json' \
      -d '{}' "${base}/PublicPing"
    if [ "$PROBE_BODY" = '{"message":"public pong"}' ]; then
      ok=1
      break
    fi
    echo "PublicPing returned '$PROBE_BODY'; waiting for ingress endpoint sync (${i}/30)"
    sleep 2
  done
  if [ "$ok" != "1" ]; then
    echo "::error::Connect PublicPing never answered through the ingress"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: codewire-billing' "$PROBE_HEADERS"; then
    echo "::error::PublicPing did not reach codewire-billing (billing-owned regex must beat the /codewire. fallback)"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  # 2. The fallback routes other probe methods to orchestration
  #    (uncredentialed Ping: Connect-shaped 401 from the auth layer).
  curl_settled -X POST -H 'content-type: application/json' \
    -d '{"message":"hi"}' "${base}/Ping"
  if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
    echo "::error::uncredentialed Connect Ping through the fallback: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: codewire-orchestration' "$PROBE_HEADERS"; then
    echo "::error::Connect fallback did not reach codewire-orchestration"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  # 2a. Product credential boundary through ingress. The contract fixture
  # carries one browser session, one organization-scoped machine key, and one
  # product-scoped opaque OIDC bearer for the same non-admin user. A session
  # token is flavor 1 only: presenting that exact token in Authorization must
  # never fall back to session authentication.
  curl_settled -X POST -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d '{"message":"whoami"}' "${base}/Ping"
  if [ "$PROBE_CODE" != "200" ] || [ "$PROBE_BODY" != '{"message":"usr_contract_user"}' ]; then
    echo "::error::session-cookie Connect Ping through ingress failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  curl_settled -X POST -H 'content-type: application/json' \
    -H 'authorization: Bearer at_kind_connect_oidc_codewire_api' \
    -d '{"message":"whoami"}' "${base}/Ping"
  if [ "$PROBE_CODE" != "200" ] || [ "$PROBE_BODY" != '{"message":"usr_contract_user"}' ]; then
    echo "::error::OIDC Connect Ping through ingress failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  curl_settled -X POST -H 'content-type: application/json' \
    -H 'authorization: Bearer cw_c0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de' \
    -d '{"message":"whoami"}' "${base}/Ping"
  if [ "$PROBE_CODE" != "200" ] || [ "$PROBE_BODY" != '{"message":"usr_contract_user"}' ]; then
    echo "::error::API-key Connect Ping through ingress failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  curl_settled -X POST -H 'content-type: application/json' \
    -H 'authorization: Bearer contract-user-session-token' \
    -d '{"message":"session-bearer"}' "${base}/Ping"
  if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
    echo "::error::raw session bearer bypassed Connect auth through ingress: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  # 2b. OrganizationService uses the same package-wide fallback. Its private
  #     methods stay credentialed, while the one exact public invitation
  #     lookup bypasses auth and reaches the handler (unknown token ->
  #     not_found, never unauthenticated).
  local organization_base="${KIND_INGRESS_URL}/codewire.v1.OrganizationService"
  curl_settled -X POST -H 'content-type: application/json' \
    -d '{}' "${organization_base}/ListOrganizations"
  if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
    echo "::error::private OrganizationService method bypassed auth: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  curl_settled --get \
    --data-urlencode 'connect=v1' \
    --data-urlencode 'encoding=json' \
    --data-urlencode 'message={"token":"kind-contract-unknown"}' \
    "${organization_base}/GetInvitationByToken"
  if [ "$PROBE_CODE" != "404" ] || ! echo "$PROBE_BODY" | grep -q '"code":"not_found"'; then
    echo "::error::public invitation lookup did not bypass auth into its handler: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: codewire-orchestration' "$PROBE_HEADERS"; then
    echo "::error::OrganizationService did not reach codewire-orchestration"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  # 2c. AdminService has an explicit per-Service orchestration rule because
  # codewire.admin.v1 is split across orchestration and billing. Prove the
  # route and whole-service global-admin interceptor together.
  local admin_base="${KIND_INGRESS_URL}/codewire.admin.v1.AdminService"
  curl_settled -X POST -H 'content-type: application/json' \
    -d '{}' "${admin_base}/GetStats"
  if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
    echo "::error::uncredentialed AdminService method bypassed auth: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  curl_settled -X POST -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d '{}' "${admin_base}/GetStats"
  if [ "$PROBE_CODE" != "403" ] || ! echo "$PROBE_BODY" | grep -q '"code":"permission_denied"'; then
    echo "::error::non-admin AdminService request was not denied: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  curl_settled -X POST -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -d '{}' "${admin_base}/GetStats"
  if [ "$PROBE_CODE" != "200" ] || ! echo "$PROBE_BODY" | grep -q '"totalEnvironments"'; then
    echo "::error::global-admin AdminService request failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: codewire-orchestration' "$PROBE_HEADERS"; then
    echo "::error::AdminService did not reach codewire-orchestration"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  # 2d. BillingCatalogService shares codewire.admin.v1 with AdminService but
  # must reach the billing binary. The full billing Connect contract below
  # exercises the retained read surface; this probe makes the per-Service edge
  # split immediately diagnosable.
  local billing_catalog_base="${KIND_INGRESS_URL}/codewire.admin.v1.BillingCatalogService"
  curl_settled -X POST -H 'content-type: application/json' \
    -d '{}' "${billing_catalog_base}/GetCatalog"
  if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
    echo "::error::uncredentialed BillingCatalogService method bypassed auth: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  curl_settled -X POST -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d '{}' "${billing_catalog_base}/GetCatalog"
  if [ "$PROBE_CODE" != "403" ] || ! echo "$PROBE_BODY" | grep -q '"code":"permission_denied"'; then
    echo "::error::non-admin BillingCatalogService request was not denied: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  curl_settled -X POST -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -d '{}' "${billing_catalog_base}/GetCatalog"
  if [ "$PROBE_CODE" != "200" ] || ! echo "$PROBE_BODY" | grep -q '"plans"'; then
    echo "::error::global-admin BillingCatalogService request failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: codewire-billing' "$PROBE_HEADERS"; then
    echo "::error::BillingCatalogService did not reach codewire-billing"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  # 3a. Unknown method WITHOUT a credential: the auth layer runs before
  #     method dispatch (doc 03 D3), so method existence is not enumerable
  #     by unauthenticated callers — the answer is a Connect-shaped
  #     unauthenticated, not unimplemented.
  curl_settled -X POST -H 'content-type: application/json' -d '{}' "${base}/NoSuchMethod"
  if ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
    echo "::error::unauthenticated unknown Connect method must reject with unauthenticated (auth runs before dispatch): $PROBE_BODY"
    exit 1
  fi

  # 3b. Unknown method WITH a credential (the seeded contract session):
  #     past the auth layer, the dispatcher answers Connect-shaped
  #     unimplemented.
  curl_settled -X POST -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d '{}' "${base}/NoSuchMethod"
  if ! echo "$PROBE_BODY" | grep -q '"code":"unimplemented"'; then
    echo "::error::authenticated unknown Connect method did not yield a Connect-shaped unimplemented: $PROBE_BODY"
    exit 1
  fi

  # 4. Unmatched Connect service: answered by orchestration, never HTML.
  curl_settled -X POST -H 'content-type: application/json' \
    -d '{}' "${KIND_INGRESS_URL}/codewire.v1.NoSuchService/Method"
  if ! grep -qi '^x-codewire-service: codewire-orchestration' "$PROBE_HEADERS"; then
    echo "::error::unmatched /codewire.* path did not land on orchestration"
    cat "$PROBE_HEADERS"
    exit 1
  fi
  if echo "$PROBE_BODY" | grep -qi '<html'; then
    echo "::error::unmatched /codewire.* path answered with HTML: $PROBE_BODY"
    exit 1
  fi

  # 5. Server-streaming crosses the edge incrementally. StreamPing emits 5
  #    messages 300ms apart; buffered delivery collapses the arrival window
  #    to ~0. --trace-ascii + --trace-time timestamp every received chunk
  #    ("<= Recv data" lines) — plain -v logs headers only, so the trace
  #    file is the measurement, and a trace without data events is a
  #    probe failure, distinct from a buffering failure.
  local trace code events spread
  trace="$(mktemp)"
  for i in $(seq 1 15); do
    : > "$trace"
    code="$(printf '\x00\x00\x00\x00\x02{}' | curl -sN --no-buffer \
      --trace-ascii "$trace" --trace-time \
      -X POST -H 'content-type: application/connect+json' --data-binary @- \
      -o /dev/null -w '%{http_code}' "${base}/StreamPing")"
    if [ "$code" != "503" ]; then
      break
    fi
    echo "StreamPing got 503; waiting for ingress location sync (${i}/15)"
    sleep 2
  done
  if [ "$code" != "200" ]; then
    echo "::error::StreamPing returned ${code}, want 200"
    tail -40 "$trace"
    exit 1
  fi
  events="$(grep -c '<= Recv data' "$trace" || true)"
  if [ "${events:-0}" -lt 2 ]; then
    echo "::error::StreamPing probe could not measure chunk arrivals (${events:-0} Recv-data events in curl trace) — measurement failure, not a buffering verdict"
    head -60 "$trace"
    exit 1
  fi
  spread="$(awk '/<= Recv data/ { split($1, T, ":"); t = T[1]*3600 + T[2]*60 + T[3]; if (first == "") first = t; last = t } END { printf "%.3f", last - first }' "$trace")"
  if ! awk -v s="$spread" 'BEGIN { exit !(s >= 0.6) }'; then
    echo "::error::StreamPing arrived as one burst through ingress-nginx (${events} chunks, spread ${spread}s, want >= 0.6s) — response buffering is on"
    grep '<= Recv data' "$trace"
    exit 1
  fi
  log "Connect edge probes OK (${events} stream chunks over ${spread}s)"

  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_DIRECT_BASE_URL=http://127.0.0.1:8084 \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/prepare-stream-smoke"

  # ingress-nginx consumes the upstream X-Accel-Buffering control header.
  # The two typed heartbeat arrivals below are the end-to-end no-buffering
  # assertion at this edge.
  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_DATABASE_URL="$KIND_DATABASE_URL" \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID=env_contract_1 \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/log-stream-smoke"
}

# `codewire.internal.v1` is the sole listener-isolation exception to the
# public `/codewire.` fallback. Prove both sides of that boundary against the
# rendered Kind Service: public ingress reaches the ordinary public 8084
# not-found, an authenticated ClusterIP Service-DNS request proves the binding
# success path, and a direct port-forward proves anonymous and cross-capability
# requests fail closed on the internal listener.
internal_connect_listener_probes() {
  log "running internal Connect listener isolation probes"
  local public_base="${KIND_INGRESS_URL}/codewire.internal.v1.GatewayBindingService"
  curl_settled -X POST -H 'content-type: application/json' -d '{}' \
    "${public_base}/IssueGatewayBinding"
  if [ "$PROBE_CODE" != "404" ]; then
    echo "::error::public internal Connect path returned ${PROBE_CODE}, want public-listener 404: ${PROBE_BODY}"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: codewire-orchestration' "$PROBE_HEADERS"; then
    echo "::error::public internal Connect path did not reach the public orchestration listener"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  # The binding service rejects database-only runtime identities: the
  # referenced SandboxClaim and workspace Pod must both be live and current.
  # Install the checked-in claim CRD before the full controller deployment so this
  # listener probe can build that exact fixture without a controller racing
  # its synthetic status.
  kubectl_apply --validate=false \
    -f "$ROOT/deployments/k8s/agent-sandbox/base/crds/extensions.agents.x-k8s.io_sandboxclaims.yaml"
  kubectl wait --for=condition=established --timeout=60s \
    crd/sandboxclaims.extensions.agents.x-k8s.io

  (
    # Reuse the existing UUID-addressed coordinator fixture. The binding
    # endpoint must mint a token the real coordinator accepts, rather than
    # merely returning a syntactically plausible token from its own process.
    local bound_environment_id=00000000-0000-4000-8000-000000000501
    local bound_pod="sandbox-${bound_environment_id}"
    local bound_gateway="cw-binding-gateway-${bound_environment_id}"
    local bound_pod_ip
    local bound_port_id=port_internal_connect_kind
    local port_forward_log port_forward_pid local_port i sidecar_token in_cluster_probe
    port_forward_log="$(mktemp)"
    port_forward_pid=""

    # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
    cleanup_internal_connect_fixture() {
      set +e
      if [ -n "$port_forward_pid" ]; then
        kill "$port_forward_pid" >/dev/null 2>&1 || true
        wait "$port_forward_pid" 2>/dev/null || true
      fi
      kubectl -n "$NS" exec -i deploy/postgres -- \
        psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL >/dev/null 2>&1 || true
DELETE FROM environment_ports WHERE id = '$bound_port_id';
DELETE FROM sandbox_environment_backend WHERE environment_id = '$bound_environment_id';
SQL
      kubectl -n "$NS" delete sandboxclaim "$bound_pod" \
        --ignore-not-found=true --wait=true >/dev/null 2>&1 || true
      kubectl -n "$NS" delete pod "$bound_pod" \
        --ignore-not-found=true --wait=true >/dev/null 2>&1 || true
      kubectl -n "$NS" delete pod "$bound_gateway" \
        --ignore-not-found=true --wait=true >/dev/null 2>&1 || true
      rm -f "$port_forward_log"
    }
    trap cleanup_internal_connect_fixture EXIT

    kubectl -n "$NS" delete sandboxclaim "$bound_pod" \
      --ignore-not-found=true --wait=true >/dev/null
    kubectl -n "$NS" delete pod "$bound_pod" \
      --ignore-not-found=true --wait=true >/dev/null
    kubectl -n "$NS" delete pod "$bound_gateway" \
      --ignore-not-found=true --wait=true >/dev/null
    kubectl_apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: codewire-sandbox
  namespace: ${NS}
automountServiceAccountToken: false
---
apiVersion: v1
kind: Pod
metadata:
  name: ${bound_pod}
  namespace: ${NS}
  labels:
    codewire.sh/environment-id: ${bound_environment_id}
    codewire.sh/type: workspace
spec:
  restartPolicy: Always
  containers:
    - name: workspace
      image: ${KIND_POSTGRES_LOCAL_IMAGE}
      imagePullPolicy: Never
      command: ["sleep", "600"]
---
apiVersion: v1
kind: Pod
metadata:
  name: ${bound_gateway}
  namespace: ${NS}
  labels:
    codewire.sh/environment-id: ${bound_environment_id}
    codewire.sh/type: gateway
spec:
  serviceAccountName: codewire-sandbox
  automountServiceAccountToken: false
  restartPolicy: Always
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  containers:
    - name: gateway-binding-caller
      image: ${KIND_POSTGRES_LOCAL_IMAGE}
      imagePullPolicy: Never
      command: ["sleep", "600"]
      volumeMounts:
        - name: gateway-binding-identity
          mountPath: /var/run/secrets/codewire/gateway-binding
          readOnly: true
  volumes:
    - name: gateway-binding-identity
      projected:
        defaultMode: 288
        sources:
          - serviceAccountToken:
              audience: codewire.internal.gateway-binding.v1
              expirationSeconds: 600
              path: token
---
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${bound_pod}
  namespace: ${NS}
spec:
  warmPoolRef:
    name: kind-internal-ready-fixture
EOF
    kubectl -n "$NS" wait "pod/${bound_pod}" \
      --for=condition=Ready --timeout=60s
    kubectl -n "$NS" wait "pod/${bound_gateway}" \
      --for=condition=Ready --timeout=60s
    kubectl -n "$NS" patch sandboxclaim "$bound_pod" \
      --subresource=status --type=merge \
      -p '{"status":{"conditions":[{"lastTransitionTime":"2026-01-01T00:00:00Z","message":"Kind internal binding fixture is ready","reason":"Ready","status":"True","type":"Ready"}]}}'
    bound_pod_ip="$(
      kubectl -n "$NS" get pod "$bound_pod" -o jsonpath='{.status.podIP}'
    )"
    if [ -z "$bound_pod_ip" ]; then
      echo "::error::internal Connect fixture Pod has no IP"
      exit 1
    fi

    kubectl -n "$NS" exec -i deploy/postgres -- \
      psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
DELETE FROM sandbox_environment_backend WHERE environment_id = '$bound_environment_id';
DELETE FROM environment_ports WHERE id = '$bound_port_id';
UPDATE environments
SET state = 'running', desired_state = 'started'
WHERE id = '$bound_environment_id';
INSERT INTO sandbox_environment_backend (environment_id, namespace, pod_name, pod_ip)
VALUES ('$bound_environment_id', '$NS', '$bound_pod', '$bound_pod_ip');
INSERT INTO environment_ports (id, environment_id, port, label, access)
VALUES ('$bound_port_id', '$bound_environment_id', 3000, 'internal-connect-kind', 'creator');
SQL
    # This originates in a gateway-labeled Pod and addresses the ClusterIP by
    # Service DNS. The caller rereads its exact-audience projected token, and
    # sends no Pod coordinates; orchestration derives name, namespace, and UID
    # exclusively from TokenReview before resolving the environment label.
    # shellcheck disable=SC2016 # The shell inside the fixture Pod expands the token.
    in_cluster_probe="$(kubectl -n "$NS" exec "$bound_gateway" -- sh -ec '
      token="$(cat /var/run/secrets/codewire/gateway-binding/token)"
      exec wget -q -O - \
        --header="content-type: application/json" \
        --header="authorization: Bearer ${token}" \
        --post-data="{}" \
        http://codewire-orchestration:8085/codewire.internal.v1.GatewayBindingService/IssueGatewayBinding
    ')"
    if ! jq -e --arg environment_id "$bound_environment_id" --arg pod_ip "$bound_pod_ip" \
      '(.environmentId // .environment_id) == $environment_id
       and (.workspacePodIp // .workspace_pod_ip) == $pod_ip
       and ((.appPorts // .app_ports // []) | index(3000)) != null
       and ((.sidecarToken // .sidecar_token // "") | length > 0)' \
      <<<"$in_cluster_probe" >/dev/null; then
      echo "::error::in-cluster Service-DNS binding request did not reach the internal 8085 mount: $in_cluster_probe"
      exit 1
    fi

    kubectl -n "$NS" port-forward --address=127.0.0.1 \
      service/codewire-orchestration :8085 >"$port_forward_log" 2>&1 &
    port_forward_pid=$!

    for i in $(seq 1 30); do
      local_port="$(sed -nE 's/.*127\.0\.0\.1:([0-9]+) -> 8085.*/\1/p' "$port_forward_log" | head -n 1)"
      if [ -n "$local_port" ]; then
        break
      fi
      if ! kill -0 "$port_forward_pid" >/dev/null 2>&1; then
        echo "::error::internal-connect Service port-forward exited before becoming ready"
        sed -n '1,80p' "$port_forward_log" >&2
        exit 1
      fi
      sleep 1
    done
    if [ -z "${local_port:-}" ]; then
      echo "::error::internal-connect Service port-forward did not publish a local port"
      sed -n '1,80p' "$port_forward_log" >&2
      exit 1
    fi

    curl_settled -X POST -H 'content-type: application/json' -d '{}' \
      "http://127.0.0.1:${local_port}/codewire.internal.v1.GatewayBindingService/IssueGatewayBinding"
    if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
      echo "::error::anonymous internal binding command was not rejected: code=$PROBE_CODE body=$PROBE_BODY"
      exit 1
    fi
    if ! grep -qi '^x-codewire-service: codewire-orchestration-internal' "$PROBE_HEADERS"; then
      echo "::error::ClusterIP internal binding command did not reach the internal listener"
      cat "$PROBE_HEADERS"
      exit 1
    fi

    sidecar_token="$(jq -er '.sidecarToken // .sidecar_token // empty' <<<"$in_cluster_probe")"

    # A freshly issued coordinate-scoped Codewire HMAC bearer must not be
    # accepted as a gateway bootstrap identity. There is no HMAC or anonymous
    # fallback around the exact-audience Kubernetes TokenReview boundary.
    curl_settled -X POST -H 'content-type: application/json' \
      -H "authorization: Bearer ${sidecar_token}" -d '{}' \
      "http://127.0.0.1:${local_port}/codewire.internal.v1.GatewayBindingService/IssueGatewayBinding"
    if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
      echo "::error::coordinate capability crossed into gateway binding: code=$PROBE_CODE body=$PROBE_BODY"
      exit 1
    fi

    # The one Rust client core opens a real generated Coordinate stream. Its
    # successful setup proves the just-issued HMAC token crossed the service
    # boundary and was accepted by the coordinator, not only parsed by the
    # issuer.
    for i in $(seq 1 20); do
      if KIND_COORDINATOR_DIRECT_URL="http://127.0.0.1:18092" \
        KIND_COORDINATOR_ENVIRONMENT="$bound_environment_id" \
        KIND_COORDINATOR_SIDECAR_TOKEN="$sidecar_token" \
        KIND_COORDINATOR_BINDING_PROBE=1 \
        timeout --kill-after=5s 15s "$CARGO_CI_DIR/examples/coordinator-ingress-smoke"; then
        break
      fi
      if [ "$i" = 20 ]; then
        echo "::error::coordinator did not accept the internal binding token"
        exit 1
      fi
      echo "internal binding coordinator probe not ready (${i}/20)"
      sleep 2
    done

  )

  log "internal Connect listener isolation probes OK"
}

coordinator_ingress_smoke() {
  log "running generated primary and Mesh coordinator native-gRPC/direct-h2c smoke"
  local certificate_dir certificate_pem certificate_der alpn_output

  curl_settled -X GET \
    "http://127.0.0.1:18092/api/v1/internal/gateway/coordinate"
  if [ "$PROBE_CODE" != "404" ]; then
    echo "::error::retired primary coordinator WebSocket returned ${PROBE_CODE}, want 404"
    exit 1
  fi
  curl_settled -X POST \
    -H 'content-type: application/connect+proto' \
    --data-binary '' \
    "http://127.0.0.1:18092/coordinator.v1.CoordinatorService/Coordinate"
  if [ "$PROBE_CODE" != "404" ]; then
    echo "::error::retired coordinator.v1 route returned ${PROBE_CODE}, want 404"
    exit 1
  fi

  certificate_dir="$(mktemp -d)"
  certificate_pem="$certificate_dir/ca.pem"
  certificate_der="$certificate_dir/ca.der"
  kubectl -n "$NS" get secret/codewire-kind-ingress-ca \
    -o 'jsonpath={.data.ca\.crt}' | base64 --decode > "$certificate_pem"
  openssl x509 -in "$certificate_pem" -outform DER -out "$certificate_der"

  if ! alpn_output="$(openssl s_client \
    -connect localhost:10443 \
    -servername localhost \
    -CAfile "$certificate_pem" \
    -verify_return_error \
    -alpn h2 </dev/null 2>&1)"; then
    echo "::error::ingress TLS handshake failed before the coordinator smoke"
    printf '%s\n' "$alpn_output"
    rm -rf "$certificate_dir"
    exit 1
  fi
  if ! grep -q 'ALPN protocol: h2' <<<"$alpn_output"; then
    echo "::error::ingress TLS listener did not negotiate HTTP/2 with ALPN"
    printf '%s\n' "$alpn_output"
    rm -rf "$certificate_dir"
    exit 1
  fi

  KIND_COORDINATOR_URL="$KIND_INGRESS_TLS_URL" \
    KIND_COORDINATOR_DIRECT_URL="http://127.0.0.1:18092" \
    KIND_COORDINATOR_CA_DER="$certificate_der" \
    "$CARGO_CI_DIR/examples/coordinator-ingress-smoke"
  rm -rf "$certificate_dir"
}

exec_service_connect_smoke() {
  local environment_id="$1"
  log "running daemon-native ExecService Connect smoke and REST-retirement probe"
  local ascii_command ascii_connect_payload ascii_connect
  local invalid_command invalid_connect_payload invalid_connect

  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_DIRECT_BASE_URL=http://127.0.0.1:8084 \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/exec-stream-smoke"

  ascii_command="printf 'stdout\\n'; printf 'stderr\\n' >&2; exit 17"
  ascii_connect_payload="$(jq -cn \
    --arg org_id org_contract_1 \
    --arg environment_id "$environment_id" \
    --arg command "$ascii_command" \
    '{orgId:$org_id,environmentId:$environment_id,command:["sh","-c",$command]}')"

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "$ascii_connect_payload" \
    "${KIND_INGRESS_URL}/api/v1/organizations/org_contract_1/environments/${environment_id}/exec"
  if [ "$PROBE_CODE" != "404" ]; then
    echo "::error::retired authenticated REST exec returned ${PROBE_CODE}: ${PROBE_BODY}"
    return 1
  fi

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "$ascii_connect_payload" \
    "${KIND_INGRESS_URL}/codewire.v1.ExecService/Exec"
  if [ "$PROBE_CODE" != "200" ]; then
    echo "::error::Connect same-pod exec returned ${PROBE_CODE}: ${PROBE_BODY}"
    return 1
  fi
  if ! grep -qi '^x-codewire-service: codewire-orchestration' "$PROBE_HEADERS"; then
    echo "::error::ExecService did not reach codewire-orchestration"
    return 1
  fi
  ascii_connect="$PROBE_BODY"

  if ! jq -e \
    '.exitCode == 17 and .stdout == "c3Rkb3V0Cg==" and .stderr == "c3RkZXJyCg=="' \
    <<<"$ascii_connect" >/dev/null; then
    echo "::error::Connect Exec did not preserve stdout/stderr and exit status: ${ascii_connect}"
    return 1
  fi

  invalid_command="printf 'out\\377\\n'; printf 'err\\376\\n' >&2; exit 23"
  invalid_connect_payload="$(jq -cn \
    --arg org_id org_contract_1 \
    --arg environment_id "$environment_id" \
    --arg command "$invalid_command" \
    '{orgId:$org_id,environmentId:$environment_id,command:["sh","-c",$command]}')"

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "$invalid_connect_payload" \
    "${KIND_INGRESS_URL}/codewire.v1.ExecService/Exec"
  if [ "$PROBE_CODE" != "200" ]; then
    echo "::error::Connect invalid-byte exec returned ${PROBE_CODE}: ${PROBE_BODY}"
    return 1
  fi
  invalid_connect="$PROBE_BODY"

  if ! jq -e \
    '.exitCode == 23 and .stdout == "b3V0/wo=" and .stderr == "ZXJy/go="' \
    <<<"$invalid_connect" >/dev/null; then
    echo "::error::Connect Exec did not preserve exact stdout/stderr bytes: ${invalid_connect}"
    return 1
  fi

  log "daemon-native ExecService Connect semantics and REST retirement green"
}

environment_setup_terminal_smoke() (
  local environment_id=env-terminal-ticket-smoke
  local claim_name=sandbox-env-terminal-ticket-smoke
  local pod_name=sandbox-env-terminal-ticket-smoke
  local original_replicas pod_ip ready

  original_replicas="$(
    kubectl -n agent-sandbox-system get deploy/agent-sandbox-controller \
      -o jsonpath='{.spec.replicas}'
  )"
  if [[ ! "$original_replicas" =~ ^[0-9]+$ ]]; then
    echo "::error::agent-sandbox controller replica count is invalid: ${original_replicas:-missing}"
    return 1
  fi

  # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
  cleanup_terminal_fixture() {
    set +e
    kubectl -n "$SANDBOX_NS" delete sandboxclaim "$claim_name" \
      --ignore-not-found=true --wait=true >/dev/null
    kubectl -n "$NS" exec -i deploy/postgres -- \
      psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
DELETE FROM sandbox_environment_backend WHERE environment_id = '$environment_id';
DELETE FROM environments WHERE id = '$environment_id';
SQL
    kubectl -n "$SANDBOX_NS" delete pod "$pod_name" \
      --ignore-not-found=true --wait=true >/dev/null
    kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller \
      --replicas="$original_replicas" >/dev/null
    if [ "$original_replicas" -gt 0 ]; then
      kubectl -n agent-sandbox-system rollout status \
        deploy/agent-sandbox-controller --timeout=180s
    fi
  }
  trap cleanup_terminal_fixture EXIT

  log "proving a Connect-issued ticket opens the permanent raw terminal WebSocket"
  kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller --replicas=0
  if [ "$original_replicas" -gt 0 ]; then
    kubectl -n agent-sandbox-system wait pod -l app=agent-sandbox-controller \
      --for=delete --timeout=60s
  fi

  kubectl -n "$SANDBOX_NS" delete sandboxclaim "$claim_name" \
    --ignore-not-found=true --wait=true >/dev/null
  kubectl -n "$SANDBOX_NS" delete pod "$pod_name" \
    --ignore-not-found=true --wait=true >/dev/null
  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
DELETE FROM sandbox_environment_backend WHERE environment_id = '$environment_id';
DELETE FROM environments WHERE id = '$environment_id';
SQL

  kubectl_apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
  namespace: ${SANDBOX_NS}
  labels:
    codewire.sh/environment-id: ${environment_id}
    codewire.sh/type: workspace
spec:
  serviceAccountName: codewire-sandbox
  restartPolicy: Always
  containers:
    - name: workspace
      image: busybox:1.36
      imagePullPolicy: IfNotPresent
      command: ["sleep", "600"]
EOF
  kubectl -n "$SANDBOX_NS" wait "pod/${pod_name}" \
    --for=condition=Ready --timeout=60s
  pod_ip="$(
    kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.podIP}'
  )"
  if [ -z "$pod_ip" ]; then
    echo "::error::terminal fixture Pod has no IP"
    return 1
  fi

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
INSERT INTO environments (
  id, org_id, created_by, type, name, state, desired_state, preset_id,
  cpu_millicores, memory_mb, disk_gb,
  environment_operation_generation, state_changed_at, project_spec
)
VALUES (
  '$environment_id', 'org_contract_1', 'usr_contract_user', 'sandbox',
  'terminal-ticket-smoke', 'running', 'started', 'preset_contract_1',
  2000, 4096, 10, 1, NOW(),
  '{"schema_version":1,"working_directory":"/workspace"}'::jsonb
);

INSERT INTO sandbox_environment_backend (
  environment_id, namespace, pod_name, pod_ip,
  setup_owner_generation, setup_owner_activity_id, setup_owner_attempt,
  setup_owner_phase, setup_owner_status, setup_owner_pod_uid
)
VALUES (
  '$environment_id', '$SANDBOX_NS', '$pod_name', '$pod_ip',
  1, 'kind-terminal-ticket-smoke', 1, 0, 'claimed', NULL
);
SQL

  kubectl_apply -f - <<EOF
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${claim_name}
  namespace: ${SANDBOX_NS}
spec:
  warmPoolRef:
    name: kind-terminal-ready-fixture
EOF
  kubectl -n "$SANDBOX_NS" patch sandboxclaim "$claim_name" \
    --subresource=status --type=merge \
    -p '{"status":{"conditions":[{"lastTransitionTime":"2026-01-01T00:00:00Z","message":"Kind terminal fixture is ready","reason":"Ready","status":"True","type":"Ready"}]}}'
  ready="$(
    kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
  )"
  if [ "$ready" != "True" ]; then
    echo "::error::terminal fixture SandboxClaim Ready status is ${ready:-missing}"
    return 1
  fi

  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/environment-setup-smoke"
  log "EnvironmentSetupService ticket-to-WebSocket path green"
)

file_service_smoke() (
  local workspace_image
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  log "running daemon-native FileService client/server streaming and Connect contract smoke"
  local environment_id=env-crd-smoke
  local claim_name=sandbox-env-crd-smoke
  local daemon_pod=crd-smoke-workspace-daemon
  local gateway_token daemon_token original_replicas pod_ip pod_uid ready
  gateway_token="$(gateway_auth_token_for_environment "$environment_id")"
  daemon_token="$(daemon_auth_token_for_environment "$environment_id")"

  original_replicas="$(
    kubectl -n agent-sandbox-system get deploy/agent-sandbox-controller \
      -o jsonpath='{.spec.replicas}'
  )"
  if [[ ! "$original_replicas" =~ ^[0-9]+$ ]]; then
    echo "::error::agent-sandbox controller replica count is invalid: ${original_replicas:-missing}"
    return 1
  fi

  # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
  cleanup_file_service_binding() {
    set +e
    kubectl -n "$SANDBOX_NS" delete sandboxclaim "$claim_name" \
      --ignore-not-found=true --wait=true >/dev/null
    kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller \
      --replicas="$original_replicas" >/dev/null
    if [ "$original_replicas" -gt 0 ]; then
      kubectl -n agent-sandbox-system rollout status \
        deploy/agent-sandbox-controller --timeout=180s
    fi
  }
  trap cleanup_file_service_binding EXIT

  kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller --replicas=0
  if [ "$original_replicas" -gt 0 ]; then
    kubectl -n agent-sandbox-system wait pod -l app=agent-sandbox-controller \
      --for=delete --timeout=60s
  fi

  pod_ip="$(
    kubectl -n "$SANDBOX_NS" get pod "$daemon_pod" -o jsonpath='{.status.podIP}'
  )"
  pod_uid="$(
    kubectl -n "$SANDBOX_NS" get pod "$daemon_pod" -o jsonpath='{.metadata.uid}'
  )"
  if [ -z "$pod_ip" ] || [ -z "$pod_uid" ]; then
    echo "::error::file-service fixture Pod has no current IP/UID"
    return 1
  fi
  kubectl -n "$SANDBOX_NS" delete sandboxclaim "$claim_name" \
    --ignore-not-found=true --wait=true >/dev/null
  kubectl_apply -f - <<EOF
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${claim_name}
  namespace: ${SANDBOX_NS}
spec:
  warmPoolRef:
    name: kind-file-service-ready-fixture
EOF
  kubectl -n "$SANDBOX_NS" patch sandboxclaim "$claim_name" \
    --subresource=status --type=merge \
    -p "{\"status\":{\"sandbox\":{\"name\":\"${daemon_pod}\",\"podIPs\":[\"${pod_ip}\"]},\"conditions\":[{\"lastTransitionTime\":\"2026-01-01T00:00:00Z\",\"message\":\"Kind file-service fixture is ready\",\"reason\":\"Ready\",\"status\":\"True\",\"type\":\"Ready\"}]}}"
  ready="$(
    kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
  )"
  if [ "$ready" != "True" ]; then
    echo "::error::file-service fixture SandboxClaim Ready status is ${ready:-missing}"
    return 1
  fi

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
INSERT INTO environments (
  id, org_id, created_by, type, name, state, desired_state, preset_id,
  cpu_millicores, memory_mb, disk_gb,
  environment_operation_generation, state_changed_at, project_spec
)
VALUES (
  '$environment_id', 'org_contract_1', 'usr_contract_user', 'sandbox',
  'file-service-daemon', 'running', 'started', 'preset_contract_1',
  2000, 4096, 10, 1, NOW(),
  '{"schema_version":1,"working_directory":"/workspace"}'::jsonb
)
ON CONFLICT (id) DO UPDATE
SET state = 'running', desired_state = 'started', error_reason = NULL,
    environment_operation_generation = GREATEST(environments.environment_operation_generation, 1),
    state_changed_at = NOW();

INSERT INTO sandbox_environment_backend (
  environment_id, namespace, pod_name, pod_ip,
  setup_owner_generation, setup_owner_activity_id, setup_owner_attempt,
  setup_owner_phase, setup_owner_status, setup_owner_pod_uid
)
SELECT '$environment_id', '$SANDBOX_NS', '$daemon_pod', '$pod_ip',
       environment_operation_generation, 'kind-file-service-smoke', 1,
       0, 'claimed', NULL
FROM environments
WHERE id = '$environment_id'
ON CONFLICT (environment_id) DO UPDATE
SET namespace = EXCLUDED.namespace,
    pod_name = EXCLUDED.pod_name,
    pod_ip = EXCLUDED.pod_ip,
    setup_owner_generation = EXCLUDED.setup_owner_generation,
    setup_owner_activity_id = EXCLUDED.setup_owner_activity_id,
    setup_owner_attempt = EXCLUDED.setup_owner_attempt,
    setup_owner_phase = EXCLUDED.setup_owner_phase,
    setup_owner_status = EXCLUDED.setup_owner_status,
    setup_owner_pod_uid = EXCLUDED.setup_owner_pod_uid;
SQL

  environment_daemon_proxy_smoke "$environment_id" "$daemon_pod"
  exec_service_connect_smoke "$environment_id"
  platform_run_connect_smoke "$environment_id"
  environment_session_protocol_smoke "$environment_id"

  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_DIRECT_BASE_URL=http://127.0.0.1:8084 \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/file-service-smoke"

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
DELETE FROM sandbox_environment_backend
WHERE environment_id = '$environment_id';
DELETE FROM environments WHERE id = '$environment_id';
SQL
  kubectl -n "$SANDBOX_NS" delete sandboxclaim "$claim_name" \
    --ignore-not-found=true --wait=true >/dev/null
  kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller \
    --replicas="$original_replicas" >/dev/null
  if [ "$original_replicas" -gt 0 ]; then
    kubectl -n agent-sandbox-system rollout status \
      deploy/agent-sandbox-controller --timeout=180s
  fi
  trap - EXIT
  CRD_SMOKE_NAMESPACE="$SANDBOX_NS" \
    CRD_SMOKE_SERVER_NAMESPACE="$NS" \
    CRD_SMOKE_WORKSPACE_IMAGE="$workspace_image" \
    CRD_SMOKE_GATEWAY_TOKEN="$gateway_token" \
    CRD_SMOKE_DAEMON_AUTH_TOKEN="$daemon_token" \
    CRD_SMOKE_GATEWAY_PHASE=cleanup \
    CRD_SMOKE_LOCAL_GATEWAY=1 \
    "$CARGO_CI_DIR/crd-smoke"
  kubectl -n "$SANDBOX_NS" delete pod "$daemon_pod" --wait=true >/dev/null
  rm -rf "$GATEWAY_SMOKE_TMPDIR"
  log "daemon-native FileService streaming and black-box Connect contract green"
)

platform_run_connect_smoke() {
  local environment_id="$1"
  local certificate_dir certificate_pem

  log "running public Connect platform Run smoke through TLS ingress"
  certificate_dir="$(mktemp -d)"
  certificate_pem="$certificate_dir/ca.pem"
  kubectl -n "$NS" get secret/codewire-kind-ingress-ca \
    -o 'jsonpath={.data.ca\.crt}' | base64 --decode > "$certificate_pem"

  if ! SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_TLS_URL" \
    SMOKE_CA_CERT_FILE="$certificate_pem" \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_ACCESS_TOKEN=at_kind_connect_oidc_codewire_api \
    "$CARGO_CI_DIR/examples/platform-run-smoke"; then
    rm -rf "$certificate_dir"
    return 1
  fi
  rm -rf "$certificate_dir"
  log "public Connect platform Run pipe, PTY, and transport-loss behavior green"
}

warm_environment_session_http_upstream() {
  local base="${KIND_INGRESS_URL}/codewire.testing.v1.PingService/Ping"
  local i

  log "warming the ordinary orchestration HTTP/Connect upstream before native gRPC"
  for i in $(seq 1 24); do
    curl_settled -X POST \
      -H 'content-type: application/json' \
      -H 'authorization: Bearer at_kind_connect_oidc_codewire_api' \
      -d '{"message":"whoami"}' \
      "$base"
    if [ "$PROBE_CODE" != "200" ] \
        || [ "$PROBE_BODY" != '{"message":"usr_contract_user"}' ]; then
      echo "::error::ordinary orchestration upstream warm ${i}/24 failed: code=${PROBE_CODE} body=${PROBE_BODY}"
      return 1
    fi
  done
  log "ordinary orchestration HTTP/Connect upstream warm green"
}

assert_environment_session_grpc_service_upstream() {
  local service_ip pod_ips controller_logs matching_lines i pod_ip

  service_ip="$(
    kubectl -n "$NS" get service/codewire-orchestration-grpc \
      -o jsonpath='{.spec.clusterIP}'
  )"
  if [ -z "$service_ip" ] || [ "$service_ip" = "None" ]; then
    echo "::error::codewire-orchestration-grpc has no usable ClusterIP"
    return 1
  fi

  matching_lines=""
  controller_logs=""
  for i in $(seq 1 15); do
    controller_logs="$(
      kubectl -n ingress-nginx logs deploy/ingress-nginx-controller --since=10m
    )"
    matching_lines="$(
      printf '%s\n' "$controller_logs" \
        | grep -F '/codewire.v1.EnvironmentSessionService/LaunchSession' \
        || true
    )"
    if [ -n "$matching_lines" ]; then
      break
    fi
    sleep 1
  done
  if [ -z "$matching_lines" ]; then
    echo "::error::ingress-nginx recorded no EnvironmentSessionService LaunchSession upstream"
    printf '%s\n' "$controller_logs" | tail -n 40
    return 1
  fi
  if ! grep -Fq "${service_ip}:8084" <<<"$matching_lines"; then
    echo "::error::EnvironmentSessionService gRPC ingress did not use Service ClusterIP ${service_ip}:8084"
    printf '%s\n' "$matching_lines"
    return 1
  fi

  pod_ips="$(
    kubectl -n "$NS" get pods \
      -l app.kubernetes.io/name=codewire,app.kubernetes.io/component=orchestration \
      -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}'
  )"
  while IFS= read -r pod_ip; do
    if [ -n "$pod_ip" ] && grep -Fq "${pod_ip}:8084" <<<"$matching_lines"; then
      echo "::error::EnvironmentSessionService gRPC ingress reused orchestration pod endpoint ${pod_ip}:8084"
      printf '%s\n' "$matching_lines"
      return 1
    fi
  done <<<"$pod_ips"

  log "EnvironmentSessionService gRPC ingress upstream is isolated at Service ClusterIP ${service_ip}:8084"
}

environment_session_protocol_smoke() {
  local environment_id="$1"
  local certificate_dir certificate_pem

  log "running EnvironmentSessionService direct Connect + public native-gRPC smoke"
  certificate_dir="$(mktemp -d)"
  certificate_pem="$certificate_dir/ca.pem"
  kubectl -n "$NS" get secret/codewire-kind-ingress-ca \
    -o 'jsonpath={.data.ca\.crt}' | base64 --decode > "$certificate_pem"

  if ! SMOKE_SESSION_BASE_URL=http://127.0.0.1:8084 \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_ACCESS_TOKEN=at_kind_connect_oidc_codewire_api \
    "$CARGO_CI_DIR/examples/environment-session-smoke"; then
    rm -rf "$certificate_dir"
    return 1
  fi

  warm_environment_session_http_upstream || {
    rm -rf "$certificate_dir"
    return 1
  }

  if ! SMOKE_SESSION_BASE_URL="$KIND_INGRESS_TLS_URL" \
    SMOKE_CA_CERT_FILE="$certificate_pem" \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_ACCESS_TOKEN=at_kind_connect_oidc_codewire_api \
    "$CARGO_CI_DIR/examples/environment-session-smoke"; then
    rm -rf "$certificate_dir"
    return 1
  fi
  if ! assert_environment_session_grpc_service_upstream; then
    rm -rf "$certificate_dir"
    return 1
  fi
  rm -rf "$certificate_dir"
  log "EnvironmentSessionService direct Connect + public native-gRPC output/list/logs/exit proof green"
}

environment_daemon_proxy_smoke() {
  local environment_id="$1" pod_name="$2"
  local base="${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/GetEnvironmentDaemonStatus"

  log "running authenticated environment-daemon proxy smoke"
  curl_settled -X POST -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\"}" \
    "$base"
  if [ "$PROBE_CODE" != "401" ] \
      || ! printf '%s' "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
    echo "::error::unauthenticated daemon status bypassed product auth: code=$PROBE_CODE body=$PROBE_BODY"
    return 1
  fi

  curl_settled -X POST -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\"}" \
    "$base"
  if [ "$PROBE_CODE" != "200" ] \
      || ! printf '%s' "$PROBE_BODY" | jq -e \
        --arg pod_name "$pod_name" '
          .status.state == "ENVIRONMENT_DAEMON_STATE_READY"
          and .status.protocolVersion == 1
          and .status.minimumProtocolVersion == 1
          and .status.podName == $pod_name
          and (.status.capabilities | index("health.v1") != null)
          and (.status.capabilities | index("sessions.v1") != null)
          and (.status.capabilities | index("attach.v1") != null)
        ' >/dev/null; then
    echo "::error::authenticated daemon status did not cross the in-cluster proxy: code=$PROBE_CODE body=$PROBE_BODY"
    return 1
  fi
  if printf '%s' "$PROBE_BODY" | grep -qi 'token'; then
    echo "::error::public daemon status exposed credential-shaped data: $PROBE_BODY"
    return 1
  fi
  log "authenticated environment-daemon proxy and credential non-exposure green"
}

deploy_agent_sandbox() {
  log "deploying agent-sandbox controller and CRDs"
  kubectl_apply --validate=false -f "$(render_agent_sandbox_manifest)"
  kubectl wait --for=condition=established --timeout=60s \
    crd/sandboxclaims.extensions.agents.x-k8s.io
  kubectl -n agent-sandbox-system rollout status deploy/agent-sandbox-controller --timeout=180s
}

workspace_service_smokes() {
  gateway_host_key_restart_smoke

  log "running workspace exec smoke"
  SMOKE_NAMESPACE="$SANDBOX_NS" "$CARGO_CI_DIR/exec-smoke"
  environment_setup_terminal_smoke
  file_service_smoke
  environment_resize_smoke
}

environment_resize_smoke() (
  log "running public environment resize against the agent-sandbox controller"
  local environment_id
  environment_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  local request_id="kind-resize-${RANDOM}-${RANDOM}"
  local preset_id="preset-${environment_id}"
  local template_name="resize-template-${environment_id}"
  local shadow_pool_name="shadow-pool-resize-template-${environment_id}"
  local claim_name="sandbox-${environment_id}"
  local daemon_service="cw-daemon-${environment_id}"
  local daemon_token sandbox_name old_pod_uid new_pod_uid old_restart_count new_restart_count pod_name pod_ip pvc_name pvc_uid
  local operation_id operation_state response runtime_state marker image resources
  daemon_token="$(daemon_auth_token_for_environment "$environment_id")"

  # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
  cleanup_environment_resize_smoke() {
    local status=$?
    trap - EXIT
    set +e
    kubectl -n "$NS" exec -i deploy/postgres -- \
      psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
BEGIN;
DELETE FROM sandbox_environment_backend WHERE environment_id = '$environment_id';
DELETE FROM environments WHERE id = '$environment_id';
DELETE FROM environment_presets WHERE id = '$preset_id' AND org_id = 'org_contract_1';
COMMIT;
SQL
    [ "$?" -eq 0 ] || status=1
    # Runtime identity reconciliation creates the ordinary gateway stack.
    # Stop its Deployment and issuer request before deleting either leaf key;
    # never delete the shared fixture Issuers or public root ConfigMaps.
    if kubectl -n "$SANDBOX_NS" delete \
      "sandboxclaim/$claim_name" "sandboxwarmpool/$shadow_pool_name" \
      "sandboxtemplate/$template_name" "service/$daemon_service" \
      "deployment/cw-gateway-$environment_id" \
      "service/cw-gateway-svc-$environment_id" "service/cw-gateway-udp-$environment_id" \
      "networkpolicy/cw-gw-net-$environment_id" "networkpolicy/cw-daemon-net-$environment_id" \
      "certificate/cw-credential-gateway-$environment_id" \
      --ignore-not-found=true --cascade=foreground --wait=true --timeout=120s >/dev/null; then
      kubectl -n "$SANDBOX_NS" delete \
        "secret/cw-gateway-host-key-$environment_id" \
        "secret/cw-credential-gateway-$environment_id" \
        "configmap/cw-credential-codex-$environment_id" \
        --ignore-not-found=true --wait=true --timeout=120s >/dev/null || status=1
    else
      status=1
    fi
    exit "$status"
  }
  trap cleanup_environment_resize_smoke EXIT

  kubectl_apply -f - <<EOF
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxTemplate
metadata:
  name: ${template_name}
  namespace: ${SANDBOX_NS}
spec:
  networkPolicy:
    ingress:
      - from:
          - namespaceSelector:
              matchLabels:
                kubernetes.io/metadata.name: ${NS}
            podSelector:
              matchLabels:
                app.kubernetes.io/name: codewire
                app.kubernetes.io/component: orchestration
        ports:
          - protocol: TCP
            port: 7777
  podTemplate:
    metadata:
      labels:
        codewire.sh/environment-id: ${environment_id}
        codewire.sh/type: workspace
        codewire.sh/resize-smoke-marker: preserved
    spec:
      restartPolicy: Never
      serviceAccountName: codewire-sandbox
      containers:
        - name: workspace
          image: codewire-gateway:e2e
          imagePullPolicy: Never
          command: ["/usr/local/bin/cw", "__hosted-daemon"]
          env:
            - name: CODEWIRE_WORKSPACE_SHIM_ADDR
              value: 0.0.0.0:7777
            - name: CODEWIRE_DAEMON_AUTH_TOKEN
              value: ${daemon_token}
            - name: CODEWIRE_RESIZE_SMOKE_IDENTITY
              value: preserved
          ports:
            - name: daemon
              containerPort: 7777
          readinessProbe:
            tcpSocket:
              port: 7777
            periodSeconds: 1
            timeoutSeconds: 1
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: 250m
              memory: 256Mi
          resizePolicy:
            - resourceName: cpu
              restartPolicy: NotRequired
            - resourceName: memory
              restartPolicy: NotRequired
          volumeMounts:
            - name: workspace
              mountPath: /workspace
  volumeClaimTemplates:
    - metadata:
        name: workspace
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: standard
        resources:
          requests:
            storage: 1Gi
---
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxWarmPool
metadata:
  name: ${shadow_pool_name}
  namespace: ${SANDBOX_NS}
  labels:
    codewire.sh/environment-id: ${environment_id}
    codewire.sh/type: sandbox-claim-shadow
spec:
  replicas: 0
  sandboxTemplateRef:
    name: ${template_name}
---
apiVersion: v1
kind: Service
metadata:
  name: ${daemon_service}
  namespace: ${SANDBOX_NS}
spec:
  selector:
    codewire.sh/environment-id: ${environment_id}
    codewire.sh/type: workspace
  ports:
    - name: daemon
      port: 7777
      targetPort: 7777
EOF

  kubectl_apply -f - <<EOF
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${claim_name}
  namespace: ${SANDBOX_NS}
  labels:
    codewire.sh/environment-id: ${environment_id}
    codewire.sh/org-id: org_contract_1
    codewire.sh/type: sandbox
spec:
  warmPoolRef:
    name: ${shadow_pool_name}
  additionalPodMetadata:
    labels:
      codewire.sh/environment-id: ${environment_id}
      codewire.sh/type: workspace
      codewire.sh/resize-smoke-marker: preserved
  workspaceResources:
    - containerName: workspace
      resources:
        requests:
          cpu: 250m
          memory: 256Mi
        limits:
          cpu: 250m
          memory: 256Mi
EOF
  kubectl -n "$SANDBOX_NS" wait "sandboxclaim/${claim_name}" \
    --for=condition=Ready --timeout=180s
  sandbox_name="$(kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" \
    -o jsonpath='{.status.sandbox.name}')"
  if [ -z "$sandbox_name" ]; then
    echo "::error::resize smoke claim did not resolve a Sandbox"
    return 1
  fi
  pod_name="$sandbox_name"
  kubectl -n "$SANDBOX_NS" wait "pod/${pod_name}" \
    --for=condition=Ready --timeout=180s
  old_pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}')"
  old_restart_count="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.containerStatuses[?(@.name=="workspace")].restartCount}')"
  pod_ip="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.podIP}')"
  pvc_name="workspace-${sandbox_name}"
  kubectl -n "$SANDBOX_NS" wait "pvc/${pvc_name}" \
    --for=jsonpath='{.status.phase}'=Bound --timeout=120s
  pvc_uid="$(kubectl -n "$SANDBOX_NS" get pvc "$pvc_name" -o jsonpath='{.metadata.uid}')"
  kubectl -n "$SANDBOX_NS" exec "$pod_name" -c workspace -- \
    sh -ceu 'printf codewire-resize-data > /workspace/resize-smoke-marker'

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
BEGIN;
-- A runnable fixture owns its own preset. The shared contract preset is
-- deliberately missing runtime configuration for the Temporal failure test.
INSERT INTO environment_presets (id, org_id, name, official, project_spec)
VALUES ('$preset_id', 'org_contract_1', '$preset_id', false,
        '{"schema_version":1,"image":"codewire-gateway:e2e","working_directory":"/workspace"}'::jsonb);
INSERT INTO sandbox_template_config (preset_id, image_ref, sandbox_template_name)
VALUES ('$preset_id', 'codewire-gateway:e2e', 'resize-template');
INSERT INTO environments (
  id, org_id, created_by, type, name, state, desired_state, preset_id,
  cpu_millicores, memory_mb, disk_gb,
  state_changed_at, project_spec
)
VALUES (
  '$environment_id', 'org_contract_1', 'usr_contract_admin', 'sandbox',
  'kind-resize-smoke', 'running', 'started', '$preset_id',
  250, 256, 1, NOW(),
  '{"schema_version":1,"working_directory":"/workspace"}'::jsonb
);
INSERT INTO sandbox_environment_backend (
  environment_id, namespace, sandbox_claim_name, sandbox_claim_uid, pod_name, pod_ip
)
VALUES (
  '$environment_id', '$SANDBOX_NS', '$claim_name',
  '$(kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" -o jsonpath='{.metadata.uid}')',
  '$pod_name', '$pod_ip'
);
COMMIT;
SQL

  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\",\"cpuMillicores\":500,\"memoryMb\":512,\"diskGb\":1,\"requestId\":\"${request_id}\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/ResizeEnvironment"
  if [ "$PROBE_CODE" != "200" ]; then
    echo "::error::public resize request failed: code=$PROBE_CODE body=$PROBE_BODY"
    return 1
  fi
  operation_id="$(jq -r '.operation.id // empty' <<<"$PROBE_BODY")"
  if [ -z "$operation_id" ]; then
    echo "::error::public resize response omitted operation identity: $PROBE_BODY"
    return 1
  fi

  operation_state=""
  for _ in $(seq 1 180); do
    curl_settled -X POST \
      -H 'cookie: codewire.session_token=contract-admin-session-token' \
      -H 'content-type: application/json' \
      -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\",\"operationId\":\"${operation_id}\"}" \
      "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/GetEnvironmentResizeOperation"
    if [ "$PROBE_CODE" != "200" ]; then
      echo "::error::resize operation poll failed: code=$PROBE_CODE body=$PROBE_BODY"
      return 1
    fi
    response="$PROBE_BODY"
    operation_state="$(jq -r '.operation.state // empty' <<<"$response")"
    case "$operation_state" in
      ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED) break ;;
      ENVIRONMENT_RESIZE_OPERATION_STATE_FAILED)
        echo "::error::resize operation failed: $response"
        return 1
        ;;
    esac
    sleep 1
  done
  if [ "$operation_state" != "ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED" ]; then
    echo "::error::resize operation did not complete: state=${operation_state:-missing} body=$response"
    return 1
  fi
  if ! jq -e '
      .operation.previousResources == {"cpuMillicores":250,"memoryMb":256,"diskGb":1}
      and .operation.desiredResources == {"cpuMillicores":500,"memoryMb":512,"diskGb":1}
      and .operation.lastAppliedResources == {"cpuMillicores":500,"memoryMb":512,"diskGb":1}
      and .operation.appliedMode == "ENVIRONMENT_RESIZE_EXECUTION_MODE_IN_PLACE"
      and (.operation.podReplaced // false) == false
      and .environment.cpuMillicores == 500
      and .environment.memoryMb == 512
      and .environment.diskGb == 1
    ' <<<"$response" >/dev/null; then
    echo "::error::resize terminal response did not preserve exact resources: $response"
    return 1
  fi

  pod_name="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire -Atc \
      "SELECT pod_name FROM sandbox_environment_backend WHERE environment_id = '$environment_id'")"
  new_pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}')"
  new_restart_count="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.containerStatuses[?(@.name=="workspace")].restartCount}')"
  if [ -z "$new_pod_uid" ] || [ "$new_pod_uid" != "$old_pod_uid" ]; then
    echo "::error::live resize replaced the owned workspace Pod UID"
    return 1
  fi
  if [ "$new_restart_count" != "$old_restart_count" ]; then
    echo "::error::live resize changed workspace restart count: before=$old_restart_count after=$new_restart_count"
    return 1
  fi
  runtime_state="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire -Atc \
      "SELECT state || ':' || cpu_millicores || ':' || memory_mb || ':' || disk_gb FROM environments WHERE id = '$environment_id'")"
  if [ "$runtime_state" != "running:500:512:1" ]; then
    echo "::error::resize durable resource state is ${runtime_state:-missing}"
    return 1
  fi
  resources="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" \
    -o jsonpath='{.spec.containers[?(@.name=="workspace")].resources.requests.cpu}:{.spec.containers[?(@.name=="workspace")].resources.requests.memory}')"
  image="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" \
    -o jsonpath='{.spec.containers[?(@.name=="workspace")].image}')"
  marker="$(kubectl -n "$SANDBOX_NS" exec "$pod_name" -c workspace -- \
    sh -ceu 'cat /workspace/resize-smoke-marker')"
  if [ "$resources" != "500m:512Mi" ] || [ "$image" != "codewire-gateway:e2e" ] \
      || [ "$marker" != "codewire-resize-data" ]; then
    echo "::error::live-resized Pod lost resources/image/data: resources=$resources image=$image marker=$marker"
    return 1
  fi
  if [ "$(kubectl -n "$SANDBOX_NS" get pvc "$pvc_name" -o jsonpath='{.metadata.uid}')" != "$pvc_uid" ]; then
    echo "::error::workspace PVC identity changed across resize"
    return 1
  fi
  if [ "$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.labels.codewire\.sh/resize-smoke-marker}')" != "preserved" ]; then
    echo "::error::live-resized Pod lost the resize identity label"
    return 1
  fi
  if [ "$(kubectl -n "$SANDBOX_NS" get sandbox "$sandbox_name" -o jsonpath='{.spec.podTemplate.spec.containers[?(@.name=="workspace")].resources.requests.cpu}')" != "500m" ] \
      || [ "$(kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" -o jsonpath='{.spec.workspaceResources[?(@.containerName=="workspace")].resources.requests.cpu}')" != "500m" ]; then
    echo "::error::Sandbox or SandboxClaim did not retain the desired resize"
    return 1
  fi

  # A restart-class plan queries the daemon to enforce the active-session
  # policy. The in-place Pod /resize acknowledgement precedes Service endpoint
  # reconciliation, so prove the existing daemon is ready before exercising
  # that subsequent public request.
  local daemon_endpoints=""
  for _ in $(seq 1 120); do
    daemon_endpoints="$(kubectl -n "$SANDBOX_NS" get endpoints "$daemon_service" \
      -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)"
    if [ -n "$daemon_endpoints" ]; then
      break
    fi
    sleep 1
  done
  if [ -z "$daemon_endpoints" ]; then
    echo "::error::live-resized workspace daemon did not regain a ready Service endpoint"
    return 1
  fi

  # Memory shrink is intentionally disruptive. Prove that explicit consent
  # replaces only the Pod while preserving the PVC and workspace data.
  request_id="${request_id}-restart"
  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\",\"cpuMillicores\":500,\"memoryMb\":384,\"diskGb\":1,\"requestId\":\"${request_id}\",\"disruptionPolicy\":\"ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/ResizeEnvironment"
  if [ "$PROBE_CODE" != "200" ]; then
    echo "::error::explicit restart resize request failed: code=$PROBE_CODE body=$PROBE_BODY"
    return 1
  fi
  operation_id="$(jq -r '.operation.id // empty' <<<"$PROBE_BODY")"
  operation_state=""
  for _ in $(seq 1 180); do
    curl_settled -X POST \
      -H 'cookie: codewire.session_token=contract-admin-session-token' \
      -H 'content-type: application/json' \
      -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\",\"operationId\":\"${operation_id}\"}" \
      "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/GetEnvironmentResizeOperation"
    response="$PROBE_BODY"
    operation_state="$(jq -r '.operation.state // empty' <<<"$response")"
    case "$operation_state" in
      ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED) break ;;
      ENVIRONMENT_RESIZE_OPERATION_STATE_FAILED)
        echo "::error::explicit restart resize failed: $response"
        return 1
        ;;
    esac
    sleep 1
  done
  if [ "$operation_state" != "ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED" ] \
      || ! jq -e '.operation.appliedMode == "ENVIRONMENT_RESIZE_EXECUTION_MODE_RESTART" and .operation.podReplaced == true' <<<"$response" >/dev/null; then
    echo "::error::explicit restart was not recorded accurately: $response"
    return 1
  fi
  pod_name="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire -Atc \
      "SELECT pod_name FROM sandbox_environment_backend WHERE environment_id = '$environment_id'")"
  new_pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}')"
  if [ -z "$new_pod_uid" ] || [ "$new_pod_uid" = "$old_pod_uid" ]; then
    echo "::error::explicit restart did not replace the workspace Pod"
    return 1
  fi
  if [ "$(kubectl -n "$SANDBOX_NS" get pvc "$pvc_name" -o jsonpath='{.metadata.uid}')" != "$pvc_uid" ] \
      || [ "$(kubectl -n "$SANDBOX_NS" exec "$pod_name" -c workspace -- sh -ceu 'cat /workspace/resize-smoke-marker')" != "codewire-resize-data" ]; then
    echo "::error::explicit restart failed to preserve PVC identity or workspace data"
    return 1
  fi

  local as_user="system:serviceaccount:${NS}:codewire-orchestration"
  if [ "$(kubectl auth can-i get storageclasses.storage.k8s.io --as "$as_user")" != "yes" ] \
      || [ "$(kubectl auth can-i patch persistentvolumeclaims --namespace "$SANDBOX_NS" --as "$as_user")" != "yes" ]; then
    echo "::error::orchestration resize RBAC is incomplete"
    return 1
  fi
  log "public live resize preserved Pod identity; explicit restart preserved PVC identity and data"
)

temporal_workflow_smoke() {
  log "running Temporal workflow smoke"
  local env_id state reason
  env_id="env-temporal-kind-$RANDOM"
  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
INSERT INTO environments (id, org_id, created_by, type, state, desired_state,
                          cpu_millicores, memory_mb, disk_gb, preset_id,
                          project_spec)
VALUES ('$env_id', 'org_contract_1', 'usr_contract_admin', 'sandbox', 'pending', 'started',
        2000, 4096, 10, 'preset_contract_1',
        '{"schema_version":1,"working_directory":"/workspace"}'::jsonb);
SQL
  if ! DATABASE_URL="$KIND_DATABASE_URL" \
    SMOKE_ENV_ID="$env_id" "$CARGO_CI_DIR/temporal-smoke"; then
    kubectl -n "$NS" logs deploy/codewire-orchestration --tail=80 || true
    kubectl -n "$NS" logs deploy/temporal --tail=50 || true
    exit 1
  fi
  state="$(kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -tAc "SELECT state FROM environments WHERE id = '$env_id'")"
  reason="$(kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -tAc "SELECT error_reason FROM environments WHERE id = '$env_id'")"
  echo "temporal smoke env state=$state reason=$reason"
  if [ "$state" != "error" ] || [[ "$reason" != template\ config:* ]]; then
    echo "::error::expected error state with template-config reason from in-cluster worker"
    exit 1
  fi
}

temporal_fencing_smoke() {
  local workspace_image
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  log "running final Temporal activity-fencing smoke"
  DATABASE_URL="$KIND_DATABASE_URL" \
    TEMPORAL_ADDRESS="http://127.0.0.1:7233" \
    SMOKE_ORCHESTRATION_URL="http://127.0.0.1:8084" \
    SMOKE_WORKSPACE_IMAGE="$workspace_image" \
    "$CARGO_CI_DIR/temporal-fencing-smoke"
}

deploy_agent_sandbox_and_smoke() {
  deploy_agent_sandbox
  kind_credential_bootstrap_smoke
  kind_credential_native_smoke
  workspace_service_smokes
  temporal_workflow_smoke
  mark_retained_cluster_prepared
  temporal_fencing_smoke
}

assert_sandbox_supply_chain() {
  local service_account pods templates events workspace_image dind_image configured_dind_image

  log "verifying sandbox service-account and runtime-image provenance"
  service_account="$(kubectl -n "$SANDBOX_NS" get serviceaccount/codewire-sandbox -o json)"
  if ! jq -e '.automountServiceAccountToken == false' \
      <<<"$service_account" >/dev/null; then
    echo "::error::sandbox service account permits Kubernetes API token automount"
    return 1
  fi

  workspace_image="$(kind_workspace_runtime_image)" || return $?
  dind_image="$(kind_dind_runtime_image)"
  configured_dind_image="$(kubectl -n "$NS" get configmap/codewire-config \
    -o jsonpath='{.data.SANDBOX_DIND_IMAGE}')"
  if [ "$configured_dind_image" != "$dind_image" ]; then
    echo "::error::Kind orchestration DinD input does not match the accepted runtime image"
    return 1
  fi
  pods="$(kubectl get pods -A -o json)"
  if ! jq -e --arg workspace "$workspace_image" --arg dind "$dind_image" '
    def workspace_image:
      startswith("ghcr.io/codewiresh/workspace:") or
      startswith("ghcr.io/codewiresh/workspace@") or
      startswith("nexus.example.invalid/oci-approved/codewire/workspace@") or
      startswith("localhost/codewire-ci/workspace:");
    def dind_image:
      startswith("ghcr.io/codewiresh/" + "dind") or
      startswith("docker:" + "dind") or
      startswith("docker.io/library/docker:") or
      startswith("docker.io/library/docker@") or
      startswith("nexus.example.invalid/oci-approved/docker/dind@") or
      startswith("localhost/codewire-ci/docker-dind:");
    [
      .items[]
      | ((.spec.initContainers // []) + (.spec.containers // []))[]
      | .image
    ]
    | all(.[];
        if workspace_image then . == $workspace
        elif dind_image then . == $dind
        else true
        end)
  ' <<<"$pods" >/dev/null; then
    echo "::error::Kind pod spec contains an unaccepted workspace or DinD image reference"
    jq -r '
      .items[]
      | ((.spec.initContainers // []) + (.spec.containers // []))[]
      | .image
      | select(startswith("ghcr.io/codewiresh/workspace") or
               startswith("ghcr.io/codewiresh/" + "dind") or
               startswith("docker:" + "dind") or
               startswith("docker.io/library/docker") or
               startswith("nexus.example.invalid/oci-approved/codewire/workspace@") or
               startswith("nexus.example.invalid/oci-approved/docker/dind@") or
               startswith("localhost/codewire-ci/workspace:") or
               startswith("localhost/codewire-ci/docker-dind:"))
    ' <<<"$pods" | LC_ALL=C sort -u >&2
    return 1
  fi

  templates="$(kubectl get sandboxtemplates -A -o json)"
  if ! jq -e --arg workspace "$workspace_image" --arg dind "$dind_image" '
    [.. | strings
      | select(startswith("ghcr.io/codewiresh/workspace") or
               startswith("ghcr.io/codewiresh/" + "dind") or
               startswith("docker:" + "dind") or
               startswith("docker.io/library/docker") or
               startswith("nexus.example.invalid/oci-approved/codewire/workspace@") or
               startswith("nexus.example.invalid/oci-approved/docker/dind@") or
               startswith("localhost/codewire-ci/workspace:") or
               startswith("localhost/codewire-ci/docker-dind:"))] as $images
    | ($images | index($workspace) != null)
      and ($images | all(. == $workspace or . == $dind))
  ' <<<"$templates" >/dev/null; then
    echo "::error::rendered SandboxTemplate contains an unaccepted workspace or DinD image reference"
    jq -r '[.. | strings
      | select(startswith("ghcr.io/codewiresh/workspace") or
               startswith("ghcr.io/codewiresh/" + "dind") or
               startswith("docker:" + "dind") or
               startswith("docker.io/library/docker") or
               startswith("nexus.example.invalid/oci-approved/codewire/workspace@") or
               startswith("nexus.example.invalid/oci-approved/docker/dind@") or
               startswith("localhost/codewire-ci/workspace:") or
               startswith("localhost/codewire-ci/docker-dind:"))] | unique[]' \
      <<<"$templates" >&2
    return 1
  fi

  events="$(kubectl get events -A -o json)"
  if ! jq -e '
    [
      .items[] as $event
      | select(
          (["ErrImagePull", "Failed", "FailedToRetrieveImagePullSecret", "ImagePullBackOff"]
            | index($event.reason)) != null and
          (($event.message // "")
            | test("(ghcr\\.io/codewiresh/(workspace|din[d])|docker:din[d]|docker\\.io/library/docker|nexus\\.example\\.invalid/oci-approved/(codewire/workspace|docker/dind)|localhost/codewire-ci/(workspace|docker-dind))"))
        )
      | $event
    ] | length == 0
  ' <<<"$events" >/dev/null; then
    echo "::error::Kind recorded a workspace or DinD image-provenance failure"
    jq -r '.items[]
      | select((.message // "")
          | test("(ghcr\\.io/codewiresh/(workspace|din[d])|docker:din[d]|docker\\.io/library/docker|nexus\\.example\\.invalid/oci-approved/(codewire/workspace|docker/dind)|localhost/codewire-ci/(workspace|docker-dind))"))
      | "\(.metadata.namespace // "default")/\(.involvedObject.name): \(.reason)"' \
      <<<"$events" >&2
    return 1
  fi

  log "sandbox token automount disabled and observed workspace/DinD references are immutable"
}

start_gateway_port_forward() {
  local label="$1"
  local log_file="$GATEWAY_SMOKE_TMPDIR/port-forward-${label}.log"
  local i

  stop_gateway_port_forward
  kubectl -n "$SANDBOX_NS" port-forward --address=127.0.0.1 \
    service/cw-gateway-svc-env-crd-smoke :2222 >"$log_file" 2>&1 &
  GATEWAY_PORT_FORWARD_PID=$!
  for i in $(seq 1 30); do
    GATEWAY_PORT_FORWARD_PORT="$(
      sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9][0-9]*\) -> 2222$/\1/p' \
        "$log_file" | sed -n '1p'
    )"
    if [ -n "$GATEWAY_PORT_FORWARD_PORT" ]; then
      return 0
    fi
    if ! kill -0 "$GATEWAY_PORT_FORWARD_PID" >/dev/null 2>&1; then
      echo "::error::gateway port-forward exited before becoming ready"
      sed -n '1,80p' "$log_file" >&2
      return 1
    fi
    sleep 1
  done
  echo "::error::gateway port-forward did not publish a local port"
  sed -n '1,80p' "$log_file" >&2
  return 1
}

capture_gateway_public_fingerprint() {
  local label="$1"
  local public_key=""
  local i

  start_gateway_port_forward "$label"
  for i in $(seq 1 30); do
    public_key="$(
      { ssh-keyscan -T 2 -t ed25519 -p "$GATEWAY_PORT_FORWARD_PORT" 127.0.0.1 \
          2>/dev/null || true; } | awk '$2 == "ssh-ed25519" { print; exit }'
    )"
    if [ -n "$public_key" ]; then
      break
    fi
    sleep 1
  done
  stop_gateway_port_forward
  if [ -z "$public_key" ]; then
    echo "::error::gateway did not present an Ed25519 SSH host key during ${label} probe"
    return 1
  fi
  GATEWAY_PUBLIC_FINGERPRINT="$(
    printf '%s\n' "$public_key" | ssh-keygen -lf - -E sha256 | awk '{ print $2 }'
  )"
  if [[ "$GATEWAY_PUBLIC_FINGERPRINT" != SHA256:* ]]; then
    echo "::error::gateway ${label} SSH fingerprint was malformed"
    return 1
  fi
}

gateway_host_key_restart_smoke() {
  local workspace_image
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  local daemon_pod=crd-smoke-workspace-daemon
  local gateway_deploy=cw-gateway-env-crd-smoke
  local host_key_secret=cw-gateway-host-key-env-crd-smoke
  local gateway_token daemon_token
  local before_fingerprint after_fingerprint before_uid after_uid

  log "running CRD round-trip and gateway host-key restart smoke"
  gateway_token="$(gateway_auth_token_for_environment env-crd-smoke)"
  daemon_token="$(daemon_auth_token_for_environment env-crd-smoke)"
  GATEWAY_SMOKE_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/codewire-kind-gateway.XXXXXX")"
  CRD_SMOKE_NAMESPACE="$SANDBOX_NS" \
    CRD_SMOKE_SERVER_NAMESPACE="$NS" \
    CRD_SMOKE_WORKSPACE_IMAGE="$workspace_image" \
    CRD_SMOKE_GATEWAY_TOKEN="$gateway_token" \
    CRD_SMOKE_DAEMON_AUTH_TOKEN="$daemon_token" \
    CRD_SMOKE_GATEWAY_PHASE=setup \
    CRD_SMOKE_LOCAL_GATEWAY=1 \
    "$CARGO_CI_DIR/crd-smoke"

  kubectl_apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${daemon_pod}
  namespace: ${SANDBOX_NS}
  labels:
    codewire.sh/environment-id: env-crd-smoke
    codewire.sh/type: workspace
spec:
  serviceAccountName: codewire-sandbox
  restartPolicy: Always
  containers:
    - name: codewire-daemon
      image: codewire-gateway:e2e
      imagePullPolicy: Never
      command: ["/usr/local/bin/cw", "__hosted-daemon"]
      env:
        - name: CODEWIRE_WORKSPACE_SHIM_ADDR
          value: 0.0.0.0:7777
        - name: CODEWIRE_DAEMON_AUTH_TOKEN
          value: ${daemon_token}
      readinessProbe:
        tcpSocket:
          port: 7777
        periodSeconds: 1
        timeoutSeconds: 1
      volumeMounts:
        - name: workspace
          mountPath: /home/codewire
        - name: workspace
          mountPath: /workspace
  volumes:
    - name: workspace
      emptyDir: {}
EOF
  kubectl -n "$SANDBOX_NS" wait "pod/${daemon_pod}" \
    --for=condition=Ready --timeout=120s
  kubectl -n "$SANDBOX_NS" rollout status "deployment/${gateway_deploy}" --timeout=180s

  before_uid="$(
    kubectl -n "$SANDBOX_NS" get secret "$host_key_secret" -o jsonpath='{.metadata.uid}'
  )"
  capture_gateway_public_fingerprint before-restart
  before_fingerprint="$GATEWAY_PUBLIC_FINGERPRINT"

  kubectl -n "$SANDBOX_NS" rollout restart "deployment/${gateway_deploy}" >/dev/null
  kubectl -n "$SANDBOX_NS" rollout status "deployment/${gateway_deploy}" --timeout=180s
  after_uid="$(
    kubectl -n "$SANDBOX_NS" get secret "$host_key_secret" -o jsonpath='{.metadata.uid}'
  )"
  capture_gateway_public_fingerprint after-restart
  after_fingerprint="$GATEWAY_PUBLIC_FINGERPRINT"

  if [ "$after_uid" != "$before_uid" ]; then
    echo "::error::gateway host-key Secret identity changed across gateway restart"
    return 1
  fi
  if [ "$after_fingerprint" != "$before_fingerprint" ]; then
    echo "::error::gateway SSH host-key fingerprint changed across gateway restart"
    return 1
  fi

  log "gateway host-key Secret identity and SSH fingerprint survived restart; retaining the stack for FileService"
}

billing_contract_through_ingress() {
  log "running configured Rust billing Connect contract through ingress"
  (
    cd "$ROOT"
    BILLING_BASE_URL="$KIND_INGRESS_URL" \
      BILLING_ADMIN_SESSION_TOKEN=contract-admin-session-token \
      BILLING_USER_SESSION_TOKEN=contract-user-session-token \
      BILLING_SEEDED=1 \
      BILLING_SKIP_HEALTH=1 \
      "$ROOT/scripts/ci/verify/run-host-rust-build.sh" cargo test --locked --profile ci -p codewire-billing \
        --test wire_contract configured_billing_wire_contract \
        -- --ignored --exact --nocapture | tee "$RUN_DIR/billing-contract.log"
    local passed_count
    passed_count="$(sed -nE \
      's/.*test result: ok\. ([0-9]+) passed.*/\1/p' \
      "$RUN_DIR/billing-contract.log" | tail -n 1)"
    if [ "$passed_count" != "1" ]; then
      echo "::error::configured Rust billing Connect contract reported ${passed_count:-no} passing tests; expected 1"
      exit 1
    fi
  )
}

rust_reconciler_ttl_e2e() {
  local workspace_image
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  log "running Rust reconciler TTL Kubernetes e2e"
  KIND_CLUSTER_NAME="$KIND_CLUSTER_NAME" \
    DATABASE_URL="$KIND_DATABASE_URL" \
    SMOKE_ORCHESTRATION_URL="http://127.0.0.1:8084" \
    SMOKE_SANDBOX_NAMESPACE="$SANDBOX_NS" \
    SMOKE_SESSION_TOKEN=contract-admin-session-token \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_WORKSPACE_IMAGE="$workspace_image" \
    "$CARGO_CI_DIR/reconciler-ttl-smoke"
}

host_key_authorization_smoke() {
  log "proving orchestration host-key RBAC and admission"
  local as_user="system:serviceaccount:${NS}:codewire-orchestration"
  local env_id="kind-authz-${RANDOM}-${RANDOM}"
  local secret_name="cw-gateway-host-key-${env_id}"
  local unrelated_name="kind-unrelated-${RANDOM}-${RANDOM}"
  local stderr
  AUTHZ_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/codewire-kind-authz.XXXXXX")"
  stderr="$AUTHZ_TMPDIR/stderr"

  expect_denied() {
    local label="$1" message="$2"
    shift 2
    if "$@" >"$stderr" 2>&1; then
      echo "::error::${label} unexpectedly succeeded"
      return 1
    fi
    if ! grep -Fq "$message" "$stderr"; then
      echo "::error::${label} failed outside the expected boundary"
      sed -n '1,80p' "$stderr" >&2
      return 1
    fi
  }

  host_key_manifest() {
    local namespace="$1" name="$2" environment_id="$3" managed_by="${4:-codewire}"
    cat <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: codewire-gateway
    app.kubernetes.io/component: gateway-host-key
    app.kubernetes.io/managed-by: ${managed_by}
    codewire.sh/environment-id: ${environment_id}
    codewire.sh/type: gateway-host-key
type: Opaque
stringData:
  host_ed25519: kind-e2e-synthetic-host-key
EOF
  }

  kubectl -n "$SANDBOX_NS" delete secret "$secret_name" "$unrelated_name" \
    --ignore-not-found >/dev/null

  local verb allowed
  for verb in get list watch update patch; do
    allowed="$(kubectl auth can-i "$verb" secrets -n "$SANDBOX_NS" --as "$as_user" || true)"
    if [ "$allowed" != "no" ]; then
      echo "::error::orchestration can-i ${verb} sandbox Secrets returned ${allowed}, want no"
      return 1
    fi
  done
  for verb in create delete; do
    allowed="$(kubectl auth can-i "$verb" secrets -n "$SANDBOX_NS" --as "$as_user" || true)"
    if [ "$allowed" != "yes" ]; then
      echo "::error::orchestration can-i ${verb} sandbox Secrets returned ${allowed}, want yes"
      return 1
    fi
    allowed="$(kubectl auth can-i "$verb" secrets -n "$NS" --as "$as_user" || true)"
    if [ "$allowed" != "no" ]; then
      echo "::error::orchestration can-i ${verb} application Secrets returned ${allowed}, want no"
      return 1
    fi
  done

  expect_denied "sandbox Secret read" "forbidden" \
    kubectl --as "$as_user" -n "$SANDBOX_NS" get secret "$secret_name"
  expect_denied "application Secret read" "forbidden" \
    kubectl --as "$as_user" -n "$NS" get secret codewire-secrets
  expect_denied "sandbox Secret list" "forbidden" \
    kubectl --as "$as_user" -n "$SANDBOX_NS" get secrets
  expect_denied "sandbox Secret patch" "forbidden" \
    kubectl --as "$as_user" -n "$SANDBOX_NS" patch secret "$secret_name" \
      --type=merge -p '{"metadata":{"labels":{"unexpected":"true"}}}'

  if ! host_key_manifest "$SANDBOX_NS" "$secret_name" "$env_id" |
      kubectl --as "$as_user" create -f - >/dev/null; then
    echo "::error::correctly shaped sandbox host-key Secret create was denied"
    return 1
  fi
  kubectl -n "$SANDBOX_NS" get secret "$secret_name" >/dev/null
  kubectl --as "$as_user" -n "$SANDBOX_NS" delete secret "$secret_name" >/dev/null

  if host_key_manifest "$NS" "$secret_name" "$env_id" |
      kubectl --as "$as_user" create -f - >"$stderr" 2>&1; then
    echo "::error::application namespace host-key Secret create unexpectedly succeeded"
    return 1
  fi
  grep -Fq "forbidden" "$stderr" || {
    echo "::error::application namespace create failed outside RBAC"
    sed -n '1,80p' "$stderr" >&2
    return 1
  }

  if host_key_manifest "$SANDBOX_NS" "$unrelated_name" "$env_id" |
      kubectl --as "$as_user" create -f - >"$stderr" 2>&1; then
    echo "::error::unrelated Secret create unexpectedly succeeded"
    return 1
  fi
  grep -Fq "may only create or delete gateway host-key Secrets" "$stderr" || {
    echo "::error::unrelated Secret create failed outside admission prefix enforcement"
    sed -n '1,80p' "$stderr" >&2
    return 1
  }

  if host_key_manifest "$SANDBOX_NS" "$secret_name" "$env_id" unexpected-manager |
      kubectl --as "$as_user" create -f - >"$stderr" 2>&1; then
    echo "::error::incorrectly labeled host-key Secret create unexpectedly succeeded"
    return 1
  fi
  grep -Fq "must retain the renderer's management labels" "$stderr" || {
    echo "::error::incorrect label fixture failed outside admission label enforcement"
    sed -n '1,80p' "$stderr" >&2
    return 1
  }

  kubectl -n "$SANDBOX_NS" create secret generic "$unrelated_name" \
    --from-literal=value=kind-e2e >/dev/null
  if kubectl --as "$as_user" -n "$SANDBOX_NS" delete secret "$unrelated_name" \
      >"$stderr" 2>&1; then
    echo "::error::unrelated Secret delete unexpectedly succeeded"
    return 1
  fi
  grep -Fq "may only create or delete gateway host-key Secrets" "$stderr" || {
    echo "::error::unrelated Secret delete failed outside admission prefix enforcement"
    sed -n '1,80p' "$stderr" >&2
    return 1
  }
  kubectl -n "$SANDBOX_NS" delete secret "$unrelated_name" >/dev/null
  rm -rf "$AUTHZ_TMPDIR"
  AUTHZ_TMPDIR=""
}
