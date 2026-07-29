#!/usr/bin/env bash
# Shared mechanics for the Rust product Kind suites. Source this file; invoke
# scripts/ci/verify/kind-e2e.sh as the stable entrypoint.
set -euo pipefail

export KIND_E2E_COMMON_LOADED=1
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)}"
CARGO_TARGET_DIR="$(
  "$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh" "$ROOT"
)"
export CARGO_TARGET_DIR
CARGO_CI_DIR="$CARGO_TARGET_DIR/ci"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
RUN_DIR="${RUN_DIR:-$ROOT/.tmp/codewire-kind-e2e-${KIND_CLUSTER_NAME}}"
mkdir -p "$RUN_DIR"
# Use the hostless HTTP server for the edge and transitional REST probes. The
# coordinator TLS ingress intentionally owns Host/SNI localhost below.
KIND_INGRESS_URL="${KIND_INGRESS_URL:-http://127.0.0.1:8090}"
KIND_INGRESS_TLS_URL="${KIND_INGRESS_TLS_URL:-https://localhost:10443}"
KEEP_KIND_CLUSTER="${KEEP_KIND_CLUSTER:-0}"
NS=codewire-e2e
SANDBOX_NS=dev-sandboxes
AUTHZ_TMPDIR=""
GATEWAY_SMOKE_TMPDIR=""
GATEWAY_PORT_FORWARD_PID=""
GATEWAY_PORT_FORWARD_PORT=""
GATEWAY_PUBLIC_FINGERPRINT=""
KIND_E2E_COMPATIBILITY_VERSION=1
KIND_E2E_PREPARED_CONFIGMAP=codewire-kind-e2e-prepared
RETAINED_KUBECONFIG=""

log() {
  printf '[kind-e2e] %s\n' "$*"
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
  kubectl --context "$context" -n "$NS" describe deploy/codewire-orchestration || true
  kubectl --context "$context" -n "$NS" describe deploy/codewire-coordinator || true
  kubectl --context "$context" -n "$NS" logs deploy/codewire-billing --tail=100 || true
  kubectl --context "$context" -n "$NS" logs deploy/codewire-orchestration --tail=160 || true
  kubectl --context "$context" -n "$NS" logs deploy/codewire-coordinator --tail=160 || true
  kubectl --context "$context" -n "$NS" get svc/codewire-coordinator-nodeport -o wide || true
  kubectl --context "$context" -n "$NS" logs deploy/temporal --tail=80 || true
  kubectl --context "$context" -n "$SANDBOX_NS" get sandboxclaim,sandbox,sandboxtemplate,sandboxwarmpool,pvc,pv -o wide || true
  kubectl --context "$context" -n "$SANDBOX_NS" describe sandboxclaim,sandbox,sandboxtemplate,sandboxwarmpool || true
  kubectl --context "$context" -n "$SANDBOX_NS" get events --sort-by=.lastTimestamp || true
  kubectl --context "$context" -n "$NS" get events --sort-by=.lastTimestamp || true
  kubectl --context "$context" -n ingress-nginx logs deploy/ingress-nginx-controller --tail=80 || true
  kubectl --context "$context" -n agent-sandbox-system logs -l app=agent-sandbox-controller --tail=160 --all-containers || true
}

cleanup() {
  local status=$?
  stop_gateway_port_forward
  if [ "$status" -ne 0 ]; then
    dump_cluster_state
  fi
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

  RETAINED_KUBECONFIG="$RUN_DIR/retained-kubeconfig"
  if ! kind get kubeconfig --name "$KIND_CLUSTER_NAME" >"$RETAINED_KUBECONFIG"; then
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
  local prepared_version prepared_cluster

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

  log "retained Kind cluster ${KIND_CLUSTER_NAME} accepted at compatibility version ${KIND_E2E_COMPATIBILITY_VERSION}"
}

mark_retained_cluster_prepared() {
  log "marking Kind cluster ${KIND_CLUSTER_NAME} prepared for retained suites"
  kubectl -n "$NS" create configmap "$KIND_E2E_PREPARED_CONFIGMAP" \
    --from-literal="compatibility_version=${KIND_E2E_COMPATIBILITY_VERSION}" \
    --from-literal="cluster-name=${KIND_CLUSTER_NAME}" \
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

daemon_auth_token_for_environment() {
  local environment_id="$1" secret payload encoded_payload signature
  secret="$(
    kubectl -n "$NS" get secret codewire-secrets \
      -o jsonpath='{.data.SESSION_SECRET}' | base64 --decode
  )"
  payload="$(printf '{"environment_id":"%s","scope":"coordinate"}' "$environment_id")"
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

kubectl_apply() {
  timeout "${KUBECTL_APPLY_TIMEOUT:-180s}" \
    kubectl --request-timeout="${KUBECTL_REQUEST_TIMEOUT:-30s}" apply "$@"
}

ingress_path_drift_check() {
  log "checking kind/base ingress routing drift"
  local billing_paths=(
    '/api/v1/admin/billing/catalog$'
    '/api/v1/admin/billing/catalog/(plans|prices|settings|subscription-migrations)'
    '/api/v1/billing/plans'
    '/api/v1/organizations/[^/]+/billing$'
    '/api/v1/organizations/[^/]+/billing/invoices'
    '/api/v1/organizations/[^/]+/billing/events'
    '/api/v1/organizations/[^/]+/billing/(checkout|portal|setup)'
    '/api/v1/organizations/[^/]+/environments/usage'
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
  log "building Rust services image"
  docker buildx build --load -f "$ROOT/deployments/docker/services.Dockerfile" -t codewire-services:e2e "$ROOT"
  docker image inspect codewire-services:e2e >/dev/null

  log "building Rust Mesh image"
  docker buildx build --load -f "$ROOT/deployments/docker/mesh.Dockerfile" -t codewire-mesh:e2e "$ROOT"
  docker image inspect codewire-mesh:e2e >/dev/null

  log "building Rust gateway image"
  docker buildx build --load -f "$ROOT/deployments/docker/gateway.Dockerfile" -t codewire-gateway:e2e "$ROOT"
  docker image inspect codewire-gateway:e2e >/dev/null

  log "building Rust kind smoke binaries"
  (
    cd "$ROOT"
    cargo build --profile ci -p codewire-orchestration --bin crd-smoke --bin environment-setup-smoke --bin exec-smoke --bin exec-stream-smoke --bin file-service-smoke --bin prepare-stream-smoke --bin log-stream-smoke --bin temporal-smoke --bin temporal-fencing-smoke --bin reconciler-ttl-smoke --bin sidecar-smoke --features kind-e2e
    cargo build --profile ci -p codewire-client --example platform-run-smoke --example environment-session-smoke
    cargo build --profile ci -p codewire-tailnet --example coordinator-ingress-smoke --features kind-e2e
    cargo build --profile ci -p codewire-gateway --bin coordinator-selector-smoke --features kind-e2e
  )
}

create_cluster() {
  if kind get clusters | grep -qx "$KIND_CLUSTER_NAME"; then
    log "deleting existing kind cluster ${KIND_CLUSTER_NAME}"
    kind delete cluster --name "$KIND_CLUSTER_NAME"
  fi

  log "checking Docker runtime for kind"
  docker version
  docker info --format 'Server={{.ServerVersion}} Driver={{.Driver}} CgroupDriver={{.CgroupDriver}} SecurityOptions={{json .SecurityOptions}}' || docker info || true

  log "creating kind cluster ${KIND_CLUSTER_NAME}"
  if ! kind create cluster --name "$KIND_CLUSTER_NAME" --config "$ROOT/tests/e2e/kind/kind-config.yaml" --wait 120s; then
    echo "::error::kind cluster creation failed. This gate needs a runner with a real privileged Docker runtime capable of starting kind node containers; rootless Podman/netavark runners are not sufficient."
    exit 1
  fi
}

load_images_into_kind() {
  log "loading images into kind"
  kind load docker-image --name "$KIND_CLUSTER_NAME" codewire-services:e2e
  kind load docker-image --name "$KIND_CLUSTER_NAME" codewire-mesh:e2e
  kind load docker-image --name "$KIND_CLUSTER_NAME" codewire-gateway:e2e
}

deploy_overlay() {
  log "deploying vendored ingress-nginx"
  kubectl_apply --validate=false -f "$ROOT/tests/e2e/kind/vendor/ingress-nginx-deploy.yaml"
  kubectl wait --namespace ingress-nginx \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/component=controller \
    --timeout=180s

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
  local applied=0
  for i in $(seq 1 12); do
    if kubectl_apply --validate=false -k "$ROOT/tests/e2e/kind"; then
      applied=1
      break
    fi
    echo "kubectl apply failed; retry ${i}/12 in 5s"
    sleep 5
  done
  if [ "$applied" != "1" ]; then
    echo "::error::kubectl apply -k tests/e2e/kind did not succeed"
    exit 1
  fi
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

  log "starting billing, primary authorization, Mesh, and coordinator (dependencies ready)"
  kubectl -n "$NS" scale \
    deploy/codewire-billing \
    deploy/codewire-mesh \
    deploy/codewire-orchestration \
    deploy/codewire-coordinator \
    --replicas=1
  kubectl -n "$NS" rollout status deploy/codewire-billing --timeout=300s
  kubectl -n "$NS" rollout status deploy/codewire-orchestration --timeout=300s
  kubectl -n "$NS" rollout status deploy/codewire-mesh --timeout=300s
  kubectl -n "$NS" rollout status deploy/codewire-coordinator --timeout=300s
}

mesh_product_connect_ownership_smoke() {
  log "proving Mesh primary-origin REST/Connect parity and private HMAC authorization"
  local api_key='cw_c0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de'
  local network_id='mesh-kind-owned'
  local session_network_id='mesh-kind-session'
  local invite_network_id='mesh-kind-invite'

  wait_edge_upstream mesh-networks "/api/v1/networks?org_id=org_contract_1" 401

  curl_settled -X POST \
    -H "authorization: Bearer ${api_key}" \
    -H 'content-type: application/json' \
    -d "{\"org_id\":\"org_contract_1\",\"network_id\":\"${network_id}\"}" \
    "${KIND_INGRESS_URL}/api/v1/networks"
  if [ "$PROBE_CODE" != "200" ] || [ "$PROBE_BODY" != "{\"status\":\"created\",\"network_id\":\"${network_id}\"}" ]; then
    echo "::error::Mesh primary-origin create through the HMAC receiver failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: mesh' "$PROBE_HEADERS"; then
    echo "::error::Mesh network create did not reach the Mesh workload"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  # A browser cookie is forwarded only under its canonical primary name. This
  # crosses the same private HMAC receiver as the machine key above; it never
  # falls back to Mesh's retired session middleware.
  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -H 'content-type: application/json' \
    -d "{\"org_id\":\"org_contract_1\",\"network_id\":\"${session_network_id}\"}" \
    "${KIND_INGRESS_URL}/api/v1/networks"
  if [ "$PROBE_CODE" != "200" ] || [ "$PROBE_BODY" != "{\"status\":\"created\",\"network_id\":\"${session_network_id}\"}" ]; then
    echo "::error::Mesh canonical-session bridge through the HMAC receiver failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  # Invitation administration remains owner-only. Create the invitation target
  # as the organization owner, then redeem its capability as the ordinary
  # member through the machine credential below.
  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -H 'content-type: application/json' \
    -d "{\"org_id\":\"org_contract_1\",\"network_id\":\"${invite_network_id}\"}" \
    "${KIND_INGRESS_URL}/api/v1/networks"
  if [ "$PROBE_CODE" != "200" ] || [ "$PROBE_BODY" != "{\"status\":\"created\",\"network_id\":\"${invite_network_id}\"}" ]; then
    echo "::error::Mesh owner-session invitation target create failed: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  curl_settled -H "authorization: Bearer ${api_key}" \
    "${KIND_INGRESS_URL}/api/v1/networks?org_id=org_contract_1"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e --arg network_id "$network_id" \
      'any(.[]; .id == $network_id and .org_id == "org_contract_1" and .node_count == 0 and .invite_count == 0)' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh primary-origin list did not return the exact owned network: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  curl_settled -H "authorization: Bearer ${api_key}" \
    "${KIND_INGRESS_URL}/api/v1/networks?org_id=org_contract_2"
  if [ "$PROBE_CODE" != "403" ] || ! jq -e \
      '.status == 403 and .code == "forbidden" and .detail == "forbidden"' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::exact-organization API key crossed the Mesh ownership boundary: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  # The OAuth bearer belongs to the same ordinary product user and sees the
  # same organization-owned state through the identical receiver/domain path.
  curl_settled -H 'authorization: Bearer at_kind_connect_oidc_codewire_api' \
    "${KIND_INGRESS_URL}/api/v1/networks?org_id=org_contract_1"
  if [ "$PROBE_CODE" != "200" ] || ! jq -e \
      --arg api_key_network "$network_id" \
      --arg session_network "$session_network_id" \
      --arg invite_network "$invite_network_id" \
      'length == 3 and
       any(.[]; .id == $api_key_network and .org_id == "org_contract_1") and
       any(.[]; .id == $session_network and .org_id == "org_contract_1") and
       any(.[]; .id == $invite_network and .org_id == "org_contract_1")' \
      <<<"$PROBE_BODY" >/dev/null; then
    echo "::error::Mesh OAuth bridge did not return the exact organization-owned networks: code=$PROBE_CODE body=$PROBE_BODY"
    exit 1
  fi

  local rejected_credential='Bearer rejected-bridge-credential'
  curl_settled -H "authorization: ${rejected_credential}" \
    "${KIND_INGRESS_URL}/api/v1/networks?org_id=org_contract_1"
  if [ "$PROBE_CODE" != "401" ] || ! jq -e \
      '.status == 401 and .detail == "unauthorized"' <<<"$PROBE_BODY" >/dev/null \
    || [[ "$PROBE_BODY" == *"${rejected_credential}"* ]]; then
    echo "::error::Mesh bridge leaked or accepted a rejected primary credential: code=$PROBE_CODE body=$PROBE_BODY"
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

  # Enrollment redemption is a generated, unauthenticated one-use capability
  # exchange. It returns registration metadata only and never mints or stores a
  # steady-state node bearer.
  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
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
       .enrollment.ownerUserId == "usr_contract_admin" and
       .enrollment.issuedByUserId == "usr_contract_admin" and
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

  for retired_path in \
    /api/v1/node-enrollments/redeem \
    /api/v1/network-auth/runtime/node; do
    curl_settled -X POST \
      -H 'content-type: application/json' \
      -d '{}' \
      "${KIND_INGRESS_URL}${retired_path}"
    if [ "$PROBE_CODE" != "404" ]; then
      echo "::error::retired Mesh bearer route ${retired_path} returned ${PROBE_CODE}, want 404"
      exit 1
    fi
  done

  local node_registration token_rows token_index dormant_token_columns migration_004
  node_registration="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tA -F '|' -c \
      "SELECT network_id, name, owner_subject, authorized_by, enrollment_id, peer_url, token FROM nodes WHERE network_id = '${network_id}' AND name = 'mesh-kind-node'")"
  token_rows="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tA -F '|' -c \
      "SELECT (SELECT count(*) FROM nodes WHERE token <> ''), (SELECT count(*) FROM oidc_device_flows WHERE node_token <> '')")"
  token_index="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT count(*) FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'idx_nodes_token'")"
  dormant_token_columns="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND ((table_name = 'nodes' AND column_name = 'token') OR (table_name = 'oidc_device_flows' AND column_name = 'node_token'))")"
  migration_004="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tA -F '|' -c \
      "SELECT description, success FROM _sqlx_migrations WHERE version = 4")"
  if [ "$node_registration" != "${network_id}|mesh-kind-node|usr_contract_admin|usr_contract_admin|${enrollment_id}|https://mesh-kind-node.test/peer|" ] \
    || [ "$token_rows" != "0|0" ] \
    || [ "$token_index" != "0" ] \
    || [ "$dormant_token_columns" != "2" ] \
    || [ "$migration_004" != "retire persistent node bearer|t" ]; then
    echo "::error::Mesh bearer retirement persistence proof failed: node=${node_registration:-missing} token_rows=${token_rows:-missing} index=${token_index:-missing} columns=${dormant_token_columns:-missing} migration=${migration_004:-missing}"
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
  log "Mesh primary-origin REST/Connect/HMAC/exact-org/invitation/enrollment proof OK"
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

  # Both upstreams must be reachable through the ingress before any
  # unretried probe runs — the orchestration-backed probes used to run
  # before orchestration's readiness loop and could catch a 503 during
  # endpoint sync (observed in CI as "checkout returned 503, want 404").
  wait_edge_upstream billing /api/v1/billing/plans/sandbox 401
  wait_edge_upstream orchestration /api/v1/organizations/org_contract_1/environments 401
  local code path

  for path in \
    /api/v1/organizations/org_contract_1/billing/invoices \
    /api/v1/organizations/org_contract_1/billing \
    /api/v1/organizations/org_contract_1/environments/usage; do
    require_get_code "$path" 401 "flipped billing path $path"
  done

  for path in billing/checkout billing/portal billing/setup; do
    require_post_code "/api/v1/organizations/org_contract_1/${path}" 401 "flipped billing POST $path"
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
    require_get_code "$path" 401 "flipped catalog write path $path"
  done

  require_get_code /api/v1/organizations/org_contract_1/environments 401 "flipped environments path"

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
    require_get_code "$path" 401 "flipped orchestration path $path"
  done

  require_post_code /api/v1/organizations/org_contract_1/environments/env_contract_1/exec 401 "flipped exec path"
  require_post_code /api/v1/terminal/ticket 401 "flipped terminal ticket path"
  require_get_code /api/v1/organizations/org_contract_1/environments/env_contract_1/ssh-proxy 401 "flipped ssh-proxy websocket path"
  require_get_code /api/v1/organizations/org_contract_1/environments/env_contract_1/ssh-proxy/check 401 "flipped ssh-proxy check path"

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
  # must reach the billing binary. The full billing wire contract below
  # exercises every method; this probe makes the per-Service edge split
  # immediately diagnosable.
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
    SMOKE_DATABASE_URL="postgres://codewire:codewire@127.0.0.1:25432/codewire" \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID=env_contract_1 \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/log-stream-smoke"
}

# `codewire.internal.v1` is the sole listener-isolation exception to the
# public `/codewire.` fallback. Prove both sides of that boundary against the
# rendered Kind Service: public ingress reaches the ordinary public 8084
# not-found, while a ClusterIP Service-DNS request reaches the binding mount
# and a direct port-forward validates the complete internal surface.
internal_connect_listener_probes() {
  log "running internal Connect listener isolation probes"
  local public_base="${KIND_INGRESS_URL}/codewire.internal.v1.GatewayBindingService"
  curl_settled -X POST -H 'content-type: application/json' \
    -d "{\"pod\":\"kind-internal-unbound\",\"namespace\":\"${NS}\"}" \
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

  (
    # Reuse the existing UUID-addressed coordinator fixture. The binding
    # endpoint must mint a token the real coordinator accepts, rather than
    # merely returning a syntactically plausible token from its own process.
    local bound_environment_id=00000000-0000-4000-8000-000000000501
    local bound_pod=kind-internal-bound
    local bound_pod_ip=10.244.0.251
    local bound_port_id=port_internal_connect_kind
    local port_forward_log port_forward_pid local_port i sidecar_token in_cluster_probe
    port_forward_log="$(mktemp)"
    kubectl -n "$NS" exec -i deploy/postgres -- \
      psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
DELETE FROM sandbox_environment_backend WHERE environment_id = '$bound_environment_id';
DELETE FROM environment_ports WHERE id = '$bound_port_id';
INSERT INTO sandbox_environment_backend (environment_id, namespace, pod_name, pod_ip)
VALUES ('$bound_environment_id', '$NS', '$bound_pod', '$bound_pod_ip');
INSERT INTO environment_ports (id, environment_id, port, label, access)
VALUES ('$bound_port_id', '$bound_environment_id', 3000, 'internal-connect-kind', 'creator');
SQL
    # This originates in the already-deployed Postgres pod and addresses the
    # ClusterIP by its Service DNS name. A host port-forward alone cannot prove
    # kube-proxy's 8085 Service leg or the in-cluster caller boundary. Use the
    # bound fixture because BusyBox wget intentionally discards non-2xx bodies,
    # making an unbound typed-not_found response impossible to inspect here.
    in_cluster_probe="$(kubectl -n "$NS" exec deploy/postgres -- sh -ceu '
      wget -q -O - \
        --header="content-type: application/json" \
        --post-data="{\"pod\":\"kind-internal-bound\",\"namespace\":\"codewire-e2e\"}" \
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
    cleanup_internal_connect_port_forward() {
      kubectl -n "$NS" exec -i deploy/postgres -- \
        psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL >/dev/null 2>&1 || true
DELETE FROM environment_ports WHERE id = '$bound_port_id';
DELETE FROM sandbox_environment_backend WHERE environment_id = '$bound_environment_id';
SQL
      kill "$port_forward_pid" >/dev/null 2>&1 || true
      wait "$port_forward_pid" 2>/dev/null || true
      rm -f "$port_forward_log"
    }
    trap cleanup_internal_connect_port_forward EXIT

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

    curl_settled -X POST -H 'content-type: application/json' \
      -d "{\"pod\":\"kind-internal-unbound\",\"namespace\":\"${NS}\"}" \
      "http://127.0.0.1:${local_port}/codewire.internal.v1.GatewayBindingService/IssueGatewayBinding"
    if [ "$PROBE_CODE" != "404" ] || ! echo "$PROBE_BODY" | grep -q '"code":"not_found"'; then
      echo "::error::ClusterIP internal binding command did not reach its 8085 mount: code=$PROBE_CODE body=$PROBE_BODY"
      exit 1
    fi
    if ! grep -qi '^x-codewire-service: codewire-orchestration-internal' "$PROBE_HEADERS"; then
      echo "::error::ClusterIP internal binding command did not reach the internal listener"
      cat "$PROBE_HEADERS"
      exit 1
    fi

    curl_settled -X POST -H 'content-type: application/json' \
      -d "{\"pod\":\"${bound_pod}\",\"namespace\":\"${NS}\"}" \
      "http://127.0.0.1:${local_port}/codewire.internal.v1.GatewayBindingService/IssueGatewayBinding"
    if [ "$PROBE_CODE" != "200" ]; then
      echo "::error::ClusterIP internal binding command did not issue a bound response: code=$PROBE_CODE body=$PROBE_BODY"
      exit 1
    fi
    if ! jq -e --arg environment_id "$bound_environment_id" --arg pod_ip "$bound_pod_ip" \
      '(.environmentId // .environment_id) == $environment_id
       and (.workspacePodIp // .workspace_pod_ip) == $pod_ip
       and ((.appPorts // .app_ports // []) | index(3000)) != null
       and ((.sidecarToken // .sidecar_token // "") | length > 0)' \
      <<<"$PROBE_BODY" >/dev/null; then
      echo "::error::ClusterIP internal binding response omitted a required bound field: $PROBE_BODY"
      exit 1
    fi
    sidecar_token="$(jq -er '.sidecarToken // .sidecar_token // empty' <<<"$PROBE_BODY")"

    # The selector opens a real Connect Coordinate stream. Its successful
    # setup proves the just-issued HMAC token crossed the service boundary and
    # was accepted by the coordinator, not only parsed by the issuer.
    for i in $(seq 1 20); do
      if CODEWIRE_COORDINATOR_URL="http://127.0.0.1:18092/api/v1/internal/gateway/coordinate" \
        CODEWIRE_ENVIRONMENT_ID="$bound_environment_id" \
        CODEWIRE_GATEWAY_TOKEN="$sidecar_token" \
        CODEWIRE_COORDINATE_TRANSPORT=connect \
        KIND_EXPECTED_COORDINATE_TRANSPORT=connect \
        timeout --kill-after=5s 15s "$CARGO_CI_DIR/coordinator-selector-smoke"; then
        break
      fi
      if [ "$i" = 20 ]; then
        echo "::error::coordinator did not accept the internal binding token"
        exit 1
      fi
      echo "internal binding coordinator probe not ready (${i}/20)"
      sleep 2
    done

    curl_settled -X POST -H 'content-type: application/json' -d '{}' \
      "http://127.0.0.1:${local_port}/codewire.internal.v1.EnvironmentCredentialService/IssueGitHubCredentials"
    if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
      echo "::error::ClusterIP environment credentials command did not enforce environment Bearer auth: code=$PROBE_CODE body=$PROBE_BODY"
      exit 1
    fi
    if ! grep -qi '^x-codewire-service: codewire-orchestration-internal' "$PROBE_HEADERS"; then
      echo "::error::ClusterIP environment credentials command did not reach the internal listener"
      cat "$PROBE_HEADERS"
      exit 1
    fi
  )

  log "internal Connect listener isolation probes OK"
}

coordinator_ingress_smoke() {
  log "running coordinator public gRPC + direct-h2c Connect + WebSocket smoke"
  local certificate_dir certificate_pem certificate_der alpn_output
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

gateway_selector_smoke() {
  log "running gateway coordinator selector smoke against the real coordinator"
  local direct_url environment_id sidecar_token mode expected i
  direct_url="http://127.0.0.1:18092/api/v1/internal/gateway/coordinate"
  environment_id="00000000-0000-4000-8000-000000000501"
  sidecar_token="eyJlbnZpcm9ubWVudF9pZCI6IjAwMDAwMDAwLTAwMDAtNDAwMC04MDAwLTAwMDAwMDAwMDUwMSIsInNjb3BlIjoiY29vcmRpbmF0ZSJ9.QgWM7yPYYatgrwWm5GpQ5COmBfEqjIInpqo-trLVS1w"

  run_selector() {
    mode="$1"
    expected="$2"
    for i in $(seq 1 20); do
      if CODEWIRE_COORDINATOR_URL="$direct_url" \
        CODEWIRE_ENVIRONMENT_ID="$environment_id" \
        CODEWIRE_GATEWAY_TOKEN="$sidecar_token" \
        CODEWIRE_COORDINATE_TRANSPORT="$mode" \
        KIND_EXPECTED_COORDINATE_TRANSPORT="$expected" \
        timeout --kill-after=5s 15s "$CARGO_CI_DIR/coordinator-selector-smoke"; then
        return 0
      fi
      echo "gateway selector ${mode} probe not ready (${i}/20)"
      sleep 2
    done
    echo "::error::gateway selector ${mode} probe did not select ${expected}"
    return 1
  }

  run_selector ws ws
  run_selector connect connect

  log "disabling the coordinator Connect route for auto fallback proof"
  kubectl -n "$NS" set env deploy/codewire-coordinator COORDINATOR_SERVE_CONNECT=false
  kubectl -n "$NS" rollout status deploy/codewire-coordinator --timeout=300s
  run_selector auto ws

  log "restoring the coordinator Connect route after auto fallback proof"
  kubectl -n "$NS" set env deploy/codewire-coordinator COORDINATOR_SERVE_CONNECT-
  kubectl -n "$NS" rollout status deploy/codewire-coordinator --timeout=300s
}

exec_service_parity_smoke() {
  log "running ExecService Connect/REST same-pod parity smoke"
  local environment_id=env_contract_1
  local ascii_command ascii_rest_payload ascii_connect_payload
  local ascii_rest ascii_connect
  local invalid_command invalid_rest_payload invalid_connect_payload
  local invalid_rest invalid_connect

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
UPDATE environments
SET state = 'running', desired_state = 'started', error_reason = NULL,
    state_changed_at = NOW(),
    environment_operation_generation = GREATEST(environment_operation_generation, 1)
WHERE id = '$environment_id';

-- This fixture is a raw pod, not an Agent Sandbox claim. Mark the harness as
-- the active setup owner while it exercises that pod so the real liveness
-- reconciler does not correctly reject the deliberately claim-less fixture
-- in the middle of the paced streaming comparison.
INSERT INTO sandbox_environment_backend (
  environment_id, namespace, pod_name,
  setup_owner_generation, setup_owner_activity_id, setup_owner_attempt,
  setup_owner_phase, setup_owner_status, setup_owner_pod_uid
)
SELECT '$environment_id', '$SANDBOX_NS', 'exec-smoke',
       environment_operation_generation, 'kind-exec-service-smoke', 1,
       0, 'claimed', NULL
FROM environments
WHERE id = '$environment_id'
ON CONFLICT (environment_id) DO UPDATE
SET namespace = EXCLUDED.namespace,
    pod_name = EXCLUDED.pod_name,
    setup_owner_generation = EXCLUDED.setup_owner_generation,
    setup_owner_activity_id = EXCLUDED.setup_owner_activity_id,
    setup_owner_attempt = EXCLUDED.setup_owner_attempt,
    setup_owner_phase = EXCLUDED.setup_owner_phase,
    setup_owner_status = EXCLUDED.setup_owner_status,
    setup_owner_pod_uid = EXCLUDED.setup_owner_pod_uid;
SQL

  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_DIRECT_BASE_URL=http://127.0.0.1:8084 \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/exec-stream-smoke"

  ascii_command="printf 'stdout\\n'; printf 'stderr\\n' >&2; exit 17"
  ascii_rest_payload="$(jq -cn --arg command "$ascii_command" \
    '{command:["sh","-c",$command]}')"
  ascii_connect_payload="$(jq -cn \
    --arg org_id org_contract_1 \
    --arg environment_id "$environment_id" \
    --arg command "$ascii_command" \
    '{orgId:$org_id,environmentId:$environment_id,command:["sh","-c",$command]}')"

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "$ascii_rest_payload" \
    "${KIND_INGRESS_URL}/api/v1/organizations/org_contract_1/environments/${environment_id}/exec"
  if [ "$PROBE_CODE" != "200" ]; then
    echo "::error::REST same-pod exec returned ${PROBE_CODE}: ${PROBE_BODY}"
    return 1
  fi
  ascii_rest="$PROBE_BODY"

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

  if [ "$(jq -r '.exit_code' <<<"$ascii_rest")" != "$(jq -r '.exitCode' <<<"$ascii_connect")" ]; then
    echo "::error::REST/Connect exec exit codes diverged: REST=${ascii_rest} Connect=${ascii_connect}"
    return 1
  fi
  if [ "$(jq -j '.stdout' <<<"$ascii_rest" | base64 -w0)" != "$(jq -r '.stdout' <<<"$ascii_connect")" ]; then
    echo "::error::REST/Connect exec stdout diverged: REST=${ascii_rest} Connect=${ascii_connect}"
    return 1
  fi
  if [ "$(jq -j '.stderr' <<<"$ascii_rest" | base64 -w0)" != "$(jq -r '.stderr' <<<"$ascii_connect")" ]; then
    echo "::error::REST/Connect exec stderr diverged: REST=${ascii_rest} Connect=${ascii_connect}"
    return 1
  fi

  invalid_command="printf 'out\\377\\n'; printf 'err\\376\\n' >&2; exit 23"
  invalid_rest_payload="$(jq -cn --arg command "$invalid_command" \
    '{command:["sh","-c",$command]}')"
  invalid_connect_payload="$(jq -cn \
    --arg org_id org_contract_1 \
    --arg environment_id "$environment_id" \
    --arg command "$invalid_command" \
    '{orgId:$org_id,environmentId:$environment_id,command:["sh","-c",$command]}')"

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "$invalid_rest_payload" \
    "${KIND_INGRESS_URL}/api/v1/organizations/org_contract_1/environments/${environment_id}/exec"
  if [ "$PROBE_CODE" != "200" ]; then
    echo "::error::REST invalid-byte exec returned ${PROBE_CODE}: ${PROBE_BODY}"
    return 1
  fi
  invalid_rest="$PROBE_BODY"

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
    '.exit_code == 23 and .stdout == ("out" + "\uFFFD" + "\n") and .stderr == ("err" + "\uFFFD" + "\n")' \
    <<<"$invalid_rest" >/dev/null; then
    echo "::error::REST renderer did not preserve its documented lossy UTF-8 behavior: ${invalid_rest}"
    return 1
  fi
  if ! jq -e \
    '.exitCode == 23 and .stdout == "b3V0/wo=" and .stderr == "ZXJy/go="' \
    <<<"$invalid_connect" >/dev/null; then
    echo "::error::Connect Exec did not preserve exact stdout/stderr bytes: ${invalid_connect}"
    return 1
  fi

  log "ExecService Connect/REST parity and lossless bytes green; retaining its pod for FileService"
}

environment_setup_terminal_smoke() (
  local environment_id=env-terminal-ticket-smoke
  local claim_name=sandbox-env-terminal-ticket-smoke
  local pod_name=terminal-ticket-workspace
  local original_replicas ready

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

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
INSERT INTO environments (
  id, org_id, created_by, type, name, state, desired_state, preset_id,
  cpu_millicores, memory_mb, disk_gb,
  environment_operation_generation, state_changed_at
)
VALUES (
  '$environment_id', 'org_contract_1', 'usr_contract_user', 'sandbox',
  'terminal-ticket-smoke', 'running', 'started', 'preset_contract_1',
  2000, 4096, 10, 1, NOW()
);

INSERT INTO sandbox_environment_backend (
  environment_id, namespace, pod_name,
  setup_owner_generation, setup_owner_activity_id, setup_owner_attempt,
  setup_owner_phase, setup_owner_status, setup_owner_pod_uid
)
VALUES (
  '$environment_id', '$SANDBOX_NS', '$pod_name',
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

file_service_smoke() {
  log "running FileService client/server streaming and REST parity smoke"
  local sftp_environment_id=env-crd-smoke
  local exec_environment_id=env_contract_1
  local daemon_pod=crd-smoke-workspace-daemon
  local daemon_token
  daemon_token="$(daemon_auth_token_for_environment "$sftp_environment_id")"

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
INSERT INTO environments (
  id, org_id, created_by, type, name, state, desired_state, preset_id,
  cpu_millicores, memory_mb, disk_gb,
  environment_operation_generation, state_changed_at
)
VALUES (
  '$sftp_environment_id', 'org_contract_1', 'usr_contract_user', 'sandbox',
  'file-service-sftp', 'running', 'started', 'preset_contract_1',
  2000, 4096, 10, 1, NOW()
)
ON CONFLICT (id) DO UPDATE
SET state = 'running', desired_state = 'started', error_reason = NULL,
    environment_operation_generation = GREATEST(environments.environment_operation_generation, 1),
    state_changed_at = NOW();

INSERT INTO sandbox_environment_backend (
  environment_id, namespace, pod_name,
  setup_owner_generation, setup_owner_activity_id, setup_owner_attempt,
  setup_owner_phase, setup_owner_status, setup_owner_pod_uid
)
SELECT '$sftp_environment_id', '$SANDBOX_NS', '$daemon_pod',
       environment_operation_generation, 'kind-file-service-smoke', 1,
       0, 'claimed', NULL
FROM environments
WHERE id = '$sftp_environment_id'
ON CONFLICT (environment_id) DO UPDATE
SET namespace = EXCLUDED.namespace,
    pod_name = EXCLUDED.pod_name,
    setup_owner_generation = EXCLUDED.setup_owner_generation,
    setup_owner_activity_id = EXCLUDED.setup_owner_activity_id,
    setup_owner_attempt = EXCLUDED.setup_owner_attempt,
    setup_owner_phase = EXCLUDED.setup_owner_phase,
    setup_owner_status = EXCLUDED.setup_owner_status,
    setup_owner_pod_uid = EXCLUDED.setup_owner_pod_uid;
SQL

  environment_daemon_proxy_smoke "$sftp_environment_id" "$daemon_pod"
  platform_run_connect_smoke "$sftp_environment_id"
  environment_session_protocol_smoke "$sftp_environment_id"

  kubectl -n "$SANDBOX_NS" exec pod/exec-smoke -c workspace -- \
    sh -c "mkdir -p /workspace && printf '%s\n' 'exec-only FileService download' > /workspace/exec-file-service.txt"

  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_DIRECT_BASE_URL=http://127.0.0.1:8084 \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_SFTP_ENVIRONMENT_ID="$sftp_environment_id" \
    SMOKE_EXEC_ENVIRONMENT_ID="$exec_environment_id" \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/file-service-smoke"

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
DELETE FROM sandbox_environment_backend
WHERE environment_id IN ('$sftp_environment_id', '$exec_environment_id');
DELETE FROM environments WHERE id = '$sftp_environment_id';
SQL
  kubectl -n "$SANDBOX_NS" delete pod exec-smoke --wait=true --timeout=60s >/dev/null
  CRD_SMOKE_NAMESPACE="$SANDBOX_NS" \
    CRD_SMOKE_SERVER_NAMESPACE="$NS" \
    CRD_SMOKE_GATEWAY_TOKEN="$daemon_token" \
    CRD_SMOKE_GATEWAY_PHASE=cleanup \
    CRD_SMOKE_LOCAL_GATEWAY=1 \
    "$CARGO_CI_DIR/crd-smoke"
  kubectl -n "$SANDBOX_NS" delete pod "$daemon_pod" --wait=true >/dev/null
  rm -rf "$GATEWAY_SMOKE_TMPDIR"
  GATEWAY_SMOKE_TMPDIR=""
  log "FileService streaming, backend selection, REST parity, and black-box contract green"
}

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
  kubectl_apply --validate=false -k "$ROOT/deployments/k8s/agent-sandbox/base"
  kubectl wait --for=condition=established --timeout=60s \
    crd/sandboxclaims.extensions.agents.x-k8s.io
  kubectl -n agent-sandbox-system rollout status deploy/agent-sandbox-controller --timeout=180s
}

workspace_service_smokes() {
  gateway_host_key_restart_smoke

  log "running workspace exec smoke"
  SMOKE_NAMESPACE="$SANDBOX_NS" SMOKE_KEEP_POD=1 "$CARGO_CI_DIR/exec-smoke"
  exec_service_parity_smoke
  environment_setup_terminal_smoke
  file_service_smoke
}

temporal_workflow_smoke() {
  log "running Temporal workflow smoke"
  local env_id state reason
  env_id="env-temporal-kind-$RANDOM"
  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
INSERT INTO environments (id, org_id, created_by, type, state, desired_state,
                          cpu_millicores, memory_mb, disk_gb, preset_id)
VALUES ('$env_id', 'org_contract_1', 'usr_contract_admin', 'sandbox', 'pending', 'started',
        2000, 4096, 10, 'preset_contract_1');
SQL
  if ! DATABASE_URL="postgres://codewire:codewire@127.0.0.1:25432/codewire" \
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
  log "running final Temporal activity-fencing smoke"
  DATABASE_URL="postgres://codewire:codewire@127.0.0.1:25432/codewire" \
    TEMPORAL_ADDRESS="http://127.0.0.1:7233" \
    SMOKE_ORCHESTRATION_URL="http://127.0.0.1:8084" \
    "$CARGO_CI_DIR/temporal-fencing-smoke"
}

deploy_agent_sandbox_and_smoke() {
  deploy_agent_sandbox
  workspace_service_smokes
  temporal_workflow_smoke
  mark_retained_cluster_prepared
  temporal_fencing_smoke
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
  local daemon_pod=crd-smoke-workspace-daemon
  local gateway_deploy=cw-gateway-env-crd-smoke
  local host_key_secret=cw-gateway-host-key-env-crd-smoke
  local daemon_token
  local before_fingerprint after_fingerprint before_uid after_uid

  log "running CRD round-trip and gateway host-key restart smoke"
  daemon_token="$(daemon_auth_token_for_environment env-crd-smoke)"
  GATEWAY_SMOKE_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/codewire-kind-gateway.XXXXXX")"
  CRD_SMOKE_NAMESPACE="$SANDBOX_NS" \
    CRD_SMOKE_SERVER_NAMESPACE="$NS" \
    CRD_SMOKE_GATEWAY_TOKEN="$daemon_token" \
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
      command: ["/usr/local/bin/cw", "daemon"]
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
  log "running configured Rust billing wire contract through ingress"
  (
    cd "$ROOT"
    BILLING_BASE_URL="$KIND_INGRESS_URL" \
      BILLING_FRONTEND_URL="http://127.0.0.1:8080" \
      BILLING_ADMIN_SESSION_TOKEN=contract-admin-session-token \
      BILLING_USER_SESSION_TOKEN=contract-user-session-token \
      BILLING_SEEDED=1 \
      BILLING_STRIPE_CONFIGURED=1 \
      BILLING_SKIP_HEALTH=1 \
      cargo test --locked --profile ci -p codewire-billing \
        --test wire_contract configured_billing_wire_contract \
        -- --ignored --exact --nocapture | tee "$RUN_DIR/billing-contract.log"
    local passed_count
    passed_count="$(sed -nE \
      's/.*test result: ok\. ([0-9]+) passed.*/\1/p' \
      "$RUN_DIR/billing-contract.log" | tail -n 1)"
    if [ "$passed_count" != "1" ]; then
      echo "::error::configured Rust billing wire contract reported ${passed_count:-no} passing tests; expected 1"
      exit 1
    fi
  )
}

rust_reconciler_ttl_e2e() {
  log "running Rust reconciler TTL Kubernetes e2e"
  DATABASE_URL="postgres://codewire:codewire@127.0.0.1:25432/codewire" \
    SMOKE_ORCHESTRATION_URL="http://127.0.0.1:8084" \
    SMOKE_SANDBOX_NAMESPACE="$SANDBOX_NS" \
    SMOKE_SESSION_TOKEN=contract-admin-session-token \
    SMOKE_ORG_ID=org_contract_1 \
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
