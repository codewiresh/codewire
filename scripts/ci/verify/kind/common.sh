#!/usr/bin/env bash
# Shared mechanics for the Rust product Kind suites. Source this file; invoke
# scripts/ci/verify/kind-e2e.sh as the stable entrypoint.
set -euo pipefail

export KIND_E2E_COMMON_LOADED=1
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)}"
KIND_PROFILE=0
if [ -n "${CLUSTER:-}" ]; then
  # shellcheck source=scripts/dev/kind/profile.sh
  source "$ROOT/scripts/dev/kind/profile.sh"
  kind_profile_load "$ROOT" || return $?
  KIND_CLUSTER_NAME_EXPLICIT=1
fi
# shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
source "$ROOT/scripts/ci/verify/playwright-browser-runtime.sh"
# shellcheck source=scripts/ci/verify/kind-host-runtime.sh
source "$ROOT/scripts/ci/verify/kind-host-runtime.sh"
CARGO_TARGET_DIR="$(
  "$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh" "$ROOT"
)"
export CARGO_TARGET_DIR
KIND_SMOKE_BUILD_DIR="$CARGO_TARGET_DIR/ci"
if [ "$KIND_PROFILE" = 1 ]; then
  CARGO_CI_DIR="$KIND_PROFILE_SMOKE_DIR"
else
  CARGO_CI_DIR="$KIND_SMOKE_BUILD_DIR"
fi
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
KIND_CONFIG="${KIND_CONFIG:-$ROOT/tests/e2e/kind/kind-config.yaml}"
RUN_DIR="${RUN_DIR:-$ROOT/.tmp/codewire-kind-e2e-${KIND_CLUSTER_NAME}}"
# Host topology for this harness cluster. Every hostPort the checked-in Kind
# config maps is templated, so multiple sessions can run multiple harness
# clusters on one workstation with distinct KIND_CLUSTER_NAME and port
# assignments; the defaults keep every existing flow unchanged.
if [ -n "${KIND_INGRESS_HOST_PORT:-}" ] && [ -n "${KIND_INGRESS_HTTP_HOST_PORT:-}" ] \
    && [ "$KIND_INGRESS_HOST_PORT" != "$KIND_INGRESS_HTTP_HOST_PORT" ]; then
  echo '::error::Kind ingress port selectors conflict' >&2
  return 2
fi
if [ -n "${KIND_COORDINATOR_DIRECT_HOST_PORT:-}" ] && [ -n "${KIND_COORDINATOR_HOST_PORT:-}" ] \
    && [ "$KIND_COORDINATOR_DIRECT_HOST_PORT" != "$KIND_COORDINATOR_HOST_PORT" ]; then
  echo '::error::Kind coordinator port selectors conflict' >&2
  return 2
fi
if [ -n "${KIND_ORCHESTRATION_HTTP_URL:-}" ] && [ -n "${KIND_ORCHESTRATION_URL:-}" ] \
    && [ "$KIND_ORCHESTRATION_HTTP_URL" != "$KIND_ORCHESTRATION_URL" ]; then
  echo '::error::Kind orchestration endpoint selectors conflict' >&2
  return 2
fi
if [ -n "${KIND_TEMPORAL_FRONTEND_URL:-}" ] && [ -n "${KIND_TEMPORAL_ADDRESS:-}" ] \
    && [ "$KIND_TEMPORAL_FRONTEND_URL" != "$KIND_TEMPORAL_ADDRESS" ]; then
  echo '::error::Kind Temporal endpoint selectors conflict' >&2
  return 2
fi
KIND_INGRESS_HOST_PORT="${KIND_INGRESS_HOST_PORT:-${KIND_INGRESS_HTTP_HOST_PORT:-8090}}"
KIND_INGRESS_TLS_HOST_PORT="${KIND_INGRESS_TLS_HOST_PORT:-10443}"
KIND_TEMPORAL_HOST_PORT="${KIND_TEMPORAL_HOST_PORT:-7233}"
KIND_ORCHESTRATION_HOST_PORT="${KIND_ORCHESTRATION_HOST_PORT:-8084}"
KIND_COORDINATOR_DIRECT_HOST_PORT="${KIND_COORDINATOR_DIRECT_HOST_PORT:-${KIND_COORDINATOR_HOST_PORT:-18092}}"
KIND_POSTGRES_HOST_PORT="${KIND_POSTGRES_HOST_PORT:-25432}"
KIND_HOST_PORT_VARS=(
  KIND_INGRESS_HOST_PORT
  KIND_INGRESS_TLS_HOST_PORT
  KIND_TEMPORAL_HOST_PORT
  KIND_ORCHESTRATION_HOST_PORT
  KIND_COORDINATOR_DIRECT_HOST_PORT
  KIND_POSTGRES_HOST_PORT
)
kind_host_port_var_seen=":"
for kind_host_port_var in "${KIND_HOST_PORT_VARS[@]}"; do
  kind_host_port_value="${!kind_host_port_var}"
  if ! [[ "$kind_host_port_value" =~ ^[0-9]+$ ]] \
      || [ "$kind_host_port_value" -lt 1024 ] \
      || [ "$kind_host_port_value" -gt 65535 ]; then
    echo "::error::${kind_host_port_var} must be an unprivileged TCP port"
    exit 2
  fi
  case "$kind_host_port_var_seen" in
    *":${kind_host_port_value}:"*)
      echo "::error::${kind_host_port_var} duplicates another requested Kind host port (${kind_host_port_value})"
      exit 2
      ;;
  esac
  kind_host_port_var_seen+="${kind_host_port_value}:"
done
unset kind_host_port_var kind_host_port_value kind_host_port_var_seen
# Use the hostless HTTP server for the edge and transitional REST probes. The
# coordinator TLS ingress intentionally owns Host/SNI localhost below.
KIND_INGRESS_URL="${KIND_INGRESS_URL:-http://127.0.0.1:${KIND_INGRESS_HOST_PORT}}"
KIND_INGRESS_TLS_URL="${KIND_INGRESS_TLS_URL:-https://localhost:${KIND_INGRESS_TLS_HOST_PORT}}"
KIND_ORCHESTRATION_URL="${KIND_ORCHESTRATION_HTTP_URL:-${KIND_ORCHESTRATION_URL:-http://127.0.0.1:${KIND_ORCHESTRATION_HOST_PORT}}}"
KIND_TEMPORAL_ADDRESS="${KIND_TEMPORAL_FRONTEND_URL:-${KIND_TEMPORAL_ADDRESS:-http://127.0.0.1:${KIND_TEMPORAL_HOST_PORT}}}"
KIND_INGRESS_HTTP_HOST_PORT="${KIND_INGRESS_HTTP_HOST_PORT:-$KIND_INGRESS_HOST_PORT}"
KIND_COORDINATOR_HOST_PORT="${KIND_COORDINATOR_HOST_PORT:-$KIND_COORDINATOR_DIRECT_HOST_PORT}"
KIND_DATABASE_URL="postgres://codewire:codewire@127.0.0.1:${KIND_POSTGRES_HOST_PORT}/codewire"
KIND_TEMPORAL_FRONTEND_URL="$KIND_TEMPORAL_ADDRESS"
KIND_ORCHESTRATION_HTTP_URL="$KIND_ORCHESTRATION_URL"
KIND_COORDINATOR_DIRECT_URL="${KIND_COORDINATOR_DIRECT_URL:-http://127.0.0.1:${KIND_COORDINATOR_DIRECT_HOST_PORT}}"
mkdir -p "$RUN_DIR"
KEEP_KIND_CLUSTER="${KEEP_KIND_CLUSTER:-0}"
KIND_HOST_LOCK_TIMEOUT_SECONDS="${KIND_HOST_LOCK_TIMEOUT_SECONDS:-1200}"
if ! [[ "$KIND_HOST_LOCK_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
    || [ "$KIND_HOST_LOCK_TIMEOUT_SECONDS" -lt 1 ]; then
  echo "::error::KIND_HOST_LOCK_TIMEOUT_SECONDS must be a positive integer"
  exit 2
fi
KIND_HOST_LOCK_FILE="${KIND_HOST_LOCK_FILE:-${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/codewire-kind-e2e-${UID}.lock}"
KIND_HOST_LOCK_FD=""
KIND_BUILD_PUBLICATION_LOCK_OPENED_HERE=0
NS=codewire-e2e
SANDBOX_NS=dev-sandboxes
# shellcheck source=scripts/ci/verify/kind/credentials.sh
source "$ROOT/scripts/ci/verify/kind/credentials.sh"
KIND_E2E_COMPATIBILITY_VERSION=1
KIND_E2E_PREPARED_CONFIGMAP=codewire-kind-e2e-prepared
RETAINED_KUBECONFIG=""
REMOTE_DIND_JOB_CONTAINER=""
REMOTE_DIND_KIND_NETWORK=""
REMOTE_DIND_FORWARDER_PID=""
KIND_CREATED_BY_TRANSACTION=0
KIND_TRANSACTION_NODE_ID=""
KIND_SHARD_TRANSACTION=0
# Nested external observations never inherit the creating process's cleanup.
export -n KIND_SHARD_TRANSACTION
# A shard transaction's background workspace import. kind-e2e.sh sets the
# shard's suites, KIND_SHARD_SUITE_NAMES.
KIND_WORKSPACE_LOAD_PID=""
KIND_WORKSPACE_LOAD_LOG=""
KIND_PROFILE_ARTIFACTS_VERIFIED=0
if [ -z "${DEFAULT_KIND_WORKSPACE_IMAGE+x}" ]; then
  # The published workspace pin (crates/codewire-workspace-image), never a copy.
  DEFAULT_KIND_WORKSPACE_IMAGE="$(python3 "$ROOT/scripts/ci/images/workspace-image-pin.py" show public-image)"
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
  APPROVED_KIND_INGRESS_CONTROLLER_IMAGE='registry.example.invalid/oci-approved/ingress-nginx/controller@sha256:5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180'
fi
if [ -z "${APPROVED_KIND_INGRESS_CERTGEN_IMAGE+x}" ]; then
  APPROVED_KIND_INGRESS_CERTGEN_IMAGE='registry.example.invalid/oci-approved/ingress-nginx/kube-webhook-certgen@sha256:334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053'
fi
if [ -z "${APPROVED_KIND_AGENT_SANDBOX_IMAGE+x}" ]; then
  APPROVED_KIND_AGENT_SANDBOX_IMAGE='registry.example.invalid/oci-approved/codewire/agent-sandbox-controller@sha256:fb3b81ff40a5ef07a455f1e81f2af3a9b0884ed801238e018008184520044595'
fi
if [ -z "${APPROVED_KIND_WORKSPACE_IMAGE+x}" ]; then
  APPROVED_KIND_WORKSPACE_IMAGE='registry.example.invalid/oci-approved/codewire/workspace@sha256:cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510'
fi
if [ -z "${APPROVED_KIND_DIND_IMAGE+x}" ]; then
  APPROVED_KIND_DIND_IMAGE='registry.example.invalid/oci-approved/docker/dind@sha256:66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e'
fi
if [ -z "${KIND_INGRESS_CONTROLLER_LOCAL_IMAGE+x}" ]; then
  KIND_INGRESS_CONTROLLER_LOCAL_IMAGE='localhost/codewire-ci/ingress-nginx-controller:verified-5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180'
fi
if [ -z "${KIND_INGRESS_CERTGEN_LOCAL_IMAGE+x}" ]; then
  KIND_INGRESS_CERTGEN_LOCAL_IMAGE='localhost/codewire-ci/ingress-kube-webhook-certgen:verified-334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053'
fi
if [ -z "${KIND_AGENT_SANDBOX_LOCAL_IMAGE+x}" ]; then
  KIND_AGENT_SANDBOX_LOCAL_IMAGE='localhost/codewire-ci/agent-sandbox-controller:verified-fb3b81ff40a5ef07a455f1e81f2af3a9b0884ed801238e018008184520044595'
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

log_kind_bound_endpoints() {
  log "cluster ${KIND_CLUSTER_NAME} bound endpoints:"
  log "  ingress http       ${KIND_INGRESS_URL}"
  log "  ingress tls        ${KIND_INGRESS_TLS_URL}"
  log "  temporal frontend  ${KIND_TEMPORAL_FRONTEND_URL}"
  log "  orchestration http ${KIND_ORCHESTRATION_HTTP_URL}"
  log "  coordinator direct ${KIND_COORDINATOR_DIRECT_URL}"
  log "  postgres           ${KIND_DATABASE_URL}"
}

# Best-effort holder identity for one held host port: a kind node container
# resolves to its cluster name, any other Docker publisher to its container
# name, and a non-Docker listener to a plain marker. Empty when nothing holds
# the port as far as this process can observe.
kind_host_port_holder() {
  local port="$1" container
  container="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null \
    | awk -v needle=":${port}->" 'index($0, needle) {print $1; exit}')"
  if [ -n "$container" ]; then
    case "$container" in
      *-control-plane) printf 'kind cluster %s' "${container%-control-plane}" ;;
      *) printf 'Docker container %s' "$container" ;;
    esac
    return 0
  fi
  if ss -Hltn "sport = :${port}" 2>/dev/null | grep -q .; then
    printf 'a non-Docker listener on this host'
    return 0
  fi
  return 1
}

# Fail fast when a requested host port is already held, naming the owner so a
# session never mutates another session's cluster by accident. Runs before the
# slow build phase in `up` and again inside create_cluster as the backstop.
# An optional first argument excludes a selected cluster's own holders from
# this observation. create_cluster still refuses to replace an existing cluster.
require_kind_host_ports_available() {
  local ignore_cluster="${1:-}"
  local port_var requested_port holder failures=0
  for port_var in "${KIND_HOST_PORT_VARS[@]}"; do
    requested_port="${!port_var}"
    if holder="$(kind_host_port_holder "$requested_port")"; then
      if [ -n "$ignore_cluster" ] && [ "$holder" = "kind cluster ${ignore_cluster}" ]; then
        continue
      fi
      echo "::error::${port_var}=${requested_port} for Kind cluster ${KIND_CLUSTER_NAME} is held by ${holder}; stop that owner or choose a different ${port_var}"
      failures=1
    fi
  done
  [ "$failures" -eq 0 ]
}

# The templated host-port mappings as "default:requested" lines, one per
# hostPort the checked-in Kind config declares.
kind_host_port_mappings() {
  printf '%s\n' \
    "8090:${KIND_INGRESS_HOST_PORT}" \
    "10443:${KIND_INGRESS_TLS_HOST_PORT}" \
    "7233:${KIND_TEMPORAL_HOST_PORT}" \
    "8084:${KIND_ORCHESTRATION_HOST_PORT}" \
    "18092:${KIND_COORDINATOR_DIRECT_HOST_PORT}" \
    "25432:${KIND_POSTGRES_HOST_PORT}"
}

# Render every templated hostPort mapping to its requested host port. The
# checked-in config keeps the default values, each exactly once; the rendered
# copy is per-run state under RUN_DIR.
render_kind_host_port_mappings() {
  python3 - "$ROOT/scripts/dev/kind/cluster-profile.py" "$1" "$2" "$(kind_host_port_mappings)" <<'PY_RENDER'
import importlib.util
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("kind_port_renderer", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
with Path(sys.argv[2]).open("rb") as stream:
    data = stream.read(module.JSON_BOUND + 1)
module.require(len(data) <= module.JSON_BOUND, "Kind config template exceeds its bound")
replacements = {int(original): int(requested) for original, requested in
                (line.split(":") for line in sys.argv[4].splitlines())}
Path(sys.argv[3]).write_text(module.render_host_ports(data.decode(), replacements))
PY_RENDER

}

# The checked-in overlay and credential fixture name the default host ingress
# origin. A cluster on a shifted KIND_INGRESS_HOST_PORT serves the same routes
# on its own loopback port, so their rendered copies carry KIND_INGRESS_URL
# instead. Each occurrence count is pinned so a new hard-coded origin fails here
# rather than splitting the browser and IdP origins.
KIND_OVERLAY_INGRESS_ORIGINS=4
KIND_CREDENTIAL_FIXTURE_INGRESS_ORIGINS=1

render_kind_ingress_origin() {
  local file="$1" expected="$2" default_port
  # The checked-in origin is the default ingress host port's (the first
  # templated mapping), on the loopback address the harness clients dial.
  default_port="$(kind_host_port_mappings | awk -F: 'NR == 1 { print $1 }')"
  [ -n "$default_port" ] || return 1
  python3 - "$file" "$expected" "http://127.0.0.1:${default_port}" "$KIND_INGRESS_URL" <<'PY'
from pathlib import Path
import re
import sys

file, expected, default, origin = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
if not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{3,4}", origin) or int(origin.rsplit(":", 1)[1]) > 65535:
    raise SystemExit(f"KIND_INGRESS_URL must be http://127.0.0.1:<port> for the Kind overlay, got {origin}")
path = Path(file)
pattern = re.compile(re.escape(default) + r"(?![0-9])")
text, count = pattern.subn(origin, path.read_text())
if count != expected:
    raise SystemExit(
        f"Kind ingress origin occurrence mismatch in {path.name}: expected {expected}, got {count}"
    )
path.write_text(text)
PY
}

# The credential fixture patch with this cluster's ingress origin, as a path.
render_kind_credential_fixture_patch() {
  local rendered="$RUN_DIR/credential-fixture-patch.yaml"
  mkdir -p "$RUN_DIR" || return $?
  cp "$ROOT/tests/e2e/kind/credential-fixture-patch.yaml" "$rendered" || return $?
  render_kind_ingress_origin "$rendered" "$KIND_CREDENTIAL_FIXTURE_INGRESS_ORIGINS" >&2 || return $?
  printf '%s\n' "$rendered"
}

acquire_kind_host_lock() {
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    kind_profile_lock "$ROOT"
    return $?
  fi
  # One process owns one transaction: a suite nested under an `up` or gate
  # invocation (e.g. `kind-e2e.sh shard ... runtime-acceptance`) must not
  # re-flock the file this process already holds, which would deadlock
  # against its own open description.
  if [ -n "$KIND_HOST_LOCK_FD" ]; then
    log "retaining the exclusive local Kind transaction lock"
    return 0
  fi
  mkdir -p "$(dirname "$KIND_HOST_LOCK_FILE")"
  exec {KIND_HOST_LOCK_FD}>"$KIND_HOST_LOCK_FILE"
  log "waiting for exclusive local Kind transaction lock"
  if ! flock -w "$KIND_HOST_LOCK_TIMEOUT_SECONDS" "$KIND_HOST_LOCK_FD"; then
    echo "::error::timed out waiting for the local Kind transaction lock"
    return 1
  fi
  log "acquired exclusive local Kind transaction lock"
}

acquire_kind_build_publication_lock() {
  local lock_file inherited="${KIND_BUILD_PUBLICATION_LOCK_FD:-}" descriptor_path
  lock_file="${KIND_BUILD_PUBLICATION_LOCK_FILE:-}"
  if [ -z "$lock_file" ]; then
    lock_file="$(python3 "$ROOT/scripts/dev/kind/cluster-profile.py" build-lock-path)" || return $?
  fi
  [ -f "$lock_file" ] && [ ! -L "$lock_file" ] \
    && [ "$(stat -c '%u:%a:%h' "$lock_file")" = "$(id -u):600:1" ] || {
    echo '::error::Kind build publication lock is not owner-private' >&2
    return 1
  }
  if [ -n "$inherited" ]; then
    [[ "$inherited" =~ ^[0-9]+$ ]] || return 1
    descriptor_path="/proc/$BASHPID/fd/$inherited"
    [ "$(readlink "$descriptor_path" 2>/dev/null)" = "$lock_file" ] \
      && [ "$(stat -Lc '%d:%i:%u:%a:%h' "$descriptor_path" 2>/dev/null)" \
        = "$(stat -c '%d:%i:%u:%a:%h' "$lock_file")" ] || {
      echo '::error::inherited Kind publication lock differs from the selected registry' >&2
      return 1
    }
  else
    exec {KIND_BUILD_PUBLICATION_LOCK_FD}<>"$lock_file" || return $?
    KIND_BUILD_PUBLICATION_LOCK_OPENED_HERE=1
  fi
  export KIND_BUILD_PUBLICATION_LOCK_FD
  flock -w "$KIND_HOST_LOCK_TIMEOUT_SECONDS" "$KIND_BUILD_PUBLICATION_LOCK_FD" || return $?
  descriptor_path="/proc/$BASHPID/fd/$KIND_BUILD_PUBLICATION_LOCK_FD"
  [ ! -L "$lock_file" ] \
    && [ "$(stat -Lc '%d:%i:%u:%a:%h' "$descriptor_path")" \
      = "$(stat -c '%d:%i:%u:%a:%h' "$lock_file")" ] \
    && [ "$(stat -c '%u:%a:%h' "$lock_file")" = "$(id -u):600:1" ] || {
    echo '::error::Kind publication lock was replaced while waiting' >&2
    return 1
  }
}

release_kind_build_publication_lock() {
  [ "$KIND_BUILD_PUBLICATION_LOCK_OPENED_HERE" = 1 ] || return 0
  [ -n "${KIND_BUILD_PUBLICATION_LOCK_FD:-}" ] || return 0
  exec {KIND_BUILD_PUBLICATION_LOCK_FD}>&-
  unset KIND_BUILD_PUBLICATION_LOCK_FD
  KIND_BUILD_PUBLICATION_LOCK_OPENED_HERE=0
}

use_kind_profile_smokes() {
  CARGO_CI_DIR="$KIND_PROFILE_SMOKE_DIR"
  cp -- "$KIND_PROFILE_ARTIFACT_DIR/billing-contract-build.jsonl" \
    "$RUN_DIR/billing-contract-build.jsonl" || return $?
}

delete_owned_kind_cluster() {
  kind_profile_verify_node "$ROOT" || return $?
  kind delete cluster --name "$KIND_CLUSTER_NAME" || return $?
  python3 "$ROOT/scripts/dev/kind/cluster-profile.py" mark-deleted \
    --cluster "$CLUSTER" --nonce "$KIND_PROFILE_NONCE" >/dev/null
}

run_kind_down() {
  [ "${KIND_PROFILE:-0}" = 1 ] || {
    echo '::error::kind-down requires an explicit saved CLUSTER profile' >&2
    return 2
  }
  kind_profile_lock "$ROOT" || return $?
  delete_owned_kind_cluster
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

  # Credential logs are safe only for the selected synthetic fixture. Read
  # command/marker projections, never a full object: kubectl template errors
  # can otherwise include the complete object in stderr. Check each pod too,
  # because an older real pod may still exist during a mode transition.
  local credential_identity credential_pods_json credential_pods credential_pod
  local credential_deployment_projection credential_pod_projection
  credential_deployment_projection='{.spec.template.spec.containers[?(@.name=="credential-service")].command}{.spec.template.spec.containers[?(@.name=="credential-service")].env[?(@.name=="CODEWIRE_KIND_CREDENTIAL_FIXTURE")].value}'
  credential_pod_projection='{.spec.containers[?(@.name=="credential-service")].command}{.spec.containers[?(@.name=="credential-service")].env[?(@.name=="CODEWIRE_KIND_CREDENTIAL_FIXTURE")].value}'
  if credential_identity="$(kubectl --context "$context" -n "$NS" \
      get deployment/codewire-credential-service --request-timeout=5s \
      -o "jsonpath-as-json=$credential_deployment_projection" 2>/dev/null)" \
      && jq -es 'length == 2 and .[0] == [["/codewire-kind-fixtures/credential-service"]] and .[1] == ["1"]' \
        <<<"$credential_identity" >/dev/null 2>&1 \
      && credential_pods_json="$(kubectl --context "$context" -n "$NS" get pods \
        -l app.kubernetes.io/name=codewire,app.kubernetes.io/component=credential-service \
        --request-timeout=5s -o 'jsonpath-as-json={.items[*].metadata.name}' 2>/dev/null)" \
      && credential_pods="$(jq -er '
        select(type == "array" and length > 0 and length <= 8 and
          all(.[]; type == "string" and length <= 253 and
            test("^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"))) | .[]
      ' <<<"$credential_pods_json" 2>/dev/null)"; then
    while IFS= read -r credential_pod; do
      if credential_identity="$(kubectl --context "$context" -n "$NS" \
          get "pod/$credential_pod" --request-timeout=5s \
          -o "jsonpath-as-json=$credential_pod_projection" 2>/dev/null)" \
          && jq -es 'length == 2 and .[0] == [["/codewire-kind-fixtures/credential-service"]] and .[1] == ["1"]' \
            <<<"$credential_identity" >/dev/null 2>&1; then
        printf '\nSynthetic credential fixture diagnostics: %s\n' "$credential_pod"
        kubectl --context "$context" -n "$NS" get "pod/$credential_pod" \
          --request-timeout=5s \
          -o 'jsonpath={range .status.containerStatuses[?(@.name=="credential-service")]}{"current reason="}{.state.terminated.reason}{" exit_code="}{.state.terminated.exitCode}{"\nprevious reason="}{.lastState.terminated.reason}{" exit_code="}{.lastState.terminated.exitCode}{"\n"}{end}' \
          2>/dev/null || true
        kubectl --context "$context" -n "$NS" logs "pod/$credential_pod" \
          -c credential-service --request-timeout=5s --tail=80 --limit-bytes=16384 \
          2>/dev/null || true
        kubectl --context "$context" -n "$NS" logs "pod/$credential_pod" \
          -c credential-service --request-timeout=5s --tail=80 --limit-bytes=16384 --previous \
          2>/dev/null || true
      fi
    done <<<"$credential_pods"
  fi

  kubectl --context "$context" -n "$NS" get svc/codewire-coordinator-nodeport -o wide || true
  kubectl --context "$context" -n "$NS" logs deploy/temporal --tail=80 || true
  kubectl --context "$context" -n "$SANDBOX_NS" get sandboxclaim,sandbox,sandboxtemplate,sandboxwarmpool,pvc,pv -o wide || true
  kubectl --context "$context" -n "$SANDBOX_NS" describe sandboxclaim,sandbox,sandboxtemplate,sandboxwarmpool || true
  kubectl --context "$context" -n "$SANDBOX_NS" get events --sort-by=.lastTimestamp || true
  # Each remaining Sandbox's daemon log, the only record of a terminal or
  # workspace session failure once the shard cluster is deleted.
  local sandbox_pod
  for sandbox_pod in $(kubectl --context "$context" -n "$SANDBOX_NS" get pods \
      --request-timeout=10s -o 'jsonpath={.items[*].metadata.name}' 2>/dev/null); do
    printf '\nSandbox daemon log: %s\n' "$sandbox_pod"
    kubectl --context "$context" -n "$SANDBOX_NS" logs "pod/$sandbox_pod" -c workspace \
      --request-timeout=10s --tail=400 --limit-bytes=262144 2>/dev/null || true
  done
  kubectl --context "$context" -n "$NS" get events --sort-by=.lastTimestamp || true
  kubectl --context "$context" -n ingress-nginx describe pods || true
  kubectl --context "$context" -n ingress-nginx get events --sort-by=.lastTimestamp || true
  kubectl --context "$context" -n ingress-nginx logs deploy/ingress-nginx-controller --tail=80 || true
  kubectl --context "$context" -n agent-sandbox-system logs -l app=agent-sandbox-controller --tail=160 --all-containers || true
}

cleanup() {
  local status="${1:-$?}"
  stop_workspace_image_load
  if [ "$status" -ne 0 ]; then
    dump_cluster_state
  fi
  stop_remote_dind_kind_forwarding
  if [ "$KEEP_KIND_CLUSTER" != "1" ]; then
    if [ "${KIND_PROFILE:-0}" = 1 ]; then
      # No deletion on a failed precondition or failed ownership read. A name
      # alone is never authority over an existing retained cluster.
      if [ "$KIND_CREATED_BY_TRANSACTION" = 1 ]; then
        if ! delete_owned_kind_cluster; then
          [ "$status" -ne 0 ] || status=1
        fi
      fi
    else
      if [ "$KIND_CREATED_BY_TRANSACTION" = 1 ]; then
        local current_node_id
        current_node_id="$(docker container inspect --format '{{.Id}}' \
          "${KIND_CLUSTER_NAME}-control-plane" 2>/dev/null)" || current_node_id=""
        if [ "$current_node_id" = "$KIND_TRANSACTION_NODE_ID" ] \
            && [[ "$current_node_id" =~ ^[0-9a-f]{64}$ ]]; then
          kind delete cluster --name "$KIND_CLUSTER_NAME" >/dev/null 2>&1 || {
            [ "$status" -ne 0 ] || status=1
          }
        else
          echo '::error::legacy transaction node identity changed; preserving the cluster' >&2
          [ "$status" -ne 0 ] || status=1
        fi
      fi
    fi
  fi
  exit "$status"
}

assert_kind_idp_topology() {
  local issuer ingress_paths

  issuer="$(kubectl -n "$NS" get configmap codewire-config \
    -o jsonpath='{.data.PUBLIC_OIDC_ISSUER_URL}')" || return $?
  if [ "$issuer" != "$KIND_INGRESS_URL" ]; then
    echo "::error::Kind IdP issuer must match the host ingress: expected ${KIND_INGRESS_URL}, got ${issuer:-missing}"
    return 1
  fi

  kubectl -n "$NS" get deployment/codewire-idp >/dev/null || return $?
  kubectl -n "$NS" get service/codewire-idp >/dev/null || return $?
  ingress_paths="$(kubectl -n "$NS" get ingress codewire-idp-e2e \
    -o jsonpath='{range .spec.rules[*].http.paths[*]}{.path}{"\n"}{end}')" || return $?
  for required_path in \
      /api/oauth /api/auth/sign-up /api/auth/sign-in /api/auth/sessions /api/oidc \
      /.well-known/openid-configuration /.well-known/jwks.json; do
    if ! grep -Fqx "$required_path" <<<"$ingress_paths"; then
      echo "::error::Kind IdP ingress is missing permanent raw path ${required_path}"
      return 1
    fi
  done
}

retained_suite_cleanup() {
  local status=$?
  if [ "$KIND_SHARD_TRANSACTION" = 1 ]; then
    if [ -n "$RETAINED_KUBECONFIG" ]; then
      rm -f "$RETAINED_KUBECONFIG" || { [ "$status" -ne 0 ] || status=1; }
    fi
    cleanup "$status"
  fi
  if [ "$status" -ne 0 ]; then
    dump_cluster_state
  fi
  if [ -n "$RETAINED_KUBECONFIG" ]; then
    rm -f "$RETAINED_KUBECONFIG"
  fi
  log "retained suite left Kind cluster ${KIND_CLUSTER_NAME} intact"
  exit "$status"
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "::error::missing required tool: $tool"
    exit 1
  fi
}

# Bash ignores errexit for every command inside a function or subshell that
# runs as part of an && or || list, an if, while or until condition, or after
# !, even when that body sets -e again: a failed unchecked step falls through
# and only the body's last status counts. The Kind suites rely on errexit to
# stop at their unchecked kubectl, jq, cw and smoke-binary steps, so every
# suite entry runs, and calls its steps, as a plain statement; a failure then
# exits with its own status through the EXIT trap. Refuse to start anywhere
# else, and exit rather than return: that context would ignore a return too.
require_kind_errexit() {
  local probe=0
  if [[ $- == *e* ]]; then
    set +e
    (set -e; false; exit 0)
    probe=$?
    set -e
  fi
  if [ "$probe" -eq 0 ]; then
    echo "::error::${FUNCNAME[1]:-a Kind suite} must run as a plain statement with errexit in force; Bash ignores errexit under &&, ||, if, while, until and !"
    exit 70
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
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    kind_profile_lock "$ROOT" || return $?
    kind_profile_verify_node "$ROOT" || return $?
    kind_profile_verify_artifacts "$ROOT" || return $?
    KIND_PROFILE_ARTIFACTS_VERIFIED=1
    use_kind_profile_smokes || return $?
  fi

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
  if [ "${KIND_PROFILE:-0}" != 1 ]; then
  RETAINED_KUBECONFIG="$(mktemp "$RUN_DIR/retained-kubeconfig.XXXXXX")" || return $?
  if ! kind get kubeconfig "${kubeconfig_args[@]}" --name "$KIND_CLUSTER_NAME" \
      >"$RETAINED_KUBECONFIG"; then
    echo "::error::failed to pin kubeconfig for retained Kind cluster ${KIND_CLUSTER_NAME}"
    return 1
  fi
  export KUBECONFIG="$RETAINED_KUBECONFIG"
  fi
  if ! kubectl --context "$expected_context" cluster-info --request-timeout=10s >/dev/null 2>&1; then
    echo "::error::retained Kind context ${expected_context} is not reachable"
    return 1
  fi

  # Callers check this function with ||, which disables errexit inside it.
  require_available_deployment "$NS" postgres || return $?
  require_available_deployment "$NS" temporal || return $?
  require_available_deployment "$NS" codewire-billing || return $?
  require_available_deployment "$NS" codewire-orchestration || return $?
  require_available_deployment "$NS" codewire-coordinator || return $?
  require_available_deployment agent-sandbox-system agent-sandbox-controller || return $?
  if ! kubectl --request-timeout=10s get \
      crd/sandboxclaims.extensions.agents.x-k8s.io >/dev/null 2>&1; then
    echo "::error::retained Kind cluster is missing the SandboxClaim CRD"
    return 1
  fi
  log "retained Kind cluster ${KIND_CLUSTER_NAME} identity and runtime prerequisites accepted"
}

validate_retained_cluster() {
  local prepared_version prepared_cluster prepared_workspace expected_workspace
  local marker_configmap

  validate_retained_cluster_identity || return $?
  marker_configmap="$(kind_e2e_prepared_configmap)"
  if ! prepared_version="$(kubectl --request-timeout=10s -n "$NS" get \
      "configmap/${marker_configmap}" \
      -o jsonpath='{.data.compatibility_version}' 2>&1)"; then
    # A cluster prepared before the marker was cluster-scoped still carries
    # the legacy unscoped name; the cluster-name field below remains the
    # exact binding either way.
    marker_configmap="$KIND_E2E_PREPARED_CONFIGMAP"
    if ! prepared_version="$(kubectl --request-timeout=10s -n "$NS" get \
        "configmap/${marker_configmap}" \
        -o jsonpath='{.data.compatibility_version}' 2>&1)"; then
      echo "::error::retained Kind cluster ${KIND_CLUSTER_NAME} is unprepared: ${prepared_version}"
      return 1
    fi
  fi
  prepared_cluster="$(kubectl --request-timeout=10s -n "$NS" get \
    "configmap/${marker_configmap}" -o jsonpath='{.data.cluster-name}')"
  if [ "$prepared_version" != "$KIND_E2E_COMPATIBILITY_VERSION" ] \
      || [ "$prepared_cluster" != "$KIND_CLUSTER_NAME" ]; then
    echo "::error::retained Kind cluster marker is incompatible: version=${prepared_version:-missing} cluster=${prepared_cluster:-missing}; want version=${KIND_E2E_COMPATIBILITY_VERSION} cluster=${KIND_CLUSTER_NAME}"
    return 1
  fi

  prepared_workspace="$(kubectl --request-timeout=10s -n "$NS" get \
    "configmap/${marker_configmap}" -o jsonpath='{.data.workspace-image}')" || return $?
  expected_workspace="$(kind_workspace_runtime_image)" || return $?
  if [ "$prepared_workspace" != "$expected_workspace" ]; then
    echo '::error::retained Kind workspace image does not match its verified source' >&2
    return 1
  fi
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    local binding node_id manifest_sha
    node_id="$(docker container inspect --format '{{.Id}}' "${KIND_CLUSTER_NAME}-control-plane")" || return $?
    manifest_sha="$(sha256sum "$KIND_PROFILE_IMAGE_MANIFEST" | cut -d' ' -f1)" || return $?
    binding="$(kubectl --request-timeout=10s -n "$NS" get \
      "configmap/${marker_configmap}" -o json)" || return $?
    if ! jq -e --arg nonce "$KIND_PROFILE_NONCE" --arg node "$node_id" \
        --arg manifest "$manifest_sha" --arg head "$KIND_PROFILE_SOURCE_HEAD" \
        --arg tree "$KIND_PROFILE_SOURCE_TREE" '
          .data["profile-nonce"] == $nonce and .data["node-id"] == $node and
          .data["artifact-sha256"] == $manifest and .data["source-head"] == $head and
          .data["source-tree"] == $tree' <<<"$binding" >/dev/null; then
      echo '::error::retained prepared marker does not match the saved profile/node/artifact identity' >&2
      return 1
    fi
  fi

  log "retained Kind cluster ${KIND_CLUSTER_NAME} accepted at compatibility version ${KIND_E2E_COMPATIBILITY_VERSION}"
  renew_retained_synthetic_bearer
}

# A retained cluster outlives the four-hour synthetic product bearer and user
# sessions that the contract seed issues (tests/fixtures/billing/seed.sql).
# Renew only those seeded lifetimes, never the deliberately expired session, so
# a retained suite authenticates as on a fresh cluster.
renew_retained_synthetic_bearer() {
  local renewed
  renewed="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 -qtAc \
      "UPDATE oidc_access_tokens SET expires_at = NOW() + INTERVAL '4 hours'
         WHERE token_hash = encode(digest('at_kind_connect_oidc_codewire_api', 'sha256'), 'hex')
           AND client_id = 'oidc_kind_connect' RETURNING 1")" || return $?
  if [ "$(printf '%s' "$renewed" | tr -d '[:space:]')" != 1 ]; then
    echo '::error::retained Kind cluster lacks the seeded synthetic product bearer' >&2
    return 1
  fi
  renewed="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 -qtAc \
      "UPDATE sessions SET expires_at = NOW() + INTERVAL '4 hours'
         WHERE (id, token_hash) IN (
           ('ses_contract_admin', encode(digest('contract-admin-session-token', 'sha256'), 'hex')),
           ('ses_contract_user', encode(digest('contract-user-session-token', 'sha256'), 'hex')))
         RETURNING 1")" || return $?
  if [ "$(printf '%s' "$renewed" | tr -d '[:space:]')" != 11 ]; then
    echo '::error::retained Kind cluster lacks the seeded contract sessions' >&2
    return 1
  fi
  log "renewed the seeded synthetic product bearer and contract sessions"
}

# The prepared marker is scoped to its own cluster: parallel CI shard clusters
# and successive local clusters on one daemon can never alias one marker name.
# The exact cluster binding remains the marker's cluster-name data field.
kind_e2e_prepared_configmap() {
  local sanitized
  sanitized="$(printf '%s' "$KIND_CLUSTER_NAME" | tr 'A-Z_' 'a-z-')"
  printf '%s-%s\n' "$KIND_E2E_PREPARED_CONFIGMAP" "$sanitized"
}

mark_retained_cluster_prepared() {
  local workspace_image
  local -a profile_binding=()
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    local node_id manifest_sha
    kind_profile_verify_node "$ROOT" || return $?
    node_id="$(docker container inspect --format '{{.Id}}' "${KIND_CLUSTER_NAME}-control-plane")" || return $?
    manifest_sha="$(sha256sum "$KIND_PROFILE_IMAGE_MANIFEST" | cut -d' ' -f1)" || return $?
    profile_binding=(--from-literal="profile-nonce=$KIND_PROFILE_NONCE"
      --from-literal="node-id=$node_id" --from-literal="artifact-sha256=$manifest_sha"
      --from-literal="source-head=$KIND_PROFILE_SOURCE_HEAD"
      --from-literal="source-tree=$KIND_PROFILE_SOURCE_TREE")
  fi
  log "marking Kind cluster ${KIND_CLUSTER_NAME} prepared for retained suites"
  kubectl -n "$NS" create configmap "$(kind_e2e_prepared_configmap)" \
    --from-literal="compatibility_version=${KIND_E2E_COMPATIBILITY_VERSION}" \
    --from-literal="cluster-name=${KIND_CLUSTER_NAME}" \
    --from-literal="workspace-image=$workspace_image" \
    "${profile_binding[@]}" \
    --dry-run=client -o yaml | kubectl_apply -f -
}

# A retained development cluster records, on each Deployment, the source its
# images were just built from (scripts/dev/kind/deploy-service.sh), so
# `make kind-test` deploys only what later differs. Best-effort: a service it
# cannot record is rebuilt on the first `make kind-test`.
record_retained_cluster_sources() {
  local service
  [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = build-ci ] || return 0
  for service in idp orchestration credential-service billing coordinator mesh dashboard daemon; do
    KIND_DEPLOY_RECORD_ONLY=1 "$ROOT/scripts/dev/kind/deploy-service.sh" "$service" \
      || log "could not record the source of ${service}; make kind-test will rebuild it"
  done
}

reclaim_cancelled_ci_clusters() {
  local kind_config="$1"
  local clusters cluster running_containers ports port owners

  if ! clusters="$(kind get clusters 2>&1)"; then
    echo "::error::failed to enumerate Kind clusters before e2e startup: ${clusters}"
    return 1
  fi

  while IFS= read -r cluster; do
    case "$cluster" in
      "$KIND_CLUSTER_NAME")
        echo "::error::Kind cluster ${cluster} already exists; use a fresh verification profile or make kind-test"
        return 1
        ;;
    esac
  done <<< "$clusters"

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

  # The checked-in config names the default host ports; this run binds their
  # requested renderings, so the ownership check runs against those. A saved
  # profile's config is already rendered to its own requested ports.
  local requested requested_ports=""
  while IFS= read -r port; do
    if [ "${KIND_PROFILE:-0}" = 1 ]; then
      if ! kind_host_port_mappings | awk -F: -v port="$port" \
          '$2 == port { found = 1 } END { exit !found }'; then
        echo "::error::Kind profile config host port ${port} is not one of its KIND_*_HOST_PORT values"
        return 1
      fi
      requested="$port"
    elif ! requested="$(awk -F: -v port="$port" \
        '$1 == port { print $2; found = 1 } END { exit !found }' \
        < <(kind_host_port_mappings))"; then
      echo "::error::Kind config host port ${port} has no KIND_*_HOST_PORT mapping"
      return 1
    fi
    requested_ports+="${requested}"$'\n'
  done <<< "$ports"

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
  done <<< "$requested_ports"
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
  PROBE_HEADERS="$(mktemp)" || return $?
  for i in $(seq 1 15); do
    PROBE_BODY="$(curl -s -D "$PROBE_HEADERS" "$@")" || return $?
    PROBE_CODE="$(awk 'NR==1{print $2}' "$PROBE_HEADERS")" || return $?
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
    daemon) ;;
    *)
      echo "::error::unsupported environment auth token scope: $scope" >&2
      return 1
      ;;
  esac
  secret="$(
    kubectl -n "$NS" get secret codewire-secrets \
      -o jsonpath='{.data.SESSION_SECRET}' | base64 --decode
  )" || return $?
  payload="$(printf '{"environment_id":"%s","scope":"%s"}' "$environment_id" "$scope")" || return $?
  encoded_payload="$(
    printf '%s' "$payload" | openssl base64 -A | tr '+/' '-_' | tr -d '='
  )" || return $?
  signature="$(
    printf '%s' "$encoded_payload" \
      | openssl dgst -sha256 -hmac "$secret" -binary \
      | openssl base64 -A | tr '+/' '-_' | tr -d '='
  )" || return $?
  printf '%s.%s' "$encoded_payload" "$signature"
}

daemon_auth_token_for_environment() {
  auth_token_for_environment_scope "$1" daemon
}

# Mirrors codewire_server_core::peer_token::issue, whose pinned wire vector
# scripts/ci/tests/test-kind-build-workflow.py also checks against this
# function: claims in a fixed order, signed with a key derived from the
# session secret for peer tokens only.
peer_token() {
  local secret="$1" environment_id="$2" generation="$3" expires_at="$4"
  local encoded_payload derived_key signature
  case "$generation" in
    '' | *[!0-9]* | 0)
      echo "::error::peer token needs a positive operation generation, got '$generation'" >&2
      return 1
      ;;
  esac
  encoded_payload="$(
    printf '{"environment_id":"%s","exp":%s,"generation":%s,"scope":"peer"}' \
      "$environment_id" "$expires_at" "$generation" \
      | openssl base64 -A | tr '+/' '-_' | tr -d '='
  )"
  derived_key="$(
    printf '%s' 'codewire/environment-peer-token/v1' \
      | openssl dgst -sha256 -hmac "$secret" -hex | sed 's/^.*= //'
  )"
  signature="$(
    printf '%s' "$encoded_payload" \
      | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${derived_key}" -binary \
      | openssl base64 -A | tr '+/' '-_' | tr -d '='
  )"
  printf '%s.%s' "$encoded_payload" "$signature"
}

# A peer token for an environment at its current operation generation,
# valid for nine of the coordinator's ten-minute lifetime.
peer_token_for_environment() {
  local environment_id="$1" secret generation
  secret="$(
    kubectl -n "$NS" get secret codewire-secrets \
      -o jsonpath='{.data.SESSION_SECRET}' | base64 --decode
  )"
  generation="$(
    kubectl -n "$NS" exec deploy/postgres -- \
      psql -U codewire -d codewire -Atq -v ON_ERROR_STOP=1 \
      -c "SELECT environment_operation_generation FROM environments WHERE id = '$environment_id'"
  )"
  peer_token "$secret" "$environment_id" "$generation" "$(($(date +%s) + 540))"
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

prepare_kind_profile_runtime_inputs() {
  # Product images and clients are sealed in the profile. Workspace acceptance
  # belongs to the invoking checkout, and fixed support images may have been
  # removed from Docker. Resolve both before creating a replacement node.
  acquire_kind_build_publication_lock || return $?
  case "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" in
    build-ci)
      "$ROOT/scripts/ci/verify/verify-workspace-image.sh" || return $?
      ;;
    prebuilt-ci)
      RUN_DIR="$RUN_DIR" \
        EXPECTED_MANIFEST_SHA256="${CODEWIRE_KIND_WORKSPACE_MANIFEST_SHA256:?missing workspace producer digest}" \
        python3 "$ROOT/scripts/ci/verify/kind-build-artifacts.py" consume workspace \
          "${CODEWIRE_KIND_ARTIFACT_ROOT:?missing private artifact directory}/workspace" || return $?
      ;;
    *) return 2 ;;
  esac
  prepare_kind_support_images || return $?
  release_kind_build_publication_lock
}

build_images_and_smokes() {
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    local reuse_status=0
    python3 "$ROOT/scripts/ci/verify/kind/profile-artifacts.py" reuse \
      --root "$ROOT" --cargo-ci-dir "$KIND_SMOKE_BUILD_DIR" --run-dir "$RUN_DIR" || reuse_status=$?
    case "$reuse_status" in
      0)
        log 'reusing the admitted exact source image archive and smoke inventory'
        prepare_kind_profile_runtime_inputs || return $?
        use_kind_profile_smokes
        return $?
        ;;
      3) ;; # No admitted base yet: run the bounded producer transaction.
      *) return "$reuse_status" ;;
    esac
  fi
  acquire_kind_build_publication_lock || return $?
  case "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" in
    build-ci)
      log "verifying the canonical source workspace image once for Kind"
      "$ROOT/scripts/ci/verify/rehearse-build-local-image.sh" || return $?
      "$ROOT/scripts/ci/verify/verify-workspace-image.sh" || return $?
      log "building exact candidate product images once through the Kind Bake targets"
      local source_head
      source_head="$(git -C "$ROOT" rev-parse HEAD)" || return $?
      CODEWIRE_IMAGE_SOURCE_SHA="$source_head" \
        CODEWIRE_BAKE_METADATA_FILE="$RUN_DIR/kind-image-build-metadata.json" \
        "$ROOT/scripts/ci/images/build-kind-images.sh" || return $?
      ;;
    prebuilt-release)
      log "using exact prebuilt protected release images without rebuilding"
      assert_prebuilt_release_product_images || return $?
      ;;
    prebuilt-ci)
      log "importing exact same-run CI artifacts without rebuilding"
      local group manifest
      for group in workspace product daemon smokes; do
        case "$group" in
          workspace) manifest="${CODEWIRE_KIND_WORKSPACE_MANIFEST_SHA256:?missing workspace producer digest}" ;;
          product) manifest="${CODEWIRE_KIND_PRODUCT_MANIFEST_SHA256:?missing product producer digest}" ;;
          daemon) manifest="${CODEWIRE_KIND_DAEMON_MANIFEST_SHA256:?missing daemon producer digest}" ;;
          smokes) manifest="${CODEWIRE_KIND_SMOKES_MANIFEST_SHA256:?missing smoke producer digest}" ;;
        esac
        RUN_DIR="$RUN_DIR" EXPECTED_MANIFEST_SHA256="$manifest" \
          python3 "$ROOT/scripts/ci/verify/kind-build-artifacts.py" consume "$group" \
            "${CODEWIRE_KIND_ARTIFACT_ROOT:?missing private artifact directory}/$group" || return $?
      done
      ;;
    *)
      echo "::error::CODEWIRE_KIND_PRODUCT_IMAGE_MODE must be build-ci, prebuilt-ci or prebuilt-release"
      return 2
      ;;
  esac

  log "verifying the exact dashboard candidate runtime contract"
  "$ROOT/scripts/ci/verify/dashboard-image.sh" "codewire-dashboard:e2e" || return $?

  prepare_kind_support_images || return $?

  # `kind-e2e.sh up` deploys for manual testing and runs no smoke suite.
  if [ "${KIND_BUILD_SMOKES:-1}" = 1 ] \
      && [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" != prebuilt-ci ]; then
    log "building Rust kind smoke binaries"
    "$ROOT/scripts/ci/images/build-kind-smokes.sh" "$RUN_DIR/billing-contract-build.jsonl" || return $?
  fi
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    # A named retained cluster saves the complete smoke inventory at creation;
    # future tests never read a concurrent worktree's mutable target directory.
    if [ "${KIND_BUILD_SMOKES:-1}" != 1 ] \
        && [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" != prebuilt-ci ]; then
      "$ROOT/scripts/ci/images/build-kind-smokes.sh" "$RUN_DIR/billing-contract-build.jsonl" || return $?
    fi
    python3 "$ROOT/scripts/ci/verify/kind/profile-artifacts.py" seal \
      --root "$ROOT" --cargo-ci-dir "$KIND_SMOKE_BUILD_DIR" --run-dir "$RUN_DIR" || return $?
    kind_profile_load "$ROOT" || return $?
    use_kind_profile_smokes || return $?
  fi
  release_kind_build_publication_lock
}

# The smoke build groups (scripts/dev/kind/build-smokes.sh) whose binaries each
# retained suite runs. test-kind-dev-profile.py checks every smoke a suite's
# functions run is in one of its groups.
kind_suite_smoke_groups() {
  case "$1" in
    edge-contract | final-fencing | runtime-acceptance) printf '%s\n' orchestration ;;
    credentials) printf '%s\n' cli ;;
    workspace-services) printf '%s\n' orchestration client cli ;;
    integrated) printf '%s\n' client-kind-e2e billing ;;
    cw-runtime | cw-managed-agents) printf '%s\n' client cli ;;
    *)
      echo "::error::no smoke build groups are mapped for the Kind suite ${1:-missing}" >&2
      return 2
      ;;
  esac
}

# Retained suites rerun gate steps on a kept cluster. `up` builds no smoke
# binaries, so build them here; cargo makes repeated builds incremental. The CI
# shard legs instead consumed the exact same-run smoke artifact during `up`
# (kind-build-artifacts.py SMOKE_FILES/TEST_FILES), so rebuilding there would
# redo the producer's work on an empty cache; verify the consumed set instead.
# The argument names the calling suite.
build_retained_kind_smokes() {
  local suite="${1:-}" groups
  if [ -z "$suite" ]; then
    echo "::error::build_retained_kind_smokes needs the calling suite"
    return 2
  fi
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    if [ "$KIND_PROFILE_ARTIFACTS_VERIFIED" != 1 ]; then
      kind_profile_verify_artifacts "$ROOT" || return $?
    fi
    use_kind_profile_smokes
    return $?
  fi
  mkdir -p "$RUN_DIR"
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = prebuilt-ci ]; then
    local consumed missing=0
    for consumed in \
        crd-smoke environment-setup-smoke exec-smoke exec-stream-smoke \
        file-service-smoke prepare-stream-smoke log-stream-smoke temporal-smoke \
        temporal-fencing-smoke reconciler-ttl-smoke cw \
        examples/platform-run-smoke examples/environment-session-smoke \
        examples/environment-cw-runtime-smoke \
        examples/coordinator-ingress-smoke; do
      if [ ! -x "$CARGO_CI_DIR/$consumed" ]; then
        echo "::error::consumed Kind smoke binary is missing: ${CARGO_CI_DIR}/${consumed}; rerun kind-e2e.sh up"
        missing=1
      fi
    done
    if [ ! -f "$RUN_DIR/billing-contract-build.jsonl" ]; then
      echo "::error::consumed Kind smoke build receipt is missing: ${RUN_DIR}/billing-contract-build.jsonl; rerun kind-e2e.sh up"
      missing=1
    fi
    [ "$missing" -eq 0 ] || return 1
    log "consumed Kind smoke binaries verified for the retained suite"
    return 0
  fi
  if [ "${KIND_RETAINED_USE_CLUSTER_WORKSPACE:-0}" = 1 ]; then
    # `make kind-test` deploys changed services from this worktree's kind-dev
    # BuildKit target (scripts/dev/kind/deploy-service.sh). Building the smokes
    # and the host cw in that target links what the deploy already compiled
    # instead of compiling the product a second time on the host. Only this
    # suite's groups build, each once per make kind-test run (#2973).
    groups="$(kind_suite_smoke_groups "$suite")" || return $?
    CARGO_CI_DIR="$ROOT/.tmp/kind-dev/${KIND_CLUSTER_NAME}/smokes"
    log "building the ${suite} suite's Rust kind smoke binaries (${groups//$'\n'/ }) in the kind-dev target"
    # shellcheck disable=SC2086 # One word per group.
    KIND_CLUSTER_NAME="$KIND_CLUSTER_NAME" "$ROOT/scripts/dev/kind/build-smokes.sh" \
      "$CARGO_CI_DIR" "$RUN_DIR/billing-contract-build.jsonl" $groups
    return $?
  fi
  log "building Rust kind smoke binaries for the retained suite"
  "$ROOT/scripts/ci/images/build-kind-smokes.sh" "$RUN_DIR/billing-contract-build.jsonl"
}

assert_prebuilt_release_product_images() {
  local expected_sha="${CODEWIRE_KIND_EXPECTED_SOURCE_SHA:-}"
  local image image_ref profile promotable revision

  if ! [[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "::error::prebuilt release images require one exact expected source SHA"
    return 2
  fi
  for image in dashboard services mesh daemon; do
    image_ref="codewire-${image}:e2e"
    docker image inspect "$image_ref" >/dev/null || {
      echo "::error::prebuilt release image is missing: ${image_ref}"
      return 1
    }
    profile="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.build.profile" }}' "$image_ref")"
    promotable="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.promotable" }}' "$image_ref")"
    revision="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image_ref")"
    if [ "$profile" != runtime ] || [ "$promotable" != true ] \
        || [ "$revision" != "$expected_sha" ]; then
      echo "::error::prebuilt release image identity mismatch: ${image_ref}"
      return 1
    fi
  done
}

create_cluster() {
  local kind_config rendered_kind_config
  local clusters
  clusters="$(kind get clusters)" || return $?
  if grep -Fxq "$KIND_CLUSTER_NAME" <<<"$clusters"; then
    echo "::error::Kind cluster already exists; it cannot be replaced implicitly"
    return 1
  fi
  require_kind_host_ports_available "$KIND_CLUSTER_NAME" || return $?

  log "checking Docker runtime for kind"
  docker version || return $?
  docker info --format 'Server={{.ServerVersion}} Driver={{.Driver}} CgroupDriver={{.CgroupDriver}} SecurityOptions={{json .SecurityOptions}}' || docker info || true

  log "creating kind cluster ${KIND_CLUSTER_NAME}"
  kind_config="$KIND_CONFIG"
  rendered_kind_config="$RUN_DIR/kind-config.yaml"
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    python3 "$ROOT/scripts/dev/kind/cluster-profile.py" render-config \
      --cluster "$CLUSTER" --template "$ROOT/tests/e2e/kind/kind-config.yaml" >/dev/null || return $?
    rendered_kind_config="$KIND_CONFIG"
  else
    render_kind_host_port_mappings "$kind_config" "$rendered_kind_config" || return $?
  fi
  local create_status=0
  kind create cluster --name "$KIND_CLUSTER_NAME" --config "$rendered_kind_config" --wait 120s || create_status=$?
  if [ "$create_status" -ne 0 ]; then
    # A failed create cannot prove that a node now visible under this name was
    # created by this transaction. Preserve it for diagnosis rather than adopt
    # and delete it from the exit handler.
    echo "::error::kind cluster creation failed; preserving any node with unconfirmed ownership. This gate needs a privileged Docker runtime capable of starting kind node containers."
    return "$create_status"
  fi
  if docker container inspect "${KIND_CLUSTER_NAME}-control-plane" >/dev/null 2>&1; then
    local node_id
    node_id="$(docker container inspect --format '{{.Id}}' "${KIND_CLUSTER_NAME}-control-plane")" || return $?
    if ! [[ "$node_id" =~ ^[0-9a-f]{64}$ ]]; then
      echo '::error::created Kind node identity is invalid' >&2
      return 1
    fi
    if [ "${KIND_PROFILE:-0}" = 1 ]; then
      python3 "$ROOT/scripts/dev/kind/cluster-profile.py" record-node \
        --cluster "$CLUSTER" --nonce "$KIND_PROFILE_NONCE" --node-id "$node_id" >/dev/null || return $?
    fi
    KIND_TRANSACTION_NODE_ID="$node_id"
    KIND_CREATED_BY_TRANSACTION=1
  else
    echo '::error::Kind reported creation success without the expected node; ownership is unconfirmed' >&2
    return 1
  fi
  log_kind_bound_endpoints
  configure_remote_dind_kind_network || return $?
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
    --forward "${KIND_INGRESS_HOST_PORT}:80" \
    --forward "${KIND_INGRESS_TLS_HOST_PORT}:443" \
    --forward "${KIND_TEMPORAL_HOST_PORT}:30733" \
    --forward "${KIND_ORCHESTRATION_HOST_PORT}:30084" \
    --forward "${KIND_COORDINATOR_DIRECT_HOST_PORT}:30090" \
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
    "$REMOTE_DIND_JOB_CONTAINER" || return $?

  kubeconfig_path="${KUBECONFIG:-$HOME/.kube/config}"
  if [[ "$kubeconfig_path" == *:* ]]; then
    echo "::error::remote DinD Kind requires one explicit kubeconfig path"
    return 1
  fi
  mkdir -p "$(dirname "$kubeconfig_path")" || return $?
  kubeconfig_tmp="$(mktemp "${kubeconfig_path}.internal.XXXXXX")"
  chmod 600 "$kubeconfig_tmp" || return $?
  if ! kind get kubeconfig --internal --name "$KIND_CLUSTER_NAME" \
      >"$kubeconfig_tmp"; then
    shred -u "$kubeconfig_tmp"
    echo "::error::failed to render internal Kind kubeconfig for remote DinD"
    return 1
  fi
  install -m 600 "$kubeconfig_tmp" "$kubeconfig_path" || return $?
  shred -u "$kubeconfig_tmp" || return $?

  start_remote_dind_kind_forwarding "$node" || return $?
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
    echo "::error::sealed Kind inputs must match the five approved Harbor digests"
    return 2
  fi
}

kind_workspace_runtime_image() {
  # Local development (`make kind-test`) reruns retained suites against the
  # cluster as deployed, from a worktree that has usually changed since. There
  # the cluster's recorded workspace image is authoritative; the gate and CI
  # never set this and keep the verified-source receipt below.
  if [ "${KIND_RETAINED_USE_CLUSTER_WORKSPACE:-0}" = 1 ]; then
    local marker_configmap workspace_image
    marker_configmap="$(kind_e2e_prepared_configmap)"
    if workspace_image="$(kubectl --request-timeout=10s -n "$NS" get \
        "configmap/${marker_configmap}" \
        -o jsonpath='{.data.workspace-image}' 2>/dev/null)"; then
      printf '%s' "$workspace_image"
      return 0
    fi
    kubectl --request-timeout=10s -n "$NS" get \
      "configmap/${KIND_E2E_PREPARED_CONFIGMAP}" -o jsonpath='{.data.workspace-image}'
    return $?
  fi
  local sealed_status=0
  validate_sealed_kind_images || sealed_status=$?
  [ "$sealed_status" -le 1 ] || return "$sealed_status"
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" = prebuilt-ci ]; then
    # The consumed workspace artifact selected either the exact-source build
    # or the published pin pulled by digest; the helper proves either one.
    python3 "$ROOT/scripts/ci/verify/kind-build-artifacts.py" workspace-image
    return $?
  fi
  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" != prebuilt-release ]; then
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
      docker pull "$source" || return $?
    fi
  done
  for source in \
      "$KIND_POSTGRES_IMAGE|$KIND_POSTGRES_LOCAL_IMAGE" \
      "$KIND_TEMPORAL_IMAGE|$KIND_TEMPORAL_LOCAL_IMAGE"; do
    alias="${source#*|}"
    source="${source%%|*}"
    docker image tag "$source" "$alias" || return $?
  done
  prepare_kind_credential_support_images || return $?
}

# Kind suites that never run a Sandbox, and so never need the workspace image
# in the node. Any other suite, and a run that names no suites (the full gate,
# `up`), loads it (#2971).
KIND_SUITES_WITHOUT_SANDBOXES=(edge-contract integrated)

kind_suites_need_workspace_image() {
  local suite
  [ "$#" -gt 0 ] || return 0
  for suite in "$@"; do
    [[ " ${KIND_SUITES_WITHOUT_SANDBOXES[*]} " == *" ${suite} "* ]] || return 0
  done
  return 1
}

load_workspace_image_into_kind() {
  local image
  image="$(kind_workspace_runtime_image)" || return $?
  log "loading the selected verified workspace image into Kind"
  kind load docker-image --name "$KIND_CLUSTER_NAME" "$image" || return $?
  wait_for_kind_api_after_image_load
}

# A shard imports its multi-gigabyte workspace image beside the platform
# rollouts instead of before them. Every other image is already in the node,
# and nothing else imports until finish_workspace_image_load, so imports stay
# one at a time with the API recovery gate after each (#2971). A shard whose
# suites run no Sandbox skips the import.
start_workspace_image_load() {
  KIND_WORKSPACE_LOAD_PID=""
  [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" != prebuilt-release ] || return 0
  if ! kind_suites_need_workspace_image "$@"; then
    log "no suite in this shard runs a Sandbox (${*}); the workspace image stays out of Kind"
    return 0
  fi
  KIND_WORKSPACE_LOAD_LOG="$RUN_DIR/workspace-image-load.log"
  log "loading the workspace image into Kind beside the platform rollouts"
  (set -e; load_workspace_image_into_kind) >"$KIND_WORKSPACE_LOAD_LOG" 2>&1 &
  KIND_WORKSPACE_LOAD_PID=$!
}

finish_workspace_image_load() {
  local pid="${KIND_WORKSPACE_LOAD_PID:-}" status=0
  [ -n "$pid" ] || return 0
  wait "$pid" || status=$?
  KIND_WORKSPACE_LOAD_PID=""
  cat "$KIND_WORKSPACE_LOAD_LOG" >&2 || true
  if [ "$status" -ne 0 ]; then
    echo "::error::loading the workspace image into Kind failed (status ${status})"
    return "$status"
  fi
  log "workspace image loaded into Kind"
}

# A failed transaction stops a workspace import still running in the
# background before its cluster is removed.
stop_workspace_image_load() {
  local pid="${KIND_WORKSPACE_LOAD_PID:-}"
  [ -n "$pid" ] || return 0
  KIND_WORKSPACE_LOAD_PID=""
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# The argument `defer-workspace` leaves the workspace image to
# start_workspace_image_load.
load_images_into_kind() {
  local image sealed source alias defer_workspace=0
  [ "${1:-}" != defer-workspace ] || defer_workspace=1

  # Importing several release images back-to-back can make the nested
  # kube-apiserver temporarily unavailable while containerd commits layers.
  # Admit one image at a time and require the control plane to recover before
  # adding the next source of I/O pressure.
  if [ "${KIND_PROFILE:-0}" = 1 ]; then
    kind_profile_verify_node "$ROOT" || return $?
    kind_profile_verify_artifacts "$ROOT" || return $?
    log 'loading sealed source-bound product image archive into Kind'
    kind load image-archive --name "$KIND_CLUSTER_NAME" "$KIND_PROFILE_ARTIFACT_DIR/images.tar" || return $?
    wait_for_kind_api_after_image_load || return $?
  else
  for image in \
      codewire-dashboard:e2e \
      codewire-services:e2e \
      codewire-mesh:e2e \
      codewire-daemon:e2e; do
    log "loading ${image} into kind"
    kind load docker-image --name "$KIND_CLUSTER_NAME" "$image" || return $?
    wait_for_kind_api_after_image_load || return $?
  done
  fi
  for image in "$KIND_POSTGRES_LOCAL_IMAGE" "$KIND_TEMPORAL_LOCAL_IMAGE"; do
    kind load docker-image --name "$KIND_CLUSTER_NAME" "$image" || return $?
    wait_for_kind_api_after_image_load || return $?
  done

  load_kind_credential_support_images || return $?

  if [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" != prebuilt-release ] \
      && [ "$defer_workspace" = 0 ]; then
    load_workspace_image_into_kind || return $?
  fi

  if validate_sealed_kind_images; then
    # The trusted runner boundary pulls these images from Harbor before any
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
      docker image tag "$source" "$alias" || return $?
      if [ "$alias" = "$KIND_WORKSPACE_LOCAL_IMAGE" ] \
          && [ "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" != prebuilt-release ]; then
        # Only release-image runs use the approved workspace. Source and CI
        # runs loaded their selected workspace above; importing this unused
        # multi-gigabyte image cost each shard minutes.
        continue
      fi
      log "loading approved platform image into kind"
      kind load docker-image --name "$KIND_CLUSTER_NAME" "$alias" || return $?
      wait_for_kind_api_after_image_load || return $?
    done
  else
    local sealed_status=$?
    [ "$sealed_status" -eq 1 ] || return "$sealed_status"
  fi
}

# Callers capture each render with a command substitution, where Bash clears
# errexit. Check every render step, or a failed rewrite still prints its path.
render_ingress_manifest() {
  local source="$ROOT/tests/e2e/kind/vendor/ingress-nginx-deploy.yaml"
  local rendered="$RUN_DIR/ingress-nginx-deploy.yaml"

  if validate_sealed_kind_images; then
    python3 - "$source" "$rendered" \
      "$KIND_INGRESS_CONTROLLER_LOCAL_IMAGE" "$KIND_INGRESS_CERTGEN_LOCAL_IMAGE" <<'PY' || return $?
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

  kubectl kustomize "$source" >"$rendered" || return $?
  if validate_sealed_kind_images; then
    python3 - "$rendered" "$KIND_AGENT_SANDBOX_LOCAL_IMAGE" <<'PY' || return $?
from pathlib import Path
import re
import sys

rendered, local_image = sys.argv[1:]
path = Path(rendered)
text = path.read_text()
public_image = "ghcr.io/noeljackson/agent-sandbox-controller@sha256:b00759b0efbf2c654078d30573d3830841d8cbe7896655704bc8268948d72177"
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

  kubectl kustomize "$source" >"$rendered" || return $?
  python3 - "$rendered" "$KIND_POSTGRES_LOCAL_IMAGE" "$KIND_TEMPORAL_LOCAL_IMAGE" <<'PY' || return $?
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
  render_kind_ingress_origin "$rendered" "$KIND_OVERLAY_INGRESS_ORIGINS" || return $?
  if validate_sealed_kind_images; then
    python3 - "$rendered" "$KIND_DIND_LOCAL_IMAGE" <<'PY' || return $?
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
  ingress_manifest="$(render_ingress_manifest)" || return $?
  log "deploying vendored ingress-nginx"
  kubectl_apply --validate=false -f "$ingress_manifest" || return $?
  kubectl wait --namespace ingress-nginx \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/component=controller \
    --timeout=180s || return $?

  deploy_kind_credential_cert_manager || return $?

  log "ensuring isolated kind sandbox namespace"
  kubectl create namespace "$SANDBOX_NS" --dry-run=client -o yaml |
    kubectl_apply -f - || return $?
  kubectl label namespace "$SANDBOX_NS" \
    app.kubernetes.io/managed-by=codewire \
    codewire.sh/resource-type=sandbox \
    codewire.sh/runtime-scope=shared \
    --overwrite || return $?

  log "deploying kind e2e overlay"
  kubectl -n "$NS" delete job codewire-db-migrate --ignore-not-found --wait=true || return $?
  kind_overlay="$(render_kind_overlay_manifest)" || return $?
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
  assert_kind_idp_topology || return $?
  deploy_kind_credential_issuers || return $?
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
    --replicas=0 || return $?

  log "waiting for postgres and temporal (service dependencies)"
  kubectl -n "$NS" rollout status deploy/postgres --timeout=300s || return $?
  kubectl -n "$NS" rollout status deploy/temporal --timeout=600s || return $?

  log "waiting for the standard SQLx application baseline"
  if ! kubectl -n "$NS" wait --for=condition=complete \
      job/codewire-db-migrate --timeout=300s; then
    kubectl -n "$NS" logs job/codewire-db-migrate --all-containers=true || true
    return 1
  fi
  kubectl -n "$NS" logs job/codewire-db-migrate --all-containers=true || return $?
  local expected_migration_rows migration_rows
  expected_migration_rows="$(find "$ROOT/crates/codewire-server-core/migrations" \
    -maxdepth 1 -type f -name '*.sql' ! -name '*.down.sql' -print | wc -l | tr -d '[:space:]')"
  migration_rows="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire -tAc \
      'SELECT count(*) FILTER (WHERE success = true), count(*) FROM _sqlx_migrations')"
  if [ "$migration_rows" != "${expected_migration_rows}|${expected_migration_rows}" ]; then
    echo "::error::expected ${expected_migration_rows} successful SQLx migration rows and no other ledger rows, got ${migration_rows}"
    return 1
  fi

  log "loading billing and coordinator contract fixtures"
  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 < "$ROOT/tests/fixtures/billing/seed.sql" || return $?
  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 < "$ROOT/tests/e2e/kind/coordinator-seed.sql" || return $?

  start_kind_credential_fixture || return $?

  log "starting billing, IdP, primary authorization, Mesh, and coordinator (dependencies ready)"
  kubectl -n "$NS" scale \
    deploy/codewire-billing \
    deploy/codewire-idp \
    deploy/codewire-mesh \
    deploy/codewire-orchestration \
    deploy/codewire-coordinator \
    --replicas=1 || return $?
  kubectl -n "$NS" rollout status deploy/codewire-billing --timeout=300s || return $?
  kubectl -n "$NS" rollout status deploy/codewire-dashboard --timeout=300s || return $?
  kubectl -n "$NS" rollout status deploy/codewire-idp --timeout=300s || return $?
  kubectl -n "$NS" rollout status deploy/codewire-orchestration --timeout=300s || return $?
  kubectl -n "$NS" rollout status deploy/codewire-mesh --timeout=300s || return $?
  kubectl -n "$NS" rollout status deploy/codewire-coordinator --timeout=300s || return $?
}

require_dashboard_browser_host_dependencies() {
  local playwright chromium
  playwright="$ROOT/apps/dashboard/node_modules/.bin/playwright"
  if [ ! -x "$playwright" ]; then
    echo "::error::dashboard Playwright dependencies are missing; run PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 bun install --frozen-lockfile --ignore-scripts"
    return 1
  fi

  # An explicit browser, else the pinned one, installed into this checkout on
  # first use. A system Chromium is another version and would fail below.
  chromium="$(resolve_pinned_playwright_chromium "$ROOT")" || chromium=""
  if [ -z "$chromium" ] || [ ! -x "$chromium" ]; then
    echo "::error::the Kind browser gate requires the pinned Chromium; scripts/ci/install-pinned-playwright-chromium.sh could not provide it"
    return 1
  fi

  # Keep the early host-input boundary identical to the browser suite's own
  # runtime check. An arbitrary system Chromium is present on many developer
  # hosts, but accepting it here only defers a deterministic version or backing
  # failure until after the expensive image and cluster transaction.
  prepare_playwright_browser_runtime "$chromium" "$ROOT" || return $?
}

# The tag apps/dashboard/e2e/helpers/quarantine.ts gives a quarantined test.
DASHBOARD_QUARANTINE_TAG='@quarantine'

dashboard_browser_e2e() (
  local playwright chromium workspace_image credential_fixture workers
  # Playwright's shared auth/report files belong to this checkout. Serialize
  # only the browser phase within one checkout; distinct worktrees and cluster
  # runtime phases remain independent. The subshell releases the descriptor.
  local browser_lock="$ROOT/.tmp/codewire-kind-browser.lock" browser_lock_fd
  mkdir -p "$ROOT/.tmp"
  [ ! -L "$browser_lock" ] || return 1
  if [ ! -e "$browser_lock" ]; then
    (umask 077; set -C; : >"$browser_lock") 2>/dev/null || [ -f "$browser_lock" ] || return 1
  fi
  [ "$(stat -c '%u:%a' "$browser_lock")" = "$(id -u):600" ] || return 1
  exec {browser_lock_fd}<>"$browser_lock"
  flock -w "$KIND_HOST_LOCK_TIMEOUT_SECONDS" "$browser_lock_fd" || return $?
  require_dashboard_browser_host_dependencies || return $?
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  credential_fixture=0
  case "${CODEWIRE_KIND_PRODUCT_IMAGE_MODE:-build-ci}" in
    build-ci|prebuilt-ci)
      if ! kubectl -n "$NS" get deployment/codewire-credential-service -o json | jq -e '
        [.spec.template.spec.containers[] | select(.name == "credential-service")] as $containers |
        ($containers | length) == 1 and
        $containers[0].command == ["/codewire-kind-fixtures/credential-service"] and
        $containers[0].args == [
          "--exact", "runtime::kind::serve_kind_credential_fixture", "--ignored",
          "--nocapture", "--test-threads=1"
        ] and
        ([$containers[0].env[]? |
          select(.name == "CODEWIRE_KIND_CREDENTIAL_FIXTURE" and .value == "1")] | length) == 1
      ' >/dev/null; then
        echo "::error::CI dashboard browser gate requires the exact synthetic credential fixture"
        return 1
      fi
      credential_fixture=1
      ;;
    prebuilt-release) ;;
    *)
      echo "::error::CODEWIRE_KIND_PRODUCT_IMAGE_MODE must be build-ci, prebuilt-ci or prebuilt-release"
      return 2
      ;;
  esac
  playwright="$ROOT/apps/dashboard/node_modules/.bin/playwright"
  chromium="$(resolve_pinned_playwright_chromium "$ROOT")" || return $?

  prepare_playwright_browser_runtime "$chromium" "$ROOT" || return $?

  workers="${CODEWIRE_KIND_DASHBOARD_WORKERS:-1}"
  # `make kind-test` may run part of the suite (KIND_DASHBOARD_SELECTION, #2974):
  # the specs a change affects, the Playwright-changed specs, the @smoke desktop
  # tests, or all but @kind-heavy. The gate and its shards never set it.
  local -a selection=()
  local selected_spec selection_value="${KIND_DASHBOARD_SELECTION:-}"
  case "$selection_value" in
    '') ;;
    smoke) selection=(--grep @smoke --project=dashboard-ssr-desktop) ;;
    light) selection=(--grep-invert @kind-heavy) ;;
    'only-changed '*)
      [[ "${selection_value#only-changed }" =~ ^[0-9a-f]{40}$ ]] || {
        echo "::error::KIND_DASHBOARD_SELECTION only-changed needs one full commit: ${selection_value}"
        return 2
      }
      selection=(--only-changed="${selection_value#only-changed }")
      ;;
    'specs '*)
      for selected_spec in ${selection_value#specs }; do
        if [[ ! "$selected_spec" =~ ^ssr-dashboard\.[a-z0-9-]+\.ssr\.ts$ ]] \
            || [ ! -f "$ROOT/apps/dashboard/e2e/$selected_spec" ]; then
          echo "::error::KIND_DASHBOARD_SELECTION names no Kind dashboard spec: ${selected_spec}"
          return 2
        fi
        selection+=("apps/dashboard/e2e/${selected_spec}")
      done
      ;;
    *)
      echo "::error::unknown KIND_DASHBOARD_SELECTION: ${selection_value}"
      return 2
      ;;
  esac
  if [ "${#selection[@]}" -gt 0 ]; then
    log "running part of the Rust dashboard Playwright suite (${selection_value}) through Kind ingress (workers: ${workers}); not the whole suite"
  else
    log "running full Rust dashboard Playwright suite through Kind ingress (workers: ${workers})"
  fi
  require_get_code /healthz 204 "dashboard health"
  require_get_code /login 200 "dashboard login page"
  local -a browser_env=(
    DATABASE_URL="${KIND_DATABASE_URL}?sslmode=disable"
    SERVER_URL="$KIND_INGRESS_URL"
    PLAYWRIGHT_BASE_URL="$KIND_INGRESS_URL"
    PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE="$workspace_image"
    PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chromium"
    CODEWIRE_PLAYWRIGHT_USE_DEV_SHM="$CODEWIRE_PLAYWRIGHT_USE_DEV_SHM"
    KUBE_CONTEXT="kind-${KIND_CLUSTER_NAME}"
    PLAYWRIGHT_KUBE_CONTEXT="kind-${KIND_CLUSTER_NAME}"
    PLAYWRIGHT_SANDBOX_NAMESPACE="$SANDBOX_NS"
    PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE="$credential_fixture"
  )
  # A test quarantined through apps/dashboard/e2e/helpers/quarantine.ts leaves
  # the blocking run. On a whole-suite run the quarantined tests run after it,
  # in the same cluster, and their result is reported but never fails the
  # suite (#2975).
  local -a blocking=("${selection[@]}")
  if [ "$selection_value" = light ]; then
    blocking=(--grep-invert "@kind-heavy|${DASHBOARD_QUARANTINE_TAG}")
  else
    blocking+=(--grep-invert "$DASHBOARD_QUARANTINE_TAG")
  fi
  env "${browser_env[@]}" \
    "$playwright" test --config "$ROOT/apps/dashboard/playwright.config.ts" --workers="$workers" \
    "${blocking[@]}" || return $?
  if [ -z "$selection_value" ] && grep -lqsF 'quarantine(' "$ROOT"/apps/dashboard/e2e/*.ssr.ts; then
    log "running the quarantined dashboard tests; they never fail the suite"
    if env "${browser_env[@]}" \
        PLAYWRIGHT_JSON_OUTPUT_FILE="$ROOT/apps/dashboard/test-report/quarantine.json" \
        "$playwright" test --config "$ROOT/apps/dashboard/playwright.config.ts" --workers="$workers" \
        --grep "$DASHBOARD_QUARANTINE_TAG" --pass-with-no-tests --reporter=line,json \
        --output="$ROOT/apps/dashboard/test-report/quarantine-results"; then
      log "the quarantined dashboard tests passed"
    else
      echo "::warning::quarantined dashboard tests failed; they do not block (apps/dashboard/test-report/quarantine.json)"
    fi
  fi
)

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
  local migration_005 migration_006 migration_007 network_auth_rows
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
  migration_007="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tA -F '|' -c \
      "SELECT description, success FROM _sqlx_migrations WHERE version = 7")"
  network_auth_rows="$(kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire_mesh -tAc \
      "SELECT count(*) FROM kv WHERE namespace = 'mesh.networkauth'")"
  if [ "$node_registration" != "${network_id}|mesh-kind-node|usr_contract_user|usr_contract_user|${enrollment_id}|https://mesh-kind-node.test/peer" ] \
    || [ "$legacy_relations" != "0" ] \
    || [ "$legacy_columns" != "0" ] \
    || [ "$migration_004" != "retire persistent node bearer|t" ] \
    || [ "$migration_005" != "retire network auth issuer|t" ] \
    || [ "$migration_006" != "retire raw auth session device state|t" ] \
    || [ "$migration_007" != "network deletion|t" ] \
    || [ "$network_auth_rows" != "0" ]; then
    echo "::error::Mesh persistence proof failed: node=${node_registration:-missing} legacy_relations=${legacy_relations:-missing} legacy_columns=${legacy_columns:-missing} migration_004=${migration_004:-missing} migration_005=${migration_005:-missing} migration_006=${migration_006:-missing} migration_007=${migration_007:-missing} network_auth_rows=${network_auth_rows:-missing}"
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

# Connect-RPC edge proofs (connect-rpc/03, WI-4 / D5):
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
    SMOKE_DIRECT_BASE_URL="$KIND_ORCHESTRATION_HTTP_URL" \
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
# not-found, and a port-forward to the TLS internal listener, verified with
# the published roots and the Service's DNS name, proves anonymous and
# cross-capability requests fail closed there.
coordinator_runtime_smokes() {
  # The internal listener and coordinator probes share one environment. Keep
  # its live runtime until every consumer finishes; otherwise the normal
  # reconciler correctly invalidates the later public running-state check.
  log "running internal Connect listener isolation probes"
  local public_base="${KIND_INGRESS_URL}/codewire.internal.v1.MeshAuthorizationService"
  curl_settled -X POST -H 'content-type: application/json' -d '{}' \
    "${public_base}/ResolveMeshAuthorization"
  if [ "$PROBE_CODE" != "404" ]; then
    echo "::error::public internal Connect path returned ${PROBE_CODE}, want public-listener 404: ${PROBE_BODY}"
    exit 1
  fi
  if ! grep -qi '^x-codewire-service: codewire-orchestration' "$PROBE_HEADERS"; then
    echo "::error::public internal Connect path did not reach the public orchestration listener"
    cat "$PROBE_HEADERS"
    exit 1
  fi

  # The coordinator probe's environment keeps a live runtime chain (Claim,
  # Sandbox, Pod) so the reconciler leaves it running for every consumer.
  # Install the checked-in claim and Sandbox CRDs before the full controller
  # deployment so this probe can build that exact chain without a controller
  # racing its synthetic status.
  kubectl_apply --validate=false \
    -f "$ROOT/deployments/k8s/agent-sandbox/base/crds/extensions.agents.x-k8s.io_sandboxclaims.yaml" \
    -f "$ROOT/deployments/k8s/agent-sandbox/base/crds/agents.x-k8s.io_sandboxes.yaml"
  kubectl wait --for=condition=established --timeout=60s \
    crd/sandboxclaims.extensions.agents.x-k8s.io \
    crd/sandboxes.agents.x-k8s.io

  (
    # Admit the stopped UUID-addressed coordinator fixture. The real
    # coordinator must accept its coordinate-scoped token.
    local bound_environment_id=00000000-0000-4000-8000-000000000501
    local bound_claim="sandbox-${bound_environment_id}"
    # A warm-pool member's name, as adoption leaves it: never the Claim's name.
    local bound_sandbox="kind-internal-ready-fixture-${bound_environment_id##*-}"
    local bound_pod="$bound_sandbox"
    local bound_claim_uid bound_sandbox_uid bound_pod_ip bound_claim_status
    local bound_port_id=port_internal_connect_kind
    local port_forward_log port_forward_pid local_port i peer_token
    local internal_roots
    port_forward_log="$(mktemp)"
    # Public roots of the TLS internal listener, for host-side probes.
    internal_roots="$(mktemp)"
    port_forward_pid=""

    # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
    cleanup_internal_connect_fixture() {
      local status=$? cleanup_status=0
      set +e
      if [ -n "$port_forward_pid" ]; then
        kill "$port_forward_pid" >/dev/null 2>&1 || true
        wait "$port_forward_pid" 2>/dev/null || true
      fi
      if ! kubectl -n "$NS" exec -i deploy/postgres -- \
        psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL >/dev/null 2>&1
BEGIN;
UPDATE environments SET state = 'stopped', desired_state = 'stopped'
WHERE id = '$bound_environment_id';
DELETE FROM environment_ports WHERE id = '$bound_port_id';
DELETE FROM sandbox_environment_backend WHERE environment_id = '$bound_environment_id';
COMMIT;
SQL
      then
        # Preserve the runtime if its retirement transaction failed. Do not
        # manufacture another running row with no backend during cleanup.
        echo '::error::failed to retire the coordinator runtime fixture' >&2
        rm -f "$port_forward_log" "$internal_roots"
        [ "$status" -ne 0 ] || status=1
        exit "$status"
      fi
      kubectl -n "$NS" delete sandboxclaim "$bound_claim" \
        --ignore-not-found=true --wait=true >/dev/null 2>&1 || cleanup_status=1
      kubectl -n "$NS" delete sandbox "$bound_sandbox" \
        --ignore-not-found=true --wait=true >/dev/null 2>&1 || cleanup_status=1
      kubectl -n "$NS" delete pod "$bound_pod" \
        --ignore-not-found=true --wait=true >/dev/null 2>&1 || cleanup_status=1
      rm -f "$port_forward_log" "$internal_roots"
      [ "$status" -ne 0 ] || status="$cleanup_status"
      exit "$status"
    }
    trap cleanup_internal_connect_fixture EXIT

    kubectl -n "$NS" delete sandboxclaim "$bound_claim" \
      --ignore-not-found=true --wait=true >/dev/null
    kubectl -n "$NS" delete sandbox "$bound_sandbox" \
      --ignore-not-found=true --wait=true >/dev/null
    kubectl -n "$NS" delete pod "$bound_pod" \
      --ignore-not-found=true --wait=true >/dev/null
    kubectl_apply -f - <<EOF
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${bound_claim}
  namespace: ${NS}
spec:
  warmPoolRef:
    name: kind-internal-ready-fixture
EOF
    bound_claim_uid="$(
      kubectl -n "$NS" get sandboxclaim "$bound_claim" -o jsonpath='{.metadata.uid}'
    )"
    if [ -z "$bound_claim_uid" ]; then
      echo "::error::internal Connect fixture SandboxClaim has no UID"
      exit 1
    fi
    # The Claim controls its adopted Sandbox, which publishes its Pod's name.
    kubectl_apply -f - <<EOF
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: ${bound_sandbox}
  namespace: ${NS}
  annotations:
    agents.x-k8s.io/pod-name: ${bound_pod}
  ownerReferences:
    - apiVersion: extensions.agents.x-k8s.io/v1beta1
      kind: SandboxClaim
      name: ${bound_claim}
      uid: ${bound_claim_uid}
      controller: true
spec:
  podTemplate:
    spec:
      containers:
        - name: workspace
          image: ${KIND_POSTGRES_LOCAL_IMAGE}
EOF
    bound_sandbox_uid="$(
      kubectl -n "$NS" get sandbox "$bound_sandbox" -o jsonpath='{.metadata.uid}'
    )"
    if [ -z "$bound_sandbox_uid" ]; then
      echo "::error::internal Connect fixture Sandbox has no UID"
      exit 1
    fi
    # The workspace Pod is the one that Sandbox controls.
    kubectl_apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${bound_pod}
  namespace: ${NS}
  labels:
    codewire.sh/environment-id: ${bound_environment_id}
    codewire.sh/type: workspace
  ownerReferences:
    - apiVersion: agents.x-k8s.io/v1beta1
      kind: Sandbox
      name: ${bound_sandbox}
      uid: ${bound_sandbox_uid}
      controller: true
spec:
  restartPolicy: Always
  containers:
    - name: workspace
      image: ${KIND_POSTGRES_LOCAL_IMAGE}
      imagePullPolicy: Never
      command: ["sleep", "600"]
EOF
    kubectl -n "$NS" wait "pod/${bound_pod}" \
      --for=condition=Ready --timeout=60s
    bound_pod_ip="$(
      kubectl -n "$NS" get pod "$bound_pod" -o jsonpath='{.status.podIP}'
    )"
    if [ -z "$bound_pod_ip" ]; then
      echo "::error::internal Connect fixture Pod has no IP"
      exit 1
    fi
    # Bind the Claim to its Sandbox and mark it Ready, as the controller does.
    bound_claim_status="$(
      jq -cn --arg sandbox "$bound_sandbox" --arg pod_ip "$bound_pod_ip" '{status: {
        sandbox: {name: $sandbox, podIPs: [$pod_ip]},
        conditions: [{lastTransitionTime: "2026-01-01T00:00:00Z",
          message: "Kind internal Connect fixture is ready", reason: "Ready",
          status: "True", type: "Ready"}]}}'
    )"
    kubectl -n "$NS" patch sandboxclaim "$bound_claim" \
      --subresource=status --type=merge -p "$bound_claim_status"

    kubectl -n "$NS" exec -i deploy/postgres -- \
      psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL
BEGIN;
DELETE FROM sandbox_environment_backend WHERE environment_id = '$bound_environment_id';
DELETE FROM environment_ports WHERE id = '$bound_port_id';
INSERT INTO sandbox_environment_backend (environment_id, namespace, pod_name, pod_ip)
VALUES ('$bound_environment_id', '$NS', '$bound_pod', '$bound_pod_ip');
INSERT INTO environment_ports (id, environment_id, port, label, access)
VALUES ('$bound_port_id', '$bound_environment_id', 3000, 'internal-connect-kind', 'creator');
UPDATE environments
SET state = 'running', desired_state = 'started', error_reason = NULL
WHERE id = '$bound_environment_id';
COMMIT;
SQL
    # The environment's own peer capability at its operation generation.
    peer_token="$(peer_token_for_environment "$bound_environment_id")"
    local internal_host="codewire-orchestration.${NS}.svc.cluster.local"

    kubectl -n "$NS" get configmap codewire-orchestration-internal-roots \
      -o 'jsonpath={.data.ca\.crt}' >"$internal_roots"
    kubectl -n "$NS" port-forward --address=127.0.0.1 \
      service/codewire-orchestration :8088 >"$port_forward_log" 2>&1 &
    port_forward_pid=$!

    for i in $(seq 1 30); do
      local_port="$(sed -nE 's/.*127\.0\.0\.1:([0-9]+) -> 8088.*/\1/p' "$port_forward_log" | head -n 1)"
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

    curl_settled --cacert "$internal_roots" \
      --resolve "${internal_host}:${local_port}:127.0.0.1" \
      -X POST -H 'content-type: application/json' -d '{}' \
      "https://${internal_host}:${local_port}/codewire.internal.v1.MeshAuthorizationService/ResolveMeshAuthorization"
    if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
      echo "::error::anonymous internal command was not rejected: code=$PROBE_CODE body=$PROBE_BODY"
      exit 1
    fi
    if ! grep -qi '^x-codewire-service: codewire-orchestration-internal' "$PROBE_HEADERS"; then
      echo "::error::ClusterIP internal command did not reach the internal listener"
      cat "$PROBE_HEADERS"
      exit 1
    fi

    # An environment peer token is not the Mesh service's method-scoped
    # HMAC: no other capability crosses into the listener.
    curl_settled --cacert "$internal_roots" \
      --resolve "${internal_host}:${local_port}:127.0.0.1" \
      -X POST -H 'content-type: application/json' \
      -H "authorization: Bearer ${peer_token}" -d '{}' \
      "https://${internal_host}:${local_port}/codewire.internal.v1.MeshAuthorizationService/ResolveMeshAuthorization"
    if [ "$PROBE_CODE" != "401" ] || ! echo "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
      echo "::error::peer capability crossed into the internal listener: code=$PROBE_CODE body=$PROBE_BODY"
      exit 1
    fi

    log "internal Connect listener isolation probes OK"
    mesh_product_connect_ownership_smoke
    # The direct Coordinate stream proves the same token is accepted by the
    # coordinator for this live environment.
    KIND_COORDINATOR_ENVIRONMENT="$bound_environment_id" \
      KIND_COORDINATOR_SIDECAR_TOKEN="$peer_token" \
      coordinator_ingress_smoke
  )
}

coordinator_ingress_smoke() {
  log "running generated primary and Mesh coordinator native-gRPC/direct-h2c smoke"
  local certificate_dir certificate_pem certificate_der alpn_output

  curl_settled -X GET \
    "${KIND_COORDINATOR_DIRECT_URL}/api/v1/internal/gateway/coordinate"
  if [ "$PROBE_CODE" != "404" ]; then
    echo "::error::retired primary coordinator WebSocket returned ${PROBE_CODE}, want 404"
    exit 1
  fi
  curl_settled -X POST \
    -H 'content-type: application/connect+proto' \
    --data-binary '' \
    "${KIND_COORDINATOR_DIRECT_URL}/coordinator.v1.CoordinatorService/Coordinate"
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
    -connect "localhost:${KIND_INGRESS_TLS_HOST_PORT}" \
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
    KIND_COORDINATOR_DIRECT_URL="$KIND_COORDINATOR_DIRECT_URL" \
    KIND_COORDINATOR_CA_DER="$certificate_der" \
    "$CARGO_CI_DIR/examples/coordinator-ingress-smoke" || {
    local smoke_status=$?
    rm -rf "$certificate_dir"
    return "$smoke_status"
  }
  rm -rf "$certificate_dir"
}

exec_service_connect_smoke() {
  local environment_id="$1"
  log "running daemon-native ExecService Connect smoke and REST-retirement probe"
  local ascii_command ascii_connect_payload ascii_connect
  local invalid_command invalid_connect_payload invalid_connect

  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_DIRECT_BASE_URL="$KIND_ORCHESTRATION_HTTP_URL" \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/exec-stream-smoke" || return $?

  ascii_command="printf 'stdout\\n'; printf 'stderr\\n' >&2; exit 17"
  ascii_connect_payload="$(jq -cn \
    --arg org_id org_contract_1 \
    --arg environment_id "$environment_id" \
    --arg command "$ascii_command" \
    '{orgId:$org_id,environmentId:$environment_id,command:["sh","-c",$command]}')" || return $?

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "$ascii_connect_payload" \
    "${KIND_INGRESS_URL}/api/v1/organizations/org_contract_1/environments/${environment_id}/exec" || return $?
  if [ "$PROBE_CODE" != "404" ]; then
    echo "::error::retired authenticated REST exec returned ${PROBE_CODE}: ${PROBE_BODY}"
    return 1
  fi

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "$ascii_connect_payload" \
    "${KIND_INGRESS_URL}/codewire.v1.ExecService/Exec" || return $?
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
    '{orgId:$org_id,environmentId:$environment_id,command:["sh","-c",$command]}')" || return $?

  curl_settled -X POST \
    -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "$invalid_connect_payload" \
    "${KIND_INGRESS_URL}/codewire.v1.ExecService/Exec" || return $?
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
  local environment_id="$1"

  log "proving a Connect-issued ticket opens the permanent raw terminal WebSocket"
  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/environment-setup-smoke" || return $?
  log "EnvironmentSetupService ticket-to-WebSocket path green"
)

file_service_smoke() (
  local workspace_image
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  log "running daemon-native FileService client/server streaming and Connect contract smoke"
  local environment_id=env-crd-smoke
  local claim_name=sandbox-env-crd-smoke
  local daemon_pod=crd-smoke-workspace-daemon
  # The Sandbox that controls the daemon Pod, named like it, as the
  # controller names a Sandbox's own Pod.
  local sandbox_name="$daemon_pod"
  local original_replicas pod_ip pod_uid ready
  local claim_uid sandbox_uid pod_owner

  original_replicas="$(
    kubectl -n agent-sandbox-system get deploy/agent-sandbox-controller \
      -o jsonpath='{.spec.replicas}'
  )" || return $?
  if [[ ! "$original_replicas" =~ ^[0-9]+$ ]]; then
    echo "::error::agent-sandbox controller replica count is invalid: ${original_replicas:-missing}"
    return 1
  fi

  # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
  cleanup_file_service_binding() {
    local status=$? cleanup_status=0
    trap - EXIT
    set +e
    # Orphan the retained daemon Pod: it outlives its synthetic Sandbox.
    kubectl -n "$SANDBOX_NS" delete sandbox "$sandbox_name" --cascade=orphan \
      --ignore-not-found=true --wait=true >/dev/null || cleanup_status=$?
    kubectl -n "$SANDBOX_NS" delete sandboxclaim "$claim_name" \
      --ignore-not-found=true --wait=true >/dev/null || cleanup_status=$?
    kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller \
      --replicas="$original_replicas" >/dev/null || cleanup_status=$?
    if [ "$original_replicas" -gt 0 ]; then
      kubectl -n agent-sandbox-system rollout status \
        deploy/agent-sandbox-controller --timeout=180s || cleanup_status=$?
    fi
    if [ "$status" -eq 0 ]; then
      status="$cleanup_status"
    fi
    exit "$status"
  }
  trap cleanup_file_service_binding EXIT

  kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller --replicas=0 || return $?
  if [ "$original_replicas" -gt 0 ]; then
    kubectl -n agent-sandbox-system wait pod -l app=agent-sandbox-controller \
      --for=delete --timeout=60s || return $?
  fi

  pod_ip="$(
    kubectl -n "$SANDBOX_NS" get pod "$daemon_pod" -o jsonpath='{.status.podIP}'
  )" || return $?
  pod_uid="$(
    kubectl -n "$SANDBOX_NS" get pod "$daemon_pod" -o jsonpath='{.metadata.uid}'
  )" || return $?
  if [ -z "$pod_ip" ] || [ -z "$pod_uid" ]; then
    echo "::error::file-service fixture Pod has no current IP/UID"
    return 1
  fi
  kubectl -n "$SANDBOX_NS" delete sandbox "$sandbox_name" --cascade=orphan \
    --ignore-not-found=true --wait=true >/dev/null || return $?
  kubectl -n "$SANDBOX_NS" delete sandboxclaim "$claim_name" \
    --ignore-not-found=true --wait=true >/dev/null || return $?
  kubectl_apply -f - <<EOF || return $?
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${claim_name}
  namespace: ${SANDBOX_NS}
spec:
  warmPoolRef:
    name: kind-file-service-ready-fixture
EOF
  # Orchestration reaches a workspace Pod only through Claim status ->
  # bound Sandbox -> the Pod that Sandbox controls, and derives an unbound
  # legacy daemon's credential only from that exact Pod (Program #2238 B2).
  # Give the retained daemon Pod that chain while the controller is
  # quiesced, so nothing reconciles the synthetic Sandbox.
  claim_uid="$(
    kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" -o jsonpath='{.metadata.uid}'
  )" || return $?
  if [ -z "$claim_uid" ]; then
    echo "::error::file-service fixture SandboxClaim has no UID"
    return 1
  fi
  kubectl_apply -f - <<EOF || return $?
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: ${sandbox_name}
  namespace: ${SANDBOX_NS}
  annotations:
    agents.x-k8s.io/pod-name: ${daemon_pod}
  ownerReferences:
    - apiVersion: extensions.agents.x-k8s.io/v1beta1
      kind: SandboxClaim
      name: ${claim_name}
      uid: ${claim_uid}
      controller: true
spec:
  podTemplate:
    spec:
      containers:
        - name: workspace
          image: codewire-daemon:e2e
EOF
  sandbox_uid="$(
    kubectl -n "$SANDBOX_NS" get sandbox "$sandbox_name" -o jsonpath='{.metadata.uid}'
  )" || return $?
  if [ -z "$sandbox_uid" ]; then
    echo "::error::file-service fixture Sandbox has no UID"
    return 1
  fi
  pod_owner="$(
    jq -cn --arg sandbox "$sandbox_name" --arg uid "$sandbox_uid" --arg pod_uid "$pod_uid" \
      '{metadata: {uid: $pod_uid, ownerReferences: [{apiVersion: "agents.x-k8s.io/v1beta1",
        kind: "Sandbox", name: $sandbox, uid: $uid, controller: true}]}}'
  )" || return $?
  kubectl -n "$SANDBOX_NS" patch pod "$daemon_pod" --type=merge -p "$pod_owner" || return $?
  kubectl -n "$SANDBOX_NS" patch sandboxclaim "$claim_name" \
    --subresource=status --type=merge \
    -p "{\"status\":{\"sandbox\":{\"name\":\"${daemon_pod}\",\"podIPs\":[\"${pod_ip}\"]},\"conditions\":[{\"lastTransitionTime\":\"2026-01-01T00:00:00Z\",\"message\":\"Kind file-service fixture is ready\",\"reason\":\"Ready\",\"status\":\"True\",\"type\":\"Ready\"}]}}" || return $?
  ready="$(
    kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
  )" || return $?
  if [ "$ready" != "True" ]; then
    echo "::error::file-service fixture SandboxClaim Ready status is ${ready:-missing}"
    return 1
  fi

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL || return $?
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
  setup_complete,
  setup_owner_generation, setup_owner_activity_id, setup_owner_attempt,
  setup_owner_phase, setup_owner_status, setup_owner_pod_uid
)
SELECT '$environment_id', '$SANDBOX_NS', '$daemon_pod', '$pod_ip',
       true, NULL, NULL, NULL, NULL, NULL, NULL
FROM environments
WHERE id = '$environment_id'
ON CONFLICT (environment_id) DO UPDATE
SET namespace = EXCLUDED.namespace,
    pod_name = EXCLUDED.pod_name,
    pod_ip = EXCLUDED.pod_ip,
    setup_complete = true,
    setup_owner_generation = NULL,
    setup_owner_activity_id = NULL,
    setup_owner_attempt = NULL,
    setup_owner_phase = NULL,
    setup_owner_status = NULL,
    setup_owner_pod_uid = NULL;

-- This caller-owned fixture is already bootstrapped and Ready, not an active
-- setup workflow. Its completed state must satisfy the production admission
-- guard before exercising durable session mutations.
DO \$fixture\$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM sandbox_environment_backend
    WHERE environment_id = '$environment_id' AND setup_complete
      AND setup_owner_generation IS NULL AND setup_owner_activity_id IS NULL
      AND setup_owner_attempt IS NULL AND setup_owner_phase IS NULL
      AND setup_owner_status IS NULL AND setup_owner_pod_uid IS NULL
  ) THEN
    RAISE EXCEPTION 'prepared FileService fixture is not ready and idle';
  END IF;
END
\$fixture\$;
SQL

  environment_daemon_proxy_smoke "$environment_id" "$daemon_pod" || return $?
  environment_setup_terminal_smoke "$environment_id" || return $?
  exec_service_connect_smoke "$environment_id" || return $?
  platform_run_connect_smoke "$environment_id" || return $?
  environment_session_protocol_smoke "$environment_id" || return $?

  SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_URL" \
    SMOKE_DIRECT_BASE_URL="$KIND_ORCHESTRATION_HTTP_URL" \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_SESSION_TOKEN=contract-user-session-token \
    "$CARGO_CI_DIR/file-service-smoke" || return $?

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL || return $?
DELETE FROM sandbox_environment_backend
WHERE environment_id = '$environment_id';
DELETE FROM environments WHERE id = '$environment_id';
SQL
  kubectl -n "$SANDBOX_NS" delete sandbox "$sandbox_name" --cascade=orphan \
    --ignore-not-found=true --wait=true >/dev/null || return $?
  kubectl -n "$SANDBOX_NS" delete sandboxclaim "$claim_name" \
    --ignore-not-found=true --wait=true >/dev/null || return $?
  kubectl -n agent-sandbox-system scale deploy/agent-sandbox-controller \
    --replicas="$original_replicas" >/dev/null || return $?
  if [ "$original_replicas" -gt 0 ]; then
    kubectl -n agent-sandbox-system rollout status \
      deploy/agent-sandbox-controller --timeout=180s || return $?
  fi
  trap - EXIT
  CRD_SMOKE_NAMESPACE="$SANDBOX_NS" \
    CRD_SMOKE_SERVER_NAMESPACE="$NS" \
    CRD_SMOKE_WORKSPACE_IMAGE="$workspace_image" \
    CRD_SMOKE_ACCESS_PHASE=cleanup \
    CRD_SMOKE_LOCAL_IMAGES=1 \
    "$CARGO_CI_DIR/crd-smoke" || return $?
  kubectl -n "$SANDBOX_NS" delete pod "$daemon_pod" --wait=true >/dev/null || return $?
  log "daemon-native FileService streaming and black-box Connect contract green"
)

platform_run_connect_smoke() {
  local environment_id="$1"
  local certificate_dir certificate_pem status

  log "running public Connect platform Run smoke through TLS ingress"
  certificate_dir="$(mktemp -d)" || return $?
  certificate_pem="$certificate_dir/ca.pem"
  kubectl -n "$NS" get secret/codewire-kind-ingress-ca \
    -o 'jsonpath={.data.ca\.crt}' | base64 --decode > "$certificate_pem" || {
      status=$?
      rm -rf "$certificate_dir"
      return "$status"
    }

  if ! SMOKE_CONNECT_BASE_URL="$KIND_INGRESS_TLS_URL" \
    SMOKE_CA_CERT_FILE="$certificate_pem" \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_ENVIRONMENT_ID="$environment_id" \
    SMOKE_ACCESS_TOKEN=at_kind_connect_oidc_codewire_api \
    "$CARGO_CI_DIR/examples/platform-run-smoke"; then
    rm -rf "$certificate_dir"
    return 1
  fi
  rm -rf "$certificate_dir" || return $?
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
      "$base" || return $?
    if [ "$PROBE_CODE" != "200" ] \
        || [ "$PROBE_BODY" != '{"message":"usr_contract_user"}' ]; then
      echo "::error::ordinary orchestration upstream warm ${i}/24 failed: code=${PROBE_CODE} body=${PROBE_BODY}"
      return 1
    fi
  done
  log "ordinary orchestration HTTP/Connect upstream warm green"
}

# Prove the native gRPC LaunchSession requests sent since SINCE, an RFC 3339
# UTC second, used the gRPC Service ClusterIP and never an orchestration Pod
# endpoint. Earlier stages launch sessions through the ordinary HTTP ingress,
# which correctly upstreams to a Pod endpoint, so the controller's log is read
# only from SINCE on.
assert_environment_session_grpc_service_upstream() {
  local since="$1" service_ip pod_ips controller_logs matching_lines i pod_ip

  if ! [[ "$since" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    echo "::error::the native gRPC upstream check needs the RFC 3339 second its smoke began"
    return 1
  fi
  service_ip="$(
    kubectl -n "$NS" get service/codewire-orchestration-grpc \
      -o jsonpath='{.spec.clusterIP}'
  )" || return $?
  if [ -z "$service_ip" ] || [ "$service_ip" = "None" ]; then
    echo "::error::codewire-orchestration-grpc has no usable ClusterIP"
    return 1
  fi

  matching_lines=""
  controller_logs=""
  for i in $(seq 1 15); do
    controller_logs="$(
      kubectl -n ingress-nginx logs deploy/ingress-nginx-controller --since-time="$since"
    )" || return $?
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
  )" || return $?
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
  local certificate_dir certificate_pem status grpc_since

  log "running EnvironmentSessionService direct Connect + public native-gRPC smoke"
  certificate_dir="$(mktemp -d)" || return $?
  certificate_pem="$certificate_dir/ca.pem"
  kubectl -n "$NS" get secret/codewire-kind-ingress-ca \
    -o 'jsonpath={.data.ca\.crt}' | base64 --decode > "$certificate_pem" || {
      status=$?
      rm -rf "$certificate_dir"
      return "$status"
    }

  if ! SMOKE_SESSION_BASE_URL="$KIND_ORCHESTRATION_HTTP_URL" \
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

  # The upstream check reads only this smoke's native gRPC requests. A log
  # query's start is a whole second, so begin it on the second after every
  # earlier request: the ordinary HTTP launches before it go to Pod endpoints.
  sleep 1 || {
    status=$?
    rm -rf "$certificate_dir"
    return "$status"
  }
  grpc_since="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || {
    status=$?
    rm -rf "$certificate_dir"
    return "$status"
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
  if ! assert_environment_session_grpc_service_upstream "$grpc_since"; then
    rm -rf "$certificate_dir"
    return 1
  fi
  rm -rf "$certificate_dir" || return $?
  log "EnvironmentSessionService direct Connect + public native-gRPC output/list/logs/exit proof green"
}

environment_daemon_proxy_smoke() {
  local environment_id="$1" pod_name="$2"
  local base="${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/GetEnvironmentDaemonStatus"

  log "running authenticated environment-daemon proxy smoke"
  curl_settled -X POST -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\"}" \
    "$base" || return $?
  if [ "$PROBE_CODE" != "401" ] \
      || ! printf '%s' "$PROBE_BODY" | grep -q '"code":"unauthenticated"'; then
    echo "::error::unauthenticated daemon status bypassed product auth: code=$PROBE_CODE body=$PROBE_BODY"
    return 1
  fi

  curl_settled -X POST -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\"}" \
    "$base" || return $?
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
  local manifest
  log "deploying agent-sandbox controller and CRDs"
  manifest="$(render_agent_sandbox_manifest)" || return $?
  kubectl_apply --validate=false -f "$manifest" || return $?
  kubectl wait --for=condition=established --timeout=60s \
    crd/sandboxclaims.extensions.agents.x-k8s.io || return $?
  kubectl -n agent-sandbox-system rollout status deploy/agent-sandbox-controller --timeout=180s || return $?
}

workspace_service_smokes() {
  # Callers check this composite with ||, which suppresses nested errexit.
  # Every stage must explicitly preserve failure before running the next one.
  workspace_access_stack_smoke || return $?

  log "running workspace exec smoke"
  SMOKE_NAMESPACE="$SANDBOX_NS" SMOKE_POD_NAME=crd-smoke-workspace-daemon \
    "$CARGO_CI_DIR/exec-smoke" || return $?
  file_service_smoke || return $?
  environment_resize_smoke || return $?
  workspace_user_ssh_smoke || return $?
}

# Bound on a new Sandbox answering its first OpenSSH command, from the create
# request.
KIND_USER_SSH_READY_SECONDS=180

# The user's SSH path, exactly as a user gets it: a synthetic personal login,
# the block `cw setup ssh` writes, and real OpenSSH through it (its
# ProxyCommand and its only host-key trust, `cw ssh known-hosts`). A new
# Sandbox must answer its first command within the bound; then a command line
# the workspace shell parses keeps its exit status, a server listening only on
# the Sandbox's loopback answers through `ssh -W`, `ssh -L` and the dynamic
# forward VS Code Remote-SSH uses (`ssh -D`) while a target outside the
# Sandbox is refused with its reason (#3045), scp round-trips in SFTP and
# legacy mode, sftp and rsync work, and a key other than the recorded one is
# refused.
workspace_user_ssh_smoke() (
  log "running the user SSH journey through the block cw setup ssh writes"
  require_tool ssh
  require_tool scp
  require_tool sftp
  require_tool curl
  require_tool python3
  require_tool pkill
  umask 077
  local name="kind-ssh-${RANDOM}${RANDOM}" environment="" image config host started first
  local output status up background=() token request reply forward_port=18765 local_port
  # codewire_daemon_proto::CREDENTIAL_BRIDGE_LOOPBACK_PORT, the platform's
  # credential bridge in every workload (test-kind-e2e-suites.sh binds it).
  local bridge_port=38081 socks_port socks_log forward_log refusal
  KIND_CREDENTIAL_CLI_HOME="$(mktemp -d /dev/shm/codewire-kind-ssh.XXXXXX)" || return 1
  # Stop OpenSSH clients started in the background: the subshell running
  # each, and its timeout, which passes the signal on to ssh.
  stop_kind_user_ssh_background() {
    local pid
    for pid in "${background[@]}"; do
      pkill -TERM -P "$pid" 2>/dev/null
      kill -TERM "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    done
    background=()
    return 0
  }
  # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
  cleanup_workspace_user_ssh_smoke() {
    local status=$?
    trap - EXIT
    set +e
    stop_kind_user_ssh_background
    if [ -n "$environment" ]; then
      kind_credential_cli --cloud rm "$environment" --yes --output json >/dev/null ||
        status=1
      wait_kind_credential_environment "$environment" destroyed || status=1
    fi
    rm -rf -- "$KIND_CREDENTIAL_CLI_HOME" || status=1
    exit "$status"
  }
  trap cleanup_workspace_user_ssh_smoke EXIT
  prepare_kind_credential_cli
  kind_credential_cli org set org_contract_1 >/dev/null
  config="$KIND_CREDENTIAL_CLI_HOME/ssh_config"
  kind_credential_cli setup ssh --ssh-config-file "$config" >/dev/null
  # OpenSSH's TOOL with the ssh config CONFIG. The block names the cw that
  # wrote it by absolute path, and its commands find the server and login
  # as that cw does, from this environment. Its input is KIND_USER_SSH_STDIN,
  # or nothing; it logs errors only, or at KIND_USER_SSH_LOG_LEVEL.
  kind_user_ssh_tool() {
    local ssh_config="$1" tool="$2"
    shift 2
    env -i PATH=/usr/bin:/bin HOME="$KIND_CREDENTIAL_CLI_HOME" \
      XDG_CONFIG_HOME="$KIND_CREDENTIAL_CLI_HOME/config" \
      CW_CONFIG_DIR="$KIND_CREDENTIAL_CLI_HOME/cw" \
      CODEWIRE_SERVER_URL="$KIND_INGRESS_URL" \
      timeout 60 "$tool" -F "$ssh_config" -o BatchMode=yes \
      -o "LogLevel=${KIND_USER_SSH_LOG_LEVEL:-ERROR}" "$@" \
      <"${KIND_USER_SSH_STDIN:-/dev/null}"
  }
  # A free loopback port on this host.
  kind_user_free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
  }
  image="$(kind_workspace_runtime_image)"
  host="cw-$name"
  started="$SECONDS"
  environment="$(kind_credential_cli --cloud create --name "$name" --image "$image" \
    --cpu 500 --memory 1Gi --disk 1Gi --ttl 1h --yes --output json | jq -er '.id')"
  first=""
  while [ $((SECONDS - started)) -lt "$KIND_USER_SSH_READY_SECONDS" ]; do
    if output="$(kind_user_ssh_tool "$config" ssh "$host" 'echo ready' 2>/dev/null)" &&
      [ "$output" = ready ]; then
      first=$((SECONDS - started))
      break
    fi
    sleep 1
  done
  [ -n "$first" ] || {
    echo "::error::ssh $host did not answer within ${KIND_USER_SSH_READY_SECONDS}s of the create request"
    return 1
  }
  log "first OpenSSH command answered ${first}s after the create request"

  status=0
  output="$(kind_user_ssh_tool "$config" ssh "$host" \
    'printf a && printf b | tr b B; echo " $((1+2)) $HOME"; exit 7')" || status=$?
  [ "$output" = "aB 3 /home/codewire" ] && [ "$status" -eq 7 ] || {
    echo "::error::ssh did not run a shell command line: output '$output', exit $status"
    return 1
  }

  # Local port forwarding into the Sandbox (#3045). A server that listens
  # only on the Sandbox's loopback, held by its own SSH session.
  token="kind-forward-${RANDOM}${RANDOM}"
  kind_user_ssh_tool "$config" ssh "$host" \
    "cd && printf %s $token >forward.txt && exec python3 -m http.server $forward_port --bind 127.0.0.1" \
    >/dev/null 2>&1 &
  background+=("$!")
  request="$KIND_CREDENTIAL_CLI_HOME/forward-request"
  printf 'GET /forward.txt HTTP/1.0\r\nHost: localhost\r\n\r\n' >"$request"
  # ssh -W: the stdio forward ProxyJump and ProxyCommand chains use.
  reply=""
  for _ in $(seq 1 30); do
    if reply="$(KIND_USER_SSH_STDIN="$request" kind_user_ssh_tool "$config" ssh \
      -W "127.0.0.1:$forward_port" "$host" 2>/dev/null)" && [ "${reply##*$'\n'}" = "$token" ]; then
      break
    fi
    sleep 1
  done
  [ "${reply##*$'\n'}" = "$token" ] || {
    echo "::error::ssh -W did not reach a server on the Sandbox's loopback: '${reply:0:200}'"
    return 1
  }
  # ssh -L, as a user forwards an application port.
  local_port="$(kind_user_free_port)"
  kind_user_ssh_tool "$config" ssh -N -o ExitOnForwardFailure=yes \
    -L "127.0.0.1:$local_port:127.0.0.1:$forward_port" "$host" >/dev/null 2>&1 &
  background+=("$!")
  reply=""
  for _ in $(seq 1 30); do
    reply="$(curl -fsS --max-time 10 "http://127.0.0.1:$local_port/forward.txt" 2>/dev/null)" &&
      [ "$reply" = "$token" ] && break
    sleep 1
  done
  [ "$reply" = "$token" ] || {
    echo "::error::ssh -L did not reach a server on the Sandbox's loopback: '${reply:0:200}'"
    return 1
  }
  # ssh -D, the dynamic forward VS Code Remote-SSH reaches its server through,
  # naming the target as localhost.
  socks_port="$(kind_user_free_port)"
  socks_log="$KIND_CREDENTIAL_CLI_HOME/socks.log"
  KIND_USER_SSH_LOG_LEVEL=INFO kind_user_ssh_tool "$config" ssh -N -o ExitOnForwardFailure=yes \
    -D "127.0.0.1:$socks_port" "$host" >/dev/null 2>"$socks_log" &
  background+=("$!")
  reply=""
  for _ in $(seq 1 30); do
    reply="$(curl -fsS --max-time 10 --socks5-hostname "127.0.0.1:$socks_port" \
      "http://localhost:$forward_port/forward.txt" 2>/dev/null)" && [ "$reply" = "$token" ] && break
    sleep 1
  done
  [ "$reply" = "$token" ] || {
    echo "::error::ssh -D did not reach a server on the Sandbox's loopback: '${reply:0:200}'"
    return 1
  }
  # The platform's own listeners stay out of reach (#3068): the credential
  # bridge, which answers provider requests with the creator's credentials,
  # through that dynamic forward and through ssh -L. Each is refused with its
  # reason, which OpenSSH logs, while the user's server stays reachable.
  status=0
  curl -sS --max-time 10 --socks5-hostname "127.0.0.1:$socks_port" \
    "http://localhost:$bridge_port/v1/models" >/dev/null 2>&1 || status=$?
  [ "$status" -ne 0 ] || {
    echo "::error::ssh -D reached the credential bridge on port $bridge_port"
    return 1
  }
  forward_log="$KIND_CREDENTIAL_CLI_HOME/bridge-forward.log"
  local_port="$(kind_user_free_port)"
  KIND_USER_SSH_LOG_LEVEL=INFO kind_user_ssh_tool "$config" ssh -N -o ExitOnForwardFailure=yes \
    -L "127.0.0.1:$local_port:127.0.0.1:$bridge_port" "$host" >/dev/null 2>"$forward_log" &
  background+=("$!")
  status=7
  for _ in $(seq 1 30); do
    status=0
    curl -sS --max-time 10 "http://127.0.0.1:$local_port/v1/models" >/dev/null 2>&1 || status=$?
    # 7: ssh -L is not listening yet.
    [ "$status" -eq 7 ] || break
    sleep 1
  done
  [ "$status" -ne 0 ] && [ "$status" -ne 7 ] || {
    echo "::error::ssh -L to the credential bridge on port $bridge_port was not refused (curl exit $status)"
    return 1
  }
  refusal="administratively prohibited: port $bridge_port is the credential bridge, which belongs to the platform"
  for _ in $(seq 1 10); do
    grep -Fq "$refusal" "$forward_log" && grep -Fq "$refusal" "$socks_log" && break
    sleep 1
  done
  grep -Fq "$refusal" "$forward_log" && grep -Fq "$refusal" "$socks_log" || {
    echo "::error::the credential bridge forwards were not refused with their reason:" \
      "$(cat "$forward_log" "$socks_log" | head -c 600)"
    return 1
  }
  reply="$(curl -fsS --max-time 10 --socks5-hostname "127.0.0.1:$socks_port" \
    "http://localhost:$forward_port/forward.txt" 2>/dev/null)" && [ "$reply" = "$token" ] || {
    echo "::error::the user's server stopped forwarding after the refused bridge forwards: '${reply:0:200}'"
    return 1
  }
  # A target outside the Sandbox, the metadata service: refused at once, with
  # the reason OpenSSH logs at its default level.
  status=0
  output="$(KIND_USER_SSH_LOG_LEVEL=INFO kind_user_ssh_tool "$config" ssh \
    -W 169.254.169.254:80 "$host" 2>&1)" || status=$?
  [ "$status" -eq 255 ] &&
    grep -Fq "port forwarding reaches only this environment's own loopback" <<<"$output" || {
    echo "::error::ssh -W to the metadata address was not refused with its reason (exit $status): ${output:0:400}"
    return 1
  }
  stop_kind_user_ssh_background

  up="$KIND_CREDENTIAL_CLI_HOME/up.txt"
  printf 'kind-ssh-%s\n' "$RANDOM" >"$up"
  kind_user_ssh_tool "$config" scp "$up" "$host:sftp-mode.txt" &&
    kind_user_ssh_tool "$config" scp "$host:sftp-mode.txt" "$KIND_CREDENTIAL_CLI_HOME/sftp-mode.txt" &&
    cmp -s "$up" "$KIND_CREDENTIAL_CLI_HOME/sftp-mode.txt" || {
    echo '::error::scp (SFTP mode) did not round-trip a file through the home directory'
    return 1
  }
  kind_user_ssh_tool "$config" scp -O "$up" "$host:legacy-mode.txt" &&
    kind_user_ssh_tool "$config" scp -O "$host:legacy-mode.txt" "$KIND_CREDENTIAL_CLI_HOME/legacy-mode.txt" &&
    cmp -s "$up" "$KIND_CREDENTIAL_CLI_HOME/legacy-mode.txt" || {
    echo '::error::scp (legacy mode) did not round-trip a file through the home directory'
    return 1
  }
  printf 'pwd\nls sftp-mode.txt\nrm sftp-mode.txt\n' >"$KIND_CREDENTIAL_CLI_HOME/sftp-batch"
  kind_user_ssh_tool "$config" sftp -b "$KIND_CREDENTIAL_CLI_HOME/sftp-batch" "$host" >/dev/null || {
    echo '::error::an sftp batch (pwd, ls, rm) failed'
    return 1
  }
  if command -v rsync >/dev/null 2>&1; then
    env -i PATH=/usr/bin:/bin HOME="$KIND_CREDENTIAL_CLI_HOME" \
      XDG_CONFIG_HOME="$KIND_CREDENTIAL_CLI_HOME/config" \
      CW_CONFIG_DIR="$KIND_CREDENTIAL_CLI_HOME/cw" \
      CODEWIRE_SERVER_URL="$KIND_INGRESS_URL" \
      timeout 60 rsync -e "ssh -F $config -o BatchMode=yes -o LogLevel=ERROR" \
      "$up" "$host:rsync.txt" </dev/null || {
      echo '::error::rsync over the managed block failed'
      return 1
    }
  else
    log "rsync is not installed on this host; its step did not run"
  fi

  # A key other than the recorded one, in place of the block's trust source.
  sed 's|KnownHostsCommand .*|KnownHostsCommand /bin/echo %H ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFak|' \
    "$config" >"$config.forged"
  status=0
  kind_user_ssh_tool "$config.forged" ssh "$host" 'echo trusted' >/dev/null 2>&1 || status=$?
  [ "$status" -eq 255 ] || {
    echo "::error::ssh trusted a host key the platform did not record (exit $status)"
    return 1
  }
  log "user SSH journey: shell syntax and exit status, forwards through -W, -L and -D with an outside target and the credential bridge refused, scp in both modes, sftp, a forged key refused"
)

environment_resize_smoke() (
  log "running public environment resize against the agent-sandbox controller"
  umask 077 || return $?
  local environment_id
  environment_id="$(python3 -c 'import uuid; print(uuid.uuid4())')" || return $?
  local request_id="kind-resize-${RANDOM}-${RANDOM}"
  local preset_id="preset-${environment_id}"
  local template_name shadow_pool_name
  local claim_name="sandbox-${environment_id}"
  local daemon_service="cw-daemon-${environment_id}"
  local sandbox_name old_pod_uid new_pod_uid old_restart_count new_restart_count pod_name pod_ip pvc_name pvc_uid claim_uid
  local resize_scoped_quota=false
  local operation_id operation_state response runtime_state marker image resources
  local current_pvc_uid resize_label sandbox_cpu claim_cpu storage_rbac pvc_rbac
  local status
  local resize_manifest="$RUN_DIR/resize-$environment_id.json"
  trap 'status=$?; rm -f -- "$resize_manifest" || status=$?; exit "$status"' EXIT

  # Render through the same production code that runtime reconciliation validates.
  # No cluster mutation occurs before these exact object identities are known.
  # The workspace is identity-free, as every commodity workspace is: Ready on
  # its daemon's local marker, and bound by the resize's runtime-identity
  # reconcile, which then waits for its SSH access as a start does.
  CRD_SMOKE_RESIZE_PHASE=render CRD_SMOKE_RESIZE_ENVIRONMENT_ID="$environment_id" \
    CRD_SMOKE_NAMESPACE="$SANDBOX_NS" CRD_SMOKE_SERVER_NAMESPACE="$NS" \
    CRD_SMOKE_LOCAL_IMAGES=1 CRD_SMOKE_WORKSPACE_IMAGE=codewire-daemon:e2e \
    SANDBOX_CREDENTIAL_BROKER_NAMESPACE="$NS" \
    "$CARGO_CI_DIR/crd-smoke" >"$resize_manifest" || return $?
  template_name="$(jq -er '.items[] | select(.kind == "SandboxTemplate") | .metadata.name' "$resize_manifest")" || return $?
  shadow_pool_name="$(jq -er '.items[] | select(.kind == "SandboxWarmPool") | .metadata.name' "$resize_manifest")" || return $?
  jq -e --arg claim "$claim_name" --arg pool "$shadow_pool_name" \
    '.items[] | select(.kind == "SandboxClaim") |
      .metadata.name == $claim and .spec.warmPoolRef.name == $pool' \
    "$resize_manifest" >/dev/null || return $?

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
    if [ "${resize_scoped_quota:-false}" = true ]; then
      kubectl -n "$NS" exec deploy/postgres -- psql -U codewire -d codewire -v ON_ERROR_STOP=1 -Atc \
        "DELETE FROM environment_quotas WHERE org_id = 'org_contract_1'" >/dev/null ||
        status=1
    fi
    # Runtime identity reconciliation creates the environment's access
    # objects. Never delete the shared fixture Issuers or public root
    # ConfigMaps.
    CRD_SMOKE_RESIZE_PHASE=release CRD_SMOKE_RESIZE_ENVIRONMENT_ID="$environment_id" \
      CRD_SMOKE_NAMESPACE="$SANDBOX_NS" "$CARGO_CI_DIR/crd-smoke" &&
      kubectl -n "$SANDBOX_NS" delete \
      "sandboxclaim/$claim_name" "sandboxwarmpool/$shadow_pool_name" \
      "sandboxtemplate/$template_name" "service/$daemon_service" \
      "service/cw-tailnet-udp-$environment_id" "networkpolicy/cw-daemon-net-$environment_id" \
      --ignore-not-found=true --cascade=foreground --wait=true --timeout=120s >/dev/null ||
      status=1
    rm -f -- "$resize_manifest" || status=1
    exit "$status"
  }
  trap cleanup_environment_resize_smoke EXIT

  kubectl_apply -f "$resize_manifest" || return $?
  kubectl -n "$SANDBOX_NS" wait "sandboxclaim/${claim_name}" \
    --for=condition=Ready --timeout=180s || return $?
  sandbox_name="$(kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" \
    -o jsonpath='{.status.sandbox.name}')" || return $?
  if [ -z "$sandbox_name" ]; then
    echo "::error::resize smoke claim did not resolve a Sandbox"
    return 1
  fi
  pod_name="$sandbox_name"
  kubectl -n "$SANDBOX_NS" wait "pod/${pod_name}" \
    --for=condition=Ready --timeout=180s || return $?
  old_pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}')" || return $?
  old_restart_count="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.containerStatuses[?(@.name=="workspace")].restartCount}')" || return $?
  pod_ip="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.podIP}')" || return $?
  pvc_name="workspace-${sandbox_name}"
  kubectl -n "$SANDBOX_NS" wait "pvc/${pvc_name}" \
    --for=jsonpath='{.status.phase}'=Bound --timeout=120s || return $?
  pvc_uid="$(kubectl -n "$SANDBOX_NS" get pvc "$pvc_name" -o jsonpath='{.metadata.uid}')" || return $?
  kubectl -n "$SANDBOX_NS" exec "$pod_name" -c workspace -- \
    sh -ceu 'printf codewire-resize-data > /workspace/resize-smoke-marker' || return $?
  claim_uid="$(kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" -o jsonpath='{.metadata.uid}')" || return $?

  kubectl -n "$NS" exec -i deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 <<SQL || return $?
BEGIN;
-- A runnable fixture owns its own preset. The shared contract preset is
-- deliberately missing runtime configuration for the Temporal failure test.
INSERT INTO environment_presets (id, org_id, name, official, project_spec)
VALUES ('$preset_id', 'org_contract_1', '$preset_id', false,
        '{"schema_version":1,"image":"codewire-daemon:e2e","working_directory":"/workspace"}'::jsonb);
INSERT INTO sandbox_template_config (preset_id, image_ref, sandbox_template_name)
VALUES ('$preset_id', 'codewire-daemon:e2e', 'resize-template');
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
-- Resize waits for setup to release a running runtime; this fixture models a
-- Sandbox whose setup already completed.
INSERT INTO sandbox_environment_backend (
  environment_id, namespace, sandbox_claim_name, sandbox_claim_uid, pod_name, pod_ip,
  setup_complete
)
VALUES (
  '$environment_id', '$SANDBOX_NS', '$claim_name',
  '$claim_uid',
  '$pod_name', '$pod_ip', true
);
COMMIT;
SQL

  curl_settled -X POST \
    -H 'cookie: codewire.session_token=contract-admin-session-token' \
    -H 'content-type: application/json' \
    -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\",\"cpuMillicores\":500,\"memoryMb\":512,\"diskGb\":1,\"requestId\":\"${request_id}\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/ResizeEnvironment" || return $?
  if [ "$PROBE_CODE" != "200" ]; then
    echo "::error::public resize request failed: code=$PROBE_CODE body=$PROBE_BODY"
    return 1
  fi
  operation_id="$(jq -r '.operation.id // empty' <<<"$PROBE_BODY")" || return $?
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
      "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/GetEnvironmentResizeOperation" || return $?
    if [ "$PROBE_CODE" != "200" ]; then
      echo "::error::resize operation poll failed: code=$PROBE_CODE body=$PROBE_BODY"
      return 1
    fi
    response="$PROBE_BODY"
    operation_state="$(jq -r '.operation.state // empty' <<<"$response")" || return $?
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
      "SELECT pod_name FROM sandbox_environment_backend WHERE environment_id = '$environment_id'")" || return $?
  new_pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}')" || return $?
  new_restart_count="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.containerStatuses[?(@.name=="workspace")].restartCount}')" || return $?
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
      "SELECT state || ':' || cpu_millicores || ':' || memory_mb || ':' || disk_gb FROM environments WHERE id = '$environment_id'")" || return $?
  if [ "$runtime_state" != "running:500:512:1" ]; then
    echo "::error::resize durable resource state is ${runtime_state:-missing}"
    return 1
  fi
  resources="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" \
    -o jsonpath='{.spec.containers[?(@.name=="workspace")].resources.requests.cpu}:{.spec.containers[?(@.name=="workspace")].resources.requests.memory}')" || return $?
  image="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" \
    -o jsonpath='{.spec.containers[?(@.name=="workspace")].image}')" || return $?
  marker="$(kubectl -n "$SANDBOX_NS" exec "$pod_name" -c workspace -- \
    sh -ceu 'cat /workspace/resize-smoke-marker')" || return $?
  if [ "$resources" != "500m:512Mi" ] || [ "$image" != "codewire-daemon:e2e" ] \
      || [ "$marker" != "codewire-resize-data" ]; then
    echo "::error::live-resized Pod lost resources/image/data: resources=$resources image=$image marker=$marker"
    return 1
  fi
  current_pvc_uid="$(kubectl -n "$SANDBOX_NS" get pvc "$pvc_name" -o jsonpath='{.metadata.uid}')" || return $?
  if [ "$current_pvc_uid" != "$pvc_uid" ]; then
    echo "::error::workspace PVC identity changed across resize"
    return 1
  fi
  resize_label="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.labels.codewire\.sh/resize-smoke-marker}')" || return $?
  if [ "$resize_label" != "preserved" ]; then
    echo "::error::live-resized Pod lost the resize identity label"
    return 1
  fi
  sandbox_cpu="$(kubectl -n "$SANDBOX_NS" get sandbox "$sandbox_name" -o jsonpath='{.spec.podTemplate.spec.containers[?(@.name=="workspace")].resources.requests.cpu}')" || return $?
  claim_cpu="$(kubectl -n "$SANDBOX_NS" get sandboxclaim "$claim_name" -o jsonpath='{.spec.workspaceResources[?(@.containerName=="workspace")].resources.requests.cpu}')" || return $?
  if [ "$sandbox_cpu" != "500m" ] || [ "$claim_cpu" != "500m" ]; then
    echo "::error::Sandbox or SandboxClaim did not retain the desired resize"
    return 1
  fi

  # The live resize waited for the kubelet to acknowledge its Pod generation
  # (#2475); record that this node reports both generation fields.
  local generation observed_generation
  generation="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.generation}')"
  observed_generation="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.observedGeneration}')"
  if [ -z "$generation" ] || [ "$observed_generation" != "$generation" ]; then
    echo "::error::live-resized Pod does not report an acknowledged generation: generation=${generation:-missing} observed=${observed_generation:-missing}"
    return 1
  fi
  log "live resize: Pod generation=$generation observedGeneration=$observed_generation on $(kubectl version -o json | jq -r .serverVersion.gitVersion)"

  # Submit one public resize and poll it until it is terminal, in $response.
  resize_until_terminal() {
    local id="$1" cpu="$2" memory="$3" operation
    curl_settled -X POST \
      -H 'cookie: codewire.session_token=contract-admin-session-token' \
      -H 'content-type: application/json' \
      -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\",\"cpuMillicores\":${cpu},\"memoryMb\":${memory},\"diskGb\":1,\"requestId\":\"${id}\"}" \
      "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/ResizeEnvironment"
    operation="$(jq -r '.operation.id // empty' <<<"$PROBE_BODY")"
    if [ "$PROBE_CODE" != "200" ] || [ -z "$operation" ]; then
      echo "::error::resize request $id failed: code=$PROBE_CODE body=$PROBE_BODY"
      return 1
    fi
    for _ in $(seq 1 240); do
      curl_settled -X POST \
        -H 'cookie: codewire.session_token=contract-admin-session-token' \
        -H 'content-type: application/json' \
        -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\",\"operationId\":\"${operation}\"}" \
        "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/GetEnvironmentResizeOperation"
      response="$PROBE_BODY"
      case "$(jq -r '.operation.state // empty' <<<"$response")" in
        ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED | ENVIRONMENT_RESIZE_OPERATION_STATE_FAILED) return 0 ;;
      esac
      sleep 1
    done
    echo "::error::resize $id did not reach a terminal state: $response"
    return 1
  }

  # Live workspace resources and pending resize reason, as cpu:cpu:reason.
  live_resources() {
    kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.spec.containers[?(@.name=="workspace")].resources.requests.cpu}:{.status.containerStatuses[?(@.name=="workspace")].resources.requests.cpu}:{.status.conditions[?(@.type=="PodResizePending")].reason}'
  }

  # A request above the node's allocatable CPU is infeasible. It fails
  # actionably, and its accepted request is withdrawn from the same Pod before
  # the reservation is released, leaving nothing to apply later (#2474).
  local node_name infeasible_cpu
  node_name="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.spec.nodeName}')"
  infeasible_cpu="$(kubectl get node "$node_name" -o jsonpath='{.status.allocatable.cpu}' |
    python3 -c 'import sys; v = sys.stdin.read().strip(); print((int(v[:-1]) if v.endswith("m") else int(float(v) * 1000)) + 1000)')"
  # The contract org's default quota (32 CPUs) may be smaller than a large
  # node. Unless the org has its own quota row, scope an unlimited CPU quota
  # to this one request.
  if [ -n "$(kubectl -n "$NS" exec deploy/postgres -- psql -U codewire -d codewire -v ON_ERROR_STOP=1 -Atc \
      "INSERT INTO environment_quotas (org_id, max_concurrent_environments, max_concurrent_sandbox, max_cpu_millicores, max_memory_mb)
       VALUES ('org_contract_1', 10, 50, -1, 65536) ON CONFLICT (org_id) DO NOTHING RETURNING org_id")" ]; then
    resize_scoped_quota=true
  fi
  resize_until_terminal "${request_id}-infeasible" "$infeasible_cpu" 512 || return 1
  if [ "$resize_scoped_quota" = true ]; then
    kubectl -n "$NS" exec deploy/postgres -- psql -U codewire -d codewire -v ON_ERROR_STOP=1 -Atc \
      "DELETE FROM environment_quotas WHERE org_id = 'org_contract_1'" >/dev/null
    resize_scoped_quota=false
  fi
  if ! jq -e '
      .operation.state == "ENVIRONMENT_RESIZE_OPERATION_STATE_FAILED"
      and .operation.failure.code == "runtime_apply_failed"
      and (.operation.failure.message | contains("request a smaller size"))
      and .operation.lastAppliedResources == {"cpuMillicores":500,"memoryMb":512,"diskGb":1}
      and .environment.cpuMillicores == 500
      and .environment.memoryMb == 512
    ' <<<"$response" >/dev/null; then
    echo "::error::infeasible live resize did not fail actionably with the running resources recorded: $response"
    return 1
  fi
  if [ "$(live_resources)" != "500m:500m:" ]; then
    echo "::error::infeasible live resize request was not withdrawn from the workspace Pod: $(live_resources)"
    return 1
  fi
  if [ "$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}')" != "$old_pod_uid" ] \
      || [ "$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.containerStatuses[?(@.name=="workspace")].restartCount}')" != "$old_restart_count" ]; then
    echo "::error::infeasible live resize changed the workspace Pod identity or restart count"
    return 1
  fi
  if [ "$(kubectl -n "$SANDBOX_NS" get sandbox "$sandbox_name" -o jsonpath='{.spec.podTemplate.spec.containers[?(@.name=="workspace")].resources.requests.cpu}')" != "500m" ] \
      || [ "$(kubectl -n "$NS" exec deploy/postgres -- psql -U codewire -d codewire -Atc \
        "SELECT state || ':' || cpu_millicores || ':' || memory_mb FROM environments WHERE id = '$environment_id'")" != "running:500:512" ]; then
    echo "::error::infeasible live resize left desired or durable resources changed"
    return 1
  fi
  log "infeasible live resize failed actionably and its request was withdrawn from Pod $old_pod_uid"

  # An Infeasible condition from an earlier Pod generation does not fail a
  # new feasible request (#2475). Leave one out of band, then recover live.
  kubectl -n "$SANDBOX_NS" patch pod "$pod_name" --subresource=resize --type=strategic \
    -p "{\"spec\":{\"containers\":[{\"name\":\"workspace\",\"resources\":{\"requests\":{\"cpu\":\"${infeasible_cpu}m\"},\"limits\":{\"cpu\":\"${infeasible_cpu}m\"}}}]}}" >/dev/null
  if ! kubectl -n "$SANDBOX_NS" wait "pod/${pod_name}" --timeout=60s \
      --for=jsonpath='{.status.conditions[?(@.type=="PodResizePending")].reason}'=Infeasible >/dev/null; then
    echo "::error::the out-of-band infeasible request was not reported Infeasible: $(live_resources)"
    return 1
  fi
  log "stale Infeasible condition at generation $(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.conditions[?(@.type=="PodResizePending")].observedGeneration}')"
  resize_until_terminal "${request_id}-recover" 750 512 || return 1
  if ! jq -e '
      .operation.state == "ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED"
      and .operation.appliedMode == "ENVIRONMENT_RESIZE_EXECUTION_MODE_IN_PLACE"
      and .operation.lastAppliedResources == {"cpuMillicores":750,"memoryMb":512,"diskGb":1}
      and .environment.cpuMillicores == 750
    ' <<<"$response" >/dev/null; then
    echo "::error::live resize did not recover from a stale Infeasible condition: $response"
    return 1
  fi
  if [ "$(live_resources)" != "750m:750m:" ] \
      || [ "$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}')" != "$old_pod_uid" ] \
      || [ "$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.status.containerStatuses[?(@.name=="workspace")].restartCount}')" != "$old_restart_count" ]; then
    echo "::error::live resize recovery changed the workspace Pod or left a request pending: $(live_resources)"
    return 1
  fi
  log "live resize recovered from a stale Infeasible condition on Pod $old_pod_uid"

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
    -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\",\"cpuMillicores\":750,\"memoryMb\":384,\"diskGb\":1,\"requestId\":\"${request_id}\",\"disruptionPolicy\":\"ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART\"}" \
    "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/ResizeEnvironment" || return $?
  if [ "$PROBE_CODE" != "200" ]; then
    echo "::error::explicit restart resize request failed: code=$PROBE_CODE body=$PROBE_BODY"
    return 1
  fi
  operation_id="$(jq -r '.operation.id // empty' <<<"$PROBE_BODY")" || return $?
  operation_state=""
  for _ in $(seq 1 180); do
    curl_settled -X POST \
      -H 'cookie: codewire.session_token=contract-admin-session-token' \
      -H 'content-type: application/json' \
      -d "{\"orgId\":\"org_contract_1\",\"environmentId\":\"${environment_id}\",\"operationId\":\"${operation_id}\"}" \
      "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/GetEnvironmentResizeOperation" || return $?
    response="$PROBE_BODY"
    operation_state="$(jq -r '.operation.state // empty' <<<"$response")" || return $?
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
      "SELECT pod_name FROM sandbox_environment_backend WHERE environment_id = '$environment_id'")" || return $?
  new_pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}')" || return $?
  if [ -z "$new_pod_uid" ] || [ "$new_pod_uid" = "$old_pod_uid" ]; then
    echo "::error::explicit restart did not replace the workspace Pod"
    return 1
  fi
  current_pvc_uid="$(kubectl -n "$SANDBOX_NS" get pvc "$pvc_name" -o jsonpath='{.metadata.uid}')" || return $?
  marker="$(kubectl -n "$SANDBOX_NS" exec "$pod_name" -c workspace -- sh -ceu 'cat /workspace/resize-smoke-marker')" || return $?
  if [ "$current_pvc_uid" != "$pvc_uid" ] || [ "$marker" != "codewire-resize-data" ]; then
    echo "::error::explicit restart failed to preserve PVC identity or workspace data"
    return 1
  fi

  # The API server enforces the UID and resourceVersion that Codewire binds a
  # live resize to on pods/resize (#2473). Replace the Pod under the same name;
  # Codewire's request shape, bound to the old incarnation, is refused and the
  # replacement keeps its resources.
  local stale_uid stale_version replacement_uid="" replacement_cpu patch_output
  stale_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}')"
  stale_version="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.resourceVersion}')"
  if ! kubectl -n "$SANDBOX_NS" delete pod "$pod_name" --wait=true --timeout=120s >/dev/null; then
    echo "::error::could not delete the workspace Pod to exercise its replacement"
    return 1
  fi
  for _ in $(seq 1 120); do
    replacement_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    if [ -n "$replacement_uid" ] && [ "$replacement_uid" != "$stale_uid" ]; then
      break
    fi
    sleep 1
  done
  if [ -z "$replacement_uid" ] || [ "$replacement_uid" = "$stale_uid" ]; then
    echo "::error::the Sandbox did not replace the deleted workspace Pod"
    return 1
  fi
  if ! kubectl -n "$SANDBOX_NS" wait "pod/${pod_name}" --for=condition=Ready --timeout=180s >/dev/null; then
    echo "::error::the replacement workspace Pod did not become Ready"
    return 1
  fi
  replacement_cpu="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.spec.containers[?(@.name=="workspace")].resources.requests.cpu}')"
  bound_resize() {
    printf '{"metadata":{"uid":"%s","resourceVersion":"%s"},"spec":{"containers":[{"name":"workspace","resources":{"requests":{"cpu":"1000m","memory":"384Mi"},"limits":{"cpu":"1000m","memory":"384Mi"}}}]}}' "$1" "$2"
  }
  if patch_output="$(kubectl -n "$SANDBOX_NS" patch pod "$pod_name" --subresource=resize \
      --type=strategic -p "$(bound_resize "$stale_uid" "$stale_version")" 2>&1)" \
      || ! grep -q 'Conflict' <<<"$patch_output"; then
    echo "::error::a resize bound to the replaced Pod was not refused as a conflict: $patch_output"
    return 1
  fi
  # The UID is enforced on its own: the replacement's current resourceVersion
  # with the old UID is invalid. Retry only a concurrent status update.
  for _ in $(seq 1 5); do
    if patch_output="$(kubectl -n "$SANDBOX_NS" patch pod "$pod_name" --subresource=resize --type=strategic \
        -p "$(bound_resize "$stale_uid" "$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.metadata.resourceVersion}')")" 2>&1)"; then
      echo "::error::a resize bound to the replaced Pod UID mutated the replacement"
      return 1
    fi
    grep -q 'Conflict' <<<"$patch_output" || break
  done
  if ! grep -q 'metadata.uid' <<<"$patch_output" \
      || [ "$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o jsonpath='{.spec.containers[?(@.name=="workspace")].resources.requests.cpu}')" != "$replacement_cpu" ]; then
    echo "::error::the replacement Pod was not protected by the UID precondition: $patch_output"
    return 1
  fi
  log "pods/resize refused requests bound to replaced Pod $stale_uid; replacement $replacement_uid unchanged"


  local as_user="system:serviceaccount:${NS}:codewire-orchestration"
  storage_rbac="$(kubectl auth can-i get storageclasses.storage.k8s.io --as "$as_user")" || return $?
  pvc_rbac="$(kubectl auth can-i patch persistentvolumeclaims --namespace "$SANDBOX_NS" --as "$as_user")" || return $?
  if [ "$storage_rbac" != "yes" ] || [ "$pvc_rbac" != "yes" ]; then
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
  # Name this cluster's frontend: the binary's default-port frontend is
  # another cluster's Temporal whenever the host ports are shifted.
  if ! DATABASE_URL="$KIND_DATABASE_URL" \
    TEMPORAL_ADDRESS="$KIND_TEMPORAL_FRONTEND_URL" \
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
    TEMPORAL_ADDRESS="$KIND_TEMPORAL_FRONTEND_URL" \
    SMOKE_ORCHESTRATION_URL="$KIND_ORCHESTRATION_HTTP_URL" \
    SMOKE_WORKSPACE_IMAGE="$workspace_image" \
    "$CARGO_CI_DIR/temporal-fencing-smoke"
}

deploy_agent_sandbox_and_smoke() {
  deploy_agent_sandbox
  # The Claude stages run during the native stage's rotation idle (#2972).
  kind_credential_native_smoke claude-session claude-sign-in
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
      startswith("registry.example.invalid/oci-approved/codewire/workspace@") or
      startswith("localhost/codewire-ci/workspace:");
    def dind_image:
      startswith("ghcr.io/codewiresh/" + "dind") or
      startswith("docker:" + "dind") or
      startswith("docker.io/library/docker:") or
      startswith("docker.io/library/docker@") or
      startswith("registry.example.invalid/oci-approved/docker/dind@") or
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
               startswith("registry.example.invalid/oci-approved/codewire/workspace@") or
               startswith("registry.example.invalid/oci-approved/docker/dind@") or
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
               startswith("registry.example.invalid/oci-approved/codewire/workspace@") or
               startswith("registry.example.invalid/oci-approved/docker/dind@") or
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
               startswith("registry.example.invalid/oci-approved/codewire/workspace@") or
               startswith("registry.example.invalid/oci-approved/docker/dind@") or
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
            | test("(ghcr\\.io/codewiresh/(workspace|din[d])|docker:din[d]|docker\\.io/library/docker|registry\\.example\\.invalid/oci-approved/(codewire/workspace|docker/dind)|localhost/codewire-ci/(workspace|docker-dind))"))
        )
      | $event
    ] | length == 0
  ' <<<"$events" >/dev/null; then
    echo "::error::Kind recorded a workspace or DinD image-provenance failure"
    jq -r '.items[]
      | select((.message // "")
          | test("(ghcr\\.io/codewiresh/(workspace|din[d])|docker:din[d]|docker\\.io/library/docker|registry\\.example\\.invalid/oci-approved/(codewire/workspace|docker/dind)|localhost/codewire-ci/(workspace|docker-dind))"))
      | "\(.metadata.namespace // "default")/\(.involvedObject.name): \(.reason)"' \
      <<<"$events" >&2
    return 1
  fi

  log "sandbox token automount disabled and observed workspace/DinD references are immutable"
}

workspace_access_stack_smoke() {
  local workspace_image
  workspace_image="$(kind_workspace_runtime_image)" || return $?
  local daemon_pod=crd-smoke-workspace-daemon
  local daemon_token

  log "running CRD round-trip and access-object smoke (no gateway objects)"
  daemon_token="$(daemon_auth_token_for_environment env-crd-smoke)" || return $?
  CRD_SMOKE_NAMESPACE="$SANDBOX_NS" \
    CRD_SMOKE_SERVER_NAMESPACE="$NS" \
    CRD_SMOKE_WORKSPACE_IMAGE="$workspace_image" \
    CRD_SMOKE_ACCESS_PHASE=setup \
    CRD_SMOKE_LOCAL_IMAGES=1 \
    "$CARGO_CI_DIR/crd-smoke" || return $?

  # Pod specs are immutable. Recreate only this owned daemon fixture when a
  # retained service smoke is repeated; the access objects stay in place.
  kubectl -n "$SANDBOX_NS" delete "pod/${daemon_pod}" \
    --ignore-not-found=true --wait=true --timeout=120s || return $?
  kubectl_apply -f - <<EOF || return $?
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
  initContainers:
    - name: codewire-daemon-init
      image: codewire-daemon:e2e
      imagePullPolicy: Never
      command:
        - sh
        - -ec
        - umask 077; mkdir -p /codewire/run/processes && chmod 0700 /codewire/run/processes && cp /usr/local/bin/cw /codewire/bin/.cw.tmp && chmod 0755 /codewire/bin/.cw.tmp && mv /codewire/bin/.cw.tmp /codewire/bin/cw
      volumeMounts:
        - name: codewire-bin
          mountPath: /codewire/bin
        - name: codewire-run
          mountPath: /codewire/run
  containers:
    - name: workspace
      image: codewire-daemon:e2e
      imagePullPolicy: Never
      command: ["/codewire/bin/cw", "__hosted-daemon"]
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
        - name: codewire-bin
          mountPath: /codewire/bin
        - name: codewire-run
          mountPath: /codewire/run
        - name: workspace
          mountPath: /home/codewire
        - name: workspace
          mountPath: /workspace
  volumes:
    - name: codewire-bin
      emptyDir: {}
    - name: codewire-run
      emptyDir:
        medium: Memory
    - name: workspace
      emptyDir: {}
EOF
  kubectl -n "$SANDBOX_NS" wait "pod/${daemon_pod}" \
    --for=condition=Ready --timeout=120s || return $?

  log "access objects verified with no gateway objects; retaining the daemon fixture for FileService"
}

billing_contract_through_ingress() {
  log "running configured Rust billing Connect contract through ingress"
  (
    cd "$ROOT"
    local binary
    binary="$(jq -ser '
      [.[] | select(.reason == "compiler-artifact" and .profile.test == true
        and .target.name == "wire_contract" and .executable != null) | .executable]
      | if length == 1 then .[0] else error("expected one billing wire contract") end
    ' "$RUN_DIR/billing-contract-build.jsonl")"
    [ -x "$binary" ] || { echo '::error::billing contract executable is missing' >&2; return 1; }
    BILLING_BASE_URL="$KIND_INGRESS_URL" \
      BILLING_ADMIN_SESSION_TOKEN=contract-admin-session-token \
      BILLING_USER_SESSION_TOKEN=contract-user-session-token \
      BILLING_SEEDED=1 \
      BILLING_SKIP_HEALTH=1 \
      "$binary" configured_billing_wire_contract \
        --ignored --exact --nocapture | tee "$RUN_DIR/billing-contract.log"
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
    SMOKE_ORCHESTRATION_URL="$KIND_ORCHESTRATION_HTTP_URL" \
    SMOKE_SANDBOX_NAMESPACE="$SANDBOX_NS" \
    SMOKE_SESSION_TOKEN=contract-admin-session-token \
    SMOKE_ORG_ID=org_contract_1 \
    SMOKE_WORKSPACE_IMAGE="$workspace_image" \
    SMOKE_KIND_E2E="$ROOT/scripts/ci/verify/kind-e2e.sh" \
    "$CARGO_CI_DIR/reconciler-ttl-smoke"
}

orchestration_authorization_smoke() {
  log "proving orchestration has no Secret or Deployment authority and reads only its published roots"
  local as_user="system:serviceaccount:${NS}:codewire-orchestration"
  local namespace verb allowed
  for namespace in "$SANDBOX_NS" "$NS"; do
    for verb in get list watch create update patch delete; do
      allowed="$(kubectl auth can-i "$verb" secrets -n "$namespace" --as "$as_user" || true)"
      if [ "$allowed" != "no" ]; then
        echo "::error::orchestration can-i ${verb} Secrets in ${namespace} returned ${allowed}, want no"
        return 1
      fi
    done
    allowed="$(kubectl auth can-i create deployments.apps -n "$namespace" --as "$as_user" || true)"
    if [ "$allowed" != "no" ]; then
      echo "::error::orchestration can-i create Deployments in ${namespace} returned ${allowed}, want no"
      return 1
    fi
  done
  allowed="$(kubectl auth can-i get configmaps/codewire-orchestration-internal-roots \
    -n "$SANDBOX_NS" --as "$as_user" || true)"
  if [ "$allowed" != "yes" ]; then
    echo "::error::orchestration cannot read its published internal roots: ${allowed}"
    return 1
  fi
  for verb in list update delete; do
    allowed="$(kubectl auth can-i "$verb" configmaps -n "$SANDBOX_NS" --as "$as_user" || true)"
    if [ "$allowed" != "no" ]; then
      echo "::error::orchestration can-i ${verb} sandbox ConfigMaps returned ${allowed}, want no"
      return 1
    fi
  done
  allowed="$(kubectl auth can-i get configmaps/codewire-coordinator-extra-roots \
    -n "$SANDBOX_NS" --as "$as_user" || true)"
  if [ "$allowed" != "no" ]; then
    echo "::error::orchestration can read another sandbox ConfigMap: ${allowed}"
    return 1
  fi
}
