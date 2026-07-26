#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
CODEWIRE_SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-dev}"
KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-$ROOT/.tmp}"
MATRIX_KEEP_ENV="${MATRIX_KEEP_ENV:-0}"
MATRIX_KEEP_NAMESPACE="${MATRIX_KEEP_NAMESPACE:-0}"
MATRIX_SANDBOX_NAMESPACE="${MATRIX_SANDBOX_NAMESPACE:-}"
MATRIX_CORDON_OTHER_RUNTIME_NODES="${MATRIX_CORDON_OTHER_RUNTIME_NODES:-1}"
EXPECTED_NODE="${EXPECTED_NODE:-}"
EXPECTED_RUNTIME_NODE_SELECTOR="${EXPECTED_RUNTIME_NODE_SELECTOR:-katacontainers.io/kata-runtime=true}"
MATRIX_WORKER_LOOPS="${MATRIX_WORKER_LOOPS:-env-reconciler,sandbox-liveness,billing-session,warm-pool-reconciler}"
MATRIX_TEMPLATE_SOURCE_NAMESPACE="${MATRIX_TEMPLATE_SOURCE_NAMESPACE:-dev-sandboxes}"
MATRIX_GATEWAY_TAG="${MATRIX_GATEWAY_TAG:-}"
MATRIX_BUILD_GATEWAY="${MATRIX_BUILD_GATEWAY:-0}"
MATRIX_CANDIDATE_IMAGES="${MATRIX_CANDIDATE_IMAGES:-services gateway}"
SMOKE_TAILNET_DIRECT_WAIT="${SMOKE_TAILNET_DIRECT_WAIT:-5s}"
SMOKE_TAILNET_PEER_TIMEOUT="${SMOKE_TAILNET_PEER_TIMEOUT:-30s}"
SMOKE_TAILNET_DIAL_TIMEOUT="${SMOKE_TAILNET_DIAL_TIMEOUT:-60s}"
SMOKE_SSH_TIMEOUT="${SMOKE_SSH_TIMEOUT:-90}"
SMOKE_SSH_CONNECT_TIMEOUT="${SMOKE_SSH_CONNECT_TIMEOUT:-60}"
MATRIX_INITIAL_SMOKE_TIMEOUT_SECONDS="${MATRIX_INITIAL_SMOKE_TIMEOUT_SECONDS:-900}"
MATRIX_DESTROY_TIMEOUT_SECONDS="${MATRIX_DESTROY_TIMEOUT_SECONDS:-300}"
EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB="${EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB:-400}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/with-dev-smoke-auth.sh scripts/runtime/dev/smoke-dev-transport-matrix.sh [options]

Creates one fresh dev commodity environment, proves direct_udp, forced DERP,
and websocket through the normal runtime smoke, then proves peer_relay against
the same environment with peer direct endpoints suppressed.

Options:
  --keep                 Keep the smoke environment after success.
  --initial-smoke-arg X  Add one argument to the initial smoke. Repeatable.
                         Use this for --timeout-seconds, --only, etc.
  --sandbox-namespace N  Use this temporary sandbox namespace instead of an
                         auto-generated one.
  --keep-namespace       Keep the temporary sandbox namespace after success.
  -h, --help            Show this help.

Environment:
  SMOKE_TAILNET_DIRECT_WAIT         direct UDP/relay settle wait, default 5s
  SMOKE_TAILNET_PEER_TIMEOUT        coordinator/DERP peer wait, default 30s
  SMOKE_TAILNET_DIAL_TIMEOUT        tailnet TCP stream dial timeout, default 60s
  SMOKE_SSH_TIMEOUT                 transport SSH command timeout, default 90
  SMOKE_SSH_CONNECT_TIMEOUT         OpenSSH ConnectTimeout, default 60
  MATRIX_DESTROY_TIMEOUT_SECONDS    environment destroy completion timeout,
                                    default 300; namespace cleanup waits for it
  MATRIX_KEEP_ENV                   keep environment on success when 1
  MATRIX_KEEP_NAMESPACE             keep smoke namespace on success when 1
  MATRIX_CORDON_OTHER_RUNTIME_NODES cordon runtime nodes other than EXPECTED_NODE
                                    during the run, default 1
  MATRIX_WORKER_LOOPS               WORKER_LOOPS override for the candidate
                                    window, default includes warm-pool-reconciler
  MATRIX_TEMPLATE_SOURCE_NAMESPACE  Namespace to copy SandboxTemplates from,
                                    default dev-sandboxes
  MATRIX_GATEWAY_TAG                Gateway image tag to test. Defaults to the
                                    currently deployed dev tag.
  MATRIX_BUILD_GATEWAY              Build and push MATRIX_GATEWAY_TAG when 1,
                                    default 0
  MATRIX_CANDIDATE_IMAGES           Space-separated candidate images to deploy,
                                    default "services gateway"
  EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB
                                    Runtime node storage preflight passed to
                                    the candidate smoke, default 400 for fresh
                                    dev transport proof nodes

The wrapper never prints API keys. On failure, it leaves the environment and
evidence directories in place.
USAGE
}

log() {
  printf '[transport-matrix] %s\n' "$*" >&2
}

die() {
  printf '[transport-matrix] ERROR: %s\n' "$*" >&2
  exit 1
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

declare -a INITIAL_SMOKE_ARGS=()
declare -a CANDIDATE_IMAGE_ARGS=()

while (($# > 0)); do
  case "$1" in
    --keep)
      MATRIX_KEEP_ENV=1
      shift
      ;;
    --initial-smoke-arg)
      [[ $# -ge 2 ]] || die "--initial-smoke-arg requires a value"
      INITIAL_SMOKE_ARGS+=("$2")
      shift 2
      ;;
    --sandbox-namespace)
      [[ $# -ge 2 ]] || die "--sandbox-namespace requires a value"
      MATRIX_SANDBOX_NAMESPACE="$2"
      shift 2
      ;;
    --keep-namespace)
      MATRIX_KEEP_NAMESPACE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]] || \
  die "CODEWIRE_DEV_SMOKE_API_KEY is required; run through scripts/runtime/dev/with-dev-smoke-auth.sh"
[[ "$CODEWIRE_DEV_SMOKE_API_KEY" =~ ^cw_[0-9a-f]{64}$ ]] || \
  die "CODEWIRE_DEV_SMOKE_API_KEY has an unexpected shape"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_cmd awk
require_cmd jq
require_cmd kubectl
require_cmd sed
require_cmd timeout

mkdir -p "$SMOKE_TMP_PARENT"
MATRIX_DIR="$(mktemp -d "$SMOKE_TMP_PARENT/codewire-transport-matrix.XXXXXX")"
INITIAL_LOG="$MATRIX_DIR/initial-direct-derp-websocket.log"

ENV_ID=""
INITIAL_EVIDENCE_DIR=""
CW_BIN=""
declare -a MATRIX_CORDONED_NODES=()

kubectl_dev() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
  export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
fi

if [[ -z "$MATRIX_SANDBOX_NAMESPACE" ]]; then
  MATRIX_SANDBOX_NAMESPACE="dev-sbx-transport-$(date -u +%m%d%H%M%S)-$RANDOM"
  MATRIX_SANDBOX_NAMESPACE="$(printf '%s' "$MATRIX_SANDBOX_NAMESPACE" | tr '[:upper:]_' '[:lower:]-' | cut -c1-63 | sed -E 's/-+$//')"
fi

current_gateway_tag() {
  local configmap image

  configmap="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment codewire-orchestration -o json |
    jq -r '.spec.template.spec.containers[]
      | select(.name == "orchestration")
      | .envFrom[]?
      | .configMapRef.name? // empty' |
    sed -n '1p')"
  [[ -n "$configmap" ]] || die "failed to resolve dev runtime ConfigMap from codewire-orchestration"

  image="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get configmap "$configmap" -o json |
    jq -r '.data.SANDBOX_GATEWAY_IMAGE // empty')"
  [[ "$image" == git.example.invalid/codewire/gateway:* ]] || \
    die "dev SANDBOX_GATEWAY_IMAGE=$image, expected git.example.invalid/codewire/gateway:<tag>"
  printf '%s\n' "${image##*:}"
}

generated_candidate_tag() {
  printf 'dev-smoke-transport-%s-%s\n' \
    "$(date -u +%Y%m%d%H%M%S)" \
    "$(git -C "$ROOT" rev-parse --short=12 HEAD)"
}

cordon_other_runtime_nodes() {
  local nodes node unschedulable

  [[ "$MATRIX_CORDON_OTHER_RUNTIME_NODES" == "1" ]] || return 0
  [[ -n "$EXPECTED_NODE" ]] || \
    die "EXPECTED_NODE is required when MATRIX_CORDON_OTHER_RUNTIME_NODES=1"

  nodes="$(kubectl_dev get nodes -l "$EXPECTED_RUNTIME_NODE_SELECTOR" -o json |
    jq -r '.items[].metadata.name')"
  while IFS= read -r node; do
    [[ -n "$node" ]] || continue
    [[ "$node" != "$EXPECTED_NODE" ]] || continue
    unschedulable="$(kubectl_dev get node "$node" -o jsonpath='{.spec.unschedulable}')"
    if [[ "$unschedulable" == "true" ]]; then
      log "runtime node $node is already cordoned; leaving it unchanged"
      continue
    fi
    log "cordoning non-target runtime node $node for fresh-node smoke"
    kubectl_dev cordon "$node" >/dev/null
    MATRIX_CORDONED_NODES+=("$node")
  done <<<"$nodes"
}

restore_cordoned_nodes() {
  local node

  for node in "${MATRIX_CORDONED_NODES[@]}"; do
    log "uncordoning runtime node $node"
    kubectl_dev uncordon "$node" >/dev/null || true
  done
}

wait_for_environment_destroyed() {
  local deadline=$((SECONDS + MATRIX_DESTROY_TIMEOUT_SECONDS))
  local state_json

  while ((SECONDS < deadline)); do
    if state_json="$({
      CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY" \
        CW_CONFIG_DIR="${INITIAL_EVIDENCE_DIR:-$MATRIX_DIR}/cw-config" \
        "$CW_BIN" --server "$CODEWIRE_SERVER_URL" env info "$ENV_ID" --output json
    } 2>/dev/null)" &&
      jq -e '.state == "destroyed" and .desired_state == "destroyed"' \
        >/dev/null <<<"$state_json"; then
      return 0
    fi
    sleep 2
  done

  return 1
}

cleanup() {
  local rc=$?

  restore_cordoned_nodes

  if [[ "$rc" == "0" && "$MATRIX_KEEP_ENV" != "1" && -n "$ENV_ID" && -x "$CW_BIN" ]]; then
    log "deleting smoke environment $ENV_ID"
    if ! CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY" \
      CW_CONFIG_DIR="${INITIAL_EVIDENCE_DIR:-$MATRIX_DIR}/cw-config" \
      "$CW_BIN" --server "$CODEWIRE_SERVER_URL" env rm --yes "$ENV_ID" >/dev/null 2>&1; then
      log "environment delete request failed; keeping namespace $MATRIX_SANDBOX_NAMESPACE"
      rc=1
    elif ! wait_for_environment_destroyed; then
      log "environment $ENV_ID did not reach destroyed before cleanup timeout; keeping namespace $MATRIX_SANDBOX_NAMESPACE"
      rc=1
    else
      log "environment $ENV_ID reached destroyed"
    fi
  elif [[ -n "$ENV_ID" ]]; then
    log "kept smoke environment $ENV_ID"
  fi

  if [[ "$rc" == "0" && "$MATRIX_KEEP_NAMESPACE" != "1" ]]; then
    log "deleting temporary sandbox namespace $MATRIX_SANDBOX_NAMESPACE"
    if ! kubectl_dev delete namespace "$MATRIX_SANDBOX_NAMESPACE" \
      --ignore-not-found --wait=true --timeout=180s >/dev/null; then
      log "temporary sandbox namespace deletion failed"
      rc=1
    fi
  elif [[ "$MATRIX_KEEP_NAMESPACE" == "1" ]]; then
    log "kept temporary sandbox namespace $MATRIX_SANDBOX_NAMESPACE"
  fi

  if [[ "$rc" == "0" ]]; then
    log "transport matrix evidence directory $MATRIX_DIR"
  else
    log "kept failed transport matrix evidence directory $MATRIX_DIR"
  fi
  exit "$rc"
}
trap cleanup EXIT

parse_runtime_smoke_log() {
  local log_file="$1"
  local env_id evidence_dir

  env_id="$(awk '/environment id / || /using existing environment / {print $NF; found=1} END {if (!found) exit 1}' "$log_file")" || \
    die "failed to parse environment id from $log_file"
  evidence_dir="$(awk '/kept evidence directory / {print $NF; found=1} END {if (!found) exit 1}' "$log_file")" || \
    die "failed to parse evidence directory from $log_file"
  [[ -d "$evidence_dir" ]] || die "parsed evidence directory does not exist: $evidence_dir"

  printf '%s\n%s\n' "$env_id" "$evidence_dir"
}

mapfile -t candidate_images < <(printf '%s\n' "$MATRIX_CANDIDATE_IMAGES" | tr ' ' '\n' | sed '/^$/d')
[[ "${#candidate_images[@]}" -gt 0 ]] || die "MATRIX_CANDIDATE_IMAGES must contain at least one image"
for image in "${candidate_images[@]}"; do
  CANDIDATE_IMAGE_ARGS+=(--image "$image")
done

if [[ -n "$MATRIX_GATEWAY_TAG" ]]; then
  GATEWAY_TAG="$MATRIX_GATEWAY_TAG"
elif [[ "$MATRIX_BUILD_GATEWAY" == "1" ]]; then
  GATEWAY_TAG="$(generated_candidate_tag)"
else
  GATEWAY_TAG="$(current_gateway_tag)"
fi
if [[ "$MATRIX_BUILD_GATEWAY" != "1" ]]; then
  CANDIDATE_IMAGE_ARGS+=(--skip-build)
fi
cordon_other_runtime_nodes

log "running fresh-node direct_udp + forced DERP + websocket smoke in $MATRIX_SANDBOX_NAMESPACE with gateway tag $GATEWAY_TAG"
if ! EXPECTED_TAILNET_PATH_TRANSPORT=direct_udp \
    CANDIDATE_WORKER_LOOPS="$MATRIX_WORKER_LOOPS" \
    CANDIDATE_SEED_SANDBOX_TEMPLATES_FROM_NAMESPACE="$MATRIX_TEMPLATE_SOURCE_NAMESPACE" \
    EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB="$EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB" \
    SMOKE_KEEP_ENV=1 \
    SMOKE_SKIP_DOCKER=1 \
    SMOKE_DERP_FALLBACK=1 \
    SMOKE_PEER_RELAY_MATRIX=1 \
    SMOKE_TAILNET_DIRECT_WAIT="$SMOKE_TAILNET_DIRECT_WAIT" \
    SMOKE_TAILNET_PEER_TIMEOUT="$SMOKE_TAILNET_PEER_TIMEOUT" \
    SMOKE_TAILNET_DIAL_TIMEOUT="$SMOKE_TAILNET_DIAL_TIMEOUT" \
    SMOKE_SSH_TIMEOUT="$SMOKE_SSH_TIMEOUT" \
    SMOKE_SSH_CONNECT_TIMEOUT="$SMOKE_SSH_CONNECT_TIMEOUT" \
    SMOKE_TIMEOUT_SECONDS="$MATRIX_INITIAL_SMOKE_TIMEOUT_SECONDS" \
    "$ROOT/scripts/runtime/dev/smoke-dev-candidate.sh" \
      "${CANDIDATE_IMAGE_ARGS[@]}" \
      --tag "$GATEWAY_TAG" \
      --force-shared-dev \
      --sandbox-namespace "$MATRIX_SANDBOX_NAMESPACE" \
      --keep-namespace \
      -- --keep --skip-docker "${INITIAL_SMOKE_ARGS[@]}" \
    >"$INITIAL_LOG" 2>&1; then
  sed 's/[[:cntrl:]]//g' "$INITIAL_LOG" >&2 || true
  die "initial direct_udp/DERP/websocket smoke failed"
fi

mapfile -t parsed < <(parse_runtime_smoke_log "$INITIAL_LOG")
ENV_ID="${parsed[0]}"
INITIAL_EVIDENCE_DIR="${parsed[1]}"
CW_BIN="$INITIAL_EVIDENCE_DIR/cw"
[[ -x "$CW_BIN" ]] || die "cw binary from initial smoke is not executable: $CW_BIN"

log "initial direct_udp smoke passed for $ENV_ID; evidence $INITIAL_EVIDENCE_DIR"
[[ -s "$INITIAL_EVIDENCE_DIR/tailnet-doctor.json" ]] || \
  die "direct_udp doctor evidence is missing from $INITIAL_EVIDENCE_DIR"
[[ -s "$INITIAL_EVIDENCE_DIR/tailnet-doctor-peer-relay.json" ]] || \
  die "peer_relay doctor evidence is missing from $INITIAL_EVIDENCE_DIR"
grep -qx 'tailnet-ssh-ok' "$INITIAL_EVIDENCE_DIR/ssh-tailnet.out" || \
  die "direct_udp SSH evidence is missing from $INITIAL_EVIDENCE_DIR"
grep -qx 'tailnet-peer-relay-ssh-ok' "$INITIAL_EVIDENCE_DIR/ssh-tailnet-peer-relay.out" || \
  die "peer_relay SSH evidence is missing from $INITIAL_EVIDENCE_DIR"
grep -qx 'tailnet-derp-ssh-ok' "$INITIAL_EVIDENCE_DIR/ssh-tailnet-derp.out" || \
  die "DERP SSH evidence is missing from $INITIAL_EVIDENCE_DIR"
grep -qx 'websocket-ssh-ok' "$INITIAL_EVIDENCE_DIR/ssh-websocket.out" || \
  die "WebSocket SSH evidence is missing from $INITIAL_EVIDENCE_DIR"

log "fresh-node transport matrix passed for $ENV_ID: direct_udp, peer_relay, derp_relay, websocket"
