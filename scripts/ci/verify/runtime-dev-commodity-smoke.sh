#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-}"
EXPECTED_CODEWIRE_DEV_SERVER_URL="${EXPECTED_CODEWIRE_DEV_SERVER_URL:-}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
CODEWIRE_SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-}"
EXPECTED_NODE="${EXPECTED_NODE:-}"
REQUIRE_TAILNET_PATH_PROBE="${REQUIRE_TAILNET_PATH_PROBE:-1}"
EXPECTED_TAILNET_PATH_TRANSPORT="${EXPECTED_TAILNET_PATH_TRANSPORT:-peer_relay}"
EXPECTED_TAILNET_PEER_RELAY_ENDPOINT="${EXPECTED_TAILNET_PEER_RELAY_ENDPOINT:-}"
EXPECTED_UDP_RELAY_BIND_ADDRS="${EXPECTED_UDP_RELAY_BIND_ADDRS:-}"
EXPECTED_UDP_RELAY_ALLOCATOR_URL="${EXPECTED_UDP_RELAY_ALLOCATOR_URL:-}"
EXPECTED_TAILNET_DIRECT_UDP_LB_IP="${EXPECTED_TAILNET_DIRECT_UDP_LB_IP:-}"
EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE="${EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE:-}"
EXPECTED_RUNTIME_TRANSPORT_REGION="${EXPECTED_RUNTIME_TRANSPORT_REGION:-}"
SMOKE_DERP_FALLBACK="${SMOKE_DERP_FALLBACK:-1}"
SMOKE_SKIP_KUBE="${SMOKE_SKIP_KUBE:-0}"
EXPECTED_KATA_AGENT_POLICY_ANNOTATION="${EXPECTED_KATA_AGENT_POLICY_ANNOTATION:-1}"
EXPECTED_KATA_COCO_INIT_DATA_ANNOTATION="${EXPECTED_KATA_COCO_INIT_DATA_ANNOTATION:-0}"
EXPECTED_KATA_COCO_KBS_URL="${EXPECTED_KATA_COCO_KBS_URL:-}"
EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI="${EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI:-}"
EXPECTED_KATA_COCO_TEST_RESOURCE_URI="${EXPECTED_KATA_COCO_TEST_RESOURCE_URI:-}"
EXPECTED_KATA_COCO_TEST_RESOURCE_PATH="${EXPECTED_KATA_COCO_TEST_RESOURCE_PATH:-}"
EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT="${EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT:-}"
SMOKE_TIMEOUT_SECONDS="${SMOKE_TIMEOUT_SECONDS:-1200}"
SMOKE_TAILNET_DIRECT_WAIT="${SMOKE_TAILNET_DIRECT_WAIT:-20s}"
SMOKE_TAILNET_PEER_TIMEOUT="${SMOKE_TAILNET_PEER_TIMEOUT:-30s}"
SMOKE_TAILNET_DOCTOR_TIMEOUT="${SMOKE_TAILNET_DOCTOR_TIMEOUT:-90}"
SMOKE_SSH_CONNECT_TIMEOUT="${SMOKE_SSH_CONNECT_TIMEOUT:-60}"

die() {
  printf '[runtime-smoke-ci] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[runtime-smoke-ci] %s\n' "$*" >&2
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

command -v jq >/dev/null 2>&1 || die "missing required command: jq"
for required in \
  CODEWIRE_SERVER_URL \
  EXPECTED_CODEWIRE_DEV_SERVER_URL \
  EXPECTED_TAILNET_PEER_RELAY_ENDPOINT \
  EXPECTED_UDP_RELAY_BIND_ADDRS \
  EXPECTED_UDP_RELAY_ALLOCATOR_URL \
  EXPECTED_TAILNET_DIRECT_UDP_LB_IP \
  EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE \
  EXPECTED_RUNTIME_TRANSPORT_REGION; do
  [[ -n "${!required:-}" ]] || die "$required is required"
done

[[ "$SMOKE_SKIP_KUBE" == "0" || "$SMOKE_SKIP_KUBE" == "1" ]] ||
  die "SMOKE_SKIP_KUBE must be 0 or 1"

if [[ "$SMOKE_SKIP_KUBE" != "1" ]]; then
  command -v kubectl >/dev/null 2>&1 || die "missing required command: kubectl"
  for required in \
    KUBE_CONTEXT \
    CODEWIRE_SERVER_NAMESPACE \
    SANDBOX_NAMESPACE \
    EXPECTED_NODE; do
    [[ -n "${!required:-}" ]] || die "$required is required"
  done
fi

kubectl_dev() {
  kubectl --context "$KUBE_CONTEXT" "$@"
}

config_json=""
cleanup() {
  [[ -z "$config_json" ]] || rm -f "$config_json"
}
trap cleanup EXIT

stun_host="${EXPECTED_GATEWAY_STUN_HOST:-}"
stun_port="${EXPECTED_GATEWAY_STUN_PORT:-3478}"
runtime_configmap="application-only"
if [[ "$SMOKE_SKIP_KUBE" != "1" ]]; then
  runtime_configmap="$(
    kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deploy codewire-orchestration -o json |
      jq -r '.spec.template.spec.containers[]
        | select(.name == "orchestration")
        | .envFrom[]?
        | .configMapRef.name? // empty' |
      head -n 1
  )"
  [[ -n "$runtime_configmap" ]] || die "failed to resolve codewire-orchestration configmap"

  config_json="$(mktemp "${TMPDIR:-/tmp}/codewire-runtime-config.XXXXXX")"
  kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get configmap "$runtime_configmap" -o json >"$config_json"

  runtime_profile="$(jq -r '.data.SANDBOX_RUNTIME_PROFILE // empty' "$config_json")"
  runtime_class="$(jq -r '.data.SANDBOX_RUNTIME_CLASS // empty' "$config_json")"
  configured_sandbox_namespace="$(jq -r '.data.SANDBOX_NAMESPACE // empty' "$config_json")"
  configured_billing_namespace="$(jq -r '.data.BILLING_CONTROLLER_NAMESPACE // empty' "$config_json")"
  stun_host="$(jq -r '.data.STUN_HOST // empty' "$config_json")"
  stun_port="$(jq -r '.data.STUN_PORT // empty' "$config_json")"
  udp_relay_advertise_addrs="$(jq -r '.data.CODEWIRE_UDP_RELAY_ADVERTISE_ADDRS // empty' "$config_json")"
  udp_relay_allocator_url="$(jq -r '.data.CODEWIRE_UDP_RELAY_ALLOCATOR_URL // empty' "$config_json")"
  udp_relay_bind_addrs="$(jq -r '.data.CODEWIRE_UDP_RELAY_BIND_ADDRS // empty' "$config_json")"
  runtime_transport_zones_json="$(jq -r '.data.CODEWIRE_RUNTIME_TRANSPORT_ZONES_JSON // empty' "$config_json")"
  kata_agent_policy_enabled="$(jq -r '.data.SANDBOX_KATA_AGENT_POLICY_ENABLED // "false"' "$config_json")"

  [[ "$runtime_profile" == "commodity" ]] || die "SANDBOX_RUNTIME_PROFILE=$runtime_profile, want commodity"
  [[ "$runtime_class" == "commodity" ]] || die "SANDBOX_RUNTIME_CLASS=$runtime_class, want commodity"
  if [[ -n "$configured_sandbox_namespace" && "$configured_sandbox_namespace" != "$SANDBOX_NAMESPACE" ]]; then
    die "runtime ConfigMap SANDBOX_NAMESPACE=$configured_sandbox_namespace, smoke SANDBOX_NAMESPACE=$SANDBOX_NAMESPACE"
  fi
  if [[ -n "$configured_billing_namespace" && "$configured_billing_namespace" != "$SANDBOX_NAMESPACE" ]]; then
    die "runtime ConfigMap BILLING_CONTROLLER_NAMESPACE=$configured_billing_namespace, smoke SANDBOX_NAMESPACE=$SANDBOX_NAMESPACE"
  fi
  [[ -n "$stun_host" ]] || die "STUN_HOST is empty; tailnet UDP discovery requires STUN"
  [[ "$stun_port" == "3478" ]] || die "STUN_PORT=$stun_port, want public UDP 3478"
  if [[ "$EXPECTED_TAILNET_PATH_TRANSPORT" == "peer_relay" ]]; then
    [[ ",$udp_relay_advertise_addrs," == *",$EXPECTED_TAILNET_PEER_RELAY_ENDPOINT,"* ]] || \
      die "CODEWIRE_UDP_RELAY_ADVERTISE_ADDRS=$udp_relay_advertise_addrs, want $EXPECTED_TAILNET_PEER_RELAY_ENDPOINT for peer_relay smoke"
    [[ -z "$udp_relay_allocator_url" ]] || \
      die "CODEWIRE_UDP_RELAY_ALLOCATOR_URL=$udp_relay_allocator_url, want transport-zone registry"
    [[ -z "$udp_relay_bind_addrs" ]] || \
      die "CODEWIRE_UDP_RELAY_BIND_ADDRS=$udp_relay_bind_addrs, want transport-zone registry"
    [[ -n "$runtime_transport_zones_json" ]] || die "CODEWIRE_RUNTIME_TRANSPORT_ZONES_JSON is empty"
    jq -e \
      --arg zone "$EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE" \
      --arg region "$EXPECTED_RUNTIME_TRANSPORT_REGION" \
      --arg endpoint "$EXPECTED_TAILNET_PEER_RELAY_ENDPOINT" \
      --arg allocator "$EXPECTED_UDP_RELAY_ALLOCATOR_URL" \
      --arg bind "$EXPECTED_UDP_RELAY_BIND_ADDRS" \
      --arg direct_ip "$EXPECTED_TAILNET_DIRECT_UDP_LB_IP" \
      '.zones[]? | select(.name == $zone and .runtime_region == $region)
        | select((.peer_relay.public_endpoints // []) | index($endpoint))
        | select(.peer_relay.allocator_url == $allocator)
        | select((.peer_relay.bind_addrs // []) | index($bind))
        | select(.direct_udp.vip == $direct_ip)' \
      <<<"$runtime_transport_zones_json" >/dev/null || \
      die "runtime transport-zone registry does not contain expected $EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE peer relay capability"
  fi
  if [[ "$EXPECTED_KATA_AGENT_POLICY_ANNOTATION" == "1" ]]; then
    [[ "$kata_agent_policy_enabled" == "true" ]] || \
      die "SANDBOX_KATA_AGENT_POLICY_ENABLED=$kata_agent_policy_enabled, want true for commodity policy smoke"
  fi

  if [[ -z "${EXPECTED_GATEWAY_IMAGE:-}" ]]; then
    EXPECTED_GATEWAY_IMAGE="$(jq -r '.data.SANDBOX_GATEWAY_IMAGE // empty' "$config_json")"
    export EXPECTED_GATEWAY_IMAGE
  fi
  [[ -n "$EXPECTED_GATEWAY_IMAGE" ]] || die "EXPECTED_GATEWAY_IMAGE is empty and could not be resolved from $runtime_configmap"
fi

export CODEWIRE_SERVER_URL
export EXPECTED_CODEWIRE_DEV_SERVER_URL
export KUBE_CONTEXT
export CODEWIRE_SERVER_NAMESPACE
export SANDBOX_NAMESPACE
export EXPECTED_NODE
export REQUIRE_TAILNET_PATH_PROBE
export EXPECTED_TAILNET_PATH_TRANSPORT
export EXPECTED_TAILNET_PEER_RELAY_ENDPOINT
export EXPECTED_UDP_RELAY_BIND_ADDRS
export EXPECTED_UDP_RELAY_ALLOCATOR_URL
export EXPECTED_TAILNET_DIRECT_UDP_LB_IP
export EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE
export EXPECTED_RUNTIME_TRANSPORT_REGION
export EXPECTED_KATA_AGENT_POLICY_ANNOTATION
export EXPECTED_GATEWAY_STUN_HOST="$stun_host"
export EXPECTED_GATEWAY_STUN_PORT="$stun_port"
export SMOKE_DERP_FALLBACK
export SMOKE_SKIP_KUBE
export EXPECTED_KATA_COCO_INIT_DATA_ANNOTATION
export EXPECTED_KATA_COCO_KBS_URL
export EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI
export EXPECTED_KATA_COCO_TEST_RESOURCE_URI
export EXPECTED_KATA_COCO_TEST_RESOURCE_PATH
export EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT
export SMOKE_TAILNET_DIRECT_WAIT
export SMOKE_TAILNET_PEER_TIMEOUT
export SMOKE_TAILNET_DOCTOR_TIMEOUT
export SMOKE_SSH_CONNECT_TIMEOUT

timeout_arg_seen=0
for arg in "$@"; do
  if [[ "$arg" == "--timeout-seconds" ]]; then
    timeout_arg_seen=1
    break
  fi
done

cmd=("$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh")
if [[ "$timeout_arg_seen" == "0" ]]; then
  cmd+=(--timeout-seconds "$SMOKE_TIMEOUT_SECONDS")
fi
cmd+=("$@")

if [[ "$SMOKE_SKIP_KUBE" == "1" ]]; then
  log "running application-only commodity smoke against $CODEWIRE_SERVER_URL"
else
  log "running commodity smoke against $CODEWIRE_SERVER_URL using $runtime_configmap and gateway image $EXPECTED_GATEWAY_IMAGE"
fi
exec "${cmd[@]}"
