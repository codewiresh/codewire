#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
CODEWIRE_SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-dev}"
KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
REGISTRY_HOST="${REGISTRY_HOST:-git.example.invalid}"
CONFIGMAP_NAME="${CONFIGMAP_NAME:-}"
DEFAULT_SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
EXPECTED_TAILNET_PATH_TRANSPORT="${EXPECTED_TAILNET_PATH_TRANSPORT:-direct_udp}"
EXPECTED_TAILNET_DIRECT_UDP_LB_IP="${EXPECTED_TAILNET_DIRECT_UDP_LB_IP:-192.0.2.36}"
EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE="${EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE:-prod-node}"
EXPECTED_RUNTIME_TRANSPORT_REGION="${EXPECTED_RUNTIME_TRANSPORT_REGION:-dev-eu}"
EXPECTED_TAILNET_PEER_RELAY_ENDPOINT="${EXPECTED_TAILNET_PEER_RELAY_ENDPOINT:-192.0.2.35:41641}"
EXPECTED_UDP_RELAY_ALLOCATOR_URL="${EXPECTED_UDP_RELAY_ALLOCATOR_URL:-http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations}"
EXPECTED_UDP_RELAY_BIND_ADDRS="${EXPECTED_UDP_RELAY_BIND_ADDRS:-codewire-udp-relay.dev.svc.cluster.local:41641}"
EXPECTED_RUNTIME_NODE_SELECTOR="${EXPECTED_RUNTIME_NODE_SELECTOR:-katacontainers.io/kata-runtime=true}"
EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB="${EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB:-400}"
CANDIDATE_WORKER_LOOPS="${CANDIDATE_WORKER_LOOPS:-}"
CANDIDATE_SEED_SANDBOX_TEMPLATES_FROM_NAMESPACE="${CANDIDATE_SEED_SANDBOX_TEMPLATES_FROM_NAMESPACE:-}"
CANDIDATE_SEED_SANDBOX_TEMPLATE_NAMES="${CANDIDATE_SEED_SANDBOX_TEMPLATE_NAMES:-workspace workspace-2000m-4096mib-10gib}"

CURRENT_DEV=0
FORCE_SHARED_DEV=0
KEEP_DEPLOY=0
KEEP_NAMESPACE=0
SKIP_BUILD=0
SKIP_PUSH=0
SKIP_DEPLOY=0
SKIP_SMOKE=0
PREFLIGHT_ONLY=0
DRY_RUN=0
DOCKER_BUILD_NO_CACHE="${DOCKER_BUILD_NO_CACHE:-0}"
TAG=""
SANDBOX_NAMESPACE_OVERRIDE=""
USE_TEMP_SANDBOX_NAMESPACE=1

declare -a REQUESTED_IMAGES=()
declare -a SMOKE_ARGS=()
declare -a CONFIGMAP_NAMES=()
declare -A IMAGE_SELECTED=()
declare -A TOUCHED_DEPLOYMENTS=()
declare -A CONFIGMAP_SELECTED=()

TMPDIR_CANDIDATE=""
DEPLOY_STATE_FILE=""
DEPLOY_ENV_STATE_FILE=""
CONFIG_STATE_FILE=""
NAMESPACE_CREATED=""
RESTORE_NEEDED=0
CONFIG_CHANGED=0
CANDIDATE_SANDBOX_NAMESPACE=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/smoke-dev-candidate.sh --current-dev [-- smoke args...]
  scripts/runtime/dev/smoke-dev-candidate.sh --image IMAGE --force-shared-dev [options] [-- smoke args...]

Images:
  services    Rust services image used by idp, orchestration, billing, coordinator
  gateway     Rust sandbox gateway image selected through SANDBOX_GATEWAY_IMAGE
  derp        DERP/STUN image
  mesh        Hosted Mesh image
  dashboard   Dashboard image
  all         All supported runtime images above

Options:
  --image IMAGE             Candidate image to build/push/deploy; repeatable
  --current-dev             Run the existing commodity smoke against current dev
  --tag TAG                 Candidate tag (default: dev-smoke-<branch>-<sha>)
  --registry-host HOST      Registry host (default: git.example.invalid)
  --sandbox-namespace NAME  Sandbox namespace for the candidate smoke
  --no-temp-sandbox-namespace
                            Use the current dev sandbox namespace instead
  --keep-namespace          Keep an auto-created sandbox namespace
  --force-shared-dev        Required before mutating the singleton dev control plane
  --keep-deploy             Do not restore dev images/config on exit
  --skip-build              Use an already-pushed candidate tag
  --skip-push               Build locally only; requires --skip-smoke or --skip-deploy
  --skip-deploy             Build/push only; requires --skip-smoke
  --skip-smoke              Do not run the runtime smoke
  --preflight-only          With --current-dev, validate live runtime config
                            without creating an environment
  --dry-run                 Print planned actions without build/push/deploy/smoke
  -h, --help                Show this help

Secret handling:
  The script never prints registry or Codewire API secrets. For registry auth,
  either pre-login with docker, set REGISTRY_PASSWORD, or set
  REGISTRY_PASSWORD_FILE. Password values are passed to docker login on stdin.
  For local Codewire API auth, wrap this script with
  scripts/runtime/dev/with-dev-smoke-auth.sh so the dedicated dev smoke API key and
  expected smoke-user email are loaded from canonical OpenBao without printing values.

Environment:
  DOCKER_BUILD_NO_CACHE=1    Build candidate images with docker buildx
                             --no-cache. Useful when proving a local Rust
                             gateway/tailnet change against dev.
  CANDIDATE_WORKER_LOOPS     Temporarily set WORKER_LOOPS while the candidate
                             smoke mutates dev, then restore it on exit.
                             Useful for isolated runtime-node smokes that must
                             not start the warm-pool reconciler.
  CANDIDATE_SEED_SANDBOX_TEMPLATES_FROM_NAMESPACE
                             Copy named SandboxTemplates from this namespace
                             into the candidate sandbox namespace before smoke.
  CANDIDATE_SEED_SANDBOX_TEMPLATE_NAMES
                             Space-separated template names to seed. Defaults
                             to workspace and workspace-2000m-4096mib-10gib.
  EXPECTED_RUNTIME_NODE_SELECTOR
                             Kubernetes selector for runtime node storage
                             preflight. Defaults to katacontainers.io/kata-runtime=true.
  EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB
                             Minimum allocatable ephemeral-storage per runtime
                             node. Defaults to 400; set 0 to skip.

Examples:
  scripts/runtime/dev/smoke-dev-candidate.sh --current-dev

  scripts/runtime/dev/smoke-dev-candidate.sh \
    --image services \
    --force-shared-dev \
    -- --skip-docker

  scripts/runtime/dev/smoke-dev-candidate.sh \
    --image gateway \
    --force-shared-dev \
    -- --timeout-seconds 1200
USAGE
}

log() {
  printf '[candidate-smoke] %s\n' "$*" >&2
}

die() {
  printf '[candidate-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

maybe_default_kubeconfig() {
  if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
    export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
  fi
}

kubectl_dev() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

resolve_configmap_name() {
  local deployment resolved

  if [[ -n "$CONFIGMAP_NAME" ]]; then
    add_configmap_name "$CONFIGMAP_NAME"
    log "using runtime ConfigMap $CONFIGMAP_NAME from CONFIGMAP_NAME"
  fi

  for deployment in \
    codewire-orchestration \
    codewire-billing \
    codewire-coordinator \
    codewire-idp \
    codewire-udp-relay
  do
    if ! kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment "$deployment" >/dev/null 2>&1; then
      continue
    fi
    while IFS= read -r resolved; do
      add_configmap_name "$resolved"
    done < <(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deploy "$deployment" -o json |
      jq -r '.spec.template.spec.containers[]
        | .envFrom[]?
        | .configMapRef.name? // empty
        | select(length > 0)')
  done

  if [[ -z "$CONFIGMAP_NAME" && "${#CONFIGMAP_NAMES[@]}" -gt 0 ]]; then
    CONFIGMAP_NAME="${CONFIGMAP_NAMES[0]}"
  fi

  [[ "${#CONFIGMAP_NAMES[@]}" -gt 0 ]] || die "failed to resolve runtime ConfigMap from dev deployments"
  log "resolved runtime ConfigMaps: ${CONFIGMAP_NAMES[*]}"
}

add_configmap_name() {
  local name="$1"
  [[ -n "$name" && "$name" != "null" ]] || return 0
  if [[ -z "${CONFIGMAP_SELECTED[$name]:-}" ]]; then
    CONFIGMAP_SELECTED[$name]=1
    CONFIGMAP_NAMES+=("$name")
  fi
}

preflight_runtime_config() {
  local expected_namespace="${1:-}"
  local config_json runtime_profile runtime_class configured_sandbox_namespace configured_billing_namespace
  local stun_host stun_port udp_relay_advertise_addrs udp_relay_allocator_url udp_relay_bind_addrs
  local direct_udp_lb_enabled direct_udp_lb_ip direct_udp_lb_class direct_udp_transport_zone
  local runtime_transport_zones_json

  [[ -n "$CONFIGMAP_NAME" ]] || die "runtime ConfigMap name is not resolved"

  config_json="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get configmap "$CONFIGMAP_NAME" -o json)"
  runtime_profile="$(jq -r '.data.SANDBOX_RUNTIME_PROFILE // empty' <<<"$config_json")"
  runtime_class="$(jq -r '.data.SANDBOX_RUNTIME_CLASS // empty' <<<"$config_json")"
  configured_sandbox_namespace="$(jq -r '.data.SANDBOX_NAMESPACE // empty' <<<"$config_json")"
  configured_billing_namespace="$(jq -r '.data.BILLING_CONTROLLER_NAMESPACE // empty' <<<"$config_json")"
  stun_host="$(jq -r '.data.STUN_HOST // empty' <<<"$config_json")"
  stun_port="$(jq -r '.data.STUN_PORT // empty' <<<"$config_json")"
  udp_relay_advertise_addrs="$(jq -r '.data.CODEWIRE_UDP_RELAY_ADVERTISE_ADDRS // empty' <<<"$config_json")"
  udp_relay_allocator_url="$(jq -r '.data.CODEWIRE_UDP_RELAY_ALLOCATOR_URL // empty' <<<"$config_json")"
  udp_relay_bind_addrs="$(jq -r '.data.CODEWIRE_UDP_RELAY_BIND_ADDRS // empty' <<<"$config_json")"
  runtime_transport_zones_json="$(jq -r '.data.CODEWIRE_RUNTIME_TRANSPORT_ZONES_JSON // empty' <<<"$config_json")"
  direct_udp_lb_enabled="$(jq -r '.data.CODEWIRE_DIRECT_UDP_LB_ENABLED // empty' <<<"$config_json")"
  direct_udp_lb_ip="$(jq -r '.data.CODEWIRE_DIRECT_UDP_LB_IP // empty' <<<"$config_json")"
  direct_udp_lb_class="$(jq -r '.data.CODEWIRE_DIRECT_UDP_LB_CLASS // empty' <<<"$config_json")"
  direct_udp_transport_zone="$(jq -r '.data.CODEWIRE_DIRECT_UDP_TRANSPORT_ZONE // empty' <<<"$config_json")"

  [[ "$runtime_profile" == "commodity" ]] || \
    die "runtime ConfigMap SANDBOX_RUNTIME_PROFILE=$runtime_profile, want commodity"
  [[ "$runtime_class" == "commodity" ]] || \
    die "runtime ConfigMap SANDBOX_RUNTIME_CLASS=$runtime_class, want commodity"
  [[ -n "$stun_host" ]] || \
    die "runtime ConfigMap STUN_HOST is empty; tailnet UDP discovery requires STUN"
  [[ "$stun_port" == "3478" ]] || \
    die "runtime ConfigMap STUN_PORT=$stun_port, want public UDP 3478"
  if [[ "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" == "direct_udp" ]]; then
    [[ "$direct_udp_lb_enabled" == "true" ]] || \
      die "runtime ConfigMap CODEWIRE_DIRECT_UDP_LB_ENABLED=$direct_udp_lb_enabled, want true for direct_udp smoke"
    [[ "$direct_udp_lb_ip" == "$EXPECTED_TAILNET_DIRECT_UDP_LB_IP" ]] || \
      die "runtime ConfigMap CODEWIRE_DIRECT_UDP_LB_IP=$direct_udp_lb_ip, want $EXPECTED_TAILNET_DIRECT_UDP_LB_IP"
    [[ "$direct_udp_lb_class" == "io.cilium/l2-announcer" ]] || \
      die "runtime ConfigMap CODEWIRE_DIRECT_UDP_LB_CLASS=$direct_udp_lb_class, want io.cilium/l2-announcer"
    [[ "$direct_udp_transport_zone" == "$EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE" ]] || \
      die "runtime ConfigMap CODEWIRE_DIRECT_UDP_TRANSPORT_ZONE=$direct_udp_transport_zone, want $EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE"
  fi
  if [[ "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" == "direct_udp" || "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" == "peer_relay" || "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" == "udp_relay" ]]; then
    [[ ",$udp_relay_advertise_addrs," == *",$EXPECTED_TAILNET_PEER_RELAY_ENDPOINT,"* ]] || \
      die "runtime ConfigMap CODEWIRE_UDP_RELAY_ADVERTISE_ADDRS=$udp_relay_advertise_addrs, want $EXPECTED_TAILNET_PEER_RELAY_ENDPOINT for peer_relay smoke"
    [[ -z "$udp_relay_allocator_url" ]] || \
      die "runtime ConfigMap CODEWIRE_UDP_RELAY_ALLOCATOR_URL=$udp_relay_allocator_url, want transport-zone registry"
    [[ -z "$udp_relay_bind_addrs" ]] || \
      die "runtime ConfigMap CODEWIRE_UDP_RELAY_BIND_ADDRS=$udp_relay_bind_addrs, want transport-zone registry"
    [[ -n "$runtime_transport_zones_json" ]] || \
      die "runtime ConfigMap CODEWIRE_RUNTIME_TRANSPORT_ZONES_JSON is empty"
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
      die "runtime transport-zone registry does not contain expected $EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE peer relay/direct UDP capability"
  fi

  if [[ -n "$expected_namespace" ]]; then
    if [[ -n "$configured_sandbox_namespace" && "$configured_sandbox_namespace" != "$expected_namespace" ]]; then
      die "runtime ConfigMap SANDBOX_NAMESPACE=$configured_sandbox_namespace, smoke SANDBOX_NAMESPACE=$expected_namespace"
    fi
    if [[ -n "$configured_billing_namespace" && "$configured_billing_namespace" != "$expected_namespace" ]]; then
      die "runtime ConfigMap BILLING_CONTROLLER_NAMESPACE=$configured_billing_namespace, smoke SANDBOX_NAMESPACE=$expected_namespace"
    fi
  fi

  log "runtime ConfigMap preflight passed: profile=$runtime_profile class=$runtime_class stun=${stun_host}:${stun_port}${expected_namespace:+ namespace=$expected_namespace}"
}

quantity_to_bytes() {
  local quantity="$1"
  local number suffix

  if [[ "$quantity" =~ ^([0-9]+)(Ki|Mi|Gi|Ti|Pi|Ei|K|M|G|T|P|E)?$ ]]; then
    number="${BASH_REMATCH[1]}"
    suffix="${BASH_REMATCH[2]:-}"
    case "$suffix" in
      "") printf '%s\n' "$number" ;;
      Ki) printf '%s\n' "$((number * 1024))" ;;
      Mi) printf '%s\n' "$((number * 1024 * 1024))" ;;
      Gi) printf '%s\n' "$((number * 1024 * 1024 * 1024))" ;;
      Ti) printf '%s\n' "$((number * 1024 * 1024 * 1024 * 1024))" ;;
      Pi) printf '%s\n' "$((number * 1024 * 1024 * 1024 * 1024 * 1024))" ;;
      Ei) printf '%s\n' "$((number * 1024 * 1024 * 1024 * 1024 * 1024 * 1024))" ;;
      K) printf '%s\n' "$((number * 1000))" ;;
      M) printf '%s\n' "$((number * 1000 * 1000))" ;;
      G) printf '%s\n' "$((number * 1000 * 1000 * 1000))" ;;
      T) printf '%s\n' "$((number * 1000 * 1000 * 1000 * 1000))" ;;
      P) printf '%s\n' "$((number * 1000 * 1000 * 1000 * 1000 * 1000))" ;;
      E) printf '%s\n' "$((number * 1000 * 1000 * 1000 * 1000 * 1000 * 1000))" ;;
    esac
    return 0
  fi

  die "unsupported Kubernetes quantity: $quantity"
}

preflight_runtime_node_storage() {
  local min_gib="$EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB"
  local min_bytes nodes_json node_count expected_node
  local name capacity allocatable disk_pressure allocatable_bytes

  [[ "$min_gib" =~ ^[0-9]+$ ]] || \
    die "EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB must be an unsigned integer, got $min_gib"
  [[ "$min_gib" != "0" ]] || {
    log "runtime node storage preflight skipped"
    return 0
  }
  min_bytes="$((min_gib * 1024 * 1024 * 1024))"
  expected_node="${EXPECTED_NODE:-}"

  if [[ -n "$expected_node" ]]; then
    nodes_json="$(kubectl_dev get node "$expected_node" -o json | jq '{items:[.]}')"
  else
    nodes_json="$(kubectl_dev get nodes -l "$EXPECTED_RUNTIME_NODE_SELECTOR" -o json)"
  fi

  node_count="$(jq '.items | length' <<<"$nodes_json")"
  [[ "$node_count" -gt 0 ]] || \
    die "no runtime nodes found for selector $EXPECTED_RUNTIME_NODE_SELECTOR"

  while IFS=$'\t' read -r name capacity allocatable disk_pressure; do
    [[ -n "$name" ]] || continue
    [[ "$disk_pressure" == "False" ]] || \
      die "runtime node $name DiskPressure=$disk_pressure"
    allocatable_bytes="$(quantity_to_bytes "$allocatable")"
    [[ "$allocatable_bytes" -ge "$min_bytes" ]] || \
      die "runtime node $name allocatable ephemeral-storage=$allocatable, want at least ${min_gib}Gi"
    log "runtime node storage preflight passed: $name capacity=$capacity allocatable=$allocatable DiskPressure=$disk_pressure min=${min_gib}Gi"
  done < <(jq -r '
    .items[]
    | [
        .metadata.name,
        .status.capacity["ephemeral-storage"],
        .status.allocatable["ephemeral-storage"],
        ([.status.conditions[]? | select(.type == "DiskPressure") | .status][0] // "Unknown")
      ]
    | @tsv
  ' <<<"$nodes_json")
}

current_gateway_image_ref() {
  if [[ -n "${IMAGE_SELECTED[gateway]:-}" ]]; then
    image_ref gateway
    return 0
  fi
  kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get configmap "$CONFIGMAP_NAME" -o json |
    jq -r '.data.SANDBOX_GATEWAY_IMAGE // empty'
}

run_or_log() {
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: $*"
    return 0
  fi
  "$@"
}

safe_ref_part() {
  local raw="$1"
  local fallback="$2"
  local out
  out="$(printf '%s' "$raw" |
    tr '[:upper:]' '[:lower:]' |
    sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//; s/-+/-/g')"
  if [[ -z "$out" ]]; then
    out="$fallback"
  fi
  printf '%s' "${out:0:28}" | sed -E 's/-+$//'
}

worktree_content_hash() {
  local tracked_dirty untracked hash

  tracked_dirty=0
  if ! git -C "$ROOT" diff --quiet --ignore-submodules -- . ':(exclude)target' ':(exclude)node_modules' 2>/dev/null; then
    tracked_dirty=1
  fi
  untracked="$(git -C "$ROOT" ls-files --others --exclude-standard 2>/dev/null | sed -n '1p' || true)"
  if [[ "$tracked_dirty" == "0" && -z "$untracked" ]]; then
    return 0
  fi

  hash="$(
    {
      git -C "$ROOT" status --porcelain=v1 --untracked-files=all -- . ':(exclude)target' ':(exclude)node_modules' 2>/dev/null || true
      git -C "$ROOT" diff --binary -- . ':(exclude)target' ':(exclude)node_modules' 2>/dev/null || true
      while IFS= read -r -d '' path; do
        [[ -f "$ROOT/$path" ]] || continue
        printf 'untracked %s\n' "$path"
        git -C "$ROOT" hash-object -- "$path"
      done < <(git -C "$ROOT" ls-files --others --exclude-standard -z 2>/dev/null || true)
    } | git -C "$ROOT" hash-object --stdin
  )"
  [[ -n "$hash" ]] || return 0
  printf 'dirty-%s' "${hash:0:12}"
}

default_tag() {
  local branch sha safe_branch dirty
  branch="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  sha="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || true)"
  safe_branch="$(safe_ref_part "${branch:-branch}" branch)"
  dirty="$(worktree_content_hash)"
  if [[ -n "$dirty" ]]; then
    printf 'dev-smoke-%s-%s-%s' "$safe_branch" "${sha:-unknown}" "$dirty"
  else
    printf 'dev-smoke-%s-%s' "$safe_branch" "${sha:-unknown}"
  fi
}

default_candidate_namespace() {
  local branch sha safe_branch
  branch="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  sha="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || true)"
  safe_branch="$(safe_ref_part "${branch:-branch}" branch)"
  printf 'dev-sbx-smoke-%s-%s' "$safe_branch" "${sha:-unknown}" |
    cut -c1-63 |
    sed -E 's/-+$//'
}

image_ref() {
  local image="$1"
  printf '%s/codewire/%s:%s' "$REGISTRY_HOST" "$image" "$TAG"
}

image_dockerfile() {
  case "$1" in
    gateway) printf 'deployments/docker/gateway.Dockerfile' ;;
    derp) printf 'deployments/docker/derp.Dockerfile' ;;
    services) printf 'deployments/docker/services.Dockerfile' ;;
    mesh) printf 'deployments/docker/mesh.Dockerfile' ;;
    dashboard) printf 'apps/dashboard/Dockerfile' ;;
    *) die "unknown image: $1" ;;
  esac
}

select_image() {
  local image="$1"
  case "$image" in
    all)
      select_image gateway
      select_image derp
      select_image services
      select_image mesh
      select_image dashboard
      ;;
    server)
      die "server image is retired from dev runtime; request services, gateway, mesh, derp, or dashboard"
      ;;
    gateway|derp|services|mesh|dashboard)
      if [[ -z "${IMAGE_SELECTED[$image]:-}" ]]; then
        IMAGE_SELECTED[$image]=1
        REQUESTED_IMAGES+=("$image")
      fi
      ;;
    *)
      die "unknown image: $image"
      ;;
  esac
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      --image)
        [[ $# -ge 2 ]] || die "--image requires a value"
        select_image "$2"
        shift 2
        ;;
      --current-dev)
        CURRENT_DEV=1
        shift
        ;;
      --tag)
        [[ $# -ge 2 ]] || die "--tag requires a value"
        TAG="$2"
        shift 2
        ;;
      --registry-host)
        [[ $# -ge 2 ]] || die "--registry-host requires a value"
        REGISTRY_HOST="$2"
        shift 2
        ;;
      --sandbox-namespace)
        [[ $# -ge 2 ]] || die "--sandbox-namespace requires a value"
        SANDBOX_NAMESPACE_OVERRIDE="$2"
        shift 2
        ;;
      --no-temp-sandbox-namespace)
        USE_TEMP_SANDBOX_NAMESPACE=0
        shift
        ;;
      --keep-namespace)
        KEEP_NAMESPACE=1
        shift
        ;;
      --force-shared-dev)
        FORCE_SHARED_DEV=1
        shift
        ;;
      --keep-deploy)
        KEEP_DEPLOY=1
        shift
        ;;
      --skip-build)
        SKIP_BUILD=1
        shift
        ;;
      --skip-push)
        SKIP_PUSH=1
        shift
        ;;
      --skip-deploy)
        SKIP_DEPLOY=1
        shift
        ;;
      --skip-smoke)
        SKIP_SMOKE=1
        shift
        ;;
      --preflight-only)
        PREFLIGHT_ONLY=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        SMOKE_ARGS+=("$@")
        break
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done
}

validate_args() {
  case "$-" in
    *x*) die "shell tracing is enabled; rerun without set -x" ;;
  esac

  if [[ "$SKIP_PUSH" == "1" && "$SKIP_BUILD" != "1" ]]; then
    SKIP_DEPLOY=1
  fi
  if [[ "$CURRENT_DEV" == "1" && "${#REQUESTED_IMAGES[@]}" -gt 0 ]]; then
    die "--current-dev cannot be combined with --image"
  fi
  if [[ "$CURRENT_DEV" != "1" && "${#REQUESTED_IMAGES[@]}" == "0" ]]; then
    die "choose --current-dev or at least one --image"
  fi
  if [[ "$PREFLIGHT_ONLY" == "1" && "$CURRENT_DEV" != "1" ]]; then
    die "--preflight-only requires --current-dev"
  fi
  if [[ "$PREFLIGHT_ONLY" == "1" && "${#SMOKE_ARGS[@]}" -gt 0 ]]; then
    die "--preflight-only does not accept smoke args"
  fi
  if [[ -n "$SANDBOX_NAMESPACE_OVERRIDE" && "$USE_TEMP_SANDBOX_NAMESPACE" == "0" ]]; then
    die "--sandbox-namespace cannot be combined with --no-temp-sandbox-namespace"
  fi
  if [[ "$SKIP_DEPLOY" == "1" && "$SKIP_SMOKE" != "1" ]]; then
    die "--skip-deploy requires --skip-smoke"
  fi
  if [[ "$SKIP_PUSH" == "1" && "$SKIP_BUILD" != "1" && "$SKIP_SMOKE" != "1" && "$SKIP_DEPLOY" != "1" ]]; then
    die "--skip-push builds a local-only image; use --skip-smoke or --skip-deploy"
  fi
  if [[ "$CURRENT_DEV" != "1" && "$FORCE_SHARED_DEV" != "1" && "$DRY_RUN" != "1" && "$SKIP_DEPLOY" != "1" ]]; then
    die "--force-shared-dev is required before mutating the singleton dev control plane"
  fi
  if [[ -z "$TAG" ]]; then
    TAG="$(default_tag)"
  fi
}

init_state() {
  TMPDIR_CANDIDATE="$(mktemp -d "${TMPDIR:-/tmp}/codewire-candidate-smoke.XXXXXX")"
  DEPLOY_STATE_FILE="$TMPDIR_CANDIDATE/deployments.tsv"
  DEPLOY_ENV_STATE_FILE="$TMPDIR_CANDIDATE/deployment-env.tsv"
  CONFIG_STATE_FILE="$TMPDIR_CANDIDATE/config.tsv"
  : >"$DEPLOY_STATE_FILE"
  : >"$DEPLOY_ENV_STATE_FILE"
  : >"$CONFIG_STATE_FILE"
}

record_deployment_state() {
  local deployment="$1"
  local container="$2"
  local candidate_ref="${3:-}"
  local current
  grep -Fq "${deployment}|${container}|" "$DEPLOY_STATE_FILE" && return 0

  current="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment "$deployment" -o json |
    jq -er --arg container "$container" \
      '.spec.template.spec.containers[] | select(.name == $container) | .image')"
  printf '%s|%s|%s|%s\n' "$deployment" "$container" "$current" "$candidate_ref" >>"$DEPLOY_STATE_FILE"
}

record_deployment_env_state() {
  local deployment="$1"
  local container="$2"
  local key="$3"
  local candidate_value="$4"
  local deploy_json present value_b64 candidate_value_b64

  grep -Fq "${deployment}|${container}|${key}|" "$DEPLOY_ENV_STATE_FILE" && return 0

  deploy_json="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment "$deployment" -o json)"
  present="$(jq -r --arg container "$container" --arg key "$key" \
    '.spec.template.spec.containers[]
      | select(.name == $container)
      | any(.env[]?; .name == $key)' <<<"$deploy_json")"
  if [[ "$present" == "true" ]]; then
    value_b64="$(jq -r --arg container "$container" --arg key "$key" \
      '.spec.template.spec.containers[]
        | select(.name == $container)
        | .env[]?
        | select(.name == $key)
        | .value // ""
        | @base64' <<<"$deploy_json" | sed -n '1p')"
  else
    present=false
    value_b64=""
  fi
  candidate_value_b64="$(printf '%s' "$candidate_value" | base64 -w0)"
  printf '%s|%s|%s|%s|%s|%s\n' \
    "$deployment" "$container" "$key" "$present" "$value_b64" "$candidate_value_b64" \
    >>"$DEPLOY_ENV_STATE_FILE"
}

record_config_state() {
  local configmap="$1"
  local key="$2"
  local candidate_value="$3"
  local cm_json present value_b64 candidate_value_b64
  grep -Fq "${configmap}|${key}|" "$CONFIG_STATE_FILE" && return 0

  cm_json="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get configmap "$configmap" -o json)"
  if jq -e --arg key "$key" '.data | has($key)' >/dev/null <<<"$cm_json"; then
    present=1
    value_b64="$(jq -r --arg key "$key" '.data[$key] | @base64' <<<"$cm_json")"
  else
    present=0
    value_b64=""
  fi
  candidate_value_b64="$(printf '%s' "$candidate_value" | base64 -w0)"
  printf '%s|%s|%s|%s|%s\n' "$configmap" "$key" "$present" "$value_b64" "$candidate_value_b64" >>"$CONFIG_STATE_FILE"
}

patch_one_config_key() {
  local configmap="$1"
  local key="$2"
  local value="$3"
  local patch

  if [[ "$DRY_RUN" != "1" ]]; then
    record_config_state "$configmap" "$key" "$value"
  fi
  patch="$(jq -cn --arg key "$key" --arg value "$value" '{data:{($key):$value}}')"
  log "patching $configmap $key"
  run_or_log kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" patch configmap "$configmap" \
    --type merge --patch "$patch" >/dev/null
}

patch_config_key() {
  local key="$1"
  local value="$2"
  local configmap

  [[ "${#CONFIGMAP_NAMES[@]}" -gt 0 ]] || die "runtime ConfigMap names are not resolved"
  for configmap in "${CONFIGMAP_NAMES[@]}"; do
    patch_one_config_key "$configmap" "$key" "$value"
  done
  CONFIG_CHANGED=1
  if [[ "$DRY_RUN" != "1" ]]; then
    RESTORE_NEEDED=1
  fi
}

restore_config_key() {
  local configmap="$1"
  local key="$2"
  local present="$3"
  local value_b64="$4"
  local value patch

  if [[ "$present" == "1" ]]; then
    value="$(printf '%s' "$value_b64" | base64 -d)"
    patch="$(jq -cn --arg key "$key" --arg value "$value" '{data:{($key):$value}}')"
    kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" patch configmap "$configmap" \
      --type merge --patch "$patch" >/dev/null || true
  else
    patch="$(jq -cn --arg path "/data/$key" '[{"op":"remove","path":$path}]')"
    kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" patch configmap "$configmap" \
      --type json --patch "$patch" >/dev/null 2>&1 || true
  fi
}

set_deployment_image() {
  local deployment="$1"
  local container="$2"
  local ref="$3"

  if [[ "$DRY_RUN" != "1" ]]; then
    record_deployment_state "$deployment" "$container" "$ref"
  fi
  TOUCHED_DEPLOYMENTS[$deployment]=1
  log "setting $deployment/$container to $ref"
  run_or_log kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" set image \
    "deployment/$deployment" "$container=$ref" >/dev/null
  if [[ "$DRY_RUN" != "1" ]]; then
    RESTORE_NEEDED=1
  fi
}

set_deployment_env() {
  local deployment="$1"
  local container="$2"
  local key="$3"
  local value="$4"

  if [[ "$DRY_RUN" != "1" ]]; then
    record_deployment_env_state "$deployment" "$container" "$key" "$value"
  fi
  TOUCHED_DEPLOYMENTS[$deployment]=1
  log "setting $deployment/$container env $key"
  run_or_log kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" set env \
    "deployment/$deployment" "$key=$value" --containers="$container" >/dev/null
  if [[ "$DRY_RUN" != "1" ]]; then
    RESTORE_NEEDED=1
  fi
}

ensure_stun_recreate_strategy() {
  local strategy

  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: ensure codewire-stun uses Recreate rollout strategy"
    return 0
  fi

  strategy="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment codewire-stun -o json |
    jq -r '.spec.strategy.type // empty')"
  if [[ "$strategy" == "Recreate" ]]; then
    return 0
  fi

  log "patching codewire-stun rollout strategy to Recreate for host-network UDP 3478"
  kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" patch deployment codewire-stun \
    --type merge \
    --patch '{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}' >/dev/null
}

delete_obsolete_stun_nodeport() {
  log "deleting obsolete codewire-derp-stun NodePort if present"
  run_or_log kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" delete service codewire-derp-stun \
    --ignore-not-found >/dev/null
}

rollout_restart_if_needed() {
  local deployment="$1"
  if [[ -n "${TOUCHED_DEPLOYMENTS[$deployment]:-}" ]]; then
    return 0
  fi
  TOUCHED_DEPLOYMENTS[$deployment]=1
  log "restarting $deployment for ConfigMap changes"
  run_or_log kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" rollout restart \
    "deployment/$deployment" >/dev/null
}

wait_for_rollouts() {
  local deployment
  for deployment in "${!TOUCHED_DEPLOYMENTS[@]}"; do
    log "waiting for $deployment rollout"
    rollout_status "$deployment"
  done
}

refresh_sandbox_templates_for_gateway_image() {
  local namespace="$1"
  local expected_image

  [[ -n "$namespace" ]] || return 0
  expected_image="$(current_gateway_image_ref)"
  [[ -n "$expected_image" ]] || return 0

  log "gateway image $expected_image is applied by per-environment gateway Deployments; skipping SandboxTemplate refresh in $namespace"
}

wait_for_gateway_templates_for_gateway_image() {
  local namespace="$1"
  local expected_image

  [[ -n "$namespace" ]] || return 0
  expected_image="$(current_gateway_image_ref)"
  [[ -n "$expected_image" ]] || return 0

  log "gateway image $expected_image will be checked on the smoke-created gateway Deployment"
}

seed_sandbox_templates_from_namespace() {
  local source_namespace="$1"
  local target_namespace="$2"
  local expected_image name

  [[ -n "$source_namespace" ]] || return 0
  [[ -n "$target_namespace" ]] || return 0
  if [[ "$source_namespace" == "$target_namespace" ]]; then
    return 0
  fi

  expected_image="$(current_gateway_image_ref)"
  log "seeding SandboxTemplates from $source_namespace into $target_namespace: $CANDIDATE_SEED_SANDBOX_TEMPLATE_NAMES"
  for name in $CANDIDATE_SEED_SANDBOX_TEMPLATE_NAMES; do
    if [[ "$DRY_RUN" == "1" ]]; then
      log "dry-run: seed SandboxTemplate $name from $source_namespace into $target_namespace"
      continue
    fi
    kubectl_dev -n "$source_namespace" get sandboxtemplates.extensions.agents.x-k8s.io "$name" -o json |
      jq --arg namespace "$target_namespace" --arg image "$expected_image" '
        .metadata = {name: .metadata.name, namespace: $namespace}
        | del(.status)
        | if $image != "" then
            .spec.podTemplate.spec.initContainers =
              ((.spec.podTemplate.spec.initContainers // [])
                | map(if .name == "codewire-daemon-init" then .image = $image else . end))
          else
            .
          end
      ' |
      kubectl_dev apply -f - >/dev/null
  done
}

cycle_warm_pool_pods_for_gateway_image() {
  local namespace="$1"
  local expected_image

  [[ -n "$namespace" ]] || return 0
  expected_image="$(current_gateway_image_ref)"
  [[ -n "$expected_image" ]] || return 0

  log "warm-pool workspace pods no longer carry the gateway image; no warm-pool cycling needed for $expected_image"
}

rollout_status() {
  local deployment="$1"
  local attempt rc err

  if [[ "$DRY_RUN" == "1" ]]; then
    run_or_log kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" rollout status \
      "deployment/$deployment" --timeout=300s
    return 0
  fi

  err="$(mktemp "${TMPDIR:-/tmp}/codewire-rollout-status.XXXXXX")"
  for attempt in 1 2 3; do
    if kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" rollout status \
      "deployment/$deployment" --timeout=300s 2>"$err"; then
      rm -f "$err"
      return 0
    fi
    rc=$?
    sed 's/[[:cntrl:]]//g' "$err" >&2 || true
    if [[ "$attempt" == "3" ]]; then
      rm -f "$err"
      return "$rc"
    fi
    log "retrying $deployment rollout after transient status failure ($attempt/3)"
    sleep 5
  done

  rm -f "$err"
}

prepare_registry_login() {
  local password=""

  if [[ "$SKIP_BUILD" == "1" || "$SKIP_PUSH" == "1" || "$DRY_RUN" == "1" ]]; then
    return 0
  fi
  if [[ -n "${REGISTRY_PASSWORD_FILE:-}" ]]; then
    password="$(<"$REGISTRY_PASSWORD_FILE")"
  elif [[ -n "${REGISTRY_PASSWORD:-}" ]]; then
    password="$REGISTRY_PASSWORD"
  fi
  if [[ -n "$password" ]]; then
    log "logging into $REGISTRY_HOST with password from environment/file"
    printf '%s' "$password" | docker login "$REGISTRY_HOST" \
      -u "${REGISTRY_USERNAME:-ci}" --password-stdin >/dev/null
  else
    log "using existing Docker credentials for $REGISTRY_HOST"
  fi
}

build_image() {
  local image="$1"
  local dockerfile ref
  local -a build_args
  dockerfile="$(image_dockerfile "$image")"
  ref="$(image_ref "$image")"

  if [[ "$SKIP_BUILD" == "1" ]]; then
    log "skipping build for $ref; assuming candidate image already exists"
    return 0
  fi

  require_cmd docker
  build_args=(docker buildx build)
  if [[ "$DOCKER_BUILD_NO_CACHE" == "1" ]]; then
    build_args+=(--no-cache)
  fi
  if [[ "$SKIP_PUSH" == "1" ]]; then
    log "building local candidate image $ref from $dockerfile"
    run_or_log "${build_args[@]}" --load -f "$dockerfile" --tag "$ref" "$ROOT"
  else
    log "building and pushing candidate image $ref from $dockerfile"
    run_or_log "${build_args[@]}" --push -f "$dockerfile" --tag "$ref" "$ROOT"
  fi
}

ensure_sandbox_namespace() {
  local namespace="$1"
  local namespace_json deletion_timestamp service_account_json
  [[ -n "$namespace" ]] || return 0

  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: ensure sandbox namespace $namespace"
    return 0
  fi
  namespace_json="$(kubectl_dev get namespace "$namespace" -o json 2>/dev/null || true)"
  if [[ -n "$namespace_json" ]]; then
    deletion_timestamp="$(jq -r '.metadata.deletionTimestamp // empty' <<<"$namespace_json")"
    [[ -z "$deletion_timestamp" ]] || \
      die "sandbox namespace $namespace is terminating; choose a different --sandbox-namespace or wait for deletion"
    log "using existing sandbox namespace $namespace"
    if [[ "$namespace" == "$DEFAULT_SANDBOX_NAMESPACE" ]]; then
      return 0
    fi
  else
    log "creating sandbox namespace $namespace"
    kubectl_dev create namespace "$namespace" >/dev/null
    NAMESPACE_CREATED="$namespace"
  fi

  kubectl_dev label namespace "$namespace" \
    app.kubernetes.io/managed-by=codewire \
    codewire.sh/resource-type=sandbox \
    codewire.sh/runtime-scope=shared \
    isol8.codewire.sh/clone-registry-secrets=true \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/enforce-version=latest \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/audit-version=latest \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/warn-version=latest \
    --overwrite >/dev/null

  log "waiting for the synchronized registry pull secret in $namespace"
  kubectl_dev -n "$namespace" wait --for=create secret/nexus-registry --timeout=120s >/dev/null || \
    die "registry pull secret was not synchronized into sandbox namespace $namespace"
  [[ "$(kubectl_dev -n "$namespace" get secret nexus-registry -o json | jq -r '.type')" == \
    "kubernetes.io/dockerconfigjson" ]] || \
    die "sandbox namespace $namespace has an invalid nexus-registry Secret type"

  service_account_json="$(kubectl_dev -n "$namespace" get serviceaccount codewire-sandbox -o json 2>/dev/null || true)"
  if [[ -z "$service_account_json" ]]; then
    kubectl_dev -n "$namespace" create serviceaccount codewire-sandbox >/dev/null
    kubectl_dev -n "$namespace" patch serviceaccount codewire-sandbox --type merge \
      --patch '{"automountServiceAccountToken":false,"imagePullSecrets":[{"name":"nexus-registry"}]}' >/dev/null
  elif ! jq -e '
    .automountServiceAccountToken == false
      and any(.imagePullSecrets[]?; .name == "nexus-registry")
  ' >/dev/null <<<"$service_account_json"; then
    die "existing codewire-sandbox ServiceAccount in $namespace lacks the fail-closed runtime shape"
  fi
}

select_candidate_sandbox_namespace() {
  local namespace suffix max_prefix prefix deletion_timestamp

  if [[ -n "$CANDIDATE_SANDBOX_NAMESPACE" ]]; then
    return 0
  fi

  if [[ -n "$SANDBOX_NAMESPACE_OVERRIDE" ]]; then
    namespace="$SANDBOX_NAMESPACE_OVERRIDE"
  elif [[ "$USE_TEMP_SANDBOX_NAMESPACE" == "1" ]]; then
    namespace="$(default_candidate_namespace)"
    if [[ "$DRY_RUN" != "1" ]]; then
      deletion_timestamp="$(kubectl_dev get namespace "$namespace" -o json 2>/dev/null |
        jq -r '.metadata.deletionTimestamp // empty' || true)"
      if [[ -n "$deletion_timestamp" ]]; then
        suffix="$(date -u +%H%M%S)"
        max_prefix="$((63 - 1 - ${#suffix}))"
        prefix="$(printf '%s' "$namespace" | cut -c1-"$max_prefix" | sed -E 's/-+$//')"
        namespace="${prefix}-${suffix}"
        log "default sandbox namespace is terminating; using fresh namespace $namespace"
      fi
    fi
  else
    namespace="$DEFAULT_SANDBOX_NAMESPACE"
  fi

  CANDIDATE_SANDBOX_NAMESPACE="$namespace"
}

candidate_sandbox_namespace() {
  if [[ -z "$CANDIDATE_SANDBOX_NAMESPACE" ]]; then
    select_candidate_sandbox_namespace
  fi
  printf '%s' "$CANDIDATE_SANDBOX_NAMESPACE"
}

apply_candidate_images() {
  local image ref namespace

  namespace="$CANDIDATE_SANDBOX_NAMESPACE"
  [[ -n "$namespace" ]] || die "candidate sandbox namespace is not selected"
  if [[ "$namespace" != "$DEFAULT_SANDBOX_NAMESPACE" ]]; then
    ensure_sandbox_namespace "$namespace"
    patch_config_key SANDBOX_NAMESPACE "$namespace"
    patch_config_key BILLING_CONTROLLER_NAMESPACE "$namespace"
  fi
  patch_config_key STUN_HOST "stun.codewire-dev.sh"
  patch_config_key STUN_PORT "3478"
  if [[ -n "$CANDIDATE_WORKER_LOOPS" ]]; then
    patch_config_key WORKER_LOOPS "$CANDIDATE_WORKER_LOOPS"
    set_deployment_env codewire-orchestration orchestration WORKER_LOOPS "$CANDIDATE_WORKER_LOOPS"
  fi
  if [[ "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" == "direct_udp" || "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" == "peer_relay" || "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" == "udp_relay" ]]; then
    local runtime_transport_zones_json
    runtime_transport_zones_json="$(jq -cn \
      --arg zone "$EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE" \
      --arg region "$EXPECTED_RUNTIME_TRANSPORT_REGION" \
      --arg endpoint "$EXPECTED_TAILNET_PEER_RELAY_ENDPOINT" \
      --arg allocator "$EXPECTED_UDP_RELAY_ALLOCATOR_URL" \
      --arg bind "$EXPECTED_UDP_RELAY_BIND_ADDRS" \
      --arg direct_ip "$EXPECTED_TAILNET_DIRECT_UDP_LB_IP" \
      '{version:1,zones:[{name:$zone,runtime_region:$region,peer_relay:{public_endpoints:[$endpoint],dns:($zone + ".mesh.codewire-dev.sh"),allocator_url:$allocator,bind_addrs:[$bind]},direct_udp:{vip:$direct_ip,port_start:32000,port_end:60999},stun:{endpoints:["stun.codewire-dev.sh:3478"]},derp:{endpoints:["derp.codewire-dev.sh"]}}]}')"
    patch_config_key CODEWIRE_UDP_RELAY_ADVERTISE_ADDRS "$EXPECTED_TAILNET_PEER_RELAY_ENDPOINT"
    patch_config_key CODEWIRE_UDP_RELAY_ALLOCATOR_URL ""
    patch_config_key CODEWIRE_UDP_RELAY_BIND_ADDRS ""
    patch_config_key CODEWIRE_RUNTIME_TRANSPORT_ZONES_JSON "$runtime_transport_zones_json"
  fi
  if [[ "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" == "direct_udp" ]]; then
    patch_config_key CODEWIRE_DIRECT_UDP_LB_ENABLED "true"
    patch_config_key CODEWIRE_DIRECT_UDP_LB_IP "$EXPECTED_TAILNET_DIRECT_UDP_LB_IP"
    patch_config_key CODEWIRE_DIRECT_UDP_LB_PORT_START "32000"
    patch_config_key CODEWIRE_DIRECT_UDP_LB_PORT_END "60999"
    patch_config_key CODEWIRE_DIRECT_UDP_LB_CLASS "io.cilium/l2-announcer"
    patch_config_key CODEWIRE_DIRECT_UDP_LB_SHARING_KEY "codewire-direct-udp"
    patch_config_key CODEWIRE_DIRECT_UDP_TRANSPORT_ZONE "$EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE"
  fi
  if [[ -n "${IMAGE_SELECTED[gateway]:-}" ]]; then
    ref="$(image_ref gateway)"
    patch_config_key SANDBOX_GATEWAY_IMAGE "$ref"
    set_deployment_env codewire-orchestration orchestration SANDBOX_GATEWAY_IMAGE "$ref"
  fi
  delete_obsolete_stun_nodeport

  for image in "${REQUESTED_IMAGES[@]}"; do
    ref="$(image_ref "$image")"
    case "$image" in
      gateway)
        :
        ;;
      derp)
        ensure_stun_recreate_strategy
        set_deployment_image codewire-derp derp "$ref"
        set_deployment_image codewire-stun stun "$ref"
        ;;
      services)
        set_deployment_image codewire-coordinator coordinator "$ref"
        set_deployment_image codewire-idp idp "$ref"
        set_deployment_image codewire-billing billing "$ref"
        set_deployment_image codewire-orchestration orchestration "$ref"
        if kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment codewire-udp-relay >/dev/null 2>&1; then
          set_deployment_image codewire-udp-relay udp-relay "$ref"
        fi
        ;;
      mesh)
        set_deployment_image codewire-mesh mesh "$ref"
        ;;
      dashboard)
        set_deployment_image codewire-dashboard dashboard "$ref"
        ;;
    esac
  done

  if [[ "$CONFIG_CHANGED" == "1" ]]; then
    rollout_restart_if_needed codewire-orchestration
    rollout_restart_if_needed codewire-billing
    if kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment codewire-udp-relay >/dev/null 2>&1; then
      rollout_restart_if_needed codewire-udp-relay
    fi
  fi

  wait_for_rollouts
  refresh_sandbox_templates_for_gateway_image "$namespace"
  seed_sandbox_templates_from_namespace "$CANDIDATE_SEED_SANDBOX_TEMPLATES_FROM_NAMESPACE" "$namespace"
  cycle_warm_pool_pods_for_gateway_image "$namespace"
  wait_for_gateway_templates_for_gateway_image "$namespace"
}

restore_dev() {
  local deployment container ref candidate_ref current_ref configmap key present value_b64 candidate_value_b64
  local cm_json current_config_value_b64 deploy_json current_env_value_b64 value

  [[ "$RESTORE_NEEDED" == "1" ]] || return 0
  [[ "$KEEP_DEPLOY" != "1" ]] || {
    log "keeping candidate dev override by request"
    return 0
  }
  [[ "$DRY_RUN" != "1" ]] || return 0

  log "restoring dev deployment images and config"
  if [[ -s "$DEPLOY_STATE_FILE" ]]; then
    while IFS='|' read -r deployment container ref candidate_ref; do
      [[ -n "$deployment" ]] || continue
      current_ref="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment "$deployment" -o json |
        jq -r --arg container "$container" \
          '.spec.template.spec.containers[] | select(.name == $container) | .image' 2>/dev/null || true)"
      if [[ -n "${candidate_ref:-}" && -n "$current_ref" && "$current_ref" != "$candidate_ref" ]]; then
        log "skipping image restore for $deployment/$container; current image changed outside candidate smoke"
        continue
      fi
      kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" set image \
        "deployment/$deployment" "$container=$ref" >/dev/null || true
      TOUCHED_DEPLOYMENTS[$deployment]=1
    done < <(tac "$DEPLOY_STATE_FILE")
  fi

  if [[ -s "$DEPLOY_ENV_STATE_FILE" ]]; then
    while IFS='|' read -r deployment container key present value_b64 candidate_value_b64; do
      [[ -n "$deployment" ]] || continue
      [[ -n "$container" ]] || continue
      [[ -n "$key" ]] || continue
      if [[ -n "${candidate_value_b64:-}" ]]; then
        deploy_json="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment "$deployment" -o json 2>/dev/null || true)"
        if [[ -n "$deploy_json" ]] && jq -e --arg container "$container" --arg key "$key" \
          '.spec.template.spec.containers[]
            | select(.name == $container)
            | any(.env[]?; .name == $key)' >/dev/null <<<"$deploy_json"; then
          current_env_value_b64="$(jq -r --arg container "$container" --arg key "$key" \
            '.spec.template.spec.containers[]
              | select(.name == $container)
              | .env[]?
              | select(.name == $key)
              | .value // ""
              | @base64' <<<"$deploy_json" | sed -n '1p')"
        else
          current_env_value_b64=""
        fi
        if [[ "$current_env_value_b64" != "$candidate_value_b64" ]]; then
          log "skipping env restore for $deployment/$container $key; current value changed outside candidate smoke"
          continue
        fi
      fi

      if [[ "$present" == "true" ]]; then
        value="$(printf '%s' "$value_b64" | base64 -d)"
        kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" set env \
          "deployment/$deployment" "$key=$value" --containers="$container" >/dev/null || true
      else
        kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" set env \
          "deployment/$deployment" "$key-" --containers="$container" >/dev/null || true
      fi
      TOUCHED_DEPLOYMENTS[$deployment]=1
    done < <(tac "$DEPLOY_ENV_STATE_FILE")
  fi

  if [[ -s "$CONFIG_STATE_FILE" ]]; then
    while IFS='|' read -r configmap key present value_b64 candidate_value_b64; do
      [[ -n "$configmap" ]] || continue
      [[ -n "$key" ]] || continue
      if [[ -n "${candidate_value_b64:-}" ]]; then
        cm_json="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get configmap "$configmap" -o json 2>/dev/null || true)"
        if [[ -n "$cm_json" ]] && jq -e --arg key "$key" '.data | has($key)' >/dev/null <<<"$cm_json"; then
          current_config_value_b64="$(jq -r --arg key "$key" '.data[$key] | @base64' <<<"$cm_json")"
        else
          current_config_value_b64=""
        fi
        if [[ "$current_config_value_b64" != "$candidate_value_b64" ]]; then
          log "skipping ConfigMap restore for $configmap/$key; current value changed outside candidate smoke"
          continue
        fi
      fi
      restore_config_key "$configmap" "$key" "$present" "$value_b64"
    done < <(tac "$CONFIG_STATE_FILE")
    TOUCHED_DEPLOYMENTS[codewire-orchestration]=1
    TOUCHED_DEPLOYMENTS[codewire-billing]=1
    if kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment codewire-udp-relay >/dev/null 2>&1; then
      TOUCHED_DEPLOYMENTS[codewire-udp-relay]=1
    fi
    kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" rollout restart \
      deployment/codewire-orchestration \
      deployment/codewire-billing >/dev/null || true
    kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" rollout restart \
      deployment/codewire-udp-relay >/dev/null 2>&1 || true
  fi

  wait_for_rollouts || true
}

cleanup() {
  local rc=$?

  restore_dev

  if [[ -n "$NAMESPACE_CREATED" && "$KEEP_NAMESPACE" != "1" && "$DRY_RUN" != "1" ]]; then
    log "deleting temporary sandbox namespace $NAMESPACE_CREATED"
    kubectl_dev delete namespace "$NAMESPACE_CREATED" --ignore-not-found --wait=false >/dev/null || true
  elif [[ -n "$NAMESPACE_CREATED" && "$KEEP_NAMESPACE" == "1" ]]; then
    log "kept temporary sandbox namespace $NAMESPACE_CREATED"
  fi

  if [[ -n "$TMPDIR_CANDIDATE" && -d "$TMPDIR_CANDIDATE" ]]; then
    rm -rf "$TMPDIR_CANDIDATE"
  fi
  exit "$rc"
}

run_smoke() {
  local namespace="$1"

  if [[ "$SKIP_SMOKE" == "1" ]]; then
    log "skipping runtime smoke"
    return 0
  fi
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run: run runtime commodity smoke"
    return 0
  fi

  export CODEWIRE_SERVER_URL
  export KUBE_CONTEXT
  export CODEWIRE_SERVER_NAMESPACE
  export SANDBOX_NAMESPACE="$namespace"
  export EXPECTED_TAILNET_PATH_TRANSPORT
  export EXPECTED_TAILNET_PEER_RELAY_ENDPOINT
  export EXPECTED_UDP_RELAY_BIND_ADDRS
  export EXPECTED_UDP_RELAY_ALLOCATOR_URL
  export EXPECTED_TAILNET_DIRECT_UDP_LB_IP
  export EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE
  export EXPECTED_RUNTIME_TRANSPORT_REGION

  if [[ -n "${IMAGE_SELECTED[gateway]:-}" ]]; then
    export EXPECTED_GATEWAY_IMAGE
    EXPECTED_GATEWAY_IMAGE="$(image_ref gateway)"
  fi

  log "running commodity smoke in sandbox namespace $namespace"
  "$ROOT/scripts/ci/verify/runtime-dev-commodity-smoke.sh" "${SMOKE_ARGS[@]}"
}

main() {
  parse_args "$@"
  validate_args
  init_state
  trap cleanup EXIT INT TERM

  maybe_default_kubeconfig
  require_cmd jq

  if [[ "$CURRENT_DEV" == "1" ]]; then
    local current_sandbox_namespace
    current_sandbox_namespace="${SANDBOX_NAMESPACE_OVERRIDE:-$DEFAULT_SANDBOX_NAMESPACE}"
    require_cmd kubectl
    resolve_configmap_name
    preflight_runtime_config "$current_sandbox_namespace"
    preflight_runtime_node_storage
    if [[ "$PREFLIGHT_ONLY" == "1" ]]; then
      log "preflight-only complete"
      return 0
    fi
    run_smoke "$current_sandbox_namespace"
    return 0
  fi

  if [[ "$SKIP_DEPLOY" != "1" && "$USE_TEMP_SANDBOX_NAMESPACE" == "0" ]]; then
    require_cmd kubectl
    resolve_configmap_name
    preflight_runtime_config "$DEFAULT_SANDBOX_NAMESPACE"
    preflight_runtime_node_storage
  fi

  prepare_registry_login
  for image in "${REQUESTED_IMAGES[@]}"; do
    build_image "$image"
  done

  if [[ "$SKIP_DEPLOY" == "1" ]]; then
    log "skipping dev deploy override"
    return 0
  fi

  require_cmd kubectl
  resolve_configmap_name
  select_candidate_sandbox_namespace
  apply_candidate_images
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run complete: skipped live post-deploy runtime config validation and smoke"
    return 0
  fi
  preflight_runtime_config "$CANDIDATE_SANDBOX_NAMESPACE"
  preflight_runtime_node_storage
  run_smoke "$CANDIDATE_SANDBOX_NAMESPACE"
}

main "$@"
