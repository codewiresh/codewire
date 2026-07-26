#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

PRESSURE_NAMESPACE="${PRESSURE_NAMESPACE:-codewire-runtime-pressure}"
PRESSURE_NODE="${PRESSURE_NODE:-${EXPECTED_NODE:-node1-codewire-dev}}"
PRESSURE_RUNTIME_CLASS="${PRESSURE_RUNTIME_CLASS:-commodity}"
PRESSURE_PODS="${PRESSURE_PODS:-8}"
PRESSURE_CPU_M="${PRESSURE_CPU_M:-10}"
PRESSURE_MEMORY_MI="${PRESSURE_MEMORY_MI:-64}"
PRESSURE_EPHEMERAL_GI="${PRESSURE_EPHEMERAL_GI:-}"
PRESSURE_OVERSUBSCRIBE_GI="${PRESSURE_OVERSUBSCRIBE_GI:-16}"
PRESSURE_TIMEOUT_SECONDS="${PRESSURE_TIMEOUT_SECONDS:-300}"
PRESSURE_KEEP="${PRESSURE_KEEP:-0}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"

CONFIRM=0
CLEANUP_ONLY=0
TMPDIR_PRESSURE=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/pressure-dev-runtime-node.sh --confirm [options]
  scripts/runtime/dev/pressure-dev-runtime-node.sh --cleanup-only

This is a guarded real-node pressure smoke for the commodity runtime. It creates
short-lived Kata pods with large ephemeral-storage requests on one selected node
until the scheduler reports an Unschedulable pod, then deletes the namespace and
waits for cleanup. By default it consumes schedulable resource accounting only;
it does not write large files to node storage.

Options:
  --confirm              Required for create/apply actions
  --cleanup-only         Delete PRESSURE_NAMESPACE and exit
  --node NAME            Node name (default: node1-codewire-dev or EXPECTED_NODE)
  --namespace NAME       Namespace (default: codewire-runtime-pressure)
  --runtime-class NAME   RuntimeClass (default: commodity)
  --pods N               Number of pods to create (default: 8)
  --ephemeral-gi N       Per-pod ephemeral request. Defaults to a computed value
                         that overcommits the target node across --pods.
  --keep                 Keep namespace/pods after the run
  --timeout-seconds N    Wait budget (default: 300)
  -h, --help             Show this help

Environment:
  KUBECONFIG             Optional; defaults to ~/src/infra/kubeconfig-oidc.yaml
                         when present.
  KUBE_CONTEXT           Optional; if unset, prefers codewire-dev, then default,
                         then current-context.
USAGE
}

log() {
  printf '[runtime-pressure] %s\n' "$*" >&2
}

die() {
  printf '[runtime-pressure] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_uint() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an unsigned integer, got '$value'"
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

while (($# > 0)); do
  case "$1" in
    --confirm)
      CONFIRM=1
      shift
      ;;
    --cleanup-only)
      CLEANUP_ONLY=1
      shift
      ;;
    --node)
      [[ $# -ge 2 ]] || die "--node requires a value"
      PRESSURE_NODE="$2"
      shift 2
      ;;
    --namespace)
      [[ $# -ge 2 ]] || die "--namespace requires a value"
      PRESSURE_NAMESPACE="$2"
      shift 2
      ;;
    --runtime-class)
      [[ $# -ge 2 ]] || die "--runtime-class requires a value"
      PRESSURE_RUNTIME_CLASS="$2"
      shift 2
      ;;
    --pods)
      [[ $# -ge 2 ]] || die "--pods requires a value"
      PRESSURE_PODS="$2"
      shift 2
      ;;
    --ephemeral-gi)
      [[ $# -ge 2 ]] || die "--ephemeral-gi requires a value"
      PRESSURE_EPHEMERAL_GI="$2"
      shift 2
      ;;
    --keep)
      PRESSURE_KEEP=1
      shift
      ;;
    --timeout-seconds)
      [[ $# -ge 2 ]] || die "--timeout-seconds requires a value"
      PRESSURE_TIMEOUT_SECONDS="$2"
      shift 2
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

kubectl_dev() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

maybe_default_kubeconfig() {
  if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
    export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
  fi
}

select_kube_context() {
  local contexts current_context candidate

  contexts="$(kubectl config get-contexts -o name)"
  if [[ -n "$KUBE_CONTEXT" ]]; then
    grep -Fxq "$KUBE_CONTEXT" <<<"$contexts" || die "KUBE_CONTEXT=$KUBE_CONTEXT is not present in the active kubeconfig"
    log "using Kubernetes context $KUBE_CONTEXT"
    return
  fi

  for candidate in codewire-dev default; do
    if grep -Fxq "$candidate" <<<"$contexts"; then
      KUBE_CONTEXT="$candidate"
      export KUBE_CONTEXT
      log "using Kubernetes context $KUBE_CONTEXT"
      return
    fi
  done

  current_context="$(kubectl config current-context)"
  [[ -n "$current_context" ]] || die "failed to select Kubernetes context"
  KUBE_CONTEXT="$current_context"
  export KUBE_CONTEXT
  log "using Kubernetes context $KUBE_CONTEXT"
}

cleanup_pressure() {
  local rc=$?
  if [[ "$PRESSURE_KEEP" != "1" && "$CLEANUP_ONLY" != "1" ]]; then
    log "deleting namespace $PRESSURE_NAMESPACE"
    kubectl_dev delete ns "$PRESSURE_NAMESPACE" --ignore-not-found --wait=true --timeout="${PRESSURE_TIMEOUT_SECONDS}s" >/dev/null 2>&1 || true
  elif [[ "$PRESSURE_KEEP" == "1" ]]; then
    log "kept namespace $PRESSURE_NAMESPACE"
  fi
  if [[ "$rc" != "0" && -n "$TMPDIR_PRESSURE" && -d "$TMPDIR_PRESSURE" ]]; then
    log "kept failed-pressure evidence directory $TMPDIR_PRESSURE"
  elif [[ -n "$TMPDIR_PRESSURE" && -d "$TMPDIR_PRESSURE" && "$PRESSURE_KEEP" != "1" ]]; then
    rm -rf "$TMPDIR_PRESSURE"
  fi
  exit "$rc"
}
trap cleanup_pressure EXIT

main() {
  require_cmd kubectl
  require_cmd jq
  require_uint PRESSURE_PODS "$PRESSURE_PODS"
  require_uint PRESSURE_CPU_M "$PRESSURE_CPU_M"
  require_uint PRESSURE_MEMORY_MI "$PRESSURE_MEMORY_MI"
  require_uint PRESSURE_OVERSUBSCRIBE_GI "$PRESSURE_OVERSUBSCRIBE_GI"
  require_uint PRESSURE_TIMEOUT_SECONDS "$PRESSURE_TIMEOUT_SECONDS"
  [[ "$PRESSURE_PODS" -ge 2 ]] || die "PRESSURE_PODS must be at least 2"

  mkdir -p "$ROOT/.tmp"
  TMPDIR_PRESSURE="$(mktemp -d "$ROOT/.tmp/codewire-runtime-pressure.XXXXXX")"

  maybe_default_kubeconfig
  select_kube_context

  if [[ "$CLEANUP_ONLY" == "1" ]]; then
    log "cleanup-only: deleting namespace $PRESSURE_NAMESPACE"
    kubectl_dev delete ns "$PRESSURE_NAMESPACE" --ignore-not-found --wait=true --timeout="${PRESSURE_TIMEOUT_SECONDS}s"
    return
  fi

  [[ "$CONFIRM" == "1" ]] || die "--confirm is required before creating pressure pods"

  local node_json node_hostname allocatable allocatable_bytes allocatable_gi request_gi
  local pods_json scheduled_count unschedulable_count reason_summary

  node_json="$TMPDIR_PRESSURE/node.json"
  kubectl_dev get node "$PRESSURE_NODE" -o json >"$node_json"
  node_hostname="$(jq -r '.metadata.labels["kubernetes.io/hostname"] // .metadata.name' "$node_json")"
  allocatable="$(jq -r '.status.allocatable["ephemeral-storage"] // empty' "$node_json")"
  [[ -n "$allocatable" ]] || die "node $PRESSURE_NODE has no allocatable ephemeral-storage"
  allocatable_bytes="$(quantity_to_bytes "$allocatable")"
  allocatable_gi="$((allocatable_bytes / 1024 / 1024 / 1024))"
  if [[ -z "$PRESSURE_EPHEMERAL_GI" ]]; then
    request_gi="$(((allocatable_gi + PRESSURE_OVERSUBSCRIBE_GI + PRESSURE_PODS - 1) / PRESSURE_PODS))"
  else
    require_uint PRESSURE_EPHEMERAL_GI "$PRESSURE_EPHEMERAL_GI"
    request_gi="$PRESSURE_EPHEMERAL_GI"
  fi
  [[ "$request_gi" -gt 0 ]] || die "computed per-pod ephemeral request is zero"

  log "target node=$PRESSURE_NODE hostname=$node_hostname allocatable_ephemeral=$allocatable per_pod_ephemeral=${request_gi}Gi pods=$PRESSURE_PODS"

  kubectl_dev create ns "$PRESSURE_NAMESPACE" --dry-run=client -o yaml | kubectl_dev apply -f -
  kubectl_dev label ns "$PRESSURE_NAMESPACE" \
    codewire.sh/runtime-pressure=true \
    pod-security.kubernetes.io/enforce=baseline \
    --overwrite >/dev/null

  for i in $(seq 1 "$PRESSURE_PODS"); do
    name="runtime-pressure-$i"
    cat <<YAML | kubectl_dev apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${PRESSURE_NAMESPACE}
  labels:
    codewire.sh/runtime-pressure: "true"
spec:
  runtimeClassName: ${PRESSURE_RUNTIME_CLASS}
  restartPolicy: Never
  nodeSelector:
    kubernetes.io/hostname: ${node_hostname}
  tolerations:
    - operator: Exists
  containers:
    - name: pause
      image: registry.k8s.io/pause:3.10
      resources:
        requests:
          cpu: ${PRESSURE_CPU_M}m
          memory: ${PRESSURE_MEMORY_MI}Mi
          ephemeral-storage: ${request_gi}Gi
YAML
  done

  log "waiting for scheduler pressure evidence"
  sleep 10
  pods_json="$TMPDIR_PRESSURE/pods.json"
  local deadline
  deadline=$(( $(date +%s) + PRESSURE_TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    kubectl_dev -n "$PRESSURE_NAMESPACE" get pods -o json >"$pods_json"
    scheduled_count="$(jq '[.items[] | select(any(.status.conditions[]?; .type == "PodScheduled" and .status == "True"))] | length' "$pods_json")"
    unschedulable_count="$(jq '[.items[] | select(any(.status.conditions[]?; .type == "PodScheduled" and .status == "False" and .reason == "Unschedulable"))] | length' "$pods_json")"
    if [[ "$scheduled_count" -gt 0 && "$unschedulable_count" -gt 0 ]]; then
      break
    fi
    sleep 5
  done

  kubectl_dev -n "$PRESSURE_NAMESPACE" get pods -o wide >"$TMPDIR_PRESSURE/pods.txt"
  kubectl_dev -n "$PRESSURE_NAMESPACE" describe pods >"$TMPDIR_PRESSURE/pods.describe.txt" || true
  scheduled_count="$(jq '[.items[] | select(any(.status.conditions[]?; .type == "PodScheduled" and .status == "True"))] | length' "$pods_json")"
  unschedulable_count="$(jq '[.items[] | select(any(.status.conditions[]?; .type == "PodScheduled" and .status == "False" and .reason == "Unschedulable"))] | length' "$pods_json")"
  reason_summary="$(jq -r '[.items[] | .status.conditions[]? | select(.type == "PodScheduled" and .status == "False") | .message] | unique | join(" | ")' "$pods_json")"

  [[ "$scheduled_count" -gt 0 ]] || die "no pressure pod scheduled on $PRESSURE_NODE"
  [[ "$unschedulable_count" -gt 0 ]] || die "did not observe an Unschedulable pressure pod; evidence in $TMPDIR_PRESSURE"
  log "pressure evidence ok: scheduled=$scheduled_count unschedulable=$unschedulable_count reason=${reason_summary:-<none>}"

  if [[ "$PRESSURE_KEEP" != "1" ]]; then
    log "verifying namespace cleanup"
    kubectl_dev delete ns "$PRESSURE_NAMESPACE" --wait=true --timeout="${PRESSURE_TIMEOUT_SECONDS}s"
    kubectl_dev get ns "$PRESSURE_NAMESPACE" >/dev/null 2>&1 && die "namespace $PRESSURE_NAMESPACE still exists after cleanup"
  fi
  log "runtime node pressure smoke passed"
}

main "$@"
