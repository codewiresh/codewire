#!/usr/bin/env bash
# The dev transport matrix: one fresh environment proves direct UDP, the
# shared UDP relay, forced DERP and WebSocket. See usage below.
#
# How long a run can take. MATRIX_TIMEOUT_SECONDS bounds the smoke itself;
# after it, the smoke gets SIGTERM and MATRIX_KILL_AFTER_SECONDS to stop.
# Cleanup then runs to completion, ignoring further INT, TERM and HUP so it
# never abandons a cordoned node, and each of its steps is bounded:
#   cordoned nodes   MATRIX_CLEANUP_ATTEMPTS requests of up to 30 s each,
#                    plus retry pauses, per node (and 60 s per node to cordon)
#   environment      120 s to request removal, MATRIX_DESTROY_TIMEOUT_SECONDS
#                    plus up to 62 s for it to reach destroyed
#   namespace        180 s, candidate target only
# With the defaults, --current-dev and no cordoning, that is
# 2400 + 600 + 120 + 362 = 3482 s, about 58 minutes. A job that runs this
# needs a longer timeout (65 minutes covers it); the run logs its own worst
# case when it starts. Only SIGKILL of this script skips cleanup: a smoke
# still running then is left to timeout, which kills its process group at
# its bound, and its cordons are recovered by the next run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
CODEWIRE_SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-dev}"
KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-$ROOT/.tmp}"
MATRIX_CURRENT_DEV="${MATRIX_CURRENT_DEV:-0}"
MATRIX_CLEANUP_ON_FAILURE="${MATRIX_CLEANUP_ON_FAILURE:-0}"
MATRIX_KEEP_ENV="${MATRIX_KEEP_ENV:-0}"
MATRIX_KEEP_NAMESPACE="${MATRIX_KEEP_NAMESPACE:-0}"
MATRIX_SANDBOX_NAMESPACE="${MATRIX_SANDBOX_NAMESPACE:-}"
MATRIX_CORDON_OTHER_RUNTIME_NODES="${MATRIX_CORDON_OTHER_RUNTIME_NODES:-1}"
EXPECTED_NODE="${EXPECTED_NODE:-}"
EXPECTED_RUNTIME_NODE_SELECTOR="${EXPECTED_RUNTIME_NODE_SELECTOR:-katacontainers.io/kata-runtime=true}"
MATRIX_WORKER_LOOPS="${MATRIX_WORKER_LOOPS:-env-reconciler,sandbox-liveness,billing-session}"
MATRIX_DAEMON_TAG="${MATRIX_DAEMON_TAG:-}"
MATRIX_BUILD_DAEMON="${MATRIX_BUILD_DAEMON:-0}"
MATRIX_CANDIDATE_IMAGES="${MATRIX_CANDIDATE_IMAGES:-services daemon}"
MATRIX_CW_BIN="${CW_BIN:-}"
SMOKE_SKIP_KUBE="${SMOKE_SKIP_KUBE:-0}"
SMOKE_NAME="${SMOKE_NAME:-transport-matrix-$(date -u +%Y%m%d%H%M%S)}"
SMOKE_TAILNET_DIRECT_WAIT="${SMOKE_TAILNET_DIRECT_WAIT:-5s}"
SMOKE_TAILNET_PEER_TIMEOUT="${SMOKE_TAILNET_PEER_TIMEOUT:-30s}"
SMOKE_TAILNET_DIAL_TIMEOUT="${SMOKE_TAILNET_DIAL_TIMEOUT:-60s}"
SMOKE_SSH_TIMEOUT="${SMOKE_SSH_TIMEOUT:-90}"
SMOKE_SSH_CONNECT_TIMEOUT="${SMOKE_SSH_CONNECT_TIMEOUT:-60}"
MATRIX_INITIAL_SMOKE_TIMEOUT_SECONDS="${MATRIX_INITIAL_SMOKE_TIMEOUT_SECONDS:-900}"
MATRIX_TIMEOUT_SECONDS="${MATRIX_TIMEOUT_SECONDS:-2400}"
MATRIX_KILL_AFTER_SECONDS="${MATRIX_KILL_AFTER_SECONDS:-600}"
MATRIX_DESTROY_TIMEOUT_SECONDS="${MATRIX_DESTROY_TIMEOUT_SECONDS:-300}"
MATRIX_CLEANUP_ATTEMPTS="${MATRIX_CLEANUP_ATTEMPTS:-3}"
EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB="${EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB:-400}"

# Every runtime node this script cordons carries this annotation, valued
# "<start epoch seconds>:<run id>", until it uncordons the node. A run that
# was killed before its cleanup leaves it behind; the next run undoes that
# cordon, and refuses to start while a recent run still holds one.
readonly MATRIX_CORDON_ANNOTATION="codewire.sh/transport-matrix-cordon"

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/with-dev-smoke-auth.sh scripts/runtime/dev/smoke-dev-transport-matrix.sh [options]

Creates one fresh dev commodity environment and proves every tailnet path on
it through the runtime smoke: direct_udp as the primary path, forced DERP,
websocket, and the shared UDP relay (udp_relay) with peer direct endpoints
suppressed. With Kubernetes (the default), it also asserts the direct-UDP
LoadBalancer, the relay NetworkPolicy and the daemon's tailnet logs, and the
environment must land on EXPECTED_NODE. With SMOKE_SKIP_KUBE=1 and
--current-dev, it holds no Kubernetes identity at all, as Dev acceptance:
only the Codewire API and the tailnet paths are exercised.

Two targets:
  (default)      Candidate: deploy the candidate images to the singleton dev
                 control plane (--force-shared-dev), point it at a temporary
                 sandbox namespace, run, then restore dev. Manual use only.
  --current-dev  The deployed dev, unchanged: no image, ConfigMap or namespace
                 change. The environment lives in dev's sandbox namespace.
                 This is the target for unattended runs.

Options:
  --current-dev          Test the deployed dev without changing it.
  --cleanup-on-failure   Remove the environment (and a candidate run's
                         temporary namespace) on failure too, after keeping
                         the evidence directory. Use it for unattended runs.
  --keep                 Keep the smoke environment after success.
  --initial-smoke-arg X  Add one argument to the runtime smoke. Repeatable.
                         Use this for --timeout-seconds, --only, etc.
  --sandbox-namespace N  Candidate only: use this temporary sandbox namespace
                         instead of an auto-generated one.
  --keep-namespace       Candidate only: keep the temporary sandbox namespace
                         after success.
  -h, --help            Show this help.

Environment:
  CW_BIN                            Prebuilt cw to use; otherwise the smoke
                                    builds one with cargo
  SMOKE_SKIP_KUBE                   1 runs the application and tailnet smoke
                                    without Kubernetes: no kubectl, no
                                    runtime preflight, no EXPECTED_NODE.
                                    Default 0
  SMOKE_NAME                        environment name, default
                                    transport-matrix-<UTC time>
  EXPECTED_NODE                     Runtime node the environment must land
                                    on; required by the Kubernetes smoke
                                    and while cordoning
  MATRIX_CORDON_OTHER_RUNTIME_NODES cordon runtime nodes other than
                                    EXPECTED_NODE during the run, default 1.
                                    Needs kubectl and node patch rights
  MATRIX_TIMEOUT_SECONDS            bound on the whole smoke, default 2400;
                                    the smoke then gets SIGTERM and
                                    MATRIX_KILL_AFTER_SECONDS (default 600)
                                    to restore what it changed. Cleanup comes
                                    after both; see the worst case in the
                                    script header
  MATRIX_INITIAL_SMOKE_TIMEOUT_SECONDS
                                    the smoke's own per-wait bound, default 900
  MATRIX_DESTROY_TIMEOUT_SECONDS    environment destroy completion timeout,
                                    default 300; namespace cleanup waits for it
  MATRIX_CLEANUP_ATTEMPTS           tries per uncordon, default 3
  SMOKE_TAILNET_DIRECT_WAIT         direct UDP settle wait, default 5s
  SMOKE_TAILNET_PEER_TIMEOUT        coordinator/DERP peer wait, default 30s
  SMOKE_TAILNET_DIAL_TIMEOUT        tailnet TCP stream dial timeout, default 60s
  SMOKE_SSH_TIMEOUT                 transport SSH command timeout, default 90
  SMOKE_SSH_CONNECT_TIMEOUT         OpenSSH ConnectTimeout, default 60
  MATRIX_KEEP_ENV                   keep environment on success when 1
  MATRIX_KEEP_NAMESPACE             candidate: keep smoke namespace on success
  MATRIX_WORKER_LOOPS               candidate: WORKER_LOOPS override for the
                                    candidate window
  MATRIX_DAEMON_TAG                 candidate: workspace daemon image tag to
                                    test (the "daemon" image,
                                    SANDBOX_DAEMON_IMAGE). Defaults to the
                                    currently deployed dev tag.
  MATRIX_BUILD_DAEMON               candidate: build and push MATRIX_DAEMON_TAG
                                    when 1, default 0
  MATRIX_CANDIDATE_IMAGES           candidate: space-separated images to
                                    deploy, default "services daemon"
  EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB
                                    Runtime node storage preflight passed to
                                    the candidate smoke, default 400 for fresh
                                    dev transport proof nodes

Exit status is 0 only when every path passed and cleanup completed. On a
smoke failure an error line names the failed path (direct_udp, udp_relay,
derp_relay or websocket) with the smoke's acceptance stage and class. Every
failed exit ends with one line that holds no name, ID or path:
  [transport-matrix] exit-failure step=STEP cleanup=CLEANUP legs=LEGS
STEP is setup, smoke, evidence or cleanup: what the run was doing when it
failed. CLEANUP is ok or the first cleanup step that failed: nodes, cw,
request, wait or namespace. LEGS is passed once the evidence of all four
paths is confirmed, otherwise unproven. Every node this run cordoned is
uncordoned on every exit path the shell can trap. The wrapper never prints
API keys. Without --cleanup-on-failure, a
failed run leaves the environment and evidence directories in place.

The environment is removed once the smoke has logged its id, which it does
as soon as cw create returns. A smoke stopped while cw create is still in
flight can leave an environment this run never learned of; it is named
SMOKE_NAME, and its --ttl (SMOKE_TTL, default 2h) sets its shutdown time.
USAGE
}

log() {
  printf '[transport-matrix] %s\n' "$*" >&2
}

die() {
  printf '[transport-matrix] ERROR: %s\n' "$*" >&2
  exit 1
}

# What this run was doing, for the one line that ends a failed exit. The line
# holds only values from these closed sets, so it can leave a private capture.
MATRIX_STEP=setup
MATRIX_CLEANUP_FAILED=ok
MATRIX_LEGS=unproven

report_exit_failure() {
  log "exit-failure step=$MATRIX_STEP cleanup=$MATRIX_CLEANUP_FAILED legs=$MATRIX_LEGS"
}

# Replaced by cleanup once there is something to clean up.
trap 'rc=$?; ((rc == 0)) || report_exit_failure; exit "$rc"' EXIT

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

declare -a INITIAL_SMOKE_ARGS=()
declare -a CANDIDATE_ARGS=()
SANDBOX_NAMESPACE_REQUESTED=0

while (($# > 0)); do
  case "$1" in
    --current-dev)
      MATRIX_CURRENT_DEV=1
      shift
      ;;
    --cleanup-on-failure)
      MATRIX_CLEANUP_ON_FAILURE=1
      shift
      ;;
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
      SANDBOX_NAMESPACE_REQUESTED=1
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

require_bool01() {
  [[ "$2" == "0" || "$2" == "1" ]] || die "$1 must be 0 or 1, got '$2'"
}

require_uint() {
  [[ "$2" =~ ^[0-9]+$ ]] || die "$1 must be an unsigned integer, got '$2'"
}

for flag in MATRIX_CURRENT_DEV MATRIX_CLEANUP_ON_FAILURE MATRIX_KEEP_ENV \
    MATRIX_KEEP_NAMESPACE MATRIX_CORDON_OTHER_RUNTIME_NODES MATRIX_BUILD_DAEMON \
    SMOKE_SKIP_KUBE; do
  require_bool01 "$flag" "${!flag}"
done
for bound in MATRIX_TIMEOUT_SECONDS MATRIX_KILL_AFTER_SECONDS \
    MATRIX_DESTROY_TIMEOUT_SECONDS MATRIX_INITIAL_SMOKE_TIMEOUT_SECONDS MATRIX_CLEANUP_ATTEMPTS; do
  require_uint "$bound" "${!bound}"
done
((MATRIX_TIMEOUT_SECONDS > 0)) || die "MATRIX_TIMEOUT_SECONDS must be positive"
((MATRIX_CLEANUP_ATTEMPTS > 0)) || die "MATRIX_CLEANUP_ATTEMPTS must be positive"

if [[ "$MATRIX_CURRENT_DEV" == "1" ]]; then
  # The deployed dev is tested as it is; nothing here may change it.
  [[ "$SANDBOX_NAMESPACE_REQUESTED" == "0" && -z "$MATRIX_SANDBOX_NAMESPACE" ]] || \
    die "--current-dev uses dev's sandbox namespace; --sandbox-namespace is candidate-only"
  [[ "$MATRIX_KEEP_NAMESPACE" == "0" ]] || die "--keep-namespace is candidate-only"
  [[ -z "$MATRIX_DAEMON_TAG" && "$MATRIX_BUILD_DAEMON" == "0" ]] || \
    die "--current-dev tests the deployed daemon; MATRIX_DAEMON_TAG and MATRIX_BUILD_DAEMON are candidate-only"
fi

[[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]] || \
  die "CODEWIRE_DEV_SMOKE_API_KEY is required; run through scripts/runtime/dev/with-dev-smoke-auth.sh"
[[ "$CODEWIRE_DEV_SMOKE_API_KEY" =~ ^cw_[0-9a-f]{64}$ ]] || \
  die "CODEWIRE_DEV_SMOKE_API_KEY has an unexpected shape"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_cmd awk
require_cmd jq
require_cmd sed
require_cmd timeout
# This script reads Kubernetes only to cordon nodes and, for a candidate, to
# find the deployed daemon tag and delete its namespace. The smoke checks its
# own needs.
if [[ "$MATRIX_CORDON_OTHER_RUNTIME_NODES" == "1" || "$MATRIX_CURRENT_DEV" != "1" ]]; then
  require_cmd kubectl
fi

if [[ -n "$MATRIX_CW_BIN" ]]; then
  [[ -x "$MATRIX_CW_BIN" ]] || die "CW_BIN is not executable: $MATRIX_CW_BIN"
  export CW_BIN="$MATRIX_CW_BIN"
fi

mkdir -p "$SMOKE_TMP_PARENT"
MATRIX_DIR="$(mktemp -d "$SMOKE_TMP_PARENT/codewire-transport-matrix.XXXXXX")"
INITIAL_LOG="$MATRIX_DIR/initial-direct-derp-websocket.log"
MATRIX_RUN_STARTED="$(date -u +%s)"
MATRIX_RUN_ID="$(basename "$MATRIX_DIR")"

ENV_ID=""
INITIAL_EVIDENCE_DIR=""
MATRIX_CLI=""
SMOKE_PID=""
SMOKE_PGID=""
MATRIX_OWNS_NAMESPACE=0
declare -a MATRIX_CORDONED_NODES=()

kubectl_dev() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

# Node reads and writes are single requests; none may hang a cleanup.
kubectl_node() {
  kubectl_dev --request-timeout=30s "$@"
}

# Cordon or uncordon NODE and set or clear its annotation in one merge patch,
# so the two never disagree; clearing an absent annotation succeeds.
patch_node_cordon() {
  local node="$1" cordoned="$2" patch

  if [[ "$cordoned" == "1" ]]; then
    patch="$(jq -cn --arg key "$MATRIX_CORDON_ANNOTATION" --arg value "$MATRIX_RUN_STARTED:$MATRIX_RUN_ID" \
      '{spec: {unschedulable: true}, metadata: {annotations: {($key): $value}}}')"
  else
    patch="$(jq -cn --arg key "$MATRIX_CORDON_ANNOTATION" \
      '{spec: {unschedulable: null}, metadata: {annotations: {($key): null}}}')"
  fi
  kubectl_node patch node "$node" --type=merge -p "$patch" >/dev/null
}

if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
  export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
fi

if [[ "$MATRIX_CURRENT_DEV" != "1" ]]; then
  if [[ -z "$MATRIX_SANDBOX_NAMESPACE" ]]; then
    MATRIX_SANDBOX_NAMESPACE="dev-sbx-transport-$(date -u +%m%d%H%M%S)-$RANDOM"
    MATRIX_SANDBOX_NAMESPACE="$(printf '%s' "$MATRIX_SANDBOX_NAMESPACE" | tr '[:upper:]_' '[:lower:]-' | cut -c1-63 | sed -E 's/-+$//')"
  fi
  MATRIX_OWNS_NAMESPACE=1
fi

current_daemon_tag() {
  local configmap image

  configmap="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment codewire-orchestration -o json |
    jq -r '.spec.template.spec.containers[]
      | select(.name == "orchestration")
      | .envFrom[]?
      | .configMapRef.name? // empty' |
    sed -n '1p')"
  [[ -n "$configmap" ]] || die "failed to resolve dev runtime ConfigMap from codewire-orchestration"

  image="$(kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get configmap "$configmap" -o json |
    jq -r '.data.SANDBOX_DAEMON_IMAGE // empty')"
  [[ -n "${CODEWIRE_IMAGE_REGISTRY:-}" ]] || die "CODEWIRE_IMAGE_REGISTRY: set to the image registry host"
  [[ "$image" == "$CODEWIRE_IMAGE_REGISTRY"/codewire/daemon:* ]] || \
    die "dev SANDBOX_DAEMON_IMAGE=$image, expected $CODEWIRE_IMAGE_REGISTRY/codewire/daemon:<tag>"
  printf '%s\n' "${image##*:}"
}

generated_candidate_tag() {
  printf 'dev-smoke-transport-%s-%s\n' \
    "$(date -u +%Y%m%d%H%M%S)" \
    "$(git -C "$ROOT" rev-parse --short=12 HEAD)"
}

# The longest a run with NODES cordoned nodes can take, cleanup included;
# the script header lists the terms.
matrix_worst_case_seconds() {
  local nodes="$1" per_node namespace=0

  per_node=$((60 + MATRIX_CLEANUP_ATTEMPTS * 30 + MATRIX_CLEANUP_ATTEMPTS * (MATRIX_CLEANUP_ATTEMPTS - 1) / 2))
  [[ "$MATRIX_OWNS_NAMESPACE" != "1" ]] || namespace=180
  printf '%s\n' $((MATRIX_TIMEOUT_SECONDS + MATRIX_KILL_AFTER_SECONDS + nodes * per_node \
    + 120 + MATRIX_DESTROY_TIMEOUT_SECONDS + 62 + namespace))
}

# Undo the cordon of a run that was killed before its cleanup, and refuse to
# start while a recent run may still hold its nodes.
recover_interrupted_cordons() {
  local nodes_json node value started now stale_after

  now="$(date -u +%s)"
  nodes_json="$(kubectl_node get nodes -l "$EXPECTED_RUNTIME_NODE_SELECTOR" -o json)"
  # A run that could still be alive holds its cordon at most this long.
  stale_after="$(matrix_worst_case_seconds "$(jq '.items | length' <<<"$nodes_json")")"
  while IFS=$'\t' read -r node value; do
    [[ -n "$node" ]] || continue
    started="${value%%:*}"
    if [[ "$started" =~ ^[0-9]+$ ]] && ((now - started < stale_after)); then
      die "runtime node $node is cordoned by transport matrix run ${value#*:}, started $((now - started))s ago; two runs never share the runtime nodes"
    fi
    log "uncordoning runtime node $node, left cordoned by interrupted transport matrix run ${value#*:}"
    patch_node_cordon "$node" 0
  done < <(jq -r --arg key "$MATRIX_CORDON_ANNOTATION" '
    .items[] | select(.metadata.annotations[$key]? != null)
    | [.metadata.name, .metadata.annotations[$key]] | @tsv' <<<"$nodes_json")
}

cordon_other_runtime_nodes() {
  local nodes node unschedulable

  [[ "$MATRIX_CORDON_OTHER_RUNTIME_NODES" == "1" ]] || return 0
  [[ -n "$EXPECTED_NODE" ]] || \
    die "EXPECTED_NODE is required when MATRIX_CORDON_OTHER_RUNTIME_NODES=1"

  recover_interrupted_cordons
  nodes="$(kubectl_node get nodes -l "$EXPECTED_RUNTIME_NODE_SELECTOR" -o json |
    jq -r '.items[].metadata.name')"
  grep -qxF -- "$EXPECTED_NODE" <<<"$nodes" || \
    die "EXPECTED_NODE $EXPECTED_NODE is not a runtime node ($EXPECTED_RUNTIME_NODE_SELECTOR)"
  while IFS= read -r node; do
    [[ -n "$node" ]] || continue
    [[ "$node" != "$EXPECTED_NODE" ]] || continue
    unschedulable="$(kubectl_node get node "$node" -o jsonpath='{.spec.unschedulable}')"
    if [[ "$unschedulable" == "true" ]]; then
      log "runtime node $node is already cordoned; leaving it unchanged"
      continue
    fi
    log "cordoning non-target runtime node $node for fresh-node smoke"
    # Recorded before the change, so an interruption during the request
    # still restores the node.
    MATRIX_CORDONED_NODES+=("$node")
    patch_node_cordon "$node" 1
  done <<<"$nodes"
}

uncordon_node() {
  local node="$1" attempt

  for ((attempt = 1; attempt <= MATRIX_CLEANUP_ATTEMPTS; attempt++)); do
    patch_node_cordon "$node" 0 && return 0
    ((attempt == MATRIX_CLEANUP_ATTEMPTS)) || sleep "$attempt"
  done
  return 1
}

restore_cordoned_nodes() {
  local node failed=0

  for node in "${MATRIX_CORDONED_NODES[@]}"; do
    log "uncordoning runtime node $node"
    if ! uncordon_node "$node"; then
      log "ERROR: runtime node $node is still cordoned; uncordon it and remove its $MATRIX_CORDON_ANNOTATION annotation"
      failed=1
    fi
  done
  MATRIX_CORDONED_NODES=()
  return "$failed"
}

wait_for_environment_destroyed() {
  local deadline=$((SECONDS + MATRIX_DESTROY_TIMEOUT_SECONDS))
  local report_json

  # info resolves only live environments, so it fails once removal completes,
  # and absence is not proof of removal. report reads this exact ID, deleted
  # or not.
  while ((SECONDS < deadline)); do
    if report_json="$({
      CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY" \
        CW_CONFIG_DIR="${INITIAL_EVIDENCE_DIR:-$MATRIX_DIR}/cw-config" \
        timeout 60 "$MATRIX_CLI" --server "$CODEWIRE_SERVER_URL" report "$ENV_ID" --output json
    } 2>/dev/null)" &&
      jq -e --arg id "$ENV_ID" '.environment.id == $id and .environment.state == "destroyed"' \
        >/dev/null <<<"$report_json"; then
      return 0
    fi
    sleep 2
  done

  return 1
}

# The environment and evidence directory the smoke logged, whether it passed
# or not; the cw it used is the one this run removes the environment with.
read_initial_smoke_log() {
  [[ -s "$INITIAL_LOG" ]] || return 0
  ENV_ID="$(awk '/environment id / || /using existing environment / {id = $NF} END {print id}' "$INITIAL_LOG")"
  INITIAL_EVIDENCE_DIR="$(awk '/kept (failed-smoke )?evidence directory / {dir = $NF} END {print dir}' "$INITIAL_LOG")"
  if [[ -n "$MATRIX_CW_BIN" ]]; then
    MATRIX_CLI="$MATRIX_CW_BIN"
  elif [[ -n "$INITIAL_EVIDENCE_DIR" ]]; then
    MATRIX_CLI="$INITIAL_EVIDENCE_DIR/cw"
  fi
}

# The tailnet path a smoke acceptance stage proves.
stage_path() {
  case "$1" in
    direct-udp) printf 'direct_udp\n' ;;
    udp-relay) printf 'udp_relay\n' ;;
    derp-ssh) printf 'derp_relay\n' ;;
    websocket-ssh) printf 'websocket\n' ;;
    *) printf 'none\n' ;;
  esac
}

# One line that names what failed: the smoke's last acceptance-failure stage
# and class, the path that stage proves, and whether the bound ran out.
failure_summary() {
  local rc="$1" line stage=unknown class=unknown bound=""

  line="$(grep -E '^\[runtime-smoke\] acceptance-failure stage=[a-z-]+ class=[a-z0-9_]+$' "$INITIAL_LOG" 2>/dev/null | tail -n 1 || true)"
  if [[ -n "$line" ]]; then
    stage="$(sed -E 's/.* stage=([a-z-]+) .*/\1/' <<<"$line")"
    class="$(sed -E 's/.* class=([a-z0-9_]+)$/\1/' <<<"$line")"
  fi
  if [[ "$rc" == "124" || "$rc" == "137" ]]; then
    bound=" after MATRIX_TIMEOUT_SECONDS=$MATRIX_TIMEOUT_SECONDS"
  fi
  printf 'path=%s stage=%s class=%s%s\n' "$(stage_path "$stage")" "$stage" "$class" "$bound"
}

# timeout leads its own process group, so a signal to this shell never
# reaches the smoke. SIGTERM to timeout, which forwards it to that group, lets
# the smoke restore what it changed; MATRIX_KILL_AFTER_SECONDS later SIGKILL
# to the group ends whatever is left, including anything that outlived a
# smoke that already exited.
stop_running_smoke() {
  local deadline

  [[ -n "$SMOKE_PGID" ]] || return 0
  if [[ -n "$SMOKE_PID" ]] && kill -0 "$SMOKE_PID" 2>/dev/null; then
    log "stopping the running smoke"
    kill -TERM "$SMOKE_PID" 2>/dev/null || true
    deadline=$((SECONDS + MATRIX_KILL_AFTER_SECONDS))
    while kill -0 "$SMOKE_PID" 2>/dev/null && ((SECONDS < deadline)); do
      sleep 1
    done
  fi
  kill -KILL -- "-$SMOKE_PGID" 2>/dev/null || true
  if [[ -n "$SMOKE_PID" ]]; then
    wait "$SMOKE_PID" 2>/dev/null || true
  fi
  SMOKE_PID=""
  SMOKE_PGID=""
}

# The first cleanup step that failed names the failure; every one still runs.
cleanup_failed() {
  [[ "$MATRIX_CLEANUP_FAILED" != ok ]] || MATRIX_CLEANUP_FAILED="$1"
  rc=1
}

cleanup() {
  local rc=$?
  local remove_env=0 env_removed=1

  # Every cleanup step is bounded; a second signal must not abandon it with
  # runtime nodes still cordoned.
  trap '' INT TERM HUP
  stop_running_smoke
  restore_cordoned_nodes || cleanup_failed nodes
  [[ -n "$ENV_ID" ]] || read_initial_smoke_log

  if [[ "$MATRIX_KEEP_ENV" != "1" && ( "$rc" == "0" || "$MATRIX_CLEANUP_ON_FAILURE" == "1" ) ]]; then
    remove_env=1
  fi
  if [[ "$remove_env" == "1" && -n "$ENV_ID" ]]; then
    env_removed=0
    log "deleting smoke environment $ENV_ID"
    if [[ ! -x "$MATRIX_CLI" ]]; then
      log "ERROR: no cw to delete environment $ENV_ID with; it remains"
      cleanup_failed cw
    elif ! CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY" \
      CW_CONFIG_DIR="${INITIAL_EVIDENCE_DIR:-$MATRIX_DIR}/cw-config" \
      timeout 120 "$MATRIX_CLI" --server "$CODEWIRE_SERVER_URL" rm --yes "$ENV_ID" >/dev/null 2>&1; then
      log "ERROR: environment $ENV_ID delete request failed; it remains"
      cleanup_failed request
    elif ! wait_for_environment_destroyed; then
      log "ERROR: environment $ENV_ID did not reach destroyed within ${MATRIX_DESTROY_TIMEOUT_SECONDS}s"
      cleanup_failed wait
    else
      log "environment $ENV_ID reached destroyed"
      env_removed=1
    fi
  elif [[ -n "$ENV_ID" ]]; then
    log "kept smoke environment $ENV_ID"
  fi

  # Only a candidate run's own temporary namespace is ever deleted, and only
  # once its environment is gone.
  if [[ "$MATRIX_OWNS_NAMESPACE" == "1" ]]; then
    if [[ "$remove_env" == "1" && "$env_removed" == "1" && "$MATRIX_KEEP_NAMESPACE" != "1" ]]; then
      log "deleting temporary sandbox namespace $MATRIX_SANDBOX_NAMESPACE"
      if ! kubectl_dev delete namespace "$MATRIX_SANDBOX_NAMESPACE" \
        --ignore-not-found --wait=true --timeout=180s >/dev/null; then
        log "ERROR: temporary sandbox namespace $MATRIX_SANDBOX_NAMESPACE deletion failed"
        cleanup_failed namespace
      fi
    else
      log "kept temporary sandbox namespace $MATRIX_SANDBOX_NAMESPACE"
    fi
  fi

  if [[ "$rc" == "0" ]]; then
    log "transport matrix evidence directory $MATRIX_DIR"
  else
    log "kept failed transport matrix evidence directory $MATRIX_DIR"
    report_exit_failure
  fi
  exit "$rc"
}

on_signal() {
  trap - INT TERM HUP
  log "interrupted; cleaning up"
  exit "$1"
}

trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
trap 'on_signal 129' HUP

if [[ "$MATRIX_CURRENT_DEV" == "1" ]]; then
  CANDIDATE_ARGS=(--current-dev)
  target_description="deployed dev"
else
  mapfile -t candidate_images < <(printf '%s\n' "$MATRIX_CANDIDATE_IMAGES" | tr ' ' '\n' | sed '/^$/d')
  [[ "${#candidate_images[@]}" -gt 0 ]] || die "MATRIX_CANDIDATE_IMAGES must contain at least one image"
  for image in "${candidate_images[@]}"; do
    CANDIDATE_ARGS+=(--image "$image")
  done

  if [[ -n "$MATRIX_DAEMON_TAG" ]]; then
    DAEMON_TAG="$MATRIX_DAEMON_TAG"
  elif [[ "$MATRIX_BUILD_DAEMON" == "1" ]]; then
    DAEMON_TAG="$(generated_candidate_tag)"
  else
    DAEMON_TAG="$(current_daemon_tag)"
  fi
  if [[ "$MATRIX_BUILD_DAEMON" != "1" ]]; then
    CANDIDATE_ARGS+=(--skip-build)
  fi
  CANDIDATE_ARGS+=(
    --tag "$DAEMON_TAG"
    --force-shared-dev
    --sandbox-namespace "$MATRIX_SANDBOX_NAMESPACE"
    --keep-namespace
  )
  target_description="candidate daemon image tag $DAEMON_TAG in $MATRIX_SANDBOX_NAMESPACE"
fi
cordon_other_runtime_nodes

if [[ "$SMOKE_SKIP_KUBE" == "1" ]]; then
  target_description="$target_description, application and tailnet only"
fi
MATRIX_STEP=smoke
log "running fresh-node direct_udp + udp_relay + forced DERP + websocket smoke for $SMOKE_NAME against $target_description (smoke bound ${MATRIX_TIMEOUT_SECONDS}s; worst case with cleanup $(matrix_worst_case_seconds "${#MATRIX_CORDONED_NODES[@]}")s)"
# In the background so a signal reaches this shell at once and is forwarded.
EXPECTED_TAILNET_PATH_TRANSPORT=direct_udp \
  SMOKE_SKIP_KUBE="$SMOKE_SKIP_KUBE" \
  SMOKE_NAME="$SMOKE_NAME" \
  CANDIDATE_WORKER_LOOPS="$MATRIX_WORKER_LOOPS" \
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
  timeout --kill-after="$MATRIX_KILL_AFTER_SECONDS" "$MATRIX_TIMEOUT_SECONDS" \
    "$ROOT/scripts/runtime/dev/smoke-dev-candidate.sh" \
      "${CANDIDATE_ARGS[@]}" \
      -- --keep --skip-docker "${INITIAL_SMOKE_ARGS[@]}" \
  </dev/null >"$INITIAL_LOG" 2>&1 &
SMOKE_PID=$!
# timeout makes itself the leader of a new process group.
SMOKE_PGID="$SMOKE_PID"
smoke_rc=0
wait "$SMOKE_PID" || smoke_rc=$?
SMOKE_PID=""
# Nothing the smoke started may outlive it.
stop_running_smoke
read_initial_smoke_log

if [[ "$smoke_rc" != "0" ]]; then
  sed 's/[[:cntrl:]]//g' "$INITIAL_LOG" >&2 || true
  die "transport matrix failed: $(failure_summary "$smoke_rc")"
fi

MATRIX_STEP=evidence
[[ -n "$ENV_ID" ]] || die "failed to parse environment id from $INITIAL_LOG"
[[ -n "$INITIAL_EVIDENCE_DIR" && -d "$INITIAL_EVIDENCE_DIR" ]] || \
  die "failed to parse evidence directory from $INITIAL_LOG"
[[ -x "$MATRIX_CLI" ]] || die "cw binary from initial smoke is not executable: $MATRIX_CLI"

log "smoke passed for $ENV_ID; evidence $INITIAL_EVIDENCE_DIR"
[[ -s "$INITIAL_EVIDENCE_DIR/tailnet-doctor.json" ]] || \
  die "path=direct_udp: direct_udp doctor evidence is missing from $INITIAL_EVIDENCE_DIR"
[[ -s "$INITIAL_EVIDENCE_DIR/tailnet-doctor-peer-relay.json" ]] || \
  die "path=udp_relay: udp_relay doctor evidence is missing from $INITIAL_EVIDENCE_DIR"
grep -qx 'tailnet-ssh-ok' "$INITIAL_EVIDENCE_DIR/ssh-tailnet.out" || \
  die "path=direct_udp: direct_udp SSH evidence is missing from $INITIAL_EVIDENCE_DIR"
grep -qx 'tailnet-peer-relay-ssh-ok' "$INITIAL_EVIDENCE_DIR/ssh-tailnet-peer-relay.out" || \
  die "path=udp_relay: udp_relay SSH evidence is missing from $INITIAL_EVIDENCE_DIR"
grep -qx 'tailnet-derp-ssh-ok' "$INITIAL_EVIDENCE_DIR/ssh-tailnet-derp.out" || \
  die "path=derp_relay: DERP SSH evidence is missing from $INITIAL_EVIDENCE_DIR"
grep -qx 'websocket-ssh-ok' "$INITIAL_EVIDENCE_DIR/ssh-websocket.out" || \
  die "path=websocket: WebSocket SSH evidence is missing from $INITIAL_EVIDENCE_DIR"

MATRIX_STEP=cleanup
MATRIX_LEGS=passed
log "fresh-node transport matrix passed for $ENV_ID: direct_udp, udp_relay, derp_relay, websocket"
