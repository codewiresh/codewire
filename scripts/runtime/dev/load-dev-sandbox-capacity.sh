#!/usr/bin/env bash
# Sandbox capacity load (#3583, Program #2238).
#
# Ramps synthetic sandboxes of one shape onto the Kata runtime nodes in steps,
# runs a bounded CPU and memory workload in each, and records at every step
# what each node, storage and the platform report, until a stop condition
# holds. It then deletes everything the run created and proves it is gone.
#
# It runs against Dev by default, and against Production only with
# --confirm-production <the Production cluster> under Infra's kube-access for
# that cluster (owner, 2026-10-28, on #3583: "Ramp both nodes to refusal"). Either
# way it uses only that environment's dedicated smoke identity in its smoke
# organization (owner, 2026-10-28, on #3583: "Reuse smoke org, no new key"),
# and only touches environments it named itself. Kubernetes access is
# read-only (get, including get --raw through the API server's service proxy
# for LINSTOR and orchestration metrics). No credential is ever printed,
# logged or written to disk.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# Empty values take the Dev or Production default once the mode is known.
CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-}"
ORCHESTRATION_NAMESPACE="${ORCHESTRATION_NAMESPACE:-}"
ORCHESTRATION_METRICS="${ORCHESTRATION_METRICS:-codewire-orchestration:8084}"
# NAMESPACE/linstor-controller:3370; empty: found by name at start.
LINSTOR_SERVICE="${LINSTOR_SERVICE:-}"
PROM_URL="${PROM_URL:-}"
PROM_CLUSTER="${PROM_CLUSTER:-}"
LOAD_IMAGE="${LOAD_IMAGE:-workspace}"
LOAD_TTL="${LOAD_TTL:-4h}"
LOAD_TMP_PARENT="${LOAD_TMP_PARENT:-}"
CW_BIN="${CW_BIN:-}"

SHAPE="default"
STEPS="auto"
MAX_SANDBOXES=200
HOLD_SECONDS=180
READY_TIMEOUT_SECONDS=600
CLEANUP_TIMEOUT_SECONDS=900
# Every kubectl call ends within this bound, even when DNS or the credential
# plugin hangs (#3583: one unbounded call stalled a Prod run for 10 h).
KUBECTL_TIMEOUT_SECONDS="${KUBECTL_TIMEOUT_SECONDS:-60}"
# A step that runs longer than this stops the run, which then cleans up.
MAX_STEP_MINUTES=45
SSH_SAMPLE=10
WORKLOAD=synthetic
HOLD_SECONDS_SET=0
WORKLOAD_CPU=0.5
WORKLOAD_MEMORY=
# Pulled and run by the real workload; empty is the workspace image the repository
# pins. Every sandbox pulls this from one address, and public registries limit
# that: public ECR refused 2 of 10 pulls with a single sandbox.
DOCKER_IMAGE=
# Stop thresholds, checked on every node before every step; empty ones take
# the Dev or the more conservative Production default.
LATENCY_FACTOR=3
MAX_NODE_MEMORY_PCT=""
MAX_NODE_CPU_PCT=""
MAX_PSI_MEMORY_PCT=""
MAX_PSI_CPU_PCT=""
MAX_THIN_POOL_PCT=""
MODE=run
# The cluster named by --confirm-production; empty for Dev.
PRODUCTION=""
# The cluster names are deployment configuration, never written in this tree.
# An unset name refuses the mode that needs it.
readonly PRODUCTION_CLUSTER="${CODEWIRE_PROD_CLUSTER:-}"
readonly DEV_CLUSTER="${CODEWIRE_DEV_CLUSTER:-}"

# Every environment this tool creates is named NAME_PREFIX<run>-<n>; nothing
# else is ever deleted.
readonly NAME_PREFIX="cap-"
readonly MILESTONE="codewire_environment_create_milestone_seconds"

RUN_ID=""
RUN_DIR=""
# Background helpers stop once this process is gone, even after a SIGKILL.
readonly MAIN_PID=$$
CREATED=0
STOP_REASON=""
BASELINE_READY_MS=""
# The Kata runtime-candidate nodes, all measured: the scheduler may use any.
declare -a NODES=()
declare -a ENV_IDS=()
declare -A WAITER_PIDS=() SSH_PIDS=()

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/with-dev-smoke-auth.sh -- \
    scripts/runtime/dev/load-dev-sandbox-capacity.sh [options]

  Production, from the canonical Infra checkout, in an approved window:
  scripts/kube-access "$CODEWIRE_PROD_CLUSTER" -- \
    CODEWIRE/scripts/runtime/prod/with-prod-smoke-auth.sh -- \
    CODEWIRE/scripts/runtime/dev/load-dev-sandbox-capacity.sh \
    --confirm-production "$CODEWIRE_PROD_CLUSTER" [options]

Ramps sandboxes of one shape onto the Kata runtime nodes, step by step, each
running a bounded CPU and memory workload, and records per step and node: CPU,
memory and pressure (PSI); host memory per sandbox, and that less the
workload's touched memory (the Kata VM, DinD and guest overhead); requested
CPU and memory against allocatable;
pod count; LINSTOR thin-pool use and overcommit; create-to-ready and
create-to-first-SSH p50/p95 (client side, and server side from the
codewire_environment_create_milestone_seconds histogram); and the warm-pool
hit rate.

Before every step it stops when the previous step had a failed or late
create, when create-to-ready p95 exceeds --latency-factor times the first
step's p50, when any node's memory, CPU, memory PSI, CPU PSI or thin-pool
use crosses its threshold, when the scheduler refused a sandbox, or when a
node condition degrades. On every exit it deletes every environment it created and
proves that their environments, claims, Sandboxes, Pods, PVCs, PVs and
LINSTOR resources are gone. A run that died without cleaning up is cleaned up
by the next start.

Modes:
  (default)        run the ramp
  --dry-run        preflight only: leftovers, node state, predicted limits
  --cleanup-only   clean up what earlier runs left, prove it, and exit

Options:
  --shape S              every shape has an 80 GiB disk:
                         small (1 vCPU/4 GiB), default (2 vCPU/8 GiB),
                         large (4 vCPU/16 GiB), xlarge (8 vCPU/32 GiB),
                         memory (1 vCPU/32 GiB), max (32 vCPU/64 GiB, the
                         default organization quota), cpu (16 vCPU/8 GiB, which
                         runs out of CPU requests first even on a node short of
                         memory)
  --steps LIST           cumulative sandbox counts, or auto (the default):
                         25, 50, 75 and 100% of the predicted limit, then two past it
  --max-sandboxes N      hard cap on the total created (default 200)
  --hold-seconds N       time under load before each measurement (default 180,
                         or 600 for the real workload)
  --workload W           synthetic (the default), or real: what fills every
                         container at once, as a real sandbox can (#3718). The
                         workspace holds memory, writes to disk and compiles a
                         Go app; Docker pulls --docker-image and runs it,
                         writing to disk past its memory limit. A part that
                         never worked stops the run: its load wasn't there
  --docker-image IMAGE   what the real workload pulls and runs
                         (default the pinned workspace image, about 2 GiB)
  --workload-cpu F       synthetic: fraction of each sandbox's vCPUs kept busy (default 0.5)
  --workload-memory F    fraction of each sandbox's memory allocated and touched
                         (default 0.5, or 0.95 for real)
  --ssh-sample N         new sandboxes per step timed to first SSH (default 10)
  --max-step-minutes N   stop and clean up when one step runs longer (default 45)
  --latency-factor F     stop when ready p95 > F x the first step's p50 (default 3)
  --max-node-memory-pct N, --max-node-cpu-pct N,
  --max-psi-memory-pct N, --max-psi-cpu-pct N,
  --max-thin-pool-pct N  stop thresholds, per node (defaults 90, 90, 10, 50, 80;
                         in Production 85, 80, 5, 30, 70)
  --confirm-production C Production mode; C must be CODEWIRE_PROD_CLUSTER, the
                         server https://codewire.sh, and the kube context the
                         one scripts/kube-access sets for that cluster
  --cw-bin PATH          prebuilt cw binary (default: build one)
  -h, --help             show this help

Environment:
  CODEWIRE_DEV_SMOKE_API_KEY   Dev: required (set by with-dev-smoke-auth.sh)
  CODEWIRE_PROD_SMOKE_API_KEY  Production: required (set by with-prod-smoke-auth.sh)
  CODEWIRE_DEV_CLUSTER         required: the Dev cluster's name
  CODEWIRE_PROD_CLUSTER        Production: required, the Production cluster's name
  KUBECONFIG                   Dev: the one kube-access renders for the Dev cluster,
                               or by default ~/src/infra/kubeconfig-oidc.yaml;
                               Production: the one kube-access renders
  PROM_URL                     required: the System Prometheus that scrapes the cluster

Results go to .tmp/sandbox-capacity/<run>/ (Production: .tmp/sandbox-capacity-prod/<run>/):
steps.jsonl (one record per step) and summary.md. Start-up cleanup only
touches runs of the same server.
USAGE
}

log() { printf '[sandbox-capacity] %s\n' "$*" >&2; }
die() { printf '[sandbox-capacity] ERROR: %s\n' "$*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
now_ms() { date +%s%3N; }

# A sleep a signal interrupts at once: bash runs a trap only after a
# foreground command returns, but `wait` returns on the signal.
pause() { sleep "$1" & wait "$!"; }

# A read that fails to reach the server (a connection error, or the time
# bound) is retried once after 3 s, so one dropped packet does not end a run.
# An answer from the server, such as Forbidden or NotFound, is never retried;
# only get is ever sent. Output is held until the call settles, so a retry
# never follows partial output.
kubectl_ro() {
  case "$1" in
    get) ;;
    *) die "read-only kubectl refused verb $1" ;;
  esac
  local attempt rc out err
  out="$(mktemp "${TMPDIR:-/tmp}/cw-capacity-kubectl.XXXXXX")"
  err="$(mktemp "${TMPDIR:-/tmp}/cw-capacity-kubectl.XXXXXX")"
  for attempt in 1 2; do
    rc=0
    timeout -k 5 "$KUBECTL_TIMEOUT_SECONDS" \
      kubectl --request-timeout="${KUBECTL_TIMEOUT_SECONDS}s" --context "$KUBE_CONTEXT" "$@" >"$out" 2>"$err" || rc=$?
    ((rc != 0 && attempt == 1)) || break
    ! grep -q 'Error from server' "$err" || break
    if ((rc == 124 || rc == 137)) ||
      grep -qiE 'Unable to connect to the server|i/o timeout|connection refused|connection reset|TLS handshake timeout|no route to host' "$err"; then
      if ((rc == 124 || rc == 137)); then
        log "kubectl get retried once after no answer within ${KUBECTL_TIMEOUT_SECONDS} s"
      else
        log "kubectl get retried once after: $(head -n1 "$err")"
      fi
      [[ -z "${RUN_DIR:-}" || ! -d "$RUN_DIR" ]] || printf '%s\n' "$rc" >>"$RUN_DIR/kubectl-retries"
      pause 3
      continue
    fi
    break
  done
  cat "$out"
  cat "$err" >&2
  rm -f -- "$out" "$err"
  return "$rc"
}

# Every environment this tool touches is a cloud one on CODEWIRE_SERVER_URL.
cw() { timeout 120 "$CW_BIN" --cloud --server "$CODEWIRE_SERVER_URL" "$@"; }

# One instant PromQL value, empty when the series is absent.
prom() {
  curl -fsG --max-time 20 "$PROM_URL/api/v1/query" --data-urlencode "query=$1" 2>/dev/null |
    jq -r '.data.result[0].value[1] // empty' 2>/dev/null || true
}

# Nearest-rank percentile of the numbers on stdin.
percentile() {
  sort -n | awk -v p="$1" '{a[NR]=$1} END {if (NR == 0) {print ""; exit} i = int((p * NR + 99) / 100); if (i < 1) i = 1; print a[i]}'
}

is_number() { [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]; }

# Exit 0 when A > B (decimals allowed); an empty A never exceeds.
exceeds() { [[ -n "$1" ]] && awk -v a="$1" -v b="$2" 'BEGIN {exit !(a > b)}'; }

while (($# > 0)); do
  case "$1" in
    --shape) [[ $# -ge 2 ]] || die "--shape requires a value"; SHAPE="$2"; shift 2 ;;
    --steps) [[ $# -ge 2 ]] || die "--steps requires a value"; STEPS="$2"; shift 2 ;;
    --max-sandboxes) [[ $# -ge 2 ]] || die "--max-sandboxes requires a value"; MAX_SANDBOXES="$2"; shift 2 ;;
    --hold-seconds) HOLD_SECONDS_SET=1; [[ $# -ge 2 ]] || die "--hold-seconds requires a value"; HOLD_SECONDS="$2"; shift 2 ;;
    --workload) [[ $# -ge 2 ]] || die "--workload requires a value"; WORKLOAD="$2"; shift 2 ;;
    --docker-image) [[ $# -ge 2 ]] || die "--docker-image requires a value"; DOCKER_IMAGE="$2"; shift 2 ;;
    --workload-cpu) [[ $# -ge 2 ]] || die "--workload-cpu requires a value"; WORKLOAD_CPU="$2"; shift 2 ;;
    --workload-memory) [[ $# -ge 2 ]] || die "--workload-memory requires a value"; WORKLOAD_MEMORY="$2"; shift 2 ;;
    --ssh-sample) [[ $# -ge 2 ]] || die "--ssh-sample requires a value"; SSH_SAMPLE="$2"; shift 2 ;;
    --max-step-minutes) [[ $# -ge 2 ]] || die "$1 requires a value"; MAX_STEP_MINUTES="$2"; shift 2 ;;
    --latency-factor) [[ $# -ge 2 ]] || die "--latency-factor requires a value"; LATENCY_FACTOR="$2"; shift 2 ;;
    --max-node-memory-pct) [[ $# -ge 2 ]] || die "$1 requires a value"; MAX_NODE_MEMORY_PCT="$2"; shift 2 ;;
    --max-node-cpu-pct) [[ $# -ge 2 ]] || die "$1 requires a value"; MAX_NODE_CPU_PCT="$2"; shift 2 ;;
    --max-psi-memory-pct) [[ $# -ge 2 ]] || die "$1 requires a value"; MAX_PSI_MEMORY_PCT="$2"; shift 2 ;;
    --max-psi-cpu-pct) [[ $# -ge 2 ]] || die "$1 requires a value"; MAX_PSI_CPU_PCT="$2"; shift 2 ;;
    --max-thin-pool-pct) [[ $# -ge 2 ]] || die "$1 requires a value"; MAX_THIN_POOL_PCT="$2"; shift 2 ;;
    --confirm-production) [[ $# -ge 2 ]] || die "$1 requires a value"; PRODUCTION="$2"; shift 2 ;;
    --cw-bin) [[ $# -ge 2 ]] || die "--cw-bin requires a value"; CW_BIN="$2"; shift 2 ;;
    --dry-run) MODE=dry-run; shift ;;
    --cleanup-only) MODE=cleanup-only; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
[[ -z "$DEV_CLUSTER" || "$DEV_CLUSTER" != "$PRODUCTION_CLUSTER" ]] ||
  die "CODEWIRE_DEV_CLUSTER and CODEWIRE_PROD_CLUSTER name the same cluster"
if [[ -z "$PRODUCTION" ]]; then
  [[ -n "$DEV_CLUSTER" ]] || die "CODEWIRE_DEV_CLUSTER is required: the Dev cluster's name"
  : "${CODEWIRE_SERVER_URL:=https://codewire-dev.sh}" "${KUBE_CONTEXT:=codewire-dev}"
  : "${SANDBOX_NAMESPACE:=dev-sandboxes}" "${ORCHESTRATION_NAMESPACE:=dev}" "${PROM_CLUSTER:=$DEV_CLUSTER}"
  : "${MAX_NODE_MEMORY_PCT:=90}" "${MAX_NODE_CPU_PCT:=90}" "${MAX_PSI_MEMORY_PCT:=10}"
  : "${MAX_PSI_CPU_PCT:=50}" "${MAX_THIN_POOL_PCT:=80}" "${LOAD_TMP_PARENT:=$ROOT/.tmp/sandbox-capacity}"
  [[ "$CODEWIRE_SERVER_URL" == "https://codewire-dev.sh" ]] ||
    die "this load runs only against Dev unless --confirm-production names the Production cluster"
  # kube-access exports the context with a temporary kubeconfig and marks it.
  [[ "$KUBE_CONTEXT" == "codewire-dev" ||
    ("$KUBE_CONTEXT" == "$DEV_CLUSTER" && -n "${KUBECONFIG:-}" && "${INFRA_TRANSIENT_KUBE_AUTH:-}" == 1) ]] ||
    die "this load runs only against the codewire-dev context, or through scripts/kube-access $DEV_CLUSTER, in Dev mode"
  [[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]] ||
    die "CODEWIRE_DEV_SMOKE_API_KEY is required; run through scripts/runtime/dev/with-dev-smoke-auth.sh"
  SMOKE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"
else
  [[ -n "$PRODUCTION_CLUSTER" ]] || die "CODEWIRE_PROD_CLUSTER is required: the Production cluster's name"
  [[ "$PRODUCTION" == "$PRODUCTION_CLUSTER" ]] || die "--confirm-production must be $PRODUCTION_CLUSTER"
  : "${CODEWIRE_SERVER_URL:=https://codewire.sh}"
  : "${SANDBOX_NAMESPACE:=prod-sandboxes}" "${ORCHESTRATION_NAMESPACE:=prod}" "${PROM_CLUSTER:=$PRODUCTION_CLUSTER}"
  : "${MAX_NODE_MEMORY_PCT:=85}" "${MAX_NODE_CPU_PCT:=80}" "${MAX_PSI_MEMORY_PCT:=5}"
  : "${MAX_PSI_CPU_PCT:=30}" "${MAX_THIN_POOL_PCT:=70}" "${LOAD_TMP_PARENT:=$ROOT/.tmp/sandbox-capacity-prod}"
  [[ "$CODEWIRE_SERVER_URL" == "https://codewire.sh" ]] || die "Production mode runs only against https://codewire.sh"
  # kube-access exports the context with a temporary kubeconfig and marks it.
  [[ "$KUBE_CONTEXT" == "$PRODUCTION_CLUSTER" && -n "${KUBECONFIG:-}" && "${INFRA_TRANSIENT_KUBE_AUTH:-}" == 1 ]] ||
    die "Production mode runs only through scripts/kube-access $PRODUCTION_CLUSTER"
  [[ -n "${CODEWIRE_PROD_SMOKE_API_KEY:-}" ]] ||
    die "CODEWIRE_PROD_SMOKE_API_KEY is required; run through scripts/runtime/prod/with-prod-smoke-auth.sh"
  SMOKE_API_KEY="$CODEWIRE_PROD_SMOKE_API_KEY"
fi
# max is the default organization quota (32 vCPU / 64 GiB), the largest one
# environment an organization without its own quota can have; the product has
# no per-environment limit beyond the quota.
case "$SHAPE" in
  small) CPU_M=1000; MEMORY_MIB=4096 ;;
  default) CPU_M=2000; MEMORY_MIB=8192 ;;
  large) CPU_M=4000; MEMORY_MIB=16384 ;;
  xlarge) CPU_M=8000; MEMORY_MIB=32768 ;;
  memory) CPU_M=1000; MEMORY_MIB=32768 ;;
  max) CPU_M=32000; MEMORY_MIB=65536 ;;
  cpu) CPU_M=16000; MEMORY_MIB=8192 ;;
  *) die "--shape must be small, default, large, xlarge, memory, max or cpu" ;;
esac
DISK_GIB=80
if ! [[ "$MAX_SANDBOXES" =~ ^[1-9][0-9]*$ ]] || (( MAX_SANDBOXES > 500 )); then
  die "--max-sandboxes must be 1-500"
fi
STEP_COUNTS=()
if [[ "$STEPS" != auto ]]; then
  [[ "$STEPS" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || die "--steps must be auto or a comma-separated list of positive counts"
  IFS=, read -r -a STEP_COUNTS <<<"$STEPS"
  previous=0
  for count in "${STEP_COUNTS[@]}"; do
    (( count > previous )) || die "--steps must increase"
    (( count <= MAX_SANDBOXES )) || die "--steps exceeds --max-sandboxes ($MAX_SANDBOXES)"
    previous="$count"
  done
fi
[[ "$MAX_STEP_MINUTES" =~ ^[1-9][0-9]*$ ]] || die "--max-step-minutes must be a positive integer"
[[ "$KUBECTL_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || die "KUBECTL_TIMEOUT_SECONDS must be a positive integer"
for value in HOLD_SECONDS SSH_SAMPLE MAX_NODE_MEMORY_PCT MAX_NODE_CPU_PCT MAX_PSI_MEMORY_PCT \
  MAX_PSI_CPU_PCT MAX_THIN_POOL_PCT; do
  [[ "${!value}" =~ ^[0-9]+$ ]] || die "$value must be a non-negative integer"
done
for value in MAX_NODE_MEMORY_PCT MAX_NODE_CPU_PCT MAX_PSI_MEMORY_PCT MAX_PSI_CPU_PCT MAX_THIN_POOL_PCT; do
  (( ${!value} >= 1 && ${!value} <= 100 )) || die "$value must be 1-100"
done
case "$WORKLOAD" in
  synthetic) : "${WORKLOAD_MEMORY:=0.5}"; MAX_WORKLOAD_MEMORY=0.9 ;;
  real)
    : "${WORKLOAD_MEMORY:=0.95}"
    MAX_WORKLOAD_MEMORY=0.95
    # A cold pull and six 1 GiB writes, on a busy node, must fit in a hold.
    if [[ "$HOLD_SECONDS_SET" == 0 ]]; then HOLD_SECONDS=600; fi
    ;;
  *) die "--workload must be synthetic or real" ;;
esac
if [[ -z "$DOCKER_IMAGE" ]]; then
  DOCKER_IMAGE="$(sed -n 's/^pub const PUBLIC_IMAGE: &str = "\(.*\)";$/\1/p' "$ROOT/crates/codewire-workspace-image/src/pin.rs")"
fi
[[ "$DOCKER_IMAGE" =~ ^[a-zA-Z0-9][a-zA-Z0-9./:@_-]*$ ]] || die "--docker-image is not an image reference"
if ! is_number "$WORKLOAD_CPU" || ! awk -v v="$WORKLOAD_CPU" 'BEGIN {exit !(v >= 0 && v <= 0.9)}'; then
  die "WORKLOAD_CPU must be between 0 and 0.9"
fi
if ! is_number "$WORKLOAD_MEMORY" || ! awk -v v="$WORKLOAD_MEMORY" -v m="$MAX_WORKLOAD_MEMORY" 'BEGIN {exit !(v >= 0 && v <= m)}'; then
  die "WORKLOAD_MEMORY must be between 0 and $MAX_WORKLOAD_MEMORY"
fi
if ! is_number "$LATENCY_FACTOR" || ! awk -v v="$LATENCY_FACTOR" 'BEGIN {exit !(v >= 1)}'; then
  die "--latency-factor must be at least 1"
fi
[[ "$PROM_URL" =~ ^https?://[^[:space:]]+$ ]] || die "PROM_URL must name the System Prometheus that scrapes the cluster"
for command in jq kubectl curl timeout awk date sort ssh base64 pkill; do require_cmd "$command"; done
if [[ -z "$PRODUCTION" && -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
  export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
fi

umask 077
mkdir -p "$LOAD_TMP_PARENT"
RUN_ID="$(date -u +%Y%m%d%H%M%S)"
RUN_DIR="$LOAD_TMP_PARENT/$RUN_ID"
mkdir -p "$RUN_DIR"
: >"$RUN_DIR/envs.tsv"
# Each run names its server; cleanup at start skips runs of another one.
printf '%s\n' "$CODEWIRE_SERVER_URL" >"$RUN_DIR/server"
export CODEWIRE_API_KEY="$SMOKE_API_KEY"
unset SMOKE_API_KEY
export CW_CONFIG_DIR="$RUN_DIR/cw-config"
mkdir -p "$CW_CONFIG_DIR"

if [[ -z "$CW_BIN" ]]; then
  require_cmd cargo
  log "building cw"
  (cd "$ROOT" && timeout 900 cargo build --locked --profile ci -p codewire-cli-bin --bin cw) \
    >"$RUN_DIR/build.log" 2>&1 || die "cw build failed (see $RUN_DIR/build.log)"
  CW_BIN="$ROOT/target/ci/cw"
fi
[[ -x "$CW_BIN" ]] || die "cw binary is not executable: $CW_BIN"

# ------------------------------------------------------------ inventory

# Live environments of the smoke organization as "id<TAB>name" rows; fails
# when the list cannot be read, so an unreadable list never looks empty.
list_envs() {
  local listing
  listing="$(cw ls --output json 2>/dev/null)" || return 1
  jq -r '(if type == "array" then . else (.environments // []) end)[]
      | select((.state // "") != "destroyed") | [.id, (.name // "")] | @tsv' <<<"$listing"
}

# Sandbox, Pod, PVC and PV names behind one environment, as one JSON object.
env_objects() { # ID
  local id="$1" sandbox pod pvcs pv volumes="[]"
  sandbox="$(kubectl_ro get sandboxclaim -n "$SANDBOX_NAMESPACE" "sandbox-$id" -o json 2>/dev/null |
    jq -r '.status.sandbox.name // ""' || true)"
  pod=""
  if [[ -n "$sandbox" ]]; then
    pod="$(kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" "$sandbox" -o json 2>/dev/null |
      jq -r --arg s "$sandbox" '.metadata.annotations["agents.x-k8s.io/pod-name"] // $s' || true)"
  fi
  if [[ -n "$pod" ]]; then
    pvcs="$(kubectl_ro get pod -n "$SANDBOX_NAMESPACE" "$pod" -o json 2>/dev/null |
      jq -r '.spec.volumes[]? | .persistentVolumeClaim.claimName // empty' || true)"
    local pvc
    while IFS= read -r pvc; do
      [[ -n "$pvc" ]] || continue
      pv="$(kubectl_ro get pvc -n "$SANDBOX_NAMESPACE" "$pvc" -o json 2>/dev/null | jq -r '.spec.volumeName // ""' || true)"
      volumes="$(jq -c --arg pvc "$pvc" --arg pv "$pv" '. + [{pvc: $pvc, pv: $pv}]' <<<"$volumes")"
    done <<<"$pvcs"
  fi
  jq -nc --arg id "$id" --arg claim "sandbox-$id" --arg sandbox "$sandbox" --arg pod "$pod" \
    --argjson volumes "$volumes" '{id: $id, claim: $claim, sandbox: $sandbox, pod: $pod, volumes: $volumes}'
}

linstor_get() { # PATH
  local namespace="${LINSTOR_SERVICE%%/*}" service="${LINSTOR_SERVICE#*/}"
  kubectl_ro get --raw "/api/v1/namespaces/$namespace/services/$service/proxy/$1"
}

# ------------------------------------------------------------ cleanup

remove_env_ids() { # IDS...
  local id attempt error
  for id in "$@"; do
    for attempt in 1 2 3; do
      if error="$(cw rm --yes "$id" 2>&1 >/dev/null)"; then break; fi
      log "cleanup: removing $id failed, attempt $attempt: ${error:0:200}"
      cw info "$id" --output json >/dev/null 2>&1 || break
      sleep 2
    done
  done
}

# Exit 0 once nothing recorded in OBJECTS (jsonl) exists any more.
objects_gone() { # OBJECTS_FILE
  local file="$1" record id claim sandbox pod pvc pv left=0 resources
  resources="$(linstor_get v1/resource-definitions 2>/dev/null | jq -r '.[].name' 2>/dev/null || echo '?')"
  while IFS= read -r record; do
    [[ -n "$record" ]] || continue
    id="$(jq -r .id <<<"$record")"
    claim="$(jq -r .claim <<<"$record")"
    sandbox="$(jq -r .sandbox <<<"$record")"
    pod="$(jq -r .pod <<<"$record")"
    if cw info "$id" --output json 2>/dev/null | jq -e '(.state // "") != "destroyed"' >/dev/null 2>&1; then
      log "cleanup: environment $id still exists"; left=1
    fi
    kubectl_ro get sandboxclaim -n "$SANDBOX_NAMESPACE" "$claim" >/dev/null 2>&1 && { log "cleanup: claim $claim remains"; left=1; }
    [[ -z "$sandbox" ]] || ! kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" "$sandbox" >/dev/null 2>&1 ||
      { log "cleanup: Sandbox $sandbox remains"; left=1; }
    [[ -z "$pod" ]] || ! kubectl_ro get pod -n "$SANDBOX_NAMESPACE" "$pod" >/dev/null 2>&1 ||
      { log "cleanup: Pod $pod remains"; left=1; }
    while IFS=$'\t' read -r pvc pv; do
      [[ -n "$pvc" ]] || continue
      kubectl_ro get pvc -n "$SANDBOX_NAMESPACE" "$pvc" >/dev/null 2>&1 && { log "cleanup: PVC $pvc remains"; left=1; }
      if [[ -n "$pv" ]]; then
        kubectl_ro get pv "$pv" >/dev/null 2>&1 && { log "cleanup: PV $pv remains"; left=1; }
        if [[ "$resources" == '?' ]]; then
          log "cleanup: LINSTOR resource definitions unreadable"; left=1
        elif grep -qxF "$pv" <<<"$resources"; then
          log "cleanup: LINSTOR resource $pv remains"; left=1
        fi
      fi
    done < <(jq -r '.volumes[] | [.pvc, .pv] | @tsv' <<<"$record")
  done <"$file"
  return "$left"
}

# Delete one run's environments, then wait until every recorded object is
# gone. Marks the run cleaned only on proof.
clean_run_dir() { # DIR
  local dir="$1" ids=() deadline
  [[ -f "$dir/envs.tsv" ]] || return 0
  mapfile -t ids < <(cut -f1 "$dir/envs.tsv" | sort -u)
  # Objects of environments recorded before their Pod existed.
  local id
  touch "$dir/objects.jsonl"
  for id in "${ids[@]}"; do
    grep -qF "\"id\":\"$id\"" "$dir/objects.jsonl" || env_objects "$id" >>"$dir/objects.jsonl"
  done
  ((${#ids[@]} == 0)) || { log "deleting ${#ids[@]} environments of run $(basename "$dir")"; remove_env_ids "${ids[@]}"; }
  deadline=$(( $(date +%s) + CLEANUP_TIMEOUT_SECONDS ))
  until objects_gone "$dir/objects.jsonl" 2>"$dir/cleanup.log"; do
    if (( $(date +%s) >= deadline )); then
      cat "$dir/cleanup.log" >&2
      return 1
    fi
    pause 10
  done
  date -u +%FT%TZ >"$dir/cleaned"
  log "cleanup proved for run $(basename "$dir"): ${#ids[@]} environments and their claims, Sandboxes, Pods, PVCs, PVs and LINSTOR resources are gone"
}

# Earlier runs that never proved cleanup, then any environment carrying the
# tool's prefix that no run recorded.
clean_leftovers() {
  local dir orphans=() envs run_server
  for dir in "$LOAD_TMP_PARENT"/*/; do
    dir="${dir%/}"
    [[ "$dir" != "$RUN_DIR" && -f "$dir/envs.tsv" && ! -f "$dir/cleaned" ]] || continue
    # Runs from before Production mode carry no server file and were Dev's.
    run_server="$(cat "$dir/server" 2>/dev/null || echo https://codewire-dev.sh)"
    if [[ "$run_server" != "$CODEWIRE_SERVER_URL" ]]; then
      log "run $(basename "$dir") belongs to $run_server; it is cleaned only from there"
      continue
    fi
    log "run $(basename "$dir") did not prove its cleanup; cleaning it now"
    clean_run_dir "$dir" || die "could not prove cleanup of run $(basename "$dir")"
  done
  envs="$(list_envs)" || die "cannot list the smoke organization's environments"
  mapfile -t orphans < <(awk -F'\t' -v p="$NAME_PREFIX" 'index($2, p) == 1 {print $1}' <<<"$envs")
  if ((${#orphans[@]} > 0)); then
    log "found ${#orphans[@]} unrecorded $NAME_PREFIX* environments; cleaning them"
    local orphan_dir="$LOAD_TMP_PARENT/orphans-$RUN_ID"
    mkdir -p "$orphan_dir"
    printf '%s\n' "$CODEWIRE_SERVER_URL" >"$orphan_dir/server"
    printf '%s\t-\t-\n' "${orphans[@]}" >"$orphan_dir/envs.tsv"
    clean_run_dir "$orphan_dir" || die "could not prove cleanup of unrecorded environments"
  fi
}

on_exit() {
  local status=$?
  trap - EXIT
  local pid
  stop_watchdog
  for pid in "${WAITER_PIDS[@]}" "${SSH_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ -n "$RUN_DIR" && -s "$RUN_DIR/watchdog" ]]; then
    STOP_REASON="$(cat "$RUN_DIR/watchdog")"
    log "stop: $STOP_REASON"
    write_summary || true
  fi
  if [[ -n "$RUN_DIR" && "$MODE" == run ]]; then
    if ! clean_run_dir "$RUN_DIR"; then
      log "cleanup NOT proved; the next start retries it (run $RUN_ID)"
      status=1
    fi
  fi
  exit "$status"
}

# One step's wall-clock limit: a background timer records why and sends
# TERM, whose trap exits through on_exit, which cleans up. kubectl and cw
# calls are bounded, so the trap runs within KUBECTL_TIMEOUT_SECONDS.
WATCHDOG_PID=""
start_watchdog() { # STEP
  stop_watchdog
  ( sleep $((MAX_STEP_MINUTES * 60)) &&
      printf 'step %s exceeded its %s-minute limit\n' "$1" "$MAX_STEP_MINUTES" >"$RUN_DIR/watchdog" &&
      kill -TERM "$MAIN_PID" ) &
  WATCHDOG_PID=$!
}
stop_watchdog() {
  if [[ -n "$WATCHDOG_PID" ]]; then
    pkill -P "$WATCHDOG_PID" 2>/dev/null || true
    kill "$WATCHDOG_PID" 2>/dev/null || true
  fi
  WATCHDOG_PID=""
}

# ------------------------------------------------------------ node state

node_json() { kubectl_ro get node "$1" -o json; }

node_instance() { # NODE
  node_json "$1" | jq -r '.status.addresses[] | select(.type == "InternalIP") | .address' | head -n1
}

# "ok" or the node's degraded conditions.
node_condition() { # NODE
  node_json "$1" | jq -r '
    [.status.conditions[]
      | select((.type == "Ready" and .status != "True")
          or (.type != "Ready" and .status == "True"))
      | "\(.type)=\(.status)"] | if length == 0 then "ok" else join(",") end'
}

# Requested CPU (millicores) and memory (MiB) on the node, Pod overhead
# included, against allocatable, plus the pod count.
node_requests() { # NODE
  jq -n --slurpfile nodes <(node_json "$1") --slurpfile podlists <(kubectl_ro get pods -A \
    --field-selector "spec.nodeName=$1,status.phase!=Succeeded,status.phase!=Failed" -o json) '
    $nodes[0] as $node | $podlists[0] as $pods |
    def cpu: if . == null then 0 elif endswith("m") then (.[:-1] | tonumber) else (tonumber * 1000) end;
    def mib:
      if . == null then 0
      elif endswith("Ki") then (.[:-2] | tonumber / 1024)
      elif endswith("Mi") then (.[:-2] | tonumber)
      elif endswith("Gi") then (.[:-2] | tonumber * 1024)
      elif endswith("Ti") then (.[:-2] | tonumber * 1048576)
      elif endswith("k") then (.[:-1] | tonumber * 1000 / 1048576)
      elif endswith("M") then (.[:-1] | tonumber * 1000000 / 1048576)
      elif endswith("G") then (.[:-1] | tonumber * 1000000000 / 1048576)
      else (tonumber / 1048576) end;
    def pod_cpu: ([.spec.containers[].resources.requests.cpu | cpu] | add) + (.spec.overhead.cpu | cpu);
    def pod_mib: ([.spec.containers[].resources.requests.memory | mib] | add) + (.spec.overhead.memory | mib);
    {
      allocatable_cpu_m: ($node.status.allocatable.cpu | cpu),
      allocatable_memory_mib: ($node.status.allocatable.memory | mib | floor),
      allocatable_pods: ($node.status.allocatable.pods | tonumber),
      requested_cpu_m: ([$pods.items[] | pod_cpu] | add // 0),
      requested_memory_mib: ([$pods.items[] | pod_mib] | add // 0 | floor),
      pods: ($pods.items | length)
    }'
}

# What one sandbox of this shape reserves: the workspace's memory and its vCPUs
# over the CPU sharing ratio (#3635), DinD's request (the same for every shape),
# both read from the live pool members, and the commodity RuntimeClass's fixed
# Pod overhead. A shape without a pool shares at the same ratio. Members that
# disagree are a rotation in progress, whose outgoing members would also count
# against the prediction, so it refuses until the rotation has finished. The
# fork labels an unclaimed member's Pod and adoption removes the label; an adopted
# Pod keeps its cw-pool- name, so the name alone would count a user's sandbox.
sandbox_request() {
  local members kata
  members="$(kubectl_ro get pods -n "$SANDBOX_NAMESPACE" -o json 2>/dev/null | jq -c '
    [.items[] | select(.metadata.labels["agents.x-k8s.io/warm-pool-sandbox"] != null and .metadata.deletionTimestamp == null)
      | .spec.containers]' || true)"
  kata="$(kubectl_ro get runtimeclass commodity -o json 2>/dev/null | jq -c '.overhead.podFixed // empty' || true)"
  jq -nc --argjson cpu "$CPU_M" --argjson mem "$MEMORY_MIB" --argjson members "${members:-[]}" --argjson kata "${kata:-null}" '
    def cpu: if . == null then 0 elif endswith("m") then (.[:-1] | tonumber) else (tonumber * 1000) end;
    def mib: if . == null then 0 elif endswith("Mi") then (.[:-2] | tonumber)
      elif endswith("Gi") then (.[:-2] | tonumber * 1024) else (tonumber / 1048576) end;
    def resources($name): map(select(.name == $name) | .resources)[0];
    def ratio: resources("workspace") | [.requests.cpu, .limits.cpu] | map(cpu)
      | if .[0] > 0 and .[1] > 0 then (.[1] / .[0] | round | if . < 1 then 1 else . end) else 1 end;
    ($members | map(ratio) | unique) as $ratios
    | if ($ratios | length) > 1 then
        error("warm pool members run different CPU sharing ratios \($ratios); wait for the rotation to finish")
      else . end
    | ($ratios[0] // 1) as $ratio
    | ($members[0] // [] | resources("dind").requests) as $dind
    | {workspace: {cpu_m: ($cpu / $ratio | ceil), memory_mib: $mem, cpu_sharing_ratio: $ratio},
     dind: (if $dind == null then {cpu_m: 500, memory_mib: 1024, source: "template default"}
       else {cpu_m: ($dind.cpu | cpu), memory_mib: ($dind.memory | mib), source: "pool member"} end),
     kata: (if $kata == null then {cpu_m: 250, memory_mib: 130, source: "template default"}
       else {cpu_m: ($kata.cpu | cpu), memory_mib: ($kata.memory | mib), source: "RuntimeClass commodity"} end)}
    | . + {cpu_m: (.workspace.cpu_m + .dind.cpu_m + .kata.cpu_m),
           memory_mib: (.workspace.memory_mib + .dind.memory_mib + .kata.memory_mib)}'
}

# The node's LVM thin pool from a storage-pools view.
thin_pool() { # NODE POOLS_JSON
  jq -n --arg node "$1" --argjson pools "$2" '
    ([$pools[] | select(.node_name == $node and .provider_kind == "LVM_THIN")][0]) as $pool
    | if $pool == null then {thin_pool: null} else
      {
        thin_pool: $pool.storage_pool_name,
        thin_total_gib: ($pool.total_capacity / 1048576),
        thin_used_gib: (($pool.total_capacity - $pool.free_capacity) / 1048576),
        thin_used_pct: (100 * ($pool.total_capacity - $pool.free_capacity) / $pool.total_capacity)
      } end'
}

# Combine one JSON record per node (stdin) into the cluster view the stop
# checks read: sums for capacity and requests, the worst node for every
# percentage and pressure, any degraded condition, and the provisioned volume
# size against the nodes' thin pools. The per-node records stay in .nodes.
aggregate_nodes() { # DEFINITIONS_JSON
  jq -s --argjson definitions "$1" '
    def sum($k): [.[][$k] | select(. != null)] | if length == 0 then null else add end;
    def worst($k): [.[][$k] | select(. != null)] | if length == 0 then null else max end;
    def all_sum($k): if any(.[]; .[$k] == null) then null else sum($k) end;
    ([$definitions[] | .volume_definitions[]?.size_kib] | add // 0) as $provisioned_kib
    | {
        node_condition: ([.[] | select(.node_condition != "ok") | "\(.node): \(.node_condition)"]
          | if length == 0 then "ok" else join("; ") end),
        allocatable_cpu_m: sum("allocatable_cpu_m"), allocatable_memory_mib: sum("allocatable_memory_mib"),
        allocatable_pods: sum("allocatable_pods"), requested_cpu_m: sum("requested_cpu_m"),
        requested_memory_mib: sum("requested_memory_mib"), pods: sum("pods"),
        node_cpu_pct: worst("node_cpu_pct"), node_memory_pct: worst("node_memory_pct"),
        node_memory_total_gib: all_sum("node_memory_total_gib"), node_memory_used_gib: all_sum("node_memory_used_gib"),
        psi_cpu_some_pct: worst("psi_cpu_some_pct"), psi_memory_some_pct: worst("psi_memory_some_pct"),
        psi_memory_full_pct: worst("psi_memory_full_pct"), psi_io_some_pct: worst("psi_io_some_pct"),
        thin_pool: ([.[].thin_pool | select(. != null)] | unique | join(",") | if . == "" then null else . end),
        thin_total_gib: sum("thin_total_gib"), thin_used_gib: sum("thin_used_gib"), thin_used_pct: worst("thin_used_pct"),
        provisioned_gib: ($provisioned_kib / 1048576),
        overcommit: (sum("thin_total_gib") as $t | if $t == null or $t == 0 then null else ($provisioned_kib / 1048576 / $t) end),
        resource_definitions: ($definitions | length),
        nodes: .
      }'
}

# Every runtime node's condition, requests, host metrics and thin pool, and
# their aggregate.
nodes_state() {
  local node pools definitions
  pools="$(linstor_get v1/view/storage-pools 2>/dev/null || echo '[]')"
  definitions="$(linstor_get 'v1/resource-definitions?with_volume_definitions=true' 2>/dev/null || echo '[]')"
  for node in "${NODES[@]}"; do
    jq -nc --arg node "$node" --arg condition "$(node_condition "$node")" \
      --argjson requests "$(node_requests "$node")" --argjson host "$(node_metrics "$(node_instance "$node")")" \
      --argjson thin "$(thin_pool "$node" "$pools")" \
      '{node: $node, node_condition: $condition} + $requests + $host + $thin'
  done | aggregate_nodes "$definitions"
}

# Of the given environments, those whose sandbox Pod has no node yet: the
# ones a scheduler refusal leaves waiting. A Pod that is scheduled is still
# starting and becomes ready on its own.
unscheduled_ids() { # IDS...
  local pods
  pods="$(kubectl_ro get pods -n "$SANDBOX_NAMESPACE" -o json 2>/dev/null |
    jq -c '[.items[] | select(.spec.nodeName != null) | .metadata.name]')" || pods=""
  [[ -n "$pods" ]] || { printf '%s\n' "$@"; return; }
  jq -rn --argjson scheduled "$pods" --slurpfile objects "$RUN_DIR/objects.jsonl" '
    [$objects[] | .pod as $pod | select($pod != "" and ($scheduled | index($pod) != null)) | .id] as $placed
    | $ARGS.positional[] | select(. as $id | $placed | index($id) == null)' --args "$@"
}

# The run's scheduled sandbox pods per node, as {"node": count}.
run_placement() {
  kubectl_ro get pods -n "$SANDBOX_NAMESPACE" -o json 2>/dev/null |
    jq -c --slurpfile objects "$RUN_DIR/objects.jsonl" '
      ([$objects[] | .pod | select(. != "")]) as $mine
      | [.items[] | select(.metadata.name as $n | $mine | index($n) != null) | .spec.nodeName | select(. != null)]
      | group_by(.) | map({key: .[0], value: length}) | from_entries' || echo '{}'
}

node_metrics() { # INSTANCE -> JSON
  local i="$1" sel
  sel="cluster=\"$PROM_CLUSTER\",instance=\"$i:9100\""
  jq -n \
    --arg cpu "$(prom "100 * (1 - avg(rate(node_cpu_seconds_total{$sel,mode=\"idle\"}[2m])))")" \
    --arg total "$(prom "node_memory_MemTotal_bytes{$sel}")" \
    --arg avail "$(prom "node_memory_MemAvailable_bytes{$sel}")" \
    --arg psi_cpu "$(prom "100 * rate(node_pressure_cpu_waiting_seconds_total{$sel}[1m])")" \
    --arg psi_mem "$(prom "100 * rate(node_pressure_memory_waiting_seconds_total{$sel}[1m])")" \
    --arg psi_mem_full "$(prom "100 * rate(node_pressure_memory_stalled_seconds_total{$sel}[1m])")" \
    --arg psi_io "$(prom "100 * rate(node_pressure_io_waiting_seconds_total{$sel}[1m])")" '
    def num: if . == "" then null else tonumber end;
    {
      node_cpu_pct: ($cpu | num),
      node_memory_total_gib: (if ($total | num) == null then null else (($total | num) / 1073741824) end),
      node_memory_used_gib: (if ($total | num) == null or ($avail | num) == null then null
        else ((($total | num) - ($avail | num)) / 1073741824) end),
      node_memory_pct: (if ($total | num) == null or ($avail | num) == null then null
        else (100 * (1 - ($avail | num) / ($total | num))) end),
      psi_cpu_some_pct: ($psi_cpu | num),
      psi_memory_some_pct: ($psi_mem | num),
      psi_memory_full_pct: ($psi_mem_full | num),
      psi_io_some_pct: ($psi_io | num)
    }'
}

# Memory the run's own sandbox pods use, from cAdvisor's pod-level series
# (container=""). For a Kata pod this tracks the VM's cgroup, near its sized
# memory rather than what the host spends, so overhead is derived from the
# host's own usage instead.
guest_memory_gib() {
  local pods
  pods="$(jq -r '.pod | select(. != "")' "$RUN_DIR/objects.jsonl" 2>/dev/null | paste -sd'|')"
  [[ -n "$pods" ]] || { printf '\n'; return; }
  prom "sum(container_memory_working_set_bytes{cluster=\"$PROM_CLUSTER\",namespace=\"$SANDBOX_NAMESPACE\",container=\"\",pod=~\"$pods\"}) / 1073741824"
}

# The milestone histogram's bucket counts, one "milestone path le count" row
# per bucket, commodity profile only.
milestone_snapshot() {
  kubectl_ro get --raw "/api/v1/namespaces/$ORCHESTRATION_NAMESPACE/services/$ORCHESTRATION_METRICS/proxy/metrics" 2>/dev/null |
    awk -v m="${MILESTONE}_bucket" '
      index($0, m "{") == 1 && $0 ~ /profile="commodity"/ {
        # Anchor each label at a boundary: profile="..." also ends in le="...".
        match($0, /[{,]milestone="[^"]*"/); ms = substr($0, RSTART + 12, RLENGTH - 13)
        match($0, /[{,]path="[^"]*"/); path = substr($0, RSTART + 7, RLENGTH - 8)
        match($0, /[{,]le="[^"]*"/); le = substr($0, RSTART + 5, RLENGTH - 6)
        print ms, path, le, $NF
      }' || true
}

# p50 and p95 (ms) of one milestone over the creates between two snapshots,
# interpolated within buckets as histogram_quantile does. A quantile in the
# +Inf bucket is reported as the top finite bound with p*_over_top true: the
# real value is above it.
milestone_quantiles() { # BEFORE AFTER MILESTONE -> JSON
  awk -v want="$3" '
    # FILENAME, not FNR == NR: an empty first snapshot must stay "before".
    FILENAME == ARGV[1] { if ($1 == want) before[$2 " " $3] = $4; next }
    $1 == want { key = $2 " " $3; delta[$3] += $4 - (key in before ? before[key] : 0) }
    END {
      n = 0
      for (le in delta) { les[++n] = le }
      for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++) {
        a = (les[i] == "+Inf") ? 1e300 : les[i] + 0; b = (les[j] == "+Inf") ? 1e300 : les[j] + 0
        if (b < a) { t = les[i]; les[i] = les[j]; les[j] = t }
      }
      total = (n > 0) ? delta[les[n]] : 0
      if (total <= 0) { print "{\"count\":0,\"p50_ms\":null,\"p95_ms\":null,\"p50_over_top\":false,\"p95_over_top\":false}"; exit }
      split("0.5 0.95", qs, " ")
      for (q = 1; q <= 2; q++) {
        rank = qs[q] * total; prev_le = 0; prev_c = 0; out[q] = "null"; over[q] = "false"
        for (i = 1; i <= n; i++) {
          c = delta[les[i]]
          if (c >= rank) {
            if (les[i] == "+Inf") { out[q] = int(prev_le * 1000); over[q] = "true"; break }
            le = les[i] + 0
            frac = (c - prev_c > 0) ? (rank - prev_c) / (c - prev_c) : 1
            out[q] = int((prev_le + (le - prev_le) * frac) * 1000); break
          }
          prev_le = (les[i] == "+Inf") ? prev_le : les[i] + 0; prev_c = c
        }
      }
      printf "{\"count\":%d,\"p50_ms\":%s,\"p95_ms\":%s,\"p50_over_top\":%s,\"p95_over_top\":%s}\n", total, out[1], out[2], over[1], over[2]
    }' "$1" "$2"
}

# ------------------------------------------------------------ sandboxes

# A bounded workload: WORKERS processes busy DUTY of every 100 ms, and BYTES
# allocated with every page written, all ending after SECONDS.
WORKLOAD_PY='import multiprocessing as mp, sys, time
seconds, workers, duty, size = float(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4])
end = time.time() + seconds
def burn():
    while time.time() < end:
        busy = time.time() + 0.1 * duty
        while time.time() < busy:
            pass
        time.sleep(0.1 * (1 - duty))
procs = [mp.Process(target=burn) for _ in range(workers)] if duty > 0 else []
for p in procs:
    p.start()
block = bytearray(size)
block[::4096] = b"\x01" * len(range(0, size, 4096))
while time.time() < end:
    time.sleep(5)
for p in procs:
    p.join()
'

# What a real sandbox can do, all at once: every container near its limit while
# writing to disk is what gets a VM killed (#3718). Each part keeps going past a
# failure and logs it to /workspace/cap-load/log. The disk it uses is bounded:
# one workspace file and six Docker files, rewritten.
read -r -d '' REAL_WORKLOAD_SH <<'SCRIPT' || true
seconds="$1" bytes="$2" image="$3"
end=$((SECONDS + seconds))
root=/workspace/cap-load
mkdir -p "$root/app/src" "$root/docker"
log() { printf '%s %s\n' "$(date -u +%T)" "$*" >>"$root/log"; }

# What every process is doing, in memory rather than on the disk under test, so a
# blocked disk can't stop its own evidence. Bounded: one sample a minute, the
# last 40 kept.
(
  samples=/tmp/cap-load-samples
  while ((SECONDS < end)); do
    {
      echo "=== $(date -u +%T)"
      ps -eo stat,rss,etimes,wchan:18,comm --sort=-rss | head -14
      grep -E '^(MemFree|MemAvailable|Cached|Dirty|Writeback):' /proc/meminfo
      for pressure in cpu memory io; do
        printf '%s %s\n' "$pressure" "$(head -1 /proc/pressure/$pressure 2>/dev/null)"
      done
      cat /sys/fs/cgroup/memory.events 2>/dev/null | tr '\n' ' '
      echo
      # A stuck shared volume blocks every writer while other paths still answer.
      started=$SECONDS
      timeout 5 sh -c "echo x >/workspace/cap-load/probe"
      printf 'workspace write: status %s in %s s\n' "$?" "$((SECONDS - started))"
      started=$SECONDS
      timeout 5 stat /workspace/cap-load/log >/dev/null
      printf 'workspace stat: status %s in %s s\n' "$?" "$((SECONDS - started))"
      started=$SECONDS
      timeout 5 sh -c "echo x >/tmp/cap-load-probe"
      printf 'tmp write: status %s in %s s\n' "$?" "$((SECONDS - started))"
      ps -eo stat,wchan:24,comm | grep -E '^D' | head -8
      dmesg 2>/dev/null | grep -iE 'oom|killed process|hung task' | tail -3
    } >>"$samples.new"
    tail -n 1000 "$samples.new" >"$samples"
    cp "$samples" "$samples.new"
    sleep 60
  done
) &

(
  python3 -c '
import sys, time
block = bytearray(int(sys.argv[1]))
block[::4096] = b"\x01" * len(range(0, len(block), 4096))
time.sleep(int(sys.argv[2]))
' "$bytes" "$seconds"
  log "memory hold ended with status $?"
) &

(
  while ((SECONDS < end)); do
    dd if=/dev/urandom of="$root/workspace-file" bs=1M count=1024 status=none || log "workspace write failed"
  done
) &

(
  cat >"$root/app/go.mod" <<'GOMOD'
module capload

go 1.21
GOMOD
  cat >"$root/app/main.go" <<'GO'
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	out, _ := json.Marshal(map[string]any{"status": http.StatusOK, "tls": tls.VersionTLS13})
	fmt.Println(string(out))
}
GO
  cd "$root/app" || exit 1
  export GOCACHE="$root/gocache"
  while ((SECONDS < end)); do
    rm -rf "$GOCACHE"
    if go build -a -o "$root/app/app" . >>"$root/build.log" 2>&1 && "$root/app/app" >/dev/null; then
      log "app built"
    else
      log "app build failed"
      sleep 30
    fi
  done
) &

(
  for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 5; done
  while ((SECONDS < end)); do
    if ! pull_output="$(docker pull -q "$image" 2>&1)"; then
      printf '%s\n' "$pull_output" >>"$root/docker.log"
      case "$pull_output" in
        *toomanyrequests*|*"Rate exceeded"*|*"rate limit"*) log "image pull throttled" ;;
        *) log "image pull failed" ;;
      esac
      sleep 30
      continue
    fi
    log "image pulled"
    docker run --rm --entrypoint sh -v "$root/docker:/w" "$image" -c \
      'for i in 1 2 3 4 5 6; do dd if=/dev/urandom of=/w/f$i bs=1M count=1024 2>/dev/null; done' \
      >>"$root/docker.log" 2>&1 && log "image ran" || log "image run failed"
    mkdir -p "$root/build"
    printf 'FROM %s\nRUN dd if=/dev/urandom of=/layer bs=1M count=2048 && rm /layer\n' "$image" >"$root/build/Dockerfile"
    docker build -q --no-cache -t cap-load-build "$root/build" >>"$root/docker.log" 2>&1 && log "image built" || log "image build failed"
    docker rmi -f cap-load-build "$image" >/dev/null 2>&1
  done
) &

wait
SCRIPT

# The workload runs as its own detached session (`cw run --detach`), bounded
# by timeout; a short follow-up run checks that it is alive. A plain run that
# backgrounds it does not return until its session ends.
start_workload() { # ID SECONDS
  local id="$1" seconds="$2" workers bytes encoded attempt command
  workers=$(( (CPU_M + 999) / 1000 ))
  bytes="$(awk -v m="$MEMORY_MIB" -v f="$WORKLOAD_MEMORY" 'BEGIN {printf "%d", m * f * 1048576}')"
  if [[ "$WORKLOAD" == real ]]; then
    encoded="$(printf '%s' "$REAL_WORKLOAD_SH" | base64 -w0)"
    command="printf '%s' '$encoded' | base64 -d >/tmp/cap-load.sh && exec timeout $((seconds + 60)) bash /tmp/cap-load.sh $seconds $bytes $DOCKER_IMAGE"
  else
    encoded="$(printf '%s' "$WORKLOAD_PY" | base64 -w0)"
    command="printf '%s' '$encoded' | base64 -d >/tmp/cap-load.py && exec timeout $((seconds + 60)) python3 /tmp/cap-load.py $seconds $workers $WORKLOAD_CPU $bytes"
  fi
  timeout 120 "$CW_BIN" --cloud --server "$CODEWIRE_SERVER_URL" run --detach --in "$id" --name cap-load -- \
    bash -c "$command" \
    >/dev/null 2>&1 || return 1
  for attempt in 1 2 3 4 5; do
    if timeout 60 "$CW_BIN" --cloud --server "$CODEWIRE_SERVER_URL" run --no-tty --in "$id" -- \
      pgrep -f '/tmp/cap-load[.]' </dev/null >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

create_env() { # N -> environment id on stdout
  local n="$1" name out id attempt retried=0 existing
  out="$RUN_DIR/create-$n.out"
  name="${NAME_PREFIX}${RUN_ID}-${n}"
  for attempt in 1 2 3 4 5; do
    now_ms >"$RUN_DIR/create-$n.started"
    if cw create --no-file --image "$LOAD_IMAGE" --name "$name" --cpu "${CPU_M}m" \
      --memory "$MEMORY_MIB" --disk "$DISK_GIB" --isolation standard --ttl "$LOAD_TTL" \
      --no-network --no-wait --yes --output json >"$out" 2>"$out.err"; then
      break
    fi
    # Ten creates per user per 60 s (check_rate_limit); the window closes 60 s
    # after the last accepted create.
    if ((attempt < 5)) && grep -q 'too many environment creates' "$out.err"; then
      log "create rate limited; waiting 61 s"
      pause 61
      continue
    fi
    # One retry for a client-side deadline only: the request may never have
    # reached the server, or its answer was lost. An environment of this name
    # that does exist is recorded instead of created twice. A server refusal
    # is never retried.
    if ((retried == 0)) && grep -q 'client-side deadline exceeded' "$out.err"; then
      retried=1
      printf 'create %s: client-side deadline exceeded\n' "$n" >>"$RUN_DIR/create-retries"
      existing="$(list_envs 2>/dev/null | awk -F'\t' -v name="$name" '$2 == name {print $1; exit}' || true)"
      if [[ -n "$existing" ]]; then
        log "create $n: client-side deadline exceeded; $name exists, recording it"
        jq -nc --arg id "$existing" '{id: $id}' >"$out"
        break
      fi
      log "create $n: client-side deadline exceeded; retrying once"
      pause 5
      continue
    fi
    sed 's/[[:cntrl:]]//g' "$out.err" | tail -n 3 >&2
    return 1
  done
  id="$(jq -r '.id // empty' "$out" 2>/dev/null || true)"
  [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || return 1
  printf '%s\t%s\t%s\n' "$id" "$name" "$(cat "$RUN_DIR/create-$n.started")" >>"$RUN_DIR/envs.tsv"
  printf '%s\n' "$id"
}

# Background: wait until the environment is running with setup complete, then
# record its create-to-ready time, objects and pool classification.
wait_ready_bg() { # ID STARTED_MS
  local id="$1" started="$2" deadline info result="$RUN_DIR/ready-$1"
  deadline=$(( $(date +%s) + READY_TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    kill -0 "$MAIN_PID" 2>/dev/null || return 1
    info="$(cw info "$id" --output json 2>/dev/null || true)"
    if jq -e '.state == "running" and .setup_complete == true' <<<"$info" >/dev/null 2>&1; then
      printf 'ready %s\n' "$(( $(now_ms) - started ))" >"$result"
      return 0
    fi
    if jq -e '.state == "error" or ((.setup_error // "") | length > 0)' <<<"$info" >/dev/null 2>&1; then
      printf 'error %s\n' "$(jq -r '.setup_error // .state' <<<"$info" | tr -d '[:cntrl:]' | head -c 200)" >"$result"
      return 1
    fi
    sleep 1
  done
  printf 'timeout\n' >"$result"
  return 1
}

managed_ssh_config() {
  local config="$RUN_DIR/ssh_config"
  if [[ ! -s "$config" ]]; then
    "$CW_BIN" --server "$CODEWIRE_SERVER_URL" setup ssh --ssh-config-file "$config" >/dev/null ||
      { log "cw setup ssh could not write the managed SSH block"; return 1; }
  fi
  printf '%s\n' "$config"
}

first_ssh_bg() { # ID STARTED_MS CONFIG
  local id="$1" started="$2" config="$3" deadline
  deadline=$(( $(date +%s) + READY_TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    kill -0 "$MAIN_PID" 2>/dev/null || return 1
    if env CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" timeout 30 ssh -F "$config" -T \
      -o BatchMode=yes -o ConnectTimeout=20 "cw-cloud-$id" true </dev/null >/dev/null 2>&1; then
      printf '%s\n' "$(( $(now_ms) - started ))" >"$RUN_DIR/ssh-$id"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# "warm" when the Claim adopted a member of a shared pool, else "cold".
classify() { # ID
  local ref launch sandbox
  ref="$(kubectl_ro get sandboxclaim -n "$SANDBOX_NAMESPACE" "sandbox-$1" -o json 2>/dev/null |
    jq -r '.spec.warmPoolRef.name // ""' || true)"
  sandbox="$(kubectl_ro get sandboxclaim -n "$SANDBOX_NAMESPACE" "sandbox-$1" -o json 2>/dev/null |
    jq -r '.status.sandbox.name // ""' || true)"
  launch=""
  [[ -z "$sandbox" ]] || launch="$(kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" "$sandbox" -o json 2>/dev/null |
    jq -r '.metadata.labels["agents.x-k8s.io/launch-type"] // ""' || true)"
  if [[ "$ref" == cw-pool-* && "$launch" == warm ]]; then echo warm; else echo cold; fi
}

# The scheduler's resource refusal for one of the run's still-Pending pods,
# if any. Transient reasons, such as a PVC not yet bound, do not count.
scheduler_refusal() {
  local pending
  pending="$(kubectl_ro get pods -n "$SANDBOX_NAMESPACE" --field-selector status.phase=Pending -o json 2>/dev/null |
    jq -r '.items[].metadata.name' || true)"
  [[ -n "$pending" ]] || return 0
  pending="$(grep -xF -f <(jq -r '.pod | select(. != "")' "$RUN_DIR/objects.jsonl" 2>/dev/null) <<<"$pending" || true)"
  [[ -n "$pending" ]] || return 0
  kubectl_ro get events -n "$SANDBOX_NAMESPACE" --field-selector reason=FailedScheduling -o json 2>/dev/null |
    jq -r --arg pending "$pending" '
      ($pending | split("\n") | map(select(. != ""))) as $mine
      | [.items[] | select(.involvedObject.name as $n | $mine | index($n) != null)
        | .message | select(test("Insufficient|Too many pods|exceed"; "i"))][-1] // empty' || true
}

# Record each environment's Sandbox, Pod, PVCs and PVs. With "missing", only
# environments whose Pod is not recorded yet are read again.
refresh_objects() { # all|missing
  local id tmp="$RUN_DIR/objects.jsonl.new" record
  touch "$RUN_DIR/objects.jsonl"
  : >"$tmp"
  for id in "${ENV_IDS[@]}"; do
    record="$(grep -F "\"id\":\"$id\"" "$RUN_DIR/objects.jsonl" | head -n1 || true)"
    if [[ "$1" == missing && -n "$record" ]] && jq -e '.pod != "" and (.volumes | length) > 0 and all(.volumes[]; .pv != "")' <<<"$record" >/dev/null; then
      printf '%s\n' "$record" >>"$tmp"
    else
      env_objects "$id" >>"$tmp"
    fi
  done
  mv "$tmp" "$RUN_DIR/objects.jsonl"
}

# The Pods the workloads started in. A killed VM's replacement has the same name
# and 0 restarts, and looks healthy once it runs (#3718), so only its UID tells.
record_pod_uids() {
  kubectl_ro get pods -n "$SANDBOX_NAMESPACE" -o json 2>/dev/null |
    jq -c --slurpfile objects "$RUN_DIR/objects.jsonl" '
      ([$objects[] | .pod | select(. != "")]) as $mine
      | [.items[] | select(.metadata.name as $n | $mine | index($n) != null) | {key: .metadata.name, value: .metadata.uid}]
      | from_entries' >"$RUN_DIR/pod-uids.json.new"
  if [[ -s "$RUN_DIR/pod-uids.json" ]]; then
    # A UID recorded earlier stays the one to compare with.
    jq -sc '.[0] * .[1]' "$RUN_DIR/pod-uids.json.new" "$RUN_DIR/pod-uids.json" >"$RUN_DIR/pod-uids.json.merged" &&
      mv "$RUN_DIR/pod-uids.json.merged" "$RUN_DIR/pod-uids.json"
  else
    mv "$RUN_DIR/pod-uids.json.new" "$RUN_DIR/pod-uids.json"
  fi
}

# Whether what was started is still running: a killed VM refuses nothing, and
# every other number here can look fine. Read fresh, with null for what can't be
# read, so an outage of the reads never reads as nothing lost.
sandbox_health() { # -> JSON
  # In files: a namespace's Pods are too big for one command-line argument.
  local listing="$RUN_DIR/health-listing.json" pods="$RUN_DIR/health-pods.json"
  cw ls --output json >"$listing" 2>/dev/null || echo null >"$listing"
  kubectl_ro get pods -n "$SANDBOX_NAMESPACE" -o json >"$pods" 2>/dev/null || echo null >"$pods"
  [[ -s "$RUN_DIR/pod-uids.json" ]] || echo '{}' >"$RUN_DIR/pod-uids.json"
  jq -cn --slurpfile listings "$listing" --slurpfile all_pods "$pods" \
    --slurpfile objects "$RUN_DIR/objects.jsonl" --slurpfile recorded "$RUN_DIR/pod-uids.json" --args '
    ($ARGS.positional) as $ready
    | $listings[0] as $listing
    | $all_pods[0] as $pods
    | ([$objects[] | .pod | select(. != "")]) as $mine
    | (if $pods == null then null else
        [$pods.items[] | select(.metadata.name as $n | $mine | index($n) != null) | .status.containerStatuses[]?]
       end) as $containers
    | (if $pods == null then null else
        [$pods.items[] | select($recorded[0][.metadata.name] as $uid | $uid != null and $uid != .metadata.uid) | .metadata.name]
       end) as $replaced
    | {sandboxes_lost:
         (if $listing == null then null else
            [(if ($listing | type) == "array" then $listing else ($listing.environments // []) end)[]
             | select((.id as $id | $ready | index($id) != null) and .state != "running")
             | {id, state}]
          end),
       pods_replaced: $replaced,
       containers_restarted: (if $containers == null then null else [$containers[].restartCount] | add // 0 end),
       containers_oom_killed: (if $containers == null then null else
            [$containers[] | select(.lastState.terminated.reason == "OOMKilled" or .state.terminated.reason == "OOMKilled")] | length
          end)}' "$@"
}

# Whether the real workload's parts did their work in one sandbox: a sandbox
# that stays up proves nothing about a load that never ran. Null when it can't
# be read, because the sandbox may be the thing that was lost.
workload_proof() { # ID -> JSON
  local log
  if ! log="$(timeout 60 "$CW_BIN" --cloud --server "$CODEWIRE_SERVER_URL" run --no-tty --in "$1" -- \
    cat /workspace/cap-load/log </dev/null 2>/dev/null)"; then
    echo null
    return
  fi
  # Kept, because cleanup removes the sandbox they came from.
  printf '%s\n' "$log" >"$RUN_DIR/workload-$1.log"
  local kept
  for kept in /tmp/cap-load-samples /workspace/cap-load/build.log /workspace/cap-load/docker.log; do
    timeout 60 "$CW_BIN" --cloud --server "$CODEWIRE_SERVER_URL" run --no-tty --in "$1" -- \
      tail -n 1000 "$kept" </dev/null >"$RUN_DIR/workload-$1-$(basename "$kept")" 2>/dev/null || true
  done
  jq -Rsc 'split("\n") as $lines
    | def count($text): [$lines[] | select(endswith($text))] | length;
    {built: count(" app built"), build_failed: count(" app build failed"),
     pulled: count(" image pulled"), pull_failed: count(" image pull failed"),
     pull_throttled: count(" image pull throttled"),
     ran: count(" image ran"), run_failed: count(" image run failed"),
     image_built: count(" image built"), image_build_failed: count(" image build failed"),
     hold_ended: [$lines[] | select(contains(" memory hold ended with status "))] | length}' <<<"$log"
}

# Each lost sandbox's own reason. `cw ls` rows don't carry it, and cleanup removes
# the sandbox, so it's read and logged here.
log_lost_reasons() { # METRICS_JSON
  local id reason
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    reason="$(cw info "$id" --output json 2>/dev/null | jq -r '.error_reason // "no reason recorded"' || echo "reason not readable")"
    log "lost sandbox $id: $reason"
  done < <(jq -r '.health.sandboxes_lost[]?.id' <<<"$1")
}

# The proof across a sample of a run's sandboxes, because a throttled registry or a
# stuck part may hit only some. A sandbox that can't be read isn't counted, and the
# count says how many were. Null when none could be.
PROOF_SAMPLE=5
workload_proof_sample() { # IDS... -> JSON
  local id proof proofs=()
  for id in "${@:1:$PROOF_SAMPLE}"; do
    proof="$(workload_proof "$id")"
    [[ "$proof" == null ]] || proofs+=("$proof")
  done
  ((${#proofs[@]} > 0)) || { echo null; return; }
  printf '%s\n' "${proofs[@]}" | jq -sc '
    def total($key): map(.[$key]) | add;
    {sandboxes_read: length, without_build: (map(select(.built == 0)) | length),
       without_image_run: (map(select(.ran == 0)) | length),
       without_image_build: (map(select(.image_built == 0)) | length),
       built: total("built"), build_failed: total("build_failed"),
       pulled: total("pulled"), pull_failed: total("pull_failed"), pull_throttled: total("pull_throttled"),
       ran: total("ran"), run_failed: total("run_failed"),
       image_built: total("image_built"), image_build_failed: total("image_build_failed"),
       hold_ended: total("hold_ended")}'
}

# ------------------------------------------------------------ steps

stop_check() { # METRICS_JSON -> sets STOP_REASON
  local m="$1" v
  v="$(jq -r '.node_condition' <<<"$m")"
  [[ "$v" == ok ]] || { STOP_REASON="node condition degraded: $v"; return; }
  v="$(jq -r 'if .health.sandboxes_lost == null then "" else (.health.sandboxes_lost | length | tostring) end' <<<"$m")"
  if [[ -n "$v" && "$v" != 0 ]]; then
    STOP_REASON="$v sandbox(es) lost under load: $(jq -c '.health.sandboxes_lost[0:3]' <<<"$m")"
    return
  fi
  v="$(jq -r '.health.pods_replaced // [] | length' <<<"$m")"
  [[ "$v" == 0 ]] || { STOP_REASON="$v sandbox Pod(s) replaced under load, so their VMs died: $(jq -c '.health.pods_replaced[0:3]' <<<"$m")"; return; }
  v="$(jq -r '.health.containers_oom_killed // 0' <<<"$m")"
  [[ "$v" == 0 ]] || { STOP_REASON="$v container(s) OOM-killed under load"; return; }
  v="$(jq -r 'if .workload_proof == null then "" else .workload_proof
      | [if .without_build > 0 then "no app built in \(.without_build) of \(.sandboxes_read)" else empty end,
         if .without_image_run > 0 then "no image ran in \(.without_image_run) of \(.sandboxes_read)" else empty end,
         if (.without_image_build // 0) > 0 then "no image built in \(.without_image_build) of \(.sandboxes_read)" else empty end,
         if .hold_ended > 0 then "the memory hold ended early in \(.hold_ended)" else empty end]
      | join(", ") end' <<<"$m")"
  [[ -z "$v" ]] || { STOP_REASON="the real workload did not run as meant: $v: $(jq -c .workload_proof <<<"$m")"; return; }
  v="$(jq -r '.scheduler_refusal // ""' <<<"$m")"
  [[ -z "$v" ]] || { STOP_REASON="scheduler refusal: $v"; return; }
  v="$(jq -r '.failed_creates' <<<"$m")"
  [[ "$v" == 0 ]] || { STOP_REASON="$v create(s) failed or were not ready within ${READY_TIMEOUT_SECONDS} s"; return; }
  v="$(jq -r '.ready_p95_ms // empty' <<<"$m")"
  if [[ -n "$BASELINE_READY_MS" ]] && exceeds "$v" "$(awk -v b="$BASELINE_READY_MS" -v f="$LATENCY_FACTOR" 'BEGIN {print b * f}')"; then
    STOP_REASON="create-to-ready p95 ${v} ms exceeds ${LATENCY_FACTOR} x the first step's p50 (${BASELINE_READY_MS} ms)"; return
  fi
  v="$(jq -r '.node_memory_pct // empty' <<<"$m")"
  ! exceeds "$v" "$MAX_NODE_MEMORY_PCT" || { STOP_REASON="node memory ${v}% exceeds ${MAX_NODE_MEMORY_PCT}%"; return; }
  v="$(jq -r '.node_cpu_pct // empty' <<<"$m")"
  ! exceeds "$v" "$MAX_NODE_CPU_PCT" || { STOP_REASON="node CPU ${v}% exceeds ${MAX_NODE_CPU_PCT}%"; return; }
  v="$(jq -r '.psi_memory_some_pct // empty' <<<"$m")"
  ! exceeds "$v" "$MAX_PSI_MEMORY_PCT" || { STOP_REASON="memory pressure ${v}% exceeds ${MAX_PSI_MEMORY_PCT}%"; return; }
  v="$(jq -r '.psi_cpu_some_pct // empty' <<<"$m")"
  ! exceeds "$v" "$MAX_PSI_CPU_PCT" || { STOP_REASON="CPU pressure ${v}% exceeds ${MAX_PSI_CPU_PCT}%"; return; }
  v="$(jq -r '.thin_used_pct // empty' <<<"$m")"
  ! exceeds "$v" "$MAX_THIN_POOL_PCT" || { STOP_REASON="thin pool ${v}% exceeds ${MAX_THIN_POOL_PCT}%"; return; }
  STOP_REASON=""
}

measure() { # STEP TARGET NEW_IDS_FILE BEFORE_SNAPSHOT AFTER_SNAPSHOT BASE_JSON -> JSON
  local step="$1" target="$2" new_ids="$3" before="$4" after="$5" base="$6"
  local ready_ms=() ssh_ms=() failed=0 warm=0 id result guest running
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    result="$(cat "$RUN_DIR/ready-$id" 2>/dev/null || echo missing)"
    case "$result" in
      ready\ *) ready_ms+=("${result#ready }") ;;
      *) failed=$((failed + 1)); log "step $step: $id: $result" ;;
    esac
    [[ ! -s "$RUN_DIR/ssh-$id" ]] || ssh_ms+=("$(cat "$RUN_DIR/ssh-$id")")
    [[ "$(cat "$RUN_DIR/class-$id" 2>/dev/null)" != warm ]] || warm=$((warm + 1))
  done <"$new_ids"
  # Per-sandbox memory divides by the sandboxes that became ready over the
  # whole run: refused ones are Pending and use no node memory.
  running="$({ grep -l '^ready ' "$RUN_DIR"/ready-* 2>/dev/null || true; } | wc -l)"
  guest="$(guest_memory_gib)"
  jq -n \
    --argjson step "$step" --argjson target "$target" --argjson created "$CREATED" \
    --argjson new "$(grep -c . "$new_ids" || true)" --argjson failed "$failed" --argjson warm "$warm" \
    --argjson running "$running" \
    --arg ready_p50 "$(printf '%s\n' "${ready_ms[@]}" | grep . | percentile 50)" \
    --arg ready_p95 "$(printf '%s\n' "${ready_ms[@]}" | grep . | percentile 95)" \
    --arg ssh_p50 "$(printf '%s\n' "${ssh_ms[@]}" | grep . | percentile 50)" \
    --arg ssh_p95 "$(printf '%s\n' "${ssh_ms[@]}" | grep . | percentile 95)" \
    --argjson ssh_n "${#ssh_ms[@]}" \
    --argjson setup "$(milestone_quantiles "$before" "$after" setup_complete)" \
    --argjson access "$(milestone_quantiles "$before" "$after" access_ready)" \
    --argjson state "$(nodes_state)" \
    --argjson placement "$(run_placement)" \
    --argjson base "$base" \
    --arg refusal "$(scheduler_refusal)" \
    --arg guest "$guest" \
    --argjson workload_gib "$(awk -v m="$MEMORY_MIB" -v f="$WORKLOAD_MEMORY" 'BEGIN {printf "%.4f", m * f / 1024}')" '
    def num: if . == "" then null else tonumber end;
    {step: $step, target: $target, created: $created, ready_sandboxes: $running, new: $new, failed_creates: $failed,
     warm_hits: $warm, warm_hit_rate: (if $new > 0 then $warm / $new else null end),
     ready_p50_ms: ($ready_p50 | num), ready_p95_ms: ($ready_p95 | num),
     first_ssh_p50_ms: ($ssh_p50 | num), first_ssh_p95_ms: ($ssh_p95 | num), first_ssh_samples: $ssh_n,
     server_setup_complete: $setup, server_access_ready: $access,
     scheduler_refusal: (if $refusal == "" then null else $refusal end),
     pod_working_set_gib: ($guest | num), workload_memory_gib: $workload_gib, placement: $placement}
    + $state
    | . + {
        host_memory_per_sandbox_gib: (if .node_memory_used_gib == null or $base.node_memory_used_gib == null or $running == 0 then null
          else ((.node_memory_used_gib - $base.node_memory_used_gib) / $running) end),
        pod_working_set_per_sandbox_gib: (if .pod_working_set_gib == null or $running == 0 then null else (.pod_working_set_gib / $running) end)
      }
    | . + {overhead_per_sandbox_gib: (if .host_memory_per_sandbox_gib == null then null
          else (.host_memory_per_sandbox_gib - .workload_memory_gib) end)}'
}

# Per node: how many sandboxes of the shape fit by free CPU, memory and pods,
# the smallest of those, and which resource sets it. A sandbox fits on one
# node or not at all, so each node is floored on its own and the total is the
# sum of the nodes' fits.
predict() { # BASE_JSON REQUEST_JSON
  jq -n --argjson b "$1" --argjson s "$2" --arg shape "$SHAPE" '
    def fit($free; $each): if $free <= 0 then 0 else ($free / $each | floor) end;
    ($b.nodes | map(
       {node, allocatable_cpu_m, allocatable_memory_mib, allocatable_pods, requested_cpu_m, requested_memory_mib, pods,
        by_cpu: fit(.allocatable_cpu_m - .requested_cpu_m; $s.cpu_m),
        by_memory: fit(.allocatable_memory_mib - .requested_memory_mib; $s.memory_mib),
        by_pods: fit(.allocatable_pods - .pods; 1)}
       | ([.by_cpu, .by_memory, .by_pods] | min) as $fits
       | . + {fits: $fits,
              first_limit: ([if .by_cpu == $fits then "CPU requests" else empty end,
                             if .by_memory == $fits then "memory requests" else empty end,
                             if .by_pods == $fits then "pods" else empty end] | join(" and "))})) as $per_node
    | {shape: $shape, sandbox_request: $s,
       predicted_total: ($per_node | map(.fits) | add),
       predicted_by_cpu: ($per_node | map(.by_cpu) | add),
       predicted_by_memory: ($per_node | map(.by_memory) | add),
       predicted_by_pods: ($per_node | map(.by_pods) | add),
       per_node: $per_node}'
}

# auto: 25, 50, 75 and 100% of the predicted total, then two past it so the
# ramp reaches a refusal; capped at MAX_SANDBOXES.
auto_steps() { # PREDICTION_FILE
  jq -r --argjson cap "$MAX_SANDBOXES" '
    .predicted_total as $p
    | if $p < 1 then "" else
        [$p * 0.25, $p * 0.5, $p * 0.75, $p, $p + 2] | map(ceil | select(. >= 1) | if . > $cap then $cap else . end)
        | unique | map(tostring) | join(",") end' "$1"
}

preflight() { # -> base JSON
  local node request others base
  for node in "${NODES[@]}"; do
    [[ -n "$(node_instance "$node")" ]] || die "node $node has no InternalIP"
  done
  others="$(list_envs)" || die "cannot list the smoke organization's environments"
  others="$(awk -F'\t' -v p="$NAME_PREFIX" 'NF && index($2, p) != 1' <<<"$others" | wc -l)"
  [[ "$others" == 0 ]] || die "the smoke organization has $others live environments this tool did not create; wait for them to finish"
  request="$(sandbox_request)" || die "cannot work out what one sandbox reserves"
  base="$(nodes_state)"
  [[ "$(jq -r .node_condition <<<"$base")" == ok ]] ||
    die "a runtime node is degraded before the run: $(jq -r .node_condition <<<"$base")"
  predict "$base" "$request" >"$RUN_DIR/prediction.json"
  log "baseline: $(jq -c '{pods, requested_cpu_m, requested_memory_mib, node_memory_used_gib, thin_used_pct}' <<<"$base")"
  log "predicted refusals: $(jq -c . "$RUN_DIR/prediction.json")"
  printf '%s\n' "$base"
}

write_summary() {
  # shellcheck disable=SC2016 # Backticks are Markdown code spans.
  {
    printf '# Sandbox capacity: %s, shape %s (%s m CPU, %s MiB, %s GiB)\n\n' "${NODES[*]}" "$SHAPE" "$CPU_M" "$MEMORY_MIB" "$DISK_GIB"
    if [[ "$WORKLOAD" == real ]]; then
      printf 'Run `%s`. Real workload: %s of memory held, a Go build, disk writes, and %s pulled and run by Docker. Hold %s s per step.\n\n' \
        "$RUN_ID" "$WORKLOAD_MEMORY" "$DOCKER_IMAGE" "$HOLD_SECONDS"
    else
      printf 'Run `%s`. Workload: %s of each vCPU busy, %s of memory touched. Hold %s s per step.\n\n' \
        "$RUN_ID" "$WORKLOAD_CPU" "$WORKLOAD_MEMORY" "$HOLD_SECONDS"
    fi
    jq -r '
      def gib: . / 1024 * 10 | round / 10 | tostring;
      def cores: . / 1000 * 100 | round / 100 | tostring;
      .sandbox_request as $s
      | "Each sandbox reserves \($s.cpu_m | cores) CPU and \($s.memory_mib | gib) GiB: workspace \($s.workspace.cpu_m | cores) CPU\(if ($s.workspace.cpu_sharing_ratio // 1) > 1 then " (\($s.workspace.cpu_sharing_ratio):1)" else "" end) / \($s.workspace.memory_mib | gib) GiB, DinD \($s.dind.cpu_m | cores) / \($s.dind.memory_mib | gib), Kata \($s.kata.cpu_m | cores) / \($s.kata.memory_mib | gib).\n",
        "Prediction before the run, from requests (\(.predicted_total) in all):\n",
        "| Node | Allocatable CPU / GiB / pods | Requested before | Fit by CPU / memory / pods | Fits | First limit |",
        "|---|---|---|---|---|---|",
        (.per_node[] | "| \(.node) | \(.allocatable_cpu_m | cores) / \(.allocatable_memory_mib | gib) / \(.allocatable_pods) | \(.requested_cpu_m | cores) / \(.requested_memory_mib | gib) / \(.pods) | \(.by_cpu) / \(.by_memory) / \(.by_pods) | \(.fits) | \(.first_limit) |"),
        ""' "$RUN_DIR/prediction.json" 2>/dev/null || true
    printf 'Measured:\n\n'
    printf '| Sandboxes | Ready | Failed | Warm | Ready p50/p95 ms | SSH p50/p95 ms | Server setup p50/p95 ms | Pods | Req CPU %% | Req mem %% | Node CPU %% | Node mem %% | PSI mem/cpu %% | Host GiB/sb | Overhead GiB/sb | Pod WS GiB/sb | Thin %% | Overcommit |\n'
    printf '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n'
    jq -r '
      def f: if . == null then "–" else (. * 10 | round / 10 | tostring) end;
      def i: if . == null then "–" else (round | tostring) end;
      def q($k): .[$k + "_ms"] as $v | if .[$k + "_over_top"] then ">\($v|i)" else ($v|i) end;
      "| \(.created) | \(.ready_sandboxes // "–") | \(.failed_creates) | \(.warm_hits)/\(.new) | \(.ready_p50_ms|i)/\(.ready_p95_ms|i) | \(.first_ssh_p50_ms|i)/\(.first_ssh_p95_ms|i) | \(.server_setup_complete|q("p50"))/\(.server_setup_complete|q("p95")) | \(.pods)/\(.allocatable_pods) | \(100 * .requested_cpu_m / .allocatable_cpu_m | f) | \(100 * .requested_memory_mib / .allocatable_memory_mib | f) | \(.node_cpu_pct|f) | \(.node_memory_pct|f) | \(.psi_memory_some_pct|f)/\(.psi_cpu_some_pct|f) | \(.host_memory_per_sandbox_gib|f) | \(.overhead_per_sandbox_gib|f) | \(.pod_working_set_per_sandbox_gib|f) | \(.thin_used_pct|f) | \(.overcommit|f) |"
    ' "$RUN_DIR/steps.jsonl" 2>/dev/null
    printf '\nPercentages and pressure above are the worst node; per node:\n\n'
    printf '| Sandboxes | Node | Run sandboxes | Pods | Req CPU %% | Req mem %% | Node CPU %% | Node mem %% | PSI mem/cpu %% | Thin %% |\n'
    printf '|---|---|---|---|---|---|---|---|---|---|\n'
    jq -r '
      def f: if . == null then "–" else (. * 10 | round / 10 | tostring) end;
      .created as $created | (.placement // {}) as $placement | (.nodes // [])[]
      | "| \($created) | \(.node) | \($placement[.node] // 0) | \(.pods)/\(.allocatable_pods) | \(100 * .requested_cpu_m / .allocatable_cpu_m | f) | \(100 * .requested_memory_mib / .allocatable_memory_mib | f) | \(.node_cpu_pct|f) | \(.node_memory_pct|f) | \(.psi_memory_some_pct|f)/\(.psi_cpu_some_pct|f) | \(.thin_used_pct|f) |"
    ' "$RUN_DIR/steps.jsonl" 2>/dev/null
    if [[ -s "$RUN_DIR/kubectl-retries" ]]; then
      printf '\nKubectl reads retried once after a connection failure: %s\n' "$(grep -c . "$RUN_DIR/kubectl-retries")"
    fi
    if [[ -s "$RUN_DIR/create-retries" ]]; then
      printf '\nCreates retried once after a client-side deadline: %s\n' "$(grep -c . "$RUN_DIR/create-retries")"
    fi
    jq -rs 'map(select(.health != null)) | if length == 0 then empty else
      "\nAfter each hold, sandboxes lost / Pods replaced / containers restarted / OOM-killed: " +
      (map("\(.created): \(.health.sandboxes_lost | if . == null then "?" else length end) / \(.health.pods_replaced | if . == null then "?" else length end) / \(.health.containers_restarted // "?") / \(.health.containers_oom_killed // "?")") | join(", "))
      end' "$RUN_DIR/steps.jsonl" 2>/dev/null || true
    jq -rs 'map(select(.workload_proof != null)) | if length == 0 then empty else
      "\nReal workload, sampled sandboxes (read / built / images run / pulls throttled / pulls failed): " +
      (map("\(.created): \(.workload_proof | "\(.sandboxes_read) / \(.built) / \(.ran) / \(.pull_throttled) / \(.pull_failed)")") | join(", ")) +
      (if (map(.workload_proof.pull_throttled) | add) > 0 then "\n\nPulls were throttled, so this run had less load than intended." else "" end)
      end' "$RUN_DIR/steps.jsonl" 2>/dev/null || true
    printf '\nStopped: %s\n' "${STOP_REASON:-every step completed}"
  } >"$RUN_DIR/summary.md"
}

# ------------------------------------------------------------ main

if [[ "$MODE" == run ]]; then trap on_exit EXIT; fi
trap 'exit 130' HUP INT TERM

if [[ -z "$LINSTOR_SERVICE" ]]; then
  linstor_namespace="$(kubectl_ro get services -A --field-selector metadata.name=linstor-controller \
    -o jsonpath='{.items[*].metadata.namespace}')"
  [[ "$linstor_namespace" =~ ^[a-z0-9-]+$ ]] || die "no single linstor-controller service; set LINSTOR_SERVICE"
  LINSTOR_SERVICE="$linstor_namespace/linstor-controller:3370"
fi
# The commodity RuntimeClass places sandboxes on Kata runtime-candidate nodes;
# every one is measured, and each step checks no sandbox lands elsewhere.
mapfile -t NODES < <(kubectl_ro get nodes \
  -l 'katacontainers.io/kata-runtime=true,node.codewire.sh/runtime-candidate=true' -o name | sed 's#^node/##')
((${#NODES[@]} > 0)) || die "no Kata runtime-candidate node"
log "runtime nodes: ${NODES[*]}"

clean_leftovers
if [[ "$MODE" == cleanup-only ]]; then
  log "no leftovers remain"
  rm -rf -- "$RUN_DIR"
  exit 0
fi
BASE="$(preflight)"
if [[ "$MODE" == dry-run ]]; then
  cat "$RUN_DIR/prediction.json"
  rm -rf -- "$RUN_DIR"
  exit 0
fi

if [[ "$STEPS" == auto ]]; then
  STEPS="$(auto_steps "$RUN_DIR/prediction.json")"
  [[ -n "$STEPS" ]] || die "no $SHAPE sandbox fits on the runtime nodes"
  IFS=, read -r -a STEP_COUNTS <<<"$STEPS"
fi
log "steps: $STEPS"
SSH_CONFIG="$(managed_ssh_config)" || die "no managed SSH configuration"
WORKLOAD_SECONDS=$(( (${#STEP_COUNTS[@]} + 1) * (HOLD_SECONDS + READY_TIMEOUT_SECONDS) ))
: >"$RUN_DIR/steps.jsonl"
READY_IDS=()
step=0
for target in "${STEP_COUNTS[@]}"; do
  step=$((step + 1))
  if [[ -n "$STOP_REASON" ]]; then break; fi
  log "step $step: ramp to $target sandboxes"
  start_watchdog "$step"
  milestone_snapshot >"$RUN_DIR/milestones-$step.before"
  : >"$RUN_DIR/new-$step"
  sampled=0
  while (( CREATED < target )); do
    n=$((CREATED + 1))
    if ! id="$(create_env "$n")"; then
      STOP_REASON="create $n was refused"
      break
    fi
    CREATED="$n"
    ENV_IDS+=("$id")
    printf '%s\n' "$id" >>"$RUN_DIR/new-$step"
    started="$(cut -f3 <<<"$(grep -F "$id" "$RUN_DIR/envs.tsv")")"
    wait_ready_bg "$id" "$started" & WAITER_PIDS[$id]=$!
    if (( sampled < SSH_SAMPLE )); then
      first_ssh_bg "$id" "$started" "$SSH_CONFIG" & SSH_PIDS[$id]=$!
      sampled=$((sampled + 1))
    fi
  done
  mapfile -t STEP_IDS <"$RUN_DIR/new-$step"
  # Wait for this step's creates, failing fast on a scheduler refusal: the
  # refused sandboxes' waiters stop and they count as failed.
  for id in "${STEP_IDS[@]}"; do
    while kill -0 "${WAITER_PIDS[$id]}" 2>/dev/null; do
      refresh_objects missing
      refusal="$(scheduler_refusal)"
      if [[ -n "$refusal" ]]; then
        log "step $step: scheduler refused a sandbox: $refusal"
        STOP_REASON="scheduler refusal: $refusal"
        # Stop waiting only for sandboxes with no node; scheduled ones are
        # still starting and count once ready (#3583: Prod large showed 29
        # ready of 37 placed when every waiter stopped here).
        while IFS= read -r pending_id; do
          [[ -n "$pending_id" ]] || continue
          kill "${WAITER_PIDS[$pending_id]}" "${SSH_PIDS[$pending_id]:-}" 2>/dev/null || true
        done < <(unscheduled_ids "${STEP_IDS[@]}")
        break 2
      fi
      pause 5
    done
  done
  for id in "${STEP_IDS[@]}"; do
    if [[ -n "${SSH_PIDS[$id]:-}" ]]; then wait "${SSH_PIDS[$id]}" 2>/dev/null || true; unset "SSH_PIDS[$id]"; fi
    wait "${WAITER_PIDS[$id]}" 2>/dev/null || true
    unset "WAITER_PIDS[$id]"
    if [[ "$(cut -d' ' -f1 "$RUN_DIR/ready-$id" 2>/dev/null)" == ready ]]; then
      classify "$id" >"$RUN_DIR/class-$id"
      READY_IDS+=("$id")
      start_workload "$id" "$WORKLOAD_SECONDS" || log "step $step: workload did not start in $id"
    fi
  done
  refresh_objects all
  record_pod_uids
  # Every sandbox must run on a measured node.
  elsewhere="$(run_placement | jq -r --args 'keys[] | select(. as $n | $ARGS.positional | index($n) == null)' "${NODES[@]}")"
  [[ -z "$elsewhere" ]] || { STOP_REASON="sandboxes scheduled off the runtime nodes, on: $elsewhere"; }
  log "step $step: holding ${HOLD_SECONDS} s under load"
  pause "$HOLD_SECONDS"
  milestone_snapshot >"$RUN_DIR/milestones-$step.after"
  metrics="$(measure "$step" "$target" "$RUN_DIR/new-$step" "$RUN_DIR/milestones-$step.before" \
    "$RUN_DIR/milestones-$step.after" "$BASE")"
  metrics="$(jq -c --argjson health "$(sandbox_health "${READY_IDS[@]}")" '. + {health: $health}' <<<"$metrics")"
  log_lost_reasons "$metrics"
  if [[ "$WORKLOAD" == real && ${#READY_IDS[@]} -gt 0 ]]; then
    metrics="$(jq -c --argjson proof "$(workload_proof_sample "${READY_IDS[@]}")" '. + {workload_proof: $proof}' <<<"$metrics")"
    # Fewer pulls and writes than intended is a weaker test, so it's said, not hidden.
    throttled="$(jq -r '.workload_proof.pull_throttled // 0' <<<"$metrics")"
    if [[ "$throttled" != 0 ]]; then
      log "step $step: LESS LOAD THAN INTENDED: $throttled pull(s) throttled in the sampled sandboxes"
    fi
  fi
  printf '%s\n' "$metrics" >>"$RUN_DIR/steps.jsonl"
  log "step $step: $(jq -c '{created, ready_sandboxes, health, workload_proof, failed_creates, warm_hits, ready_p50_ms, ready_p95_ms, first_ssh_p50_ms, node_memory_pct, node_cpu_pct, psi_memory_some_pct, thin_used_pct, pods}' <<<"$metrics")"
  if [[ -z "$BASELINE_READY_MS" ]]; then
    BASELINE_READY_MS="$(jq -r '.ready_p50_ms // empty' <<<"$metrics")"
  fi
  [[ -n "$STOP_REASON" ]] || stop_check "$metrics"
  [[ -z "$STOP_REASON" ]] || log "stop: $STOP_REASON"
done
stop_watchdog
write_summary
log "results: $RUN_DIR/summary.md"
cat "$RUN_DIR/summary.md"
