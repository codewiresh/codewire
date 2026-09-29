#!/usr/bin/env bash
# Workspace storage measurement harness (Program #2238, slice A1-4).
#
# Measures one StorageClass through real pods on a RuntimeClass and writes JSON
# evidence. It creates only labelled PVCs, Pods, one ConfigMap and, when asked,
# VolumeSnapshots in one namespace the operator owns, and removes all of them
# on exit unless --keep is given. It reads no Secrets.
# shellcheck disable=SC2016 # jq programs are single-quoted on purpose.
set -euo pipefail

SM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SM_DIR/../../.." && pwd)"

readonly SM_LABEL_KEY=codewire.sh/storage-measure
# The busybox the commodity smoke Job already runs on the Dev runtime node
# (deployments/k8s/runtime-profiles/confidential-smoke/commodity-smoke-job.yaml).
readonly SM_DEFAULT_PROBE_IMAGE='registry.k8s.io/e2e-test-images/busybox@sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb'
# ripgrep 15.2.0: a public Rust project with a committed Cargo.lock.
readonly SM_DEFAULT_GIT_URL=https://github.com/BurntSushi/ripgrep
readonly SM_DEFAULT_GIT_COMMIT=e89fff89ac9af12e8d4ce9d5fd07beb408ca730f
readonly SM_RUNTIME_IMAGES="$ROOT/crates/codewire-server-core/src/runtime_images.rs"
readonly SM_TEMPLATE_IMAGES="$ROOT/crates/codewire-orchestration/src/sandbox/template/mod.rs"
readonly SM_PROTECTED_NAMESPACES=" default kube-system kube-public kube-node-lease "

CONTEXT=''
NAMESPACE=''
OWN_NAMESPACE=0
STORAGE_CLASS=''
SNAPSHOT_CLASS=''
REMOTE_SNAPSHOT_CLASS=''
RUNTIME_CLASS=commodity
NODE=''
RUNS=20
WARMUP=1
MAX_FAILURES=3
OUT_DIR=''
PVC_SIZE=20Gi
FIO_IMAGE=''
FIO_SIZE=4g
FIO_RUNTIME=30
FIO_RAMP=5
FIO_IOENGINE=libaio
FIO_DIRECT=1
PROBE_IMAGE="$SM_DEFAULT_PROBE_IMAGE"
WORKLOAD_IMAGE=''
GIT_URL="$SM_DEFAULT_GIT_URL"
GIT_COMMIT="$SM_DEFAULT_GIT_COMMIT"
WITH_DOCKER=0
DIND_IMAGE=''
DOCKER_DATA_SIZE=8G
DELTA_MIB=256
WORKLOAD_CPU=4
WORKLOAD_MEMORY=8Gi
IMAGE_PULL_SECRET=''
STORAGE_NAMESPACE=''
METRICS_INTERVAL=10
BASELINE_SAMPLES=3
SKIP_FIO=0
SKIP_WORKLOAD=0
ATTACH_TIMEOUT=300
SNAPSHOT_TIMEOUT=1800
DELETE_TIMEOUT=600
EXEC_TIMEOUT=3600
KEEP=0

RUN_ID=''
CONFIG_JSON=''
LOG_FILE=''
CLUSTER_TOUCHED=0
SNAPSHOT_API=0
METRICS_API=0
SAMPLER_PID=''
BENCH_POD=''
BENCH_PVC=''
BENCH_FIO_PVC=''
FAILED_PHASES=0
CLEANUP_DONE=0
PHASE_STARTED_MS=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/storage-measure/measure-storage.sh \
    --context CONTEXT --namespace NAMESPACE --i-own-this-namespace \
    --storage-class CLASS [options]

Measures workspace storage through real pods and writes JSON evidence:
provision+attach latency over N runs, fio, git/cargo/docker workloads,
snapshots and clones, remote (S3) snapshots and restore, teardown time, and
node CPU/memory from the metrics API when it is available.

Required:
  --context NAME                kubeconfig context (never defaulted)
  --namespace NAME              existing namespace the operator owns
  --i-own-this-namespace        confirm every labelled object may be created there
  --storage-class NAME          StorageClass under test

Storage and runtime:
  --snapshot-class NAME         local VolumeSnapshotClass: snapshot + clone phase
  --remote-snapshot-class NAME  remote (S3) VolumeSnapshotClass: ship, incremental
                                ship, and restore into a new PVC
  --runtime-class NAME          RuntimeClass (default: commodity; "none" omits it)
  --node NAME                   pin every pod to this kubernetes.io/hostname
  --pvc-size SIZE               PVC request (default: 20Gi)
  --runs N                      measured provision+attach runs (default: 20)
  --warmup N                    unmeasured runs first (default: 1)
  --max-failures N              stop the runs after N failures (default: 3)
  --output-dir DIR              evidence directory, new or empty
                                (default: .tmp/storage-measure/<run-id>)

Images (digest-pinned references only):
  --fio-image REF               fio image with sh and sleep; required unless --skip-fio
  --probe-image REF             attach probe (default: pinned e2e busybox)
  --workload-image REF          git/cargo image (default: DEFAULT_WORKSPACE_IMAGE
                                from crates/codewire-server-core/src/runtime_images.rs)
  --with-docker                 add a privileged dind container (default image:
                                DEFAULT_DIND_IMAGE from the sandbox template) and
                                time a docker build; the namespace must admit it
  --dind-image REF              dind image for --with-docker
  --image-pull-secret NAME      existing pull Secret name to reference (never read)

Workloads:
  --git-url URL --git-commit SHA
                                public https repository and exact commit to clone
                                and build (default: ripgrep 15.2.0)
  --workload-cpu N --workload-memory SIZE
                                workload container resources (default: 4, 8Gi)
  --docker-data-size SIZE       dind ext4 data image size (default: 8G)
  --delta-mib N                 new data before the incremental snapshot (default: 256)
  --fio-size SIZE --fio-runtime S --fio-ramp S --fio-ioengine NAME --fio-direct 0|1
                                fio settings (default: 4g, 30, 5, libaio, 1)
  --skip-fio --skip-workload    omit those phases

Metrics, timeouts and debugging:
  --storage-namespace NAME      also sum that namespace's pods on the node
                                (for example piraeus-datastore or longhorn-system)
  --metrics-interval S          metrics sample interval, 0 disables (default: 10)
  --baseline-samples N          idle node samples before any pod (default: 3; needs --node)
  --attach-timeout S            per bind/ready wait (default: 300)
  --snapshot-timeout S          per snapshot readiness wait (default: 1800)
  --delete-timeout S            per deletion wait (default: 600)
  --exec-timeout S              per in-pod command (default: 3600)
  --keep                        leave every labelled object for debugging
  -h, --help                    show this help

Every object carries the label codewire.sh/storage-measure=<run-id>. The exit
status is 0 when every selected phase succeeded, 1 when a phase failed, and 2
for invalid arguments or a refused target.
USAGE
}

log() {
  printf '[storage-measure] %s\n' "$*" >&2
  if [[ -n "$LOG_FILE" ]]; then
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG_FILE" 2>/dev/null || true
  fi
}

refuse() {
  printf '[storage-measure] REFUSED: %s\n' "$*" >&2
  exit 2
}

now_ms() {
  local t="${EPOCHREALTIME/[.,]/}"
  printf '%s\n' "$((10#$t / 1000))"
}

require_uint() {
  local name="$1" value="$2" min="$3" max="$4"
  if [[ "$value" =~ ^[0-9]{1,9}$ ]] && ((10#$value >= min && 10#$value <= max)); then
    return 0
  fi
  refuse "$name must be an integer from $min to $max, got '$value'"
}

require_digest_ref() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$ ]] ||
    refuse "$name must be a digest-pinned image reference (name@sha256:<64 hex>), got '$value'"
}

require_dns_label() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] ||
    refuse "$name must be a DNS label, got '$value'"
}

require_dns_subdomain() {
  local name="$1" value="$2"
  [[ ${#value} -le 253 && "$value" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] ||
    refuse "$name must be a DNS subdomain, got '$value'"
}

require_pattern() {
  local name="$1" value="$2" pattern="$3"
  [[ "$value" =~ $pattern ]] || refuse "$name has an invalid value '$value'"
}

# Reads one digest-pinned `pub const NAME: &str = "..."` from Rust source, so
# the product defaults stay written in exactly one place.
read_rust_image_const() {
  local file="$1" name="$2" value
  value="$(sed -n "s/^pub const $name: &str = \"\\(.*\\)\";\$/\\1/p" "$file" 2>/dev/null || true)"
  [[ "$value" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] ||
    refuse "could not read a digest-pinned $name from ${file#"$ROOT"/}"
  printf '%s\n' "$value"
}

parse_args() {
  local option value
  while (($# > 0)); do
    case "$1" in
      --i-own-this-namespace) OWN_NAMESPACE=1; shift; continue ;;
      --with-docker) WITH_DOCKER=1; shift; continue ;;
      --skip-fio) SKIP_FIO=1; shift; continue ;;
      --skip-workload) SKIP_WORKLOAD=1; shift; continue ;;
      --keep) KEEP=1; shift; continue ;;
      -h|--help) usage; exit 0 ;;
    esac
    option="$1"
    value="${2:-}"
    case "$option" in
      --context) CONTEXT="$value" ;;
      --namespace) NAMESPACE="$value" ;;
      --storage-class) STORAGE_CLASS="$value" ;;
      --snapshot-class) SNAPSHOT_CLASS="$value" ;;
      --remote-snapshot-class) REMOTE_SNAPSHOT_CLASS="$value" ;;
      --runtime-class) RUNTIME_CLASS="$value" ;;
      --node) NODE="$value" ;;
      --runs) RUNS="$value" ;;
      --warmup) WARMUP="$value" ;;
      --max-failures) MAX_FAILURES="$value" ;;
      --output-dir) OUT_DIR="$value" ;;
      --pvc-size) PVC_SIZE="$value" ;;
      --fio-image) FIO_IMAGE="$value" ;;
      --fio-size) FIO_SIZE="$value" ;;
      --fio-runtime) FIO_RUNTIME="$value" ;;
      --fio-ramp) FIO_RAMP="$value" ;;
      --fio-ioengine) FIO_IOENGINE="$value" ;;
      --fio-direct) FIO_DIRECT="$value" ;;
      --probe-image) PROBE_IMAGE="$value" ;;
      --workload-image) WORKLOAD_IMAGE="$value" ;;
      --git-url) GIT_URL="$value" ;;
      --git-commit) GIT_COMMIT="$value" ;;
      --dind-image) DIND_IMAGE="$value" ;;
      --docker-data-size) DOCKER_DATA_SIZE="$value" ;;
      --delta-mib) DELTA_MIB="$value" ;;
      --workload-cpu) WORKLOAD_CPU="$value" ;;
      --workload-memory) WORKLOAD_MEMORY="$value" ;;
      --image-pull-secret) IMAGE_PULL_SECRET="$value" ;;
      --storage-namespace) STORAGE_NAMESPACE="$value" ;;
      --metrics-interval) METRICS_INTERVAL="$value" ;;
      --baseline-samples) BASELINE_SAMPLES="$value" ;;
      --attach-timeout) ATTACH_TIMEOUT="$value" ;;
      --snapshot-timeout) SNAPSHOT_TIMEOUT="$value" ;;
      --delete-timeout) DELETE_TIMEOUT="$value" ;;
      --exec-timeout) EXEC_TIMEOUT="$value" ;;
      *) refuse "unknown option: $option" ;;
    esac
    [[ $# -ge 2 ]] || refuse "$option requires a value"
    shift 2
  done
}

# Every check here runs before the first kubectl call.
validate_args() {
  ((BASH_VERSINFO[0] >= 5)) || refuse "bash 5 or newer is required"
  [[ -n "$CONTEXT" ]] || refuse "--context is required; the current context is never assumed"
  [[ -n "$NAMESPACE" ]] || refuse "--namespace is required"
  require_dns_label --namespace "$NAMESPACE"
  if [[ "$SM_PROTECTED_NAMESPACES" == *" $NAMESPACE "* || "$NAMESPACE" == kube-* ]]; then
    refuse "namespace $NAMESPACE is a system namespace"
  fi
  ((OWN_NAMESPACE == 1)) ||
    refuse "pass --i-own-this-namespace to confirm $NAMESPACE is yours to create and delete labelled objects in"
  [[ -n "$STORAGE_CLASS" ]] || refuse "--storage-class is required"
  require_dns_subdomain --storage-class "$STORAGE_CLASS"
  [[ -z "$SNAPSHOT_CLASS" ]] || require_dns_subdomain --snapshot-class "$SNAPSHOT_CLASS"
  [[ -z "$REMOTE_SNAPSHOT_CLASS" ]] || require_dns_subdomain --remote-snapshot-class "$REMOTE_SNAPSHOT_CLASS"
  [[ "$RUNTIME_CLASS" == none ]] || require_dns_subdomain --runtime-class "$RUNTIME_CLASS"
  [[ -z "$NODE" ]] || require_dns_subdomain --node "$NODE"
  [[ -z "$IMAGE_PULL_SECRET" ]] || require_dns_subdomain --image-pull-secret "$IMAGE_PULL_SECRET"
  [[ -z "$STORAGE_NAMESPACE" ]] || require_dns_label --storage-namespace "$STORAGE_NAMESPACE"
  require_uint --runs "$RUNS" 1 500
  require_uint --warmup "$WARMUP" 0 10
  require_uint --max-failures "$MAX_FAILURES" 1 500
  require_uint --fio-runtime "$FIO_RUNTIME" 1 3600
  require_uint --fio-ramp "$FIO_RAMP" 0 600
  require_uint --fio-direct "$FIO_DIRECT" 0 1
  require_uint --delta-mib "$DELTA_MIB" 0 65536
  require_uint --metrics-interval "$METRICS_INTERVAL" 0 3600
  require_uint --baseline-samples "$BASELINE_SAMPLES" 0 60
  require_uint --attach-timeout "$ATTACH_TIMEOUT" 10 7200
  require_uint --snapshot-timeout "$SNAPSHOT_TIMEOUT" 10 21600
  require_uint --delete-timeout "$DELETE_TIMEOUT" 10 7200
  require_uint --exec-timeout "$EXEC_TIMEOUT" 10 21600
  require_pattern --pvc-size "$PVC_SIZE" '^[1-9][0-9]*(Mi|Gi|Ti)$'
  require_pattern --fio-size "$FIO_SIZE" '^[1-9][0-9]*[kmgKMG]?$'
  require_pattern --fio-ioengine "$FIO_IOENGINE" '^[a-z0-9_]+$'
  require_pattern --docker-data-size "$DOCKER_DATA_SIZE" '^[1-9][0-9]*[MGT]$'
  require_pattern --workload-cpu "$WORKLOAD_CPU" '^([1-9][0-9]*|[1-9][0-9]*m)$'
  require_pattern --workload-memory "$WORKLOAD_MEMORY" '^[1-9][0-9]*(Mi|Gi)$'
  require_pattern --git-url "$GIT_URL" '^https://[A-Za-z0-9._~/-]+$'
  require_pattern --git-commit "$GIT_COMMIT" '^[0-9a-f]{40}$'
  require_digest_ref --probe-image "$PROBE_IMAGE"

  if ((SKIP_FIO == 0)); then
    [[ -n "$FIO_IMAGE" ]] ||
      refuse "--fio-image is required (no reviewed fio image is pinned in this repository); or pass --skip-fio"
    require_digest_ref --fio-image "$FIO_IMAGE"
  fi
  # The bench pod's workload container also writes snapshot markers.
  [[ -n "$WORKLOAD_IMAGE" ]] || WORKLOAD_IMAGE="$(read_rust_image_const "$SM_RUNTIME_IMAGES" DEFAULT_WORKSPACE_IMAGE)"
  require_digest_ref --workload-image "$WORKLOAD_IMAGE"
  if ((WITH_DOCKER == 1)); then
    ((SKIP_WORKLOAD == 0)) || refuse "--with-docker needs the workload phase"
    [[ -n "$DIND_IMAGE" ]] || DIND_IMAGE="$(read_rust_image_const "$SM_TEMPLATE_IMAGES" DEFAULT_DIND_IMAGE)"
    require_digest_ref --dind-image "$DIND_IMAGE"
  fi
}

new_run_id() {
  printf 'sm-%s-%s\n' "$(date -u +%Y%m%d%H%M%S)" "$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
}

build_config() {
  CONFIG_JSON="$(jq -cn \
    --arg run_id "$RUN_ID" \
    --arg namespace "$NAMESPACE" \
    --arg storage_class "$STORAGE_CLASS" \
    --arg runtime_class "$([[ "$RUNTIME_CLASS" == none ]] || printf '%s' "$RUNTIME_CLASS")" \
    --arg node "$NODE" \
    --arg pvc_size "$PVC_SIZE" \
    --arg probe_image "$PROBE_IMAGE" \
    --arg workload_image "$WORKLOAD_IMAGE" \
    --arg fio_image "$([[ "$SKIP_FIO" == 1 ]] || printf '%s' "$FIO_IMAGE")" \
    --arg dind_image "$([[ "$WITH_DOCKER" == 0 ]] || printf '%s' "$DIND_IMAGE")" \
    --arg docker_data_size "$DOCKER_DATA_SIZE" \
    --arg workload_cpu "$WORKLOAD_CPU" \
    --arg workload_memory "$WORKLOAD_MEMORY" \
    --arg image_pull_secret "$IMAGE_PULL_SECRET" \
    --argjson probe_deadline_s "$((3 * ATTACH_TIMEOUT + DELETE_TIMEOUT + 600))" \
    --argjson bench_deadline_s "$((4 * ATTACH_TIMEOUT + 6 * (FIO_RUNTIME + FIO_RAMP) + 5 * EXEC_TIMEOUT \
      + 3 * SNAPSHOT_TIMEOUT + 3 * DELETE_TIMEOUT + 1800))" \
    '$ARGS.named')"
}

# jq with the shared function library.
smjq() {
  jq -L "$SM_DIR" "$@"
}

render() {
  local program="$1"
  shift
  smjq -n --argjson cfg "$CONFIG_JSON" "$@" "include \"measure\"; $program"
}

kube() {
  timeout -k 10 120 kubectl --context "$CONTEXT" --request-timeout=60s "$@"
}

kns() {
  kube -n "$NAMESPACE" "$@"
}

# kube_wait SECONDS ARGS...: a kubectl wait with the same outer bound.
kube_wait() {
  local seconds="$1"
  shift
  timeout -k 10 "$((seconds + 60))" kubectl --context "$CONTEXT" -n "$NAMESPACE" \
    wait --timeout="${seconds}s" "$@" >/dev/null
}

kube_exec() {
  local seconds="$1"
  shift
  timeout -k 10 "$seconds" kubectl --context "$CONTEXT" -n "$NAMESPACE" exec "$@"
}

redact_parameters() {
  jq 'with_entries(if (.key | test("secret|password|token|key|credential"; "i"))
                   then .value = "<redacted>" else . end)'
}

get_json_or_null() {
  local out="$1"
  shift
  if ! kube "$@" -o json >"$out" 2>/dev/null; then
    printf 'null\n' >"$out"
  fi
}

preflight_cluster() {
  local contexts resources ns_json sc_json rc_json node_json version_json snap_json remote_json
  local pre="$OUT_DIR/preflight"
  mkdir -p "$pre"

  contexts="$(kubectl config get-contexts -o name)"
  grep -Fxq -- "$CONTEXT" <<<"$contexts" || refuse "context $CONTEXT is not in the active kubeconfig"

  ns_json="$pre/namespace.json"
  kube get namespace "$NAMESPACE" -o json >"$ns_json" 2>/dev/null ||
    refuse "namespace $NAMESPACE does not exist in $CONTEXT; the harness never creates namespaces"
  if jq -e '.metadata.labels // {} | has("codewire.sh/runtime-scope")' "$ns_json" >/dev/null; then
    refuse "namespace $NAMESPACE is a Codewire sandbox namespace (codewire.sh/runtime-scope)"
  fi

  sc_json="$pre/storageclass.json"
  kube get storageclass "$STORAGE_CLASS" -o json >"$sc_json" 2>/dev/null ||
    refuse "StorageClass $STORAGE_CLASS does not exist"
  if [[ "$(jq -r '.volumeBindingMode // "Immediate"' "$sc_json")" != WaitForFirstConsumer ]]; then
    log "WARNING: StorageClass $STORAGE_CLASS does not use WaitForFirstConsumer; provisioning starts before scheduling"
  fi

  rc_json="$pre/runtimeclass.json"
  if [[ "$RUNTIME_CLASS" != none ]]; then
    kube get runtimeclass "$RUNTIME_CLASS" -o json >"$rc_json" 2>/dev/null ||
      refuse "RuntimeClass $RUNTIME_CLASS does not exist"
  else
    printf 'null\n' >"$rc_json"
  fi

  node_json="$pre/node.json"
  if [[ -n "$NODE" ]]; then
    kube get node "$NODE" -o json >"$node_json" 2>/dev/null || refuse "node $NODE does not exist"
  else
    printf 'null\n' >"$node_json"
  fi

  snap_json="$pre/snapshotclass.json"
  remote_json="$pre/remote-snapshotclass.json"
  printf 'null\n' >"$snap_json"
  printf 'null\n' >"$remote_json"
  if [[ -n "$SNAPSHOT_CLASS" || -n "$REMOTE_SNAPSHOT_CLASS" ]]; then
    resources="$(kube api-resources --api-group=snapshot.storage.k8s.io -o name 2>/dev/null || true)"
    grep -qx 'volumesnapshots.snapshot.storage.k8s.io' <<<"$resources" ||
      refuse "the snapshot.storage.k8s.io API is not installed"
    SNAPSHOT_API=1
    if [[ -n "$SNAPSHOT_CLASS" ]]; then
      kube get volumesnapshotclass "$SNAPSHOT_CLASS" -o json >"$snap_json" 2>/dev/null ||
        refuse "VolumeSnapshotClass $SNAPSHOT_CLASS does not exist"
    fi
    if [[ -n "$REMOTE_SNAPSHOT_CLASS" ]]; then
      kube get volumesnapshotclass "$REMOTE_SNAPSHOT_CLASS" -o json >"$remote_json" 2>/dev/null ||
        refuse "VolumeSnapshotClass $REMOTE_SNAPSHOT_CLASS does not exist"
    fi
  fi

  version_json="$pre/version.json"
  kube version -o json >"$version_json" 2>/dev/null || printf 'null\n' >"$version_json"
  if kube get --raw /apis/metrics.k8s.io/v1beta1 >/dev/null 2>&1; then
    METRICS_API=1
  else
    log "metrics.k8s.io is unavailable; node overhead will not be sampled"
  fi

  jq -n \
    --arg run_id "$RUN_ID" \
    --arg started_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg context "$CONTEXT" \
    --argjson metrics_api "$METRICS_API" \
    --argjson cfg "$CONFIG_JSON" \
    --argjson runs "$RUNS" --argjson warmup "$WARMUP" \
    --arg snapshot_class "$SNAPSHOT_CLASS" --arg remote_snapshot_class "$REMOTE_SNAPSHOT_CLASS" \
    --arg git_url "$GIT_URL" --arg git_commit "$GIT_COMMIT" \
    --arg fio_size "$FIO_SIZE" --argjson fio_runtime "$FIO_RUNTIME" --argjson fio_ramp "$FIO_RAMP" \
    --arg fio_ioengine "$FIO_IOENGINE" --argjson fio_direct "$FIO_DIRECT" \
    --argjson delta_mib "$DELTA_MIB" --argjson with_docker "$WITH_DOCKER" \
    --argjson skip_fio "$SKIP_FIO" --argjson skip_workload "$SKIP_WORKLOAD" \
    --arg storage_namespace "$STORAGE_NAMESPACE" \
    --slurpfile sc "$sc_json" --slurpfile rc "$rc_json" --slurpfile node "$node_json" \
    --slurpfile snap "$snap_json" --slurpfile remote "$remote_json" --slurpfile version "$version_json" \
    --argjson sc_parameters "$(jq '.parameters // {}' "$sc_json" | redact_parameters)" \
    --argjson snap_parameters "$(jq '.parameters // {}' "$snap_json" | redact_parameters)" \
    --argjson remote_parameters "$(jq '.parameters // {}' "$remote_json" | redact_parameters)" \
    '
    def snapshot_class($c; $p): if $c == null then null
      else {name: $c.metadata.name, driver: $c.driver, deletionPolicy: $c.deletionPolicy, parameters: $p} end;
    {
      schema: "codewire.sh/storage-measure-meta/v1",
      run_id: $run_id,
      started_at: $started_at,
      inputs: {
        context: $context, namespace: $cfg.namespace, storage_class: $cfg.storage_class,
        snapshot_class: $snapshot_class, remote_snapshot_class: $remote_snapshot_class,
        runtime_class: $cfg.runtime_class, node: $cfg.node, pvc_size: $cfg.pvc_size,
        runs: $runs, warmup: $warmup,
        probe_image: $cfg.probe_image, workload_image: $cfg.workload_image,
        fio_image: $cfg.fio_image, dind_image: $cfg.dind_image,
        git_url: $git_url, git_commit: $git_commit,
        fio: {size: $fio_size, runtime_s: $fio_runtime, ramp_s: $fio_ramp, ioengine: $fio_ioengine, direct: $fio_direct},
        workload_cpu: $cfg.workload_cpu, workload_memory: $cfg.workload_memory,
        with_docker: ($with_docker == 1), delta_mib: $delta_mib,
        skip_fio: ($skip_fio == 1), skip_workload: ($skip_workload == 1),
        storage_namespace: $storage_namespace
      },
      cluster: {
        server_version: ($version[0].serverVersion.gitVersion // null),
        metrics_api: ($metrics_api == 1),
        storage_class: {
          provisioner: $sc[0].provisioner,
          volumeBindingMode: ($sc[0].volumeBindingMode // "Immediate"),
          reclaimPolicy: ($sc[0].reclaimPolicy // "Delete"),
          allowVolumeExpansion: ($sc[0].allowVolumeExpansion // false),
          parameters: $sc_parameters
        },
        runtime_class: (if $rc[0] == null then null else {handler: $rc[0].handler, overhead: ($rc[0].overhead // null)} end),
        node: (if $node[0] == null then null else {
          name: $node[0].metadata.name,
          kernel: $node[0].status.nodeInfo.kernelVersion,
          os_image: $node[0].status.nodeInfo.osImage,
          kubelet: $node[0].status.nodeInfo.kubeletVersion,
          container_runtime: $node[0].status.nodeInfo.containerRuntimeVersion,
          capacity: {cpu: $node[0].status.capacity.cpu, memory: $node[0].status.capacity.memory},
          allocatable: {cpu: $node[0].status.allocatable.cpu, memory: $node[0].status.allocatable.memory}
        } end),
        snapshot_class: snapshot_class($snap[0]; $snap_parameters),
        remote_snapshot_class: snapshot_class($remote[0]; $remote_parameters)
      }
    }' >"$OUT_DIR/meta.json"
}

phase_begin() {
  printf '%s\n' "$1" >"$OUT_DIR/.phase"
  log "phase $1: start"
  PHASE_STARTED_MS="$(now_ms)"
}

# phase_end NAME STATUS [REASON]
phase_end() {
  local name="$1" status="$2" reason="${3:-}"
  jq -cn --arg phase "$name" --arg status "$status" --arg reason "$reason" \
    --argjson started "$PHASE_STARTED_MS" --argjson ended "$(now_ms)" \
    '{phase: $phase, status: $status, reason: (if $reason == "" then null else $reason end),
      started_ms: $started, duration_ms: ($ended - $started)}' >>"$OUT_DIR/phases.ndjson"
  if [[ "$status" == failed ]]; then
    FAILED_PHASES=$((FAILED_PHASES + 1))
    log "phase $name: FAILED${reason:+ ($reason)}"
  else
    log "phase $name: $status${reason:+ ($reason)}"
  fi
  printf 'idle\n' >"$OUT_DIR/.phase"
}

phase_skip() {
  PHASE_STARTED_MS="$(now_ms)"
  phase_end "$1" skipped "$2"
}

sample_metrics() {
  local node phase t tmp="$OUT_DIR/.metrics"
  node="$(cat "$OUT_DIR/.node" 2>/dev/null || true)"
  [[ -n "$node" ]] || return 0
  phase="$(cat "$OUT_DIR/.phase" 2>/dev/null || printf 'idle')"
  t="$(now_ms)"
  mkdir -p "$tmp"
  kube get --raw "/apis/metrics.k8s.io/v1beta1/nodes/$node" >"$tmp/node.json" 2>/dev/null || return 0
  if [[ -n "$STORAGE_NAMESPACE" ]]; then
    get_json_or_null "$tmp/pods.json" -n "$STORAGE_NAMESPACE" get pods
    kube get --raw "/apis/metrics.k8s.io/v1beta1/namespaces/$STORAGE_NAMESPACE/pods" \
      >"$tmp/pod-metrics.json" 2>/dev/null || printf 'null\n' >"$tmp/pod-metrics.json"
  else
    printf 'null\n' >"$tmp/pods.json"
    printf 'null\n' >"$tmp/pod-metrics.json"
  fi
  smjq -cn --argjson t "$t" --arg phase "$phase" --arg node "$node" \
    --slurpfile nm "$tmp/node.json" --slurpfile pods "$tmp/pods.json" \
    --slurpfile pm "$tmp/pod-metrics.json" \
    'include "measure"; metrics_sample($t; $phase; $node; $nm[0]; $pods[0]; $pm[0])' \
    >>"$OUT_DIR/metrics.ndjson"
}

metrics_sampler_loop() {
  while [[ -e "$OUT_DIR/.sampling" ]]; do
    sample_metrics 2>>"$OUT_DIR/metrics.err" || true
    sleep "$METRICS_INTERVAL"
  done
}

start_metrics() {
  ((METRICS_API == 1 && METRICS_INTERVAL > 0)) || return 0
  local i
  : >"$OUT_DIR/.sampling"
  if [[ -n "$NODE" ]] && ((BASELINE_SAMPLES > 0)); then
    phase_begin baseline
    for ((i = 0; i < BASELINE_SAMPLES; i++)); do
      ((i == 0)) || sleep "$METRICS_INTERVAL"
      sample_metrics 2>>"$OUT_DIR/metrics.err" || true
    done
    phase_end baseline ok
  fi
  metrics_sampler_loop &
  SAMPLER_PID=$!
}

stop_metrics() {
  rm -f "$OUT_DIR/.sampling"
  if [[ -n "$SAMPLER_PID" ]]; then
    kill "$SAMPLER_PID" 2>/dev/null || true
    wait "$SAMPLER_PID" 2>/dev/null || true
    SAMPLER_PID=''
  fi
}

remember_node() {
  local node="$1"
  [[ -n "$node" && "$node" != null ]] || return 0
  [[ -s "$OUT_DIR/.node" ]] || printf '%s\n' "$node" >"$OUT_DIR/.node"
}

collect_volume_objects() {
  local raw="$1" pvc="$2" pod="$3" pv
  get_json_or_null "$raw/pvc.json" -n "$NAMESPACE" get pvc "$pvc"
  get_json_or_null "$raw/pod.json" -n "$NAMESPACE" get pod "$pod"
  pv="$(jq -r '.spec.volumeName // empty' "$raw/pvc.json" 2>/dev/null || true)"
  if [[ -n "$pv" ]]; then
    get_json_or_null "$raw/pv.json" get pv "$pv"
  else
    printf 'null\n' >"$raw/pv.json"
  fi
  get_json_or_null "$raw/pvc-events.json" -n "$NAMESPACE" get events \
    --field-selector "involvedObject.kind=PersistentVolumeClaim,involvedObject.name=$pvc"
  get_json_or_null "$raw/pod-events.json" -n "$NAMESPACE" get events \
    --field-selector "involvedObject.kind=Pod,involvedObject.name=$pod"
  jq -n --slurpfile pvc "$raw/pvc.json" --slurpfile pv "$raw/pv.json" --slurpfile pod "$raw/pod.json" \
    --slurpfile pvc_events "$raw/pvc-events.json" --slurpfile pod_events "$raw/pod-events.json" \
    '{pvc: $pvc[0], pv: $pv[0], pod: $pod[0], pvc_events: $pvc_events[0], pod_events: $pod_events[0]}' \
    >"$raw/bundle.json"
}

# delete_volume RAW PVC POD: timed pod, PVC and PV deletion into RAW/teardown.json.
delete_volume() {
  local raw="$1" pvc="$2" pod="$3" pv reclaim t0 t1 t2 t3 status=ok error=''
  pv="$(jq -r '.spec.volumeName // empty' "$raw/pvc.json" 2>/dev/null || true)"
  reclaim="$(jq -r '.spec.persistentVolumeReclaimPolicy // empty' "$raw/pv.json" 2>/dev/null || true)"
  t0="$(now_ms)"
  if ! kube_wait_delete pod "$pod"; then
    status=failed
    error="pod deletion exceeded ${DELETE_TIMEOUT}s"
  fi
  t1="$(now_ms)"
  if ! kube_wait_delete pvc "$pvc"; then
    status=failed
    error="${error:+$error; }PVC deletion exceeded ${DELETE_TIMEOUT}s"
  fi
  t2="$(now_ms)"
  t3=''
  if [[ -n "$pv" && "$reclaim" != Retain && "$status" == ok ]]; then
    if timeout -k 10 "$((DELETE_TIMEOUT + 60))" kubectl --context "$CONTEXT" wait \
        --for=delete "pv/$pv" --timeout="${DELETE_TIMEOUT}s" >/dev/null 2>&1; then
      t3="$(now_ms)"
    else
      status=failed
      error="PV $pv was not removed within ${DELETE_TIMEOUT}s"
    fi
  elif [[ "$reclaim" == Retain ]]; then
    log "WARNING: PV $pv has reclaimPolicy Retain and is left for its owner"
  fi
  jq -n --arg status "$status" --arg error "$error" --arg reclaim "$reclaim" \
    --argjson t0 "$t0" --argjson t1 "$t1" --argjson t2 "$t2" --argjson t3 "${t3:-null}" \
    '{status: $status, error: (if $error == "" then null else $error end),
      reclaim_policy: (if $reclaim == "" then null else $reclaim end),
      pod_delete_ms: ($t1 - $t0), pvc_delete_ms: ($t2 - $t1),
      pv_delete_ms: (if $t3 == null then null else $t3 - $t2 end),
      total_ms: (if $t3 == null then null else $t3 - $t0 end)}' >"$raw/teardown.json"
  [[ "$status" == ok ]]
}

kube_wait_delete() {
  local kind="$1" name="$2"
  timeout -k 10 "$((DELETE_TIMEOUT + 60))" kubectl --context "$CONTEXT" -n "$NAMESPACE" \
    delete "$kind" "$name" --ignore-not-found --wait=true --timeout="${DELETE_TIMEOUT}s" >/dev/null 2>&1
}

# volume_cycle RECORD LABEL ROLE WARMUP [SNAPSHOT] [MARKER]
# Creates a PVC (optionally from a VolumeSnapshot) and a probe pod together,
# as a sandbox claim does, times bind and ContainersReady, optionally checks
# the restored marker, then times the teardown. Writes one JSON record.
volume_cycle() {
  local record="$1" label="$2" role="$3" warmup="$4" snapshot="${5:-}" marker="${6:-}"
  local name="$RUN_ID-$label" raw="$OUT_DIR/raw/$label"
  local t_create='' t_bound='' t_ready='' status=ok error='' verified=null got
  mkdir -p "$raw"
  render '[sm_pvc($cfg; $name; $role; $snapshot), sm_probe_pod($cfg; $name; $name; $role)] | sm_list' \
    --arg name "$name" --arg role "$role" --arg snapshot "$snapshot" >"$raw/manifest.json"

  t_create="$(now_ms)"
  if ! kns create -f "$raw/manifest.json" >/dev/null 2>"$raw/create.err"; then
    status=failed
    error="create failed: $(tr -d '\n' <"$raw/create.err" | cut -c1-300)"
  elif ! kube_wait "$ATTACH_TIMEOUT" "pvc/$name" --for=jsonpath='{.status.phase}'=Bound; then
    status=failed
    error="PVC not Bound within ${ATTACH_TIMEOUT}s"
  else
    t_bound="$(now_ms)"
    if kube_wait "$ATTACH_TIMEOUT" "pod/$name" --for=condition=ContainersReady; then
      t_ready="$(now_ms)"
    else
      status=failed
      error="pod not ContainersReady within ${ATTACH_TIMEOUT}s"
    fi
  fi
  collect_volume_objects "$raw" "$name" "$name"
  remember_node "$(jq -r '.spec.nodeName // empty' "$raw/pod.json" 2>/dev/null || true)"

  if [[ -n "$marker" && "$status" == ok ]]; then
    if got="$(kube_exec "$ATTACH_TIMEOUT" "$name" -c probe -- cat /workspace/sm/marker 2>/dev/null)" &&
        [[ "$got" == "$marker" ]]; then
      verified=true
    else
      verified=false
      status=failed
      error="restored volume does not hold the expected marker"
    fi
  fi

  if ((KEEP == 1)); then
    printf '{"status":"skipped","error":"--keep"}\n' >"$raw/teardown.json"
  else
    delete_volume "$raw" "$name" "$name" || true
  fi

  smjq -n --arg label "$label" --arg role "$role" --argjson warmup "$warmup" \
    --arg status "$status" --arg error "$error" --arg snapshot "$snapshot" \
    --argjson t_create "$t_create" --argjson t_bound "${t_bound:-null}" --argjson t_ready "${t_ready:-null}" \
    --argjson verified "$verified" \
    --slurpfile bundle "$raw/bundle.json" --slurpfile teardown "$raw/teardown.json" \
    'include "measure";
     {label: $label, role: $role, warmup: $warmup, status: $status,
      error: (if $error == "" then null else $error end),
      data_source: (if $snapshot == "" then null else {kind: "VolumeSnapshot", name: $snapshot} end),
      client: {
        create_to_bound_ms: delta($t_create; $t_bound),
        create_to_ready_ms: delta($t_create; $t_ready),
        bound_to_ready_ms: delta($t_bound; $t_ready)
      },
      server: ($bundle[0] | server_timeline),
      content_verified: $verified,
      teardown: $teardown[0]}' >"$record"
  [[ "$status" == ok ]]
}

phase_attach() {
  local i total failed=0 record
  total=$((WARMUP + RUNS))
  phase_begin attach
  mkdir -p "$OUT_DIR/attach"
  for ((i = 0; i < total; i++)); do
    record="$(printf '%s/attach/run-%03d.json' "$OUT_DIR" "$i")"
    if ((i < WARMUP)); then
      volume_cycle "$record" "$(printf 'attach-%03d' "$i")" attach true || failed=$((failed + 1))
    else
      volume_cycle "$record" "$(printf 'attach-%03d' "$i")" attach false || failed=$((failed + 1))
    fi
    log "attach run $((i + 1))/$total: $(jq -r '"\(.status) ready=\(.client.create_to_ready_ms)ms bound=\(.client.create_to_bound_ms)ms teardown=\(.teardown.total_ms)ms"' "$record")"
    if ((failed >= MAX_FAILURES)); then
      phase_end attach failed "stopped after $failed failed runs of $((i + 1))"
      return
    fi
  done
  if ((failed > 0)); then
    phase_end attach failed "$failed of $total runs failed"
  else
    phase_end attach ok
  fi
}

create_scripts_configmap() {
  render 'sm_scripts_configmap($cfg; $name; $workload; $dind)' \
    --arg name "$RUN_ID-scripts" \
    --rawfile workload "$SM_DIR/pod/workload.sh" \
    --rawfile dind "$SM_DIR/pod/dind-bootstrap.sh" >"$OUT_DIR/raw/scripts-configmap.json"
  kns create -f "$OUT_DIR/raw/scripts-configmap.json" >/dev/null
}

bench_start() {
  local raw="$OUT_DIR/raw/bench" fio_pvc='' t_create t_ready
  mkdir -p "$raw"
  BENCH_POD="$RUN_ID-bench"
  BENCH_PVC="$RUN_ID-bench"
  if ((SKIP_FIO == 0)); then
    fio_pvc="$RUN_ID-bench-fio"
  fi
  create_scripts_configmap || return 1
  render '[sm_pvc($cfg; $pvc; "bench"; ""),
           (if $fio_pvc == "" then empty else sm_pvc($cfg; $fio_pvc; "bench-fio"; "") end),
           sm_bench_pod($cfg; $pod; $pvc; $fio_pvc; $scripts)] | sm_list' \
    --arg pod "$BENCH_POD" --arg pvc "$BENCH_PVC" --arg fio_pvc "$fio_pvc" \
    --arg scripts "$RUN_ID-scripts" >"$raw/manifest.json"
  t_create="$(now_ms)"
  kns create -f "$raw/manifest.json" >/dev/null 2>"$raw/create.err" || return 1
  BENCH_FIO_PVC="$fio_pvc"
  if ! kube_wait "$ATTACH_TIMEOUT" "pod/$BENCH_POD" --for=condition=ContainersReady; then
    collect_volume_objects "$raw" "$BENCH_PVC" "$BENCH_POD"
    log "bench pod did not become ready; see $raw"
    return 1
  fi
  t_ready="$(now_ms)"
  collect_volume_objects "$raw" "$BENCH_PVC" "$BENCH_POD"
  remember_node "$(jq -r '.spec.nodeName // empty' "$raw/pod.json")"
  smjq -n --argjson ms "$((t_ready - t_create))" --slurpfile bundle "$raw/bundle.json" \
    'include "measure"; {create_to_ready_ms: $ms, server: ($bundle[0] | server_timeline)}' \
    >"$OUT_DIR/bench.json"
}

bench_stop() {
  [[ -n "$BENCH_POD" ]] || return 0
  local raw="$OUT_DIR/raw/bench" rc=0
  if ((KEEP == 0)); then
    delete_volume "$raw" "$BENCH_PVC" "$BENCH_POD" || rc=1
    if [[ -n "$BENCH_FIO_PVC" ]]; then
      kube_wait_delete pvc "$BENCH_FIO_PVC" || rc=1
    fi
    if [[ -s "$OUT_DIR/bench.json" ]]; then
      jq --slurpfile teardown "$raw/teardown.json" '. + {teardown: $teardown[0]}' \
        "$OUT_DIR/bench.json" >"$OUT_DIR/bench.json.tmp" && mv "$OUT_DIR/bench.json.tmp" "$OUT_DIR/bench.json"
    fi
  fi
  BENCH_POD=''
  return "$rc"
}

# fio job table: name rw block-size iodepth direction
readonly SM_FIO_JOBS=(
  'seqwrite-1m-qd16 write 1m 16 write'
  'seqread-1m-qd16 read 1m 16 read'
  'randread-4k-qd1 randread 4k 1 read'
  'randread-4k-qd16 randread 4k 16 read'
  'randwrite-4k-qd1 randwrite 4k 1 write'
  'randwrite-4k-qd16 randwrite 4k 16 write'
)

# fio can print warnings before its JSON document; keep only the document.
extract_fio_json() {
  sed -n '/^{/,$p'
}

phase_fio() {
  local job name rw bs iodepth direction out summary results=() failed=0 version
  phase_begin fio
  mkdir -p "$OUT_DIR/fio"
  version="$(kube_exec 60 "$BENCH_POD" -c fio -- fio --version 2>/dev/null | tr -cd 'A-Za-z0-9._-' || true)"
  for job in "${SM_FIO_JOBS[@]}"; do
    read -r name rw bs iodepth direction <<<"$job"
    out="$OUT_DIR/fio/$name.json"
    log "fio $name"
    if ! kube_exec "$((FIO_RUNTIME + FIO_RAMP + EXEC_TIMEOUT))" "$BENCH_POD" -c fio -- \
        fio --name="$name" --filename=/fio/sm-fio.dat --size="$FIO_SIZE" \
          --rw="$rw" --bs="$bs" --iodepth="$iodepth" --numjobs=1 \
          --ioengine="$FIO_IOENGINE" --direct="$FIO_DIRECT" --invalidate=1 \
          --time_based --runtime="$FIO_RUNTIME" --ramp_time="$FIO_RAMP" \
          --group_reporting --percentile_list=50:95:99:99.9 --output-format=json \
          >"$out.raw" 2>"$out.err"; then
      failed=$((failed + 1))
      log "fio $name failed: $(tail -n 3 "$out.err" | tr '\n' ' ')"
      continue
    fi
    extract_fio_json <"$out.raw" >"$out"
    if summary="$(smjq -c --arg name "$name" --arg rw "$rw" --arg bs "$bs" \
        --argjson iodepth "$iodepth" --arg direction "$direction" \
        'include "measure"; fio_summary({name: $name, rw: $rw, bs: $bs, iodepth: $iodepth, direction: $direction})' \
        "$out")" && jq -e '(.error // 0) == 0 and .iops != null' <<<"$summary" >/dev/null; then
      results+=("$summary")
    else
      failed=$((failed + 1))
      log "fio $name produced no usable result"
    fi
  done
  kube_exec 120 "$BENCH_POD" -c fio -- rm -f /fio/sm-fio.dat >/dev/null 2>&1 || true
  printf '%s\n' "${results[@]}" | jq -s --arg version "$version" 'map(. + {fio_version: $version})' \
    >"$OUT_DIR/fio.json"
  if ((failed > 0)); then
    phase_end fio failed "$failed fio jobs failed"
  else
    phase_end fio ok
  fi
}

# parse_workload_output STDOUT_FILE EXIT_CODE: workload.sh output to JSON.
parse_workload_output() {
  local stdout="$1" exit_code="$2"
  jq -Rn --argjson exit_code "$exit_code" '
    [inputs] as $lines
    | {
        exit_code: $exit_code,
        info: ([$lines[] | select(startswith("SM_INFO ")) | .[8:] | fromjson] | first // null),
        steps: [$lines[] | select(startswith("SM_RESULT ")) | .[10:] | fromjson]
      }' <"$stdout"
}

phase_workload() {
  local rc=0 docker_wait=0
  phase_begin workload
  ((WITH_DOCKER == 0)) || docker_wait=180
  # Each step is bounded by --exec-timeout inside the pod; this bounds them all.
  kube_exec "$((4 * EXEC_TIMEOUT))" "$BENCH_POD" -c workload -- \
    env SM_ROOT=/workspace/sm SM_GIT_URL="$GIT_URL" SM_GIT_COMMIT="$GIT_COMMIT" \
      SM_STEP_TIMEOUT_SECONDS="$EXEC_TIMEOUT" SM_DOCKER_WAIT_SECONDS="$docker_wait" \
      bash /sm/workload.sh >"$OUT_DIR/workload.out" 2>"$OUT_DIR/workload.err" || rc=$?
  if ! parse_workload_output "$OUT_DIR/workload.out" "$rc" >"$OUT_DIR/workload.json"; then
    phase_end workload failed "unreadable workload output"
    return
  fi
  if ((rc != 0)); then
    phase_end workload failed "workload exited $rc"
  else
    phase_end workload ok
  fi
}

write_marker() {
  local value="$1" delta_mib="${2:-0}"
  kube_exec "$EXEC_TIMEOUT" "$BENCH_POD" -c workload -- \
    env SM_ROOT=/workspace/sm bash /sm/workload.sh --write-marker "$value" "$delta_mib" \
    >/dev/null 2>>"$OUT_DIR/marker.err"
}

volume_used_mib() {
  kube_exec 120 "$BENCH_POD" -c workload -- df -Pm /workspace 2>/dev/null |
    awk 'NR == 2 { print $3 }' | tr -cd '0-9'
}

# snapshot_measure RECORD LABEL CLASS PVC: create a VolumeSnapshot and time
# create to readyToUse. Leaves the snapshot in place for restore.
snapshot_measure() {
  local record="$1" label="$2" class="$3" pvc="$4"
  local name="$RUN_ID-$label" raw="$OUT_DIR/raw/$label" t0 t1='' status=ok error='' used
  mkdir -p "$raw"
  used="$(volume_used_mib || true)"
  render 'sm_volume_snapshot($cfg; $name; $class; $pvc; $role)' \
    --arg name "$name" --arg class "$class" --arg pvc "$pvc" --arg role "$label" >"$raw/manifest.json"
  t0="$(now_ms)"
  if ! kns create -f "$raw/manifest.json" >/dev/null 2>"$raw/create.err"; then
    status=failed
    error="create failed: $(tr -d '\n' <"$raw/create.err" | cut -c1-300)"
  elif kube_wait "$SNAPSHOT_TIMEOUT" "volumesnapshot/$name" --for=jsonpath='{.status.readyToUse}'=true; then
    t1="$(now_ms)"
  else
    status=failed
    error="VolumeSnapshot not readyToUse within ${SNAPSHOT_TIMEOUT}s"
  fi
  get_json_or_null "$raw/volumesnapshot.json" -n "$NAMESPACE" get volumesnapshot "$name"
  get_json_or_null "$raw/volumesnapshotcontent.json" get volumesnapshotcontent \
    "$(jq -r '.status.boundVolumeSnapshotContentName // "none"' "$raw/volumesnapshot.json")"
  smjq -n --arg label "$label" --arg class "$class" --arg status "$status" --arg error "$error" \
    --argjson t0 "$t0" --argjson t1 "${t1:-null}" --argjson used "${used:-null}" \
    --slurpfile vs "$raw/volumesnapshot.json" --slurpfile vsc "$raw/volumesnapshotcontent.json" \
    'include "measure";
     {label: $label, class: $class, status: $status,
      error: (if $error == "" then ($vs[0].status.error.message // null) else $error end),
      source_used_mib: $used,
      create_to_ready_ms: delta($t0; $t1),
      server_cut_after_create_ms: delta($vs[0].metadata.creationTimestamp | ts_ms; $vs[0].status.creationTime | ts_ms),
      restore_size: ($vs[0].status.restoreSize // null),
      content: ($vsc[0].metadata.name // null),
      snapshot_handle_present: (($vsc[0].status.snapshotHandle // "") != "")}' >"$record"
  [[ "$status" == ok ]]
}

snapshot_created() {
  jq -e '.metadata.name != null' "$OUT_DIR/raw/$1/volumesnapshot.json" >/dev/null 2>&1
}

# snapshot_delete LABEL: time VolumeSnapshot deletion and its content's removal.
snapshot_delete() {
  local label="$1" name="$RUN_ID-$1" raw="$OUT_DIR/raw/$1" content t0 t1 t2='' status=ok
  content="$(jq -r '.status.boundVolumeSnapshotContentName // empty' "$raw/volumesnapshot.json" 2>/dev/null || true)"
  t0="$(now_ms)"
  kube_wait_delete volumesnapshot "$name" || status=failed
  t1="$(now_ms)"
  if [[ -n "$content" && "$status" == ok ]]; then
    if timeout -k 10 "$((DELETE_TIMEOUT + 60))" kubectl --context "$CONTEXT" wait \
        --for=delete "volumesnapshotcontent/$content" --timeout="${DELETE_TIMEOUT}s" >/dev/null 2>&1; then
      t2="$(now_ms)"
    else
      status=failed
    fi
  fi
  jq -cn --arg status "$status" --argjson t0 "$t0" --argjson t1 "$t1" --argjson t2 "${t2:-null}" \
    '{status: $status, snapshot_delete_ms: ($t1 - $t0),
      content_delete_ms: (if $t2 == null then null else $t2 - $t1 end)}'
  [[ "$status" == ok ]]
}

phase_snapshot() {
  local marker="local:$RUN_ID" snap="$OUT_DIR/raw/snapshot-local.json" clone="$OUT_DIR/raw/clone-local.json"
  local deletion='null' status=ok reason=''
  phase_begin snapshot
  if ! write_marker "$marker" 0; then
    phase_end snapshot failed "could not write the marker"
    return
  fi
  if snapshot_measure "$snap" snapshot-local "$SNAPSHOT_CLASS" "$BENCH_PVC"; then
    volume_cycle "$clone" clone-local clone false "$RUN_ID-snapshot-local" "$marker" || {
      status=failed
      reason="clone from snapshot failed"
    }
  else
    status=failed
    reason="snapshot did not become ready"
    printf 'null\n' >"$clone"
  fi
  if ((KEEP == 0)) && snapshot_created snapshot-local; then
    deletion="$(snapshot_delete snapshot-local)" ||
      { status=failed; reason="${reason:+$reason; }snapshot deletion failed"; }
  fi
  jq -n --slurpfile snapshot "$snap" --slurpfile clone "$clone" --argjson deletion "$deletion" \
    '{snapshot: $snapshot[0], clone: $clone[0], deletion: $deletion}' >"$OUT_DIR/snapshot.json"
  phase_end snapshot "$status" "$reason"
}

phase_remote() {
  local full="$OUT_DIR/raw/remote-full.json" incr="$OUT_DIR/raw/remote-incremental.json"
  local restore="$OUT_DIR/raw/restore-remote.json" marker1="remote-1:$RUN_ID" marker2="remote-2:$RUN_ID"
  local del_full='null' del_incr='null' status=ok reason='' source_deleted=false
  phase_begin remote
  printf 'null\n' >"$incr"
  printf 'null\n' >"$restore"
  if ! write_marker "$marker1" 0; then
    phase_end remote failed "could not write the marker"
    return
  fi
  if ! snapshot_measure "$full" remote-full "$REMOTE_SNAPSHOT_CLASS" "$BENCH_PVC"; then
    status=failed
    reason="first remote snapshot did not become ready"
  elif ! write_marker "$marker2" "$DELTA_MIB"; then
    status=failed
    reason="could not write the incremental delta"
  elif ! snapshot_measure "$incr" remote-incremental "$REMOTE_SNAPSHOT_CLASS" "$BENCH_PVC"; then
    status=failed
    reason="incremental remote snapshot did not become ready"
  else
    # Restore with the source volume gone, as after losing its node.
    if ((KEEP == 0)); then
      bench_stop && source_deleted=true
    fi
    volume_cycle "$restore" restore-remote restore false "$RUN_ID-remote-incremental" "$marker2" || {
      status=failed
      reason="restore from the remote snapshot failed"
    }
  fi
  if ((KEEP == 0)); then
    if snapshot_created remote-incremental; then
      del_incr="$(snapshot_delete remote-incremental)" ||
        { status=failed; reason="${reason:+$reason; }incremental snapshot deletion failed"; }
    fi
    if snapshot_created remote-full; then
      del_full="$(snapshot_delete remote-full)" ||
        { status=failed; reason="${reason:+$reason; }full snapshot deletion failed"; }
    fi
  fi
  jq -n --slurpfile full "$full" --slurpfile incremental "$incr" --slurpfile restore "$restore" \
    --argjson delta_mib "$DELTA_MIB" --argjson source_deleted "$source_deleted" \
    --argjson del_full "${del_full:-null}" --argjson del_incr "${del_incr:-null}" \
    '{full: $full[0], incremental: ($incremental[0] + {delta_mib: $delta_mib}),
      source_deleted_before_restore: $source_deleted, restore: $restore[0],
      deletion: {full: $del_full, incremental: $del_incr}}' >"$OUT_DIR/remote.json"
  phase_end remote "$status" "$reason"
}

delete_labelled_kind() {
  timeout -k 10 "$((DELETE_TIMEOUT + 60))" kubectl --context "$CONTEXT" -n "$NAMESPACE" \
    delete "$1" -l "$2" --ignore-not-found --wait=true --timeout="${DELETE_TIMEOUT}s" >/dev/null 2>&1
}

delete_labelled() {
  local selector="$SM_LABEL_KEY=$RUN_ID" kinds=pod,pvc,configmap leftovers
  log "removing every object labelled $selector"
  delete_labelled_kind pod "$selector" || true
  delete_labelled_kind pvc,configmap "$selector" || true
  if ((SNAPSHOT_API == 1)); then
    kinds="$kinds,volumesnapshot"
    delete_labelled_kind volumesnapshot "$selector" || true
  fi
  leftovers="$(kns get "$kinds" -l "$selector" -o name 2>/dev/null || printf 'unknown\n')"
  jq -n --arg leftovers "$leftovers" \
    '{status: (if $leftovers == "" then "clean" else "leftovers" end),
      leftovers: ($leftovers | split("\n") | map(select(. != "")))}' >"$OUT_DIR/cleanup.json"
  if [[ -n "$leftovers" ]]; then
    log "WARNING: objects remain; inspect with: kubectl --context $CONTEXT -n $NAMESPACE get $kinds -l $selector"
  fi
}

cleanup() {
  local rc=$?
  ((CLEANUP_DONE == 0)) || return 0
  CLEANUP_DONE=1
  trap - EXIT INT TERM
  stop_metrics
  if ((CLUSTER_TOUCHED == 1)); then
    if ((KEEP == 1)); then
      log "--keep: objects remain; list them with: kubectl --context $CONTEXT -n $NAMESPACE get pod,pvc,configmap -l $SM_LABEL_KEY=$RUN_ID"
      printf '{"status":"kept","leftovers":[]}\n' >"$OUT_DIR/cleanup.json"
    else
      delete_labelled
    fi
  fi
  if [[ -n "$OUT_DIR" ]]; then
    rm -f "$OUT_DIR/.phase" "$OUT_DIR/.node" "$OUT_DIR/.sampling"
    rm -rf "$OUT_DIR/.metrics"
  fi
  if [[ -n "$OUT_DIR" && -s "$OUT_DIR/meta.json" ]]; then
    if "$SM_DIR/summarize.sh" "$OUT_DIR" >"$OUT_DIR/summary.json.tmp"; then
      mv "$OUT_DIR/summary.json.tmp" "$OUT_DIR/summary.json"
      log "summary: $OUT_DIR/summary.json"
    else
      log "WARNING: summary failed; raw evidence is in $OUT_DIR"
    fi
  fi
  if ((rc == 0 && FAILED_PHASES > 0)); then
    rc=1
  fi
  exit "$rc"
}

prepare_output() {
  if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="$ROOT/.tmp/storage-measure/$RUN_ID"
  fi
  if [[ -e "$OUT_DIR" ]] && [[ -n "$(ls -A "$OUT_DIR" 2>/dev/null)" ]]; then
    refuse "output directory $OUT_DIR is not empty"
  fi
  mkdir -p "$OUT_DIR/raw"
  OUT_DIR="$(cd "$OUT_DIR" && pwd)"
  LOG_FILE="$OUT_DIR/harness.log"
  printf 'idle\n' >"$OUT_DIR/.phase"
  if [[ -n "$NODE" ]]; then
    printf '%s\n' "$NODE" >"$OUT_DIR/.node"
  fi
}

main() {
  parse_args "$@"
  validate_args
  local tool
  for tool in kubectl jq timeout od; do
    command -v "$tool" >/dev/null 2>&1 || refuse "missing required command: $tool"
  done
  RUN_ID="$(new_run_id)"
  build_config
  prepare_output
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  log "run $RUN_ID: context=$CONTEXT namespace=$NAMESPACE storageClass=$STORAGE_CLASS runtimeClass=$RUNTIME_CLASS evidence=$OUT_DIR"
  preflight_cluster
  CLUSTER_TOUCHED=1
  start_metrics

  phase_attach

  if ((SKIP_FIO == 1 && SKIP_WORKLOAD == 1)) && [[ -z "$SNAPSHOT_CLASS" && -z "$REMOTE_SNAPSHOT_CLASS" ]]; then
    log "no bench phases selected"
  else
    phase_begin bench
    if bench_start; then
      phase_end bench ok
      if ((SKIP_FIO == 0)); then phase_fio; else phase_skip fio "--skip-fio"; fi
      if ((SKIP_WORKLOAD == 0)); then phase_workload; else phase_skip workload "--skip-workload"; fi
      if [[ -n "$SNAPSHOT_CLASS" ]]; then phase_snapshot; else phase_skip snapshot "no --snapshot-class"; fi
      if [[ -n "$REMOTE_SNAPSHOT_CLASS" ]]; then phase_remote; else phase_skip remote "no --remote-snapshot-class"; fi
    else
      phase_end bench failed "bench pod did not start"
    fi
    phase_begin bench-teardown
    if bench_stop; then phase_end bench-teardown ok; else phase_end bench-teardown failed "bench deletion failed"; fi
  fi
  log "finished: $FAILED_PHASES failed phase(s); evidence in $OUT_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
