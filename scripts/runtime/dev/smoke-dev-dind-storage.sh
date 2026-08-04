#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
NAMESPACE="${DIND_STORAGE_NAMESPACE:-dev-sandboxes}"
RUNTIME_CLASS="${DIND_STORAGE_RUNTIME_CLASS:-confidential}"
NODE="${DIND_STORAGE_NODE:-}"
DIND_IMAGE="${DIND_STORAGE_IMAGE:-docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c}"
DATA_IMAGE="${DIND_STORAGE_DATA_IMAGE:-/workspace/.codewire/docker-data.ext4}"
DATA_ROOT="${DIND_STORAGE_DATA_ROOT:-/var/lib/docker}"
DATA_SIZE="${DIND_STORAGE_DATA_SIZE:-4G}"
MOUNT_MODE="${DIND_STORAGE_MOUNT_MODE:-loop}"
PVC_SIZE="${DIND_STORAGE_PVC_SIZE:-8Gi}"
STORAGE_CLASS="${DIND_STORAGE_STORAGE_CLASS:-local-path}"
WAIT_SECONDS="${DIND_STORAGE_WAIT_SECONDS:-420}"
RUN_DOCKER="${DIND_STORAGE_RUN_DOCKER:-0}"
EXPECT_FAILURE="${DIND_STORAGE_EXPECT_FAILURE:-0}"
KEEP_PROBE="${DIND_STORAGE_KEEP_PROBE:-0}"
COCO_ANNOTATIONS="${DIND_STORAGE_COCO_ANNOTATIONS:-auto}"
COCO_KBS_URL="${DIND_STORAGE_COCO_KBS_URL:-http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080}"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/smoke-dev-dind-storage.sh [options]

Runs a focused Kubernetes probe for the Codewire guest-local dind storage
bootstrap. This intentionally bypasses Codewire environment creation, gateway,
auth, and transport checks so dind mount failures can be debugged quickly.

Options:
  --runtime-class NAME  RuntimeClass to use (default: confidential)
  --namespace NAME      Namespace to create the probe in (default: dev-sandboxes)
  --node NAME           Optional kubernetes.io/hostname node pin
  --image REF           dind image (default: pinned public Codewire dind digest)
  --data-image PATH     ext4 image path (default: /workspace/.codewire/docker-data.ext4)
  --data-root PATH      dockerd data root and mount target (default: /var/lib/docker)
  --data-size SIZE      truncate size for ext4 image (default: 4G)
  --mount-mode MODE     loop or none (default: loop)
  --pvc-size SIZE       probe workspace PVC request (default: 8Gi)
  --storage-class NAME  PVC StorageClass (default: local-path)
  --wait-seconds N      wait for probe pod completion (default: 420)
  --run-docker          After dockerd is ready, run hello-world
  --expect-failure      Treat a failed probe pod as expected and exit 0
  --keep-probe          Leave pod, ConfigMap, and PVC in place
  --coco-kbs-url URL    KBS URL for confidential CoCo annotations
  --no-coco-annotations Do not add CoCo annotations for confidential probes
  --evidence-dir DIR    Store evidence in DIR instead of repo .tmp
  -h, --help            Show this help

Examples:
  # Reproduce the current confidential target.
  scripts/runtime/dev/smoke-dev-dind-storage.sh \
    --runtime-class confidential \
    --node node1-codewire-dev \
    --data-root /var/lib/docker

  # Test the proposed workspace-local dockerd data root.
  scripts/runtime/dev/smoke-dev-dind-storage.sh \
    --runtime-class confidential \
    --node node1-codewire-dev \
    --data-root /workspace/.codewire/docker-root \
    --run-docker

Safety:
  - uses no Codewire API key and reads no secrets
  - creates only one pod, one ConfigMap, and one PVC
  - never mounts host Docker or containerd sockets
  - for confidential probes, adds dev Trustee/KBS CoCo annotations by default
USAGE
}

log() {
  printf '[dind-storage-smoke] %s\n' "$*" >&2
}

die() {
  printf '[dind-storage-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --runtime-class)
      [[ "$#" -ge 2 ]] || die "--runtime-class requires a value"
      RUNTIME_CLASS="$2"
      shift 2
      ;;
    --namespace)
      [[ "$#" -ge 2 ]] || die "--namespace requires a value"
      NAMESPACE="$2"
      shift 2
      ;;
    --node)
      [[ "$#" -ge 2 ]] || die "--node requires a value"
      NODE="$2"
      shift 2
      ;;
    --image)
      [[ "$#" -ge 2 ]] || die "--image requires a value"
      DIND_IMAGE="$2"
      shift 2
      ;;
    --data-image)
      [[ "$#" -ge 2 ]] || die "--data-image requires a value"
      DATA_IMAGE="$2"
      shift 2
      ;;
    --data-root)
      [[ "$#" -ge 2 ]] || die "--data-root requires a value"
      DATA_ROOT="$2"
      shift 2
      ;;
    --data-size)
      [[ "$#" -ge 2 ]] || die "--data-size requires a value"
      DATA_SIZE="$2"
      shift 2
      ;;
    --mount-mode)
      [[ "$#" -ge 2 ]] || die "--mount-mode requires a value"
      MOUNT_MODE="$2"
      shift 2
      ;;
    --pvc-size)
      [[ "$#" -ge 2 ]] || die "--pvc-size requires a value"
      PVC_SIZE="$2"
      shift 2
      ;;
    --storage-class)
      [[ "$#" -ge 2 ]] || die "--storage-class requires a value"
      STORAGE_CLASS="$2"
      shift 2
      ;;
    --wait-seconds)
      [[ "$#" -ge 2 ]] || die "--wait-seconds requires a value"
      WAIT_SECONDS="$2"
      shift 2
      ;;
    --run-docker)
      RUN_DOCKER=1
      shift
      ;;
    --expect-failure)
      EXPECT_FAILURE=1
      shift
      ;;
    --keep-probe)
      KEEP_PROBE=1
      shift
      ;;
    --coco-kbs-url)
      [[ "$#" -ge 2 ]] || die "--coco-kbs-url requires a value"
      COCO_KBS_URL="$2"
      shift 2
      ;;
    --no-coco-annotations)
      COCO_ANNOTATIONS=0
      shift
      ;;
    --evidence-dir)
      [[ "$#" -ge 2 ]] || die "--evidence-dir requires a value"
      EVIDENCE_DIR="$2"
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

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_bool01() {
  local name="$1"
  local value="$2"
  [[ "$value" == "0" || "$value" == "1" ]] || die "$name must be 0 or 1, got $value"
}

require_cmd kubectl
require_cmd jq

require_bool01 RUN_DOCKER "$RUN_DOCKER"
require_bool01 EXPECT_FAILURE "$EXPECT_FAILURE"
require_bool01 KEEP_PROBE "$KEEP_PROBE"
[[ "$WAIT_SECONDS" =~ ^[0-9]+$ ]] || die "--wait-seconds must be an integer"
[[ "$MOUNT_MODE" == "loop" || "$MOUNT_MODE" == "none" ]] || die "--mount-mode must be loop or none"
if [[ "$COCO_ANNOTATIONS" == "auto" ]]; then
  if [[ "$RUNTIME_CLASS" == "confidential" ]]; then
    COCO_ANNOTATIONS=1
  else
    COCO_ANNOTATIONS=0
  fi
fi
require_bool01 COCO_ANNOTATIONS "$COCO_ANNOTATIONS"
if [[ "$COCO_ANNOTATIONS" == "1" ]]; then
  require_cmd base64
  require_cmd gzip
fi

if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
  export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
fi

if [[ -z "$EVIDENCE_DIR" ]]; then
  mkdir -p "$ROOT/.tmp"
  EVIDENCE_DIR="$(mktemp -d "$ROOT/.tmp/codewire-dind-storage.XXXXXX")"
else
  mkdir -p "$EVIDENCE_DIR"
fi

kubectl_dev() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

rand_suffix() {
  od -An -N3 -tx1 /dev/urandom | tr -d ' \n'
}

NAME="dind-storage-${RUNTIME_CLASS}-$(date -u +%Y%m%d%H%M%S)-$(rand_suffix)"
PROBE_SCRIPT="$EVIDENCE_DIR/probe.sh"
MANIFEST="$EVIDENCE_DIR/probe.yaml"

build_coco_init_data() {
  cat <<EOF | gzip -n -c | base64 -w0
version = "0.1.0"
algorithm = "sha256"

[data]
"policy.rego" = '''
package agent_policy

default AddARPNeighborsRequest := true
default AddSwapPathRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CopyFileRequest := true
default CreateContainerRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := true
default GetDiagnosticDataRequest := false
default GetIPTablesRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemAgentCompactConfig := true
default MemAgentMemcgConfig := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default ReadStreamRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResizeVolumeRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SetIPTablesRequest := true
default SetPolicyRequest := false
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := false
default StatsContainerRequest := true
default StopTracingRequest := false
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default VolumeStatsRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
'''

"aa.toml" = '''
[token_configs]
[token_configs.kbs]
url = "${COCO_KBS_URL}"
'''

"cdh.toml" = '''
socket = "unix:///run/confidential-containers/cdh.sock"

[kbc]
name = "cc_kbc"
url = "${COCO_KBS_URL}"
'''
EOF
}

cleanup() {
  local rc="$1"
  if [[ "$KEEP_PROBE" == "1" ]]; then
    log "keeping probe resources by request: $NAME"
    return 0
  fi
  kubectl_dev -n "$NAMESPACE" delete pod "$NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl_dev -n "$NAMESPACE" delete cm "$NAME" --ignore-not-found >/dev/null 2>&1 || true
  kubectl_dev -n "$NAMESPACE" delete netpol "$NAME" --ignore-not-found >/dev/null 2>&1 || true
  kubectl_dev -n "$NAMESPACE" delete pvc "$NAME-workspace" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  return "$rc"
}

collect_evidence() {
  kubectl_dev -n "$NAMESPACE" get pod "$NAME" -o json >"$EVIDENCE_DIR/pod.json" 2>"$EVIDENCE_DIR/pod-json.err" || true
  kubectl_dev -n "$NAMESPACE" get pod "$NAME" -o yaml >"$EVIDENCE_DIR/pod.yaml.live" 2>"$EVIDENCE_DIR/pod-yaml.err" || true
  kubectl_dev -n "$NAMESPACE" describe pod "$NAME" >"$EVIDENCE_DIR/pod.describe.txt" 2>"$EVIDENCE_DIR/pod-describe.err" || true
  kubectl_dev -n "$NAMESPACE" logs "$NAME" -c dind >"$EVIDENCE_DIR/dind.log" 2>"$EVIDENCE_DIR/dind-log.err" || true
  kubectl_dev -n "$NAMESPACE" get pvc "$NAME-workspace" -o yaml >"$EVIDENCE_DIR/pvc.yaml" 2>"$EVIDENCE_DIR/pvc-yaml.err" || true
  kubectl_dev -n "$NAMESPACE" get events --sort-by=.lastTimestamp >"$EVIDENCE_DIR/events.txt" 2>"$EVIDENCE_DIR/events.err" || true
}

trap 'rc=$?; collect_evidence; cleanup "$rc"; exit "$rc"' EXIT

cat >"$PROBE_SCRIPT" <<'PROBE'
#!/bin/sh
set -eu

log() {
  printf '[dind-probe] %s\n' "$*"
}

docker_sock="${CODEWIRE_DOCKER_SOCK:-/var/run/docker/docker.sock}"
data_image="${CODEWIRE_DOCKER_DATA_IMAGE:-/workspace/.codewire/docker-data.ext4}"
data_root="${CODEWIRE_DOCKER_DATA_ROOT:-/var/lib/docker}"
data_size="${CODEWIRE_DOCKER_DATA_SIZE:-4G}"
mount_mode="${CODEWIRE_DOCKER_MOUNT_MODE:-loop}"
run_docker="${CODEWIRE_DOCKER_RUN_TEST:-0}"
codewire_dir="$(dirname "$data_image")"

log "runtime probe starting"
uname -a || true
id || true
log "data_image=$data_image"
log "data_root=$data_root"
log "data_size=$data_size"
log "mount_mode=$mount_mode"

mkdir -pv "$codewire_dir" "$data_root"
chown 1000:1000 "$codewire_dir"
chmod 0775 "$codewire_dir"

log "path state before mkfs/mount"
ls -ld / /var /var/lib /workspace "$codewire_dir" "$data_root" 2>&1 || true
if [ -L "$data_root" ]; then
  readlink "$data_root" || true
fi
log "loop/ext4 state before mount"
ls -l /dev/loop-control /dev/loop* 2>&1 || true
if command -v losetup >/dev/null 2>&1; then
  losetup -f 2>&1 || true
fi
grep -E '(^nodev[[:space:]]+)?ext4$|(^nodev[[:space:]]+)?loop$' /proc/filesystems 2>&1 || true

if [ "$mount_mode" = "loop" ]; then
  if [ ! -s "$data_image" ]; then
    log "creating ext4 image"
    truncate -s "$data_size" "$data_image"
    mkfs.ext4 -q -F "$data_image"
  fi

  log "mounting ext4 image"
  if ! awk -v target="$data_root" '$2 == target && $3 == "ext4" { found = 1 } END { exit found ? 0 : 1 }' /proc/mounts; then
    mount -o loop "$data_image" "$data_root"
  fi
else
  log "using plain directory data root"
fi
findmnt "$data_root" || true

log "starting dockerd"
dockerd --host "unix://$docker_sock" --group 1000 --data-root "$data_root" --storage-driver vfs > /tmp/dockerd.log 2>&1 &
dockerd_pid="$!"
trap 'kill "$dockerd_pid" 2>/dev/null || true; wait "$dockerd_pid" 2>/dev/null || true' EXIT

i=0
while [ "$i" -lt 90 ]; do
  if docker -H "unix://$docker_sock" info >/tmp/docker-info.txt 2>/tmp/docker-info.err; then
    log "dockerd ready"
    cat /tmp/docker-info.txt
    break
  fi
  i=$((i + 1))
  sleep 1
done

if [ "$i" -ge 90 ]; then
  log "dockerd did not become ready"
  cat /tmp/docker-info.err 2>/dev/null || true
  tail -200 /tmp/dockerd.log 2>/dev/null || true
  exit 1
fi

if [ "$run_docker" = "1" ]; then
  log "running hello-world"
  docker -H "unix://$docker_sock" run --rm hello-world
fi

log "probe passed"
PROBE
chmod 0755 "$PROBE_SCRIPT"

cat >"$MANIFEST" <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${NAME}-workspace
  namespace: ${NAMESPACE}
  labels:
    codewire.sh/probe: dind-storage
    codewire.sh/probe-id: ${NAME}
    codewire.sh/runtime-class: ${RUNTIME_CLASS}
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: ${STORAGE_CLASS}
  resources:
    requests:
      storage: ${PVC_SIZE}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${NAME}
  namespace: ${NAMESPACE}
  labels:
    codewire.sh/probe: dind-storage
    codewire.sh/probe-id: ${NAME}
    codewire.sh/runtime-class: ${RUNTIME_CLASS}
data:
  probe.sh: |
$(sed 's/^/    /' "$PROBE_SCRIPT")
---
apiVersion: v1
kind: Pod
metadata:
  name: ${NAME}
  namespace: ${NAMESPACE}
YAML

if [[ "$COCO_ANNOTATIONS" == "1" ]]; then
  COCO_INIT_DATA="$(build_coco_init_data)"
  COCO_KERNEL_PARAMS="agent.guest_components_rest_api=resource agent.aa_kbc_params=cc_kbc::${COCO_KBS_URL}"
  cat >>"$MANIFEST" <<YAML
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: ${COCO_INIT_DATA}
    io.katacontainers.config.hypervisor.kernel_params: "${COCO_KERNEL_PARAMS}"
YAML
fi

cat >>"$MANIFEST" <<YAML
  labels:
    codewire.sh/probe: dind-storage
    codewire.sh/probe-id: ${NAME}
    codewire.sh/runtime-class: ${RUNTIME_CLASS}
    codewire.sh/type: workspace
    app.kubernetes.io/managed-by: codewire-dind-storage-smoke
spec:
  restartPolicy: Never
  runtimeClassName: ${RUNTIME_CLASS}
  tolerations:
    - key: node.codewire.sh/runtime-candidate
      operator: Equal
      value: "true"
      effect: NoSchedule
YAML

if [[ -n "$NODE" ]]; then
  cat >>"$MANIFEST" <<YAML
  nodeSelector:
    kubernetes.io/hostname: ${NODE}
YAML
fi

cat >>"$MANIFEST" <<YAML
  containers:
    - name: dind
      image: ${DIND_IMAGE}
      imagePullPolicy: IfNotPresent
      command:
        - /bin/sh
        - /probe/probe.sh
      securityContext:
        privileged: true
        runAsUser: 0
        runAsGroup: 0
      env:
        - name: DOCKER_TLS_CERTDIR
          value: ""
        - name: CODEWIRE_DOCKER_DATA_IMAGE
          value: ${DATA_IMAGE}
        - name: CODEWIRE_DOCKER_DATA_ROOT
          value: ${DATA_ROOT}
        - name: CODEWIRE_DOCKER_DATA_SIZE
          value: ${DATA_SIZE}
        - name: CODEWIRE_DOCKER_MOUNT_MODE
          value: ${MOUNT_MODE}
        - name: CODEWIRE_DOCKER_RUN_TEST
          value: "${RUN_DOCKER}"
      volumeMounts:
        - name: workspace
          mountPath: /workspace
        - name: docker-sock
          mountPath: /var/run/docker
        - name: probe
          mountPath: /probe
          readOnly: true
      resources:
        requests:
          cpu: 500m
          memory: 1Gi
        limits:
          cpu: "2"
          memory: 4Gi
  volumes:
    - name: workspace
      persistentVolumeClaim:
        claimName: ${NAME}-workspace
    - name: docker-sock
      emptyDir: {}
    - name: probe
      configMap:
        name: ${NAME}
        defaultMode: 0755
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${NAME}
  namespace: ${NAMESPACE}
  labels:
    codewire.sh/probe: dind-storage
    codewire.sh/probe-id: ${NAME}
    codewire.sh/runtime-class: ${RUNTIME_CLASS}
spec:
  podSelector:
    matchLabels:
      codewire.sh/probe-id: ${NAME}
  policyTypes:
    - Egress
  egress:
    - ports:
        - port: 443
          protocol: TCP
      to:
        - ipBlock:
            cidr: 0.0.0.0/0
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
      to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
    - ports:
        - port: 8080
          protocol: TCP
      to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: codewire-trustee
          podSelector:
            matchLabels:
              app.kubernetes.io/name: codewire-trustee-kbs
YAML

log "evidence: $EVIDENCE_DIR"
log "creating probe $NAME runtimeClass=$RUNTIME_CLASS data_root=$DATA_ROOT"
kubectl_dev apply -f "$MANIFEST"

deadline=$((SECONDS + WAIT_SECONDS))
phase=""
while (( SECONDS < deadline )); do
  phase="$(kubectl_dev -n "$NAMESPACE" get pod "$NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  case "$phase" in
    Succeeded|Failed)
      break
      ;;
  esac
  sleep 5
done

collect_evidence

if [[ "$phase" == "Succeeded" ]]; then
  if [[ "$EXPECT_FAILURE" == "1" ]]; then
    die "probe succeeded but --expect-failure was set; evidence: $EVIDENCE_DIR"
  fi
  log "probe passed; evidence: $EVIDENCE_DIR"
  exit 0
fi

if [[ "$phase" != "Failed" ]]; then
  die "probe timed out in phase=${phase:-unknown}; evidence: $EVIDENCE_DIR"
fi

if [[ "$EXPECT_FAILURE" == "1" ]]; then
  log "probe failed as expected; evidence: $EVIDENCE_DIR"
  exit 0
fi

die "probe failed; evidence: $EVIDENCE_DIR"
