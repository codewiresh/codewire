#!/usr/bin/env bash
# Focused owned commodity fixture; see docs/dev/AGENT-WORKFLOW.md.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SOURCE_ROOT="$ROOT"
SUPPORT_IMAGE=''
STORAGE_CLASS=''
EVIDENCE_DIR=''
RENDERED_FIXTURE=''
FIXTURE_SHA256=''
EXPECTED_STORE=containerd
BASELINE=0
RENDER_ONLY=0
KEEP_PROBE=0
WAIT_SECONDS=420
NAME="dind-storage-$(date -u +%Y%m%d%H%M%S)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
POD_UID=''
PVC_UID=''
POLICY_UID=''
POLICY_NAME=''
readonly NAMESPACE=dev-sandboxes DEV_CLUSTER=cw-dev-hz-eu-1

log() { printf '[dind-storage-smoke] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
select_host_timeout() {
  TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
  [[ -n "$TIMEOUT_BIN" ]] || die 'missing timeout or gtimeout; install coreutils for bounded fixture commands'
  "$TIMEOUT_BIN" 1 sh -c ':' >/dev/null 2>&1 || die 'host timeout tool is unusable'
}
usage() {
  cat <<'HELP'
Usage: smoke-dev-dind-storage.sh --support-image REF --storage-class NAME [options]

Render the candidate's actual commodity Block-workspace preparation and DinD
bootstrap. The bootstrap is container PID1; a separate unprivileged client
uses its guest-only Unix socket. Creates its own Pod, workspace PVC and exact
product-rendered NetworkPolicy. No credential values, host sockets, custom
network rules or admission exceptions.

  --source-root DIR       Clean product checkout to render (default this checkout)
  --support-image REF     Current admitted daemon support image, pinned by digest
  --storage-class NAME    Current commodity workspace StorageClass
  --baseline              Record VFS first-child cgroup matrix, not qualification
  --render-only           Export a nonsecret fixture bundle without Kubernetes auth
  --rendered-fixture FILE Apply a separately exported bundle on the trusted host
  --fixture-sha256 HASH   Expected bundle hash recorded at the offline render
  --evidence-dir DIR      New empty directory for selected evidence
  --wait-seconds N        Readiness budget, 1–1800 seconds (default420)
  --keep-probe            Keep the exact named fixture for follow-up
  -h, --help              Show help without credentials or Kubernetes access

Run live only through the existing infrastructure kube-access wrapper for
cw-dev-hz-eu-1. A baseline can record expected resource failures; admission,
bootstrap and readiness errors always fail. Qualification requires actual
containerd/overlayfs, resource enforcement and build/save/reload custody.
HELP
}
case "$-" in *x*) die 'shell tracing is enabled' ;; esac
while (($#)); do
  case "$1" in
    --source-root|--support-image|--storage-class|--evidence-dir|--wait-seconds|--rendered-fixture|--fixture-sha256)
      (($# >= 2)) || die "$1 requires a value"
      case "$1" in
        --source-root) SOURCE_ROOT="$2" ;; --support-image) SUPPORT_IMAGE="$2" ;;
        --storage-class) STORAGE_CLASS="$2" ;;
        --evidence-dir) EVIDENCE_DIR="$2" ;; --wait-seconds) WAIT_SECONDS="$2" ;;
        --rendered-fixture) RENDERED_FIXTURE="$2" ;; --fixture-sha256) FIXTURE_SHA256="$2" ;;
      esac
      shift 2 ;;
    --baseline) BASELINE=1; EXPECTED_STORE=vfs; shift ;;
    --render-only) RENDER_ONLY=1; shift ;;
    --keep-probe) KEEP_PROBE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ "$SUPPORT_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] || die '--support-image must be digest-pinned'
[[ "$STORAGE_CLASS" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die '--storage-class is required'
if [[ ! "$WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] || ((WAIT_SECONDS > 1800)); then die '--wait-seconds must be1–1800'; fi
for cmd in git jq shasum python3; do command -v "$cmd" >/dev/null || die "missing command: $cmd"; done
SOURCE_ROOT="$(cd "$SOURCE_ROOT" && pwd)"
[[ -f "$SOURCE_ROOT/crates/codewire-orchestration/examples/dind-storage-fixture.rs" ]] || die 'candidate lacks the checked-in fixture renderer'
[[ -z "$(git -C "$SOURCE_ROOT" status --porcelain --untracked-files=normal)" ]] || die 'candidate source must be clean, including untracked inputs'
source_sha="$(git -C "$SOURCE_ROOT" rev-parse HEAD)"
source_tree="$(git -C "$SOURCE_ROOT" rev-parse 'HEAD^{tree}')"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]] || die 'probe tooling checkout must also be clean'
tool_sha="$(git -C "$ROOT" rev-parse HEAD)"
guest_sha="$(shasum -a 256 "$ROOT/scripts/runtime/dev/docker-store-guest.sh" | cut -d ' ' -f 1)"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ && "$source_tree" =~ ^[0-9a-f]{40}$ ]] || die 'invalid source identity'
if [[ -z "$EVIDENCE_DIR" ]]; then
  mkdir -p "$ROOT/.tmp"
  EVIDENCE_DIR="$(mktemp -d "$ROOT/.tmp/dind-storage.XXXXXX")"
else
  [[ ! -e "$EVIDENCE_DIR" ]] || die '--evidence-dir must not exist'
  mkdir -p "$EVIDENCE_DIR"
fi
if [[ -n "$RENDERED_FIXTURE" ]]; then
  [[ "$RENDER_ONLY" == 0 && "$FIXTURE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die 'apply requires --fixture-sha256 and cannot use --render-only'
  [[ -f "$RENDERED_FIXTURE" && ! -L "$RENDERED_FIXTURE" ]] || die 'fixture must be a regular file'
  (( $(wc -c <"$RENDERED_FIXTURE") <= 2097152 )) || die 'fixture exceeds two MiB'
  [[ "$(shasum -a 256 "$RENDERED_FIXTURE" | cut -d ' ' -f 1)" == "$FIXTURE_SHA256" ]] || die 'fixture bundle hash mismatch'
  jq -e '.schema_version == 1 and (.receipt | type == "object") and (.render | type == "object")' "$RENDERED_FIXTURE" >/dev/null || die 'invalid fixture bundle'
  jq '.receipt' "$RENDERED_FIXTURE" >"$EVIDENCE_DIR/source-receipt.json"
  jq -cS '.render' "$RENDERED_FIXTURE" >"$EVIDENCE_DIR/rendered.json"
  NAME="$(jq -er '.name | select(type == "string")' "$EVIDENCE_DIR/source-receipt.json")"
else
  [[ "$RENDER_ONLY" == 1 ]] || die 'live use requires --rendered-fixture and --fixture-sha256; render separately without Kubernetes credentials'
  [[ -z "${KUBECONFIG:-}" && "${INFRA_TRANSIENT_KUBE_AUTH:-0}" != 1 ]] || die 'offline rendering refuses Kubernetes credentials'
  command -v cargo >/dev/null || die 'offline rendering requires cargo'
  (cd "$SOURCE_ROOT" && cargo run --quiet --locked --jobs 2 -p codewire-orchestration \
    --example dind-storage-fixture -- "$NAME" "$SUPPORT_IMAGE" "$STORAGE_CLASS") >"$EVIDENCE_DIR/rendered.raw.json"
  [[ "$(git -C "$SOURCE_ROOT" rev-parse HEAD)" == "$source_sha" && -z "$(git -C "$SOURCE_ROOT" status --porcelain --untracked-files=normal)" ]] || die 'candidate changed while rendering'
  jq -cS '.' "$EVIDENCE_DIR/rendered.raw.json" >"$EVIDENCE_DIR/rendered.json"
  render_sha="$(shasum -a 256 "$EVIDENCE_DIR/rendered.json" | cut -d ' ' -f 1)"
  jq -n --arg source "$source_sha" --arg tree "$source_tree" --arg hash "$render_sha" \
    --arg name "$NAME" --arg expected "$EXPECTED_STORE" --arg tool "$tool_sha" --arg guest "$guest_sha" --argjson baseline "$BASELINE" \
    --slurpfile render "$EVIDENCE_DIR/rendered.json" \
    '{schema_version:1,source_sha:$source,source_tree:$tree,tool_source_sha:$tool,guest_script_sha256:$guest,render_sha256:$hash,name:$name,
      expected_store:$expected,baseline:($baseline == 1),bootstrap_argv_sha256:$render[0].bootstrap_argv_sha256,
      support_image:$render[0].support_image,dind_image:$render[0].dind_image,network_policy_sha256:$render[0].network_policy_sha256,network_policy_name:$render[0].objects[2].metadata.name}' >"$EVIDENCE_DIR/source-receipt.json"
fi
[[ "$NAME" =~ ^dind-storage-[a-z0-9]([a-z0-9-]*[a-z0-9])?$ && ${#NAME} -le 48 ]] || die 'fixture name is outside owned prefix'
render_sha="$(shasum -a 256 "$EVIDENCE_DIR/rendered.json" | cut -d ' ' -f 1)"
jq -e --arg source "$source_sha" --arg tree "$source_tree" --arg tool "$tool_sha" --arg guest "$guest_sha" \
  --arg hash "$render_sha" --arg name "$NAME" --arg image "$SUPPORT_IMAGE" --argjson baseline "$BASELINE" \
  --slurpfile render "$EVIDENCE_DIR/rendered.json" '
  .schema_version == 1 and .source_sha == $source and .source_tree == $tree and .tool_source_sha == $tool
  and .guest_script_sha256 == $guest and .render_sha256 == $hash and .name == $name
  and .support_image == $image and .dind_image == $render[0].dind_image
  and .bootstrap_argv_sha256 == $render[0].bootstrap_argv_sha256
  and .network_policy_sha256 == $render[0].network_policy_sha256
  and .network_policy_name == $render[0].objects[2].metadata.name and .baseline == ($baseline == 1)
' "$EVIDENCE_DIR/source-receipt.json" >/dev/null || die 'fixture source or receipt binding mismatch'
# This is one maintained fixture shape, never an arbitrary Kubernetes apply
# channel. The out-of-band bundle hash binds evidence; it does not attest
# execution in the rendering sandbox. Admission remains authoritative.
jq -e --arg name "$NAME" --arg image "$SUPPORT_IMAGE" --arg storage "$STORAGE_CLASS" '
  .schema_version == 1 and .support_image == $image and (.objects | length == 3)
  and (.dind_image | test("^docker.io/library/docker:[^@]+@sha256:[0-9a-f]{64}$"))
  and (all(.objects[]; .metadata.namespace == "dev-sandboxes"))
  and .objects[0].kind == "PersistentVolumeClaim" and .objects[0].apiVersion == "v1"
  and .objects[0].metadata.name == ($name + "-workspace")
  and .objects[0].spec.storageClassName == $storage and .objects[0].spec.volumeMode == "Block"
  and .objects[0].spec.resources.requests.storage == "8Gi" and .objects[0].spec.accessModes == ["ReadWriteOnce"]
  and (.objects[0].spec | (has("dataSource") or has("dataSourceRef") or has("volumeName") or has("selector")) | not)
  and .objects[1].kind == "Pod" and .objects[1].apiVersion == "v1" and .objects[1].metadata.name == $name
  and .objects[1].metadata.annotations["codewire.sh/workspace"] == "true"
  and (.objects[1].spec as $p |
    $p.runtimeClassName == "commodity" and $p.restartPolicy == "Never"
    and $p.serviceAccountName == "codewire-sandbox" and $p.automountServiceAccountToken == false
    and ([$p.hostPID,$p.hostIPC,$p.hostNetwork,$p.shareProcessNamespace] | all(. != true))
    and ($p.containers | length == 2) and $p.containers[0].name == "dind" and $p.containers[0].image == .dind_image
    and $p.containers[0].resources.limits == {"cpu":"2","memory":"2Gi"}
    and $p.containers[1].name == "client" and $p.containers[1].image == .dind_image
    and $p.containers[1].command == ["sh","-ec","umask 077; mkdir \"$DOCKER_CONFIG\"; exec sleep 86400"]
    and $p.containers[1].env == [
      {"name":"DOCKER_HOST","value":"unix:///var/run/docker/docker.sock"},
      {"name":"DOCKER_CONFIG","value":"/tmp/codewire-dind-client"}
    ]
    and $p.containers[1].resources.limits == {"cpu":"1","memory":"512Mi"}
    and $p.containers[1].securityContext.runAsUser == 1000
    and $p.containers[1].securityContext.allowPrivilegeEscalation == false
    and ($p.containers[1].securityContext.privileged // false) == false
    and $p.containers[1].securityContext.capabilities.drop == ["ALL"]
    and ($p.containers[1].securityContext.capabilities.add // [] | length) == 0
    and (all($p.volumes[]; (has("hostPath") or has("secret") or has("projected")) | not))
    and (all($p.volumes[]; (has("emptyDir") or has("image") or has("persistentVolumeClaim"))))
    and (all($p.volumes[] | select(has("persistentVolumeClaim")); .name == "workspace" and .persistentVolumeClaim.claimName == ($name + "-workspace")))
    and (any($p.volumes[]; .name == "workspace" and .persistentVolumeClaim.claimName == ($name + "-workspace")))
    and (any($p.initContainers[].volumeDevices[]?; .name == "workspace" and .devicePath == "/dev/cwws"))
    and (all(($p.containers[],$p.initContainers[]); (.envFrom // [] | length) == 0 and (all(.env[]?; (has("valueFrom") | not) and has("value") and (.value | type == "string")))))
    and (all($p.containers[].ports[]?; (.hostPort // 0) == 0))
    and (all($p.initContainers[]; .image == $image and (.name == "mount-workspace" or .name == "workspace-flush" or .name == "codewire-docker-data-init")))
    and (all($p.initContainers[] | select(.securityContext.privileged == true); .name == "mount-workspace"))
  )
  and .objects[2].kind == "NetworkPolicy" and .objects[2].apiVersion == "networking.k8s.io/v1"
  and .objects[2].metadata.name == ("cw-daemon-net-" + $name)
  and .objects[2].spec.podSelector.matchLabels == {"codewire.sh/environment-id":$name,"codewire.sh/type":"workspace"}
  and .objects[1].metadata.labels["codewire.sh/environment-id"] == $name
  and .objects[1].metadata.labels["codewire.sh/type"] == "workspace"
' "$EVIDENCE_DIR/rendered.json" >/dev/null || die 'unsafe or unexpected fixture shape'
python3 - "$EVIDENCE_DIR/rendered.json" <<'HASHES'
import hashlib, json, sys
render = json.load(open(sys.argv[1], encoding="utf-8"))
def digest(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()
if digest(render["objects"][1]["spec"]["containers"][0]["command"]) != render["bootstrap_argv_sha256"]:
    sys.exit("fixture bootstrap hash mismatch")
if digest(render["objects"][2]) != render["network_policy_sha256"]:
    sys.exit("fixture network policy hash mismatch")
HASHES
jq -n --slurpfile receipt "$EVIDENCE_DIR/source-receipt.json" --slurpfile render "$EVIDENCE_DIR/rendered.json" \
  '{schema_version:1,receipt:$receipt[0],render:$render[0]}' >"$EVIDENCE_DIR/fixture.json"
if [[ "$RENDER_ONLY" == 1 ]]; then
  bundle_sha="$(shasum -a 256 "$EVIDENCE_DIR/fixture.json" | cut -d ' ' -f 1)"
  log "offline fixture=$EVIDENCE_DIR/fixture.json sha256=$bundle_sha"
  exit 0
fi
select_host_timeout
[[ "${KUBE_CONTEXT:-}" == "$DEV_CLUSTER" && "${INFRA_TRANSIENT_KUBE_AUTH:-}" == 1 && -n "${KUBECONFIG:-}" ]] || \
  die 'run through infrastructure scripts/kube-access cw-dev-hz-eu-1; ambient kubeconfig is refused'
command -v kubectl >/dev/null || die 'missing command: kubectl'
k() { kubectl --context "$DEV_CLUSTER" -n "$NAMESPACE" "$@"; }

collect_status() {
  k get pod "$NAME" -o json | jq '{name:.metadata.name,uid:.metadata.uid,node:.spec.nodeName,
    phase:.status.phase,conditions:[.status.conditions[]? | {type,status,reason}],
    containers:[(.status.initContainerStatuses[]?,.status.containerStatuses[]?) |
      {name,imageID,restartCount,state:(if .state.running then "running" elif .state.waiting then .state.waiting.reason else .state.terminated.reason end),exit_code:.state.terminated.exitCode}]}' \
    >"$EVIDENCE_DIR/status.json" || return 1
}
cleanup() {
  local rc=$? current preserve=0
  trap - EXIT INT TERM
  if [[ -n "$POD_UID" ]]; then
    collect_status || log 'selected final status unavailable'
    if [[ "$KEEP_PROBE" == 0 ]]; then
      current="$(k get pod "$NAME" -o jsonpath='{.metadata.uid}')" || current=''
      if [[ "$current" == "$POD_UID" ]]; then
        k delete pod "$NAME" --ignore-not-found --wait=true --timeout=180s >/dev/null || rc=1
      else log 'Pod identity changed; cleanup preserved it and its workspace'; rc=1; preserve=1; fi
    else log "kept exact fixture $NAME"; fi
  fi
  if [[ -n "$POLICY_UID" && "$KEEP_PROBE" == 0 && "$preserve" == 0 ]]; then
    current="$(k get networkpolicy "$POLICY_NAME" -o jsonpath='{.metadata.uid}')" || current=''
    if [[ "$current" == "$POLICY_UID" ]]; then
      k delete networkpolicy "$POLICY_NAME" --ignore-not-found --wait=true --timeout=60s >/dev/null || rc=1
    else log 'NetworkPolicy identity changed; cleanup preserved it'; rc=1; fi
  fi
  if [[ -n "$PVC_UID" && "$KEEP_PROBE" == 0 && "$preserve" == 0 ]]; then
    current="$(k get pvc "$NAME-workspace" -o jsonpath='{.metadata.uid}')" || current=''
    if [[ "$current" == "$PVC_UID" ]]; then
      k annotate pvc "$NAME-workspace" platform.noel.sh/allow-deletion=true >/dev/null || rc=1
      k delete pvc "$NAME-workspace" --ignore-not-found --wait=true --timeout=180s >/dev/null || rc=1
    else log 'PVC identity changed; cleanup preserved it'; rc=1; fi
  fi
  log "result=$rc evidence=$EVIDENCE_DIR"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Single-object creates are atomic and refuse collisions. Record each
# returned UID before attempting the next object; an admission denial cannot
# authorize deletion of an object this invocation did not create.
jq '.objects[0]' "$EVIDENCE_DIR/rendered.json" >"$EVIDENCE_DIR/pvc.json"
jq '.objects[1]' "$EVIDENCE_DIR/rendered.json" >"$EVIDENCE_DIR/pod.json"
k create -f "$EVIDENCE_DIR/pvc.json" -o json >"$EVIDENCE_DIR/pvc-created.json" 2>"$EVIDENCE_DIR/create-pvc.err"
PVC_UID="$(jq -er '.metadata.uid' "$EVIDENCE_DIR/pvc-created.json")"
jq '.objects[2]' "$EVIDENCE_DIR/rendered.json" >"$EVIDENCE_DIR/network-policy.json"
POLICY_NAME="$(jq -er '.metadata.name' "$EVIDENCE_DIR/network-policy.json")"
k create -f "$EVIDENCE_DIR/network-policy.json" -o jsonpath='{.metadata.uid}' >"$EVIDENCE_DIR/policy-uid.txt" 2>"$EVIDENCE_DIR/create-policy.err"
POLICY_UID="$(cat "$EVIDENCE_DIR/policy-uid.txt")"
k create -f "$EVIDENCE_DIR/pod.json" -o jsonpath='{.metadata.uid}' >"$EVIDENCE_DIR/pod-uid.txt" 2>"$EVIDENCE_DIR/create-pod.err"
POD_UID="$(cat "$EVIDENCE_DIR/pod-uid.txt")"
jq -n --arg pod "$POD_UID" --arg pvc "$PVC_UID" --arg policy "$POLICY_UID" \
  '{pod_uid:$pod,pvc_uid:$pvc,network_policy_uid:$policy}' >"$EVIDENCE_DIR/created-identities.json"
rm "$EVIDENCE_DIR/pvc-created.json"
k wait "pod/$NAME" --for=condition=Ready --timeout="${WAIT_SECONDS}s" >"$EVIDENCE_DIR/ready.log" 2>"$EVIDENCE_DIR/ready.err"
collect_status
k exec "$NAME" -c dind -- sh -ec 'uname -r; uname -m; runc --version; command -v cmp rm mv awk read printf mkdir' >"$EVIDENCE_DIR/runtime-versions.txt"
cgroup_state() {
  # shellcheck disable=SC2016 # Executed by the guest shell.
  k exec "$NAME" -c dind -- sh -ec '
    printf "pid1="; cat /proc/1/comm
    printf "membership="; cat /proc/1/cgroup
    for path in /sys/fs/cgroup /sys/fs/cgroup/docker /sys/fs/cgroup/init; do
      test -d "$path" || continue
      printf "cgroup=%s\n" "$path"
      for field in cgroup.type cgroup.controllers cgroup.subtree_control; do
        test ! -r "$path/$field" || { printf "%s=" "$field"; cat "$path/$field"; }
      done
    done' >"$EVIDENCE_DIR/cgroup-$1.txt"
}
client_for() {
  local budget="$1"
  shift
  "$TIMEOUT_BIN" "$((budget + 5))" kubectl --context "$DEV_CLUSTER" -n "$NAMESPACE" exec "$NAME" -c client -- timeout "$budget" "$@"
}
client() { client_for 90 "$@"; }
deadline=$((SECONDS + WAIT_SECONDS))
ready=0
while ((SECONDS < deadline)); do
  if client_for 5 docker info --format '{{.Driver}}' >"$EVIDENCE_DIR/driver.txt" 2>"$EVIDENCE_DIR/docker-ready.err"; then ready=1; break; fi
  sleep 1
done
((ready == 1)) || die 'rendered bootstrap did not start Docker'
client docker info --format '{{json .DriverStatus}}' >"$EVIDENCE_DIR/driver-status.json"
client docker version --format '{{json .Server}}' >"$EVIDENCE_DIR/engine-version.json"
base='registry.k8s.io/e2e-test-images/busybox@sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb'
client docker pull "$base" >"$EVIDENCE_DIR/pull.log" 2>"$EVIDENCE_DIR/pull.err"
cgroup_state before-child
: >"$EVIDENCE_DIR/resource-matrix.tsv"
for label in cpu-first plain pids cpu-after memory; do
  flags=(--network none)
  case "$label" in cpu-*) flags+=(--cpus 1) ;; pids) flags+=(--pids-limit 64) ;; memory) flags+=(--memory 128m --memory-swap 128m) ;; esac
  rc=0
  client docker run --rm "${flags[@]}" "$base" true >"$EVIDENCE_DIR/$label.log" 2>"$EVIDENCE_DIR/$label.err" || rc=$?
  printf '%s\t%s\n' "$label" "$rc" >>"$EVIDENCE_DIR/resource-matrix.tsv"
  cgroup_state "$label"
  if [[ "$BASELINE" == 0 && "$rc" != 0 ]]; then die "resource case $label failed exit$rc"; fi
done
if [[ "$BASELINE" == 1 ]]; then
  [[ "$(cat "$EVIDENCE_DIR/driver.txt")" == vfs ]] || die 'baseline expected VFS'
  awk '$1 == "plain" || $1 == "pids" { if ($2 != 0) exit 1; seen++ } END { if (seen != 2) exit 1 }' "$EVIDENCE_DIR/resource-matrix.tsv" || die 'plain/PID baseline failed'
  log 'VFS baseline recorded; CPU/memory results are observations, not qualification'
else
  guest="$(cat "$ROOT/scripts/runtime/dev/docker-store-guest.sh")
set -eu
docker_store_guest core ${NAME//-/} $EXPECTED_STORE"
  client_for 300 sh -ec "$guest" >"$EVIDENCE_DIR/qualification.log" 2>"$EVIDENCE_DIR/qualification.err"
  log 'actual Docker backend/resource/image-custody qualification passed'
fi
