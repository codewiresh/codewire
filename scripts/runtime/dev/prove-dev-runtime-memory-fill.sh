#!/usr/bin/env bash
# Dev proof that a Kata commodity Pod survives every container reaching its memory
# limit while writing to disk (#3718). A guest with full RAM leaves the Pod's cgroup
# only its RuntimeClass overhead for the VMM, virtiofsd and their host page cache;
# past that the host OOM-kills the VM.
#
# Each try runs one test Pod of the given shape in the probe namespace, with both
# containers writing to one linstor-local volume. It exits non-zero if any try dies.
# It creates only objects named cw-fill-*, and removes them on exit. A host kill shows
# here as a failed Pod; read the node's kernel log to confirm it
# ("Memory cgroup out of memory: Killed process").
#
# Options:
#   --overhead SIZE    Test this overhead on a throwaway RuntimeClass, copying
#                      commodity's handler and scheduling (default: use commodity)
#   --main-gib N       First container's memory limit (default 4)
#   --second-gib N     Second container's memory limit (default 2)
#   --tries N          Tries (default 3)
#
# KUBE_CONTEXT selects the cluster (default codewire-dev).
set -euo pipefail
umask 077
KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
NAMESPACE="${FILL_NAMESPACE:-codewire-runtime-probes}"
STORAGE_CLASS="${FILL_STORAGE_CLASS:-linstor-local}"
readonly IMAGE='docker.io/library/busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
readonly TEST_NAME=cw-fill-test
OVERHEAD=""
MAIN_GIB=4
SECOND_GIB=2
TRIES=3
RUNTIME_CLASS=commodity
POD_TIMEOUT_SECONDS="${FILL_POD_TIMEOUT_SECONDS:-900}"

log() { printf '[memory-fill] %s\n' "$*" >&2; }
die() { printf '[memory-fill] ERROR: %s\n' "$*" >&2; exit 1; }
k() { kubectl --context "$KUBE_CONTEXT" "$@"; }

usage() { sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# Writes twice its limit, so its page cache reaches that limit, then removes the files.
fill_command() {
  cat <<'SH'
i=0
while [ "$i" -lt "$COUNT" ]; do
  dd if=/dev/urandom of="/data/$NAME.$i" bs=1M count=1024 2>/dev/null
  sync
  i=$((i + 1))
  echo "$NAME wrote ${i}GiB"
done
rm -f "/data/$NAME".*
echo "$NAME FILL_COMPLETE"
SH
}

container_json() { # NAME LIMIT_GIB
  jq -n --arg name "$1" --arg image "$IMAGE" --arg command "$(fill_command)" \
    --argjson gib "$2" '{
      name: $name, image: $image,
      env: [{name: "NAME", value: $name}, {name: "COUNT", value: "\($gib * 2)"}],
      command: ["sh", "-ec", $command],
      resources: {
        requests: {cpu: "1", memory: "\($gib)Gi"},
        limits: {cpu: "1", memory: "\($gib)Gi"}
      },
      volumeMounts: [{name: "data", mountPath: "/data"}]
    }'
}

pod_json() {
  jq -n --arg name "$TEST_NAME" --arg ns "$NAMESPACE" --arg rc "$RUNTIME_CLASS" \
    --argjson main "$(container_json main "$MAIN_GIB")" \
    --argjson second "$(container_json second "$SECOND_GIB")" '{
      apiVersion: "v1", kind: "Pod",
      metadata: {name: $name, namespace: $ns, labels: {"codewire.sh/test": $name}},
      spec: {
        runtimeClassName: $rc, automountServiceAccountToken: false,
        restartPolicy: "Never", securityContext: {runAsUser: 0},
        containers: [$main, $second],
        volumes: [{name: "data", persistentVolumeClaim: {claimName: $name}}]
      }
    }'
}

volume_json() {
  jq -n --arg name "$TEST_NAME" --arg ns "$NAMESPACE" --arg class "$STORAGE_CLASS" \
    --arg size "$(( (MAIN_GIB + SECOND_GIB) * 2 + 10 ))Gi" '{
      apiVersion: "v1", kind: "PersistentVolumeClaim",
      metadata: {name: $name, namespace: $ns},
      spec: {
        accessModes: ["ReadWriteOnce"], storageClassName: $class,
        resources: {requests: {storage: $size}}
      }
    }'
}

runtime_class_json() { # COMMODITY_JSON
  jq --arg name "$TEST_NAME" --arg memory "$OVERHEAD" '{
    apiVersion: "node.k8s.io/v1", kind: "RuntimeClass",
    metadata: {name: $name},
    handler: .handler,
    overhead: {podFixed: (.overhead.podFixed + {memory: $memory})},
    scheduling: .scheduling
  }' <<<"$1"
}

delete_pod() {
  k -n "$NAMESPACE" delete pod "$TEST_NAME" --ignore-not-found --wait=true --timeout=180s >/dev/null 2>&1 || true
}

# PVCs here are under the cluster deletion guard. This volume is the tool's own and
# holds only fill data, so it is annotated and deleted by its exact name.
cleanup() {
  delete_pod
  k -n "$NAMESPACE" annotate pvc "$TEST_NAME" platform.noel.sh/allow-deletion=true >/dev/null 2>&1 || true
  k -n "$NAMESPACE" delete pvc "$TEST_NAME" --ignore-not-found --timeout=180s >/dev/null 2>&1 || true
  if [[ "$RUNTIME_CLASS" == "$TEST_NAME" ]]; then
    k delete runtimeclass "$TEST_NAME" --ignore-not-found >/dev/null 2>&1 || true
  fi
}

wait_for_end() {
  local deadline=$(( $(date +%s) + POD_TIMEOUT_SECONDS )) phase=""
  while (( $(date +%s) < deadline )); do
    phase="$(k -n "$NAMESPACE" get pod "$TEST_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [[ "$phase" == Succeeded || "$phase" == Failed ]]; then break; fi
    sleep 10
  done
  printf '%s' "$phase"
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --overhead) OVERHEAD="${2:?}"; shift 2 ;;
      --main-gib) MAIN_GIB="${2:?}"; shift 2 ;;
      --second-gib) SECOND_GIB="${2:?}"; shift 2 ;;
      --tries) TRIES="${2:?}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  [[ "$MAIN_GIB" =~ ^[1-9][0-9]*$ && "$SECOND_GIB" =~ ^[1-9][0-9]*$ ]] || die "sizes must be whole GiB"
  [[ "$TRIES" =~ ^[1-9][0-9]*$ ]] || die "--tries must be a positive integer"
  if [[ -n "$OVERHEAD" && ! "$OVERHEAD" =~ ^[1-9][0-9]*(Mi|Gi)$ ]]; then
    die "--overhead must look like 512Mi or 1Gi"
  fi
}

main() {
  parse_args "$@"
  local failures=0 try started phase
  trap cleanup EXIT
  if [[ -n "$OVERHEAD" ]]; then
    RUNTIME_CLASS="$TEST_NAME"
    runtime_class_json "$(k get runtimeclass commodity -o json)" | k apply -f - >/dev/null
  fi
  volume_json | k apply -f - >/dev/null
  log "shape=${MAIN_GIB}+${SECOND_GIB}GiB runtime_class=$RUNTIME_CLASS overhead=${OVERHEAD:-from-commodity}"
  for (( try = 1; try <= TRIES; try++ )); do
    pod_json | k apply -f - >/dev/null
    started="$(date +%s)"
    phase="$(wait_for_end)"
    log "try=$try phase=${phase:-unknown} seconds=$(( $(date +%s) - started ))"
    [[ "$phase" == Succeeded ]] || failures=$((failures + 1))
    delete_pod
  done
  if (( failures > 0 )); then
    log "FAILED $failures of $TRIES; check the node's kernel log for a host OOM kill"
    exit 1
  fi
  log "PASSED $TRIES of $TRIES"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
