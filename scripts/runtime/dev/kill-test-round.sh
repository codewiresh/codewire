#!/usr/bin/env bash
# One round of the commodity overhead kill test (#3718; design
# 2026-11-01-commodity-workspace-direct-io §4), for kill-test-overhead-matrix.sh.
#
#   kill-test-round.sh MAIN_GIB SECOND_GIB OVERHEAD     run one round, print one JSON line
#   kill-test-round.sh --print MAIN_GIB SECOND_GIB OVERHEAD   the objects it would apply
#
# One test Pod alone on the sampler's node, in a throwaway RuntimeClass that copies
# commodity's with this overhead. Each container holds all but 1 GiB of its limit in
# guest memory, so guest RAM is full; then buffered writers run on every writer path
# for KILL_TEST_WRITE_SECONDS. The sampler Pod, which must already run on the node,
# reads the test Pod's host cgroup twice a second.
#
# Prints: survived, seconds, peak_dirty_writeback_mib (the Pod cgroup's file_dirty +
# file_writeback), peak_host_processes_mib (its anon + kernel: the VMM's own memory,
# virtiofsd and the shim), peak_shmem_mib and evidence. Guest RAM is shared memory,
# since the root filesystem is on virtio-fs, so it isn't in anon. A round whose shmem
# stays well short of the guest's holds says that's not so here, and is unknown.
# Exit 0 survived, 1 lost, 2 could not run or can't be read.
#
# Settings (environment):
#   KUBE_CONTEXT              cluster (default codewire-dev)
#   KILL_TEST_NAMESPACE       default codewire-runtime-probes
#   KILL_TEST_SAMPLER         the hostPID sampler Pod there (default cw-oom-sampler)
#   KILL_TEST_VOLUME          block (default): a Block volume the guest formats; or
#                             virtiofs: a filesystem volume shared over virtio-fs
#   KILL_TEST_HANDLER         RuntimeClass handler (default: commodity's)
#   KILL_TEST_STORAGE_CLASS   default linstor-local
#   KILL_TEST_WRITERS         space-separated writer directories in the main container
#                             (default "/data /tmp /usr/local"; /data is the workspace)
#   KILL_TEST_WRITE_SECONDS   how long the writers run (default 120)
#   KILL_TEST_DMESG           optional command printing the node's kernel log, used to
#                             count host kills of the VM since the round began
set -euo pipefail
umask 077

KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
NAMESPACE="${KILL_TEST_NAMESPACE:-codewire-runtime-probes}"
SAMPLER="${KILL_TEST_SAMPLER:-cw-oom-sampler}"
VOLUME="${KILL_TEST_VOLUME:-block}"
HANDLER="${KILL_TEST_HANDLER:-}"
STORAGE_CLASS="${KILL_TEST_STORAGE_CLASS:-linstor-local}"
WRITERS="${KILL_TEST_WRITERS:-/data /tmp /usr/local}"
WRITE_SECONDS="${KILL_TEST_WRITE_SECONDS:-120}"
DMESG="${KILL_TEST_DMESG:-}"
KEEP_TRACE="${KILL_TEST_KEEP_TRACE:-}"
# The product's workspace image, as the repository pins it: usually already on a
# runtime node, and it has sh and dd.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGE="$(sed -n 's/^pub const PUBLIC_IMAGE: &str = "\(.*\)";$/\1/p' "$ROOT/crates/codewire-workspace-image/src/pin.rs")"
readonly IMAGE
readonly TEST_NAME=cw-kill-test

log() { printf '[kill-test-round] %s\n' "$*" >&2; }
die() { printf '[kill-test-round] ERROR: %s\n' "$*" >&2; exit 2; }
k() { kubectl --context "$KUBE_CONTEXT" "$@"; }

# Holds all but 1 GiB of the container's limit in tmpfs, then writes until told to
# stop: two buffered writers per directory, each rewriting eight 1 GiB files.
container_script() {
  cat <<'SH'
set -eu
if [ "$MOUNT_BLOCK" = 1 ]; then
  mkfs.ext4 -q -F /dev/cwblk
  mkdir -p /data
  mount /dev/cwblk /data
fi
half=$(( (LIMIT_GIB - 1) * 512 ))
if [ "$half" -gt 0 ]; then
  dd if=/dev/zero of=/hold/a bs=1M count="$half" 2>/dev/null &
  dd if=/dev/zero of=/hold/b bs=1M count="$half" 2>/dev/null &
  wait
fi
echo "$NAME holding $(( LIMIT_GIB - 1 ))GiB"
end=$(( $(date +%s) + WRITE_SECONDS ))
for dir in $WRITERS; do
  mkdir -p "$dir/cw-kill-test"
  for writer in a b; do
    ( i=0
      while [ "$(date +%s)" -lt "$end" ]; do
        dd if=/dev/zero of="$dir/cw-kill-test/$writer.$((i % 8))" bs=1M count=1024 2>/dev/null || exit 1
        i=$((i + 1))
      done ) &
  done
done
wait
echo "$NAME WRITES_DONE"
sleep 3600
SH
}

container_json() { # NAME LIMIT_GIB WRITERS MOUNT_BLOCK
  jq -n --arg name "$1" --argjson gib "$2" --arg writers "$3" --arg block "$4" \
    --arg image "$IMAGE" --arg script "$(container_script)" --arg seconds "$WRITE_SECONDS" '{
      name: $name, image: $image, command: ["sh", "-c", $script],
      env: [{name: "NAME", value: $name}, {name: "LIMIT_GIB", value: "\($gib)"},
            {name: "WRITERS", value: $writers}, {name: "WRITE_SECONDS", value: $seconds},
            {name: "MOUNT_BLOCK", value: $block}],
      securityContext: (if $block == "1" then {privileged: true, runAsUser: 0} else {runAsUser: 0} end),
      resources: {requests: {cpu: "2", memory: "\($gib)Gi"}, limits: {cpu: "2", memory: "\($gib)Gi"}},
      volumeMounts: [{name: "hold-\($name)", mountPath: "/hold"}]
    }'
}

# The second container, as DinD, writes to the workspace too, except on Block: a
# filesystem the guest mounts in one container can't be mounted again in another.
pod_json() { # MAIN_GIB SECOND_GIB NODE
  local main second
  if [[ "$VOLUME" == block ]]; then
    main="$(container_json main "$1" "$WRITERS" 1 | jq '. + {volumeDevices: [{name: "data", devicePath: "/dev/cwblk"}]}')"
    second="$(container_json second "$2" "" 0)"
  else
    main="$(container_json main "$1" "$WRITERS" 0 | jq '.volumeMounts += [{name: "data", mountPath: "/data"}]')"
    second="$(container_json second "$2" "/data" 0 | jq '.volumeMounts += [{name: "data", mountPath: "/data"}]')"
  fi
  jq -n --arg name "$TEST_NAME" --arg ns "$NAMESPACE" --arg node "$3" \
    --argjson main "$main" --argjson second "$second" '{
      apiVersion: "v1", kind: "Pod",
      metadata: {name: $name, namespace: $ns, labels: {"codewire.sh/test": $name}},
      spec: {
        runtimeClassName: $name, nodeSelector: {"kubernetes.io/hostname": $node},
        automountServiceAccountToken: false, restartPolicy: "Never",
        tolerations: [{operator: "Exists"}],
        containers: [$main, $second],
        volumes: [{name: "data", persistentVolumeClaim: {claimName: $name}},
                  {name: "hold-main", emptyDir: {medium: "Memory"}},
                  {name: "hold-second", emptyDir: {medium: "Memory"}}]
      }
    }'
}

volume_json() { # MAIN_GIB SECOND_GIB
  # Room for every writer's eight 1 GiB files, the second container's and some slack.
  local paths; paths="$(wc -w <<<"$WRITERS")"
  jq -n --arg name "$TEST_NAME" --arg ns "$NAMESPACE" --arg class "$STORAGE_CLASS" \
    --arg mode "$([[ "$VOLUME" == block ]] && echo Block || echo Filesystem)" \
    --arg size "$(( (paths + 1) * 16 + 10 ))Gi" '{
      apiVersion: "v1", kind: "PersistentVolumeClaim",
      metadata: {name: $name, namespace: $ns},
      spec: {accessModes: ["ReadWriteOnce"], storageClassName: $class, volumeMode: $mode,
             resources: {requests: {storage: $size}}}
    }'
}

runtime_class_json() { # COMMODITY_JSON OVERHEAD
  jq --arg name "$TEST_NAME" --arg memory "$2" --arg handler "$HANDLER" '{
    apiVersion: "node.k8s.io/v1", kind: "RuntimeClass", metadata: {name: $name},
    handler: (if $handler == "" then .handler else $handler end),
    overhead: {podFixed: (.overhead.podFixed + {memory: $memory})},
    scheduling: .scheduling
  }' <<<"$1"
}

# Host kills of the VM in the node's kernel log since the round began, or "unread"
# when there's no command or it gives nothing: a log that wasn't read never counts as
# no kills. The Pod cgroup's own oom_kill count decides survival either way.
kernel_vm_kills() { # SINCE
  local text
  [[ -n "$DMESG" ]] || { echo unread; return; }
  if ! text="$(bash -c "$DMESG" 2>/dev/null)" || [[ -z "$text" ]]; then echo unread; return; fi
  awk -v s="[$1" 'match($0, /\[20[0-9-]+T[0-9:.]+Z\]/) { if (substr($0, RSTART, RLENGTH) >= s) print }' <<<"$text" |
    grep -c 'out of memory: Killed process [0-9]* (cloud-hyperviso)' || true
}

# Only this tool's own objects, by their exact names.
cleanup() {
  k -n "$NAMESPACE" delete pod "$TEST_NAME" --ignore-not-found --wait=true --timeout=180s >/dev/null 2>&1 || true
  k -n "$NAMESPACE" annotate pvc "$TEST_NAME" platform.noel.sh/allow-deletion=true >/dev/null 2>&1 || true
  k -n "$NAMESPACE" delete pvc "$TEST_NAME" --ignore-not-found --timeout=180s >/dev/null 2>&1 || true
  k delete runtimeclass "$TEST_NAME" --ignore-not-found >/dev/null 2>&1 || true
}

# The Pod cgroup each half second: file_dirty + file_writeback, anon + kernel, the
# oom_kill event count and shmem, as "dirty_wb host oom_kill shmem".
sample_script() {
  cat <<'SH'
C=/host-cgroup/kubepods/burstable/pod$POD_UID
[ -d "$C" ] || C=/host-cgroup/kubepods/pod$POD_UID
[ -d "$C" ] || { echo NO_CGROUP; exit 2; }
echo "MEMORY_MAX $(cat "$C/memory.max")"
while [ -d "$C" ]; do
  awk -v evs="$(tr '\n' ' ' <"$C/memory.events")" '
    { v[$1] = $2 }
    END { n = split(evs, e, " "); for (i = 1; i < n; i += 2) ev[e[i]] = e[i + 1]
          M = 1048576
          printf "%d %d %d %d %d %d %d\n", (v["file_dirty"] + v["file_writeback"]) / M, (v["anon"] + v["kernel"]) / M, ev["oom_kill"], v["shmem"] / M,
            v["anon"] / M, v["kernel"] / M, v["file"] / M }' "$C/memory.stat"
  sleep 0.5
done
echo CGROUP_GONE
SH
}

peaks() { # TRACE -> "dirty_wb host shmem", or nulls
  awk '$1 ~ /^[0-9]+$/ { if ($1 > d) d = $1; if ($2 > h) h = $2; if ($4 > s) s = $4; n++ }
    END { if (n) printf "%d %d %d", d, h, s; else printf "null null null" }' "$1" 2>/dev/null || echo "null null null"
}

result() { # SURVIVED SECONDS TRACE EVIDENCE
  local dirty host shmem
  read -r dirty host shmem <<<"$(peaks "$3")"
  jq -cn --argjson survived "$1" --argjson seconds "$2" --arg evidence "$4" \
    --argjson dirty "$dirty" --argjson host "$host" --argjson shmem "$shmem" \
    '{survived: $survived, seconds: $seconds, peak_dirty_writeback_mib: $dirty,
      peak_host_processes_mib: $host, peak_shmem_mib: $shmem, evidence: $evidence}'
}

# Guest RAM must be shared memory for anon + kernel to be the host processes alone:
# at least 90% of what the containers hold. Otherwise the round can't be read.
shmem_short() { # TRACE MAIN_GIB SECOND_GIB -> prints a reason when short
  local shmem want
  shmem="$(peaks "$1" | cut -d' ' -f3)"
  want=$(( ($2 + $3 - 2) * 1024 * 9 / 10 ))
  [[ "$shmem" == null ]] && { echo "no shmem was read"; return; }
  (( shmem >= want )) || echo "shmem peaked at $shmem MiB, short of the $want MiB the holds alone need: guest RAM may not be shared memory here, so the host-process figure is not the host processes"
}

round() { # MAIN_GIB SECOND_GIB OVERHEAD
  local main="$1" second="$2" overhead="$3" node started since uid phase sampler_pid
  local deadline log kills cgroup_kills mglru reason short
  node="$(k -n "$NAMESPACE" get pod "$SAMPLER" -o jsonpath='{.spec.nodeName}')" ||
    die "no sampler Pod $SAMPLER in $NAMESPACE"
  [[ -n "$node" ]] || die "the sampler Pod isn't on a node"
  mglru="$(k -n "$NAMESPACE" exec "$SAMPLER" -- cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null | tail -1)"
  # Global, so the EXIT trap still sees it after the round returns.
  trace="$(mktemp)"
  trap 'cleanup; [[ -z "$KEEP_TRACE" ]] || cp "${trace:-/dev/null}" "$KEEP_TRACE" 2>/dev/null; rm -f "${trace:-}"' EXIT
  cleanup
  runtime_class_json "$(k get runtimeclass commodity -o json)" "$overhead" | k apply -f - >/dev/null
  volume_json "$main" "$second" | k apply -f - >/dev/null
  since="$(date -u +%Y-%m-%dT%H:%M:%S)"
  started="$(date +%s)"
  pod_json "$main" "$second" "$node" | k apply -f - >/dev/null
  for _ in $(seq 1 120); do
    uid="$(k -n "$NAMESPACE" get pod "$TEST_NAME" -o jsonpath='{.metadata.uid} {.status.phase}' 2>/dev/null || true)"
    [[ "${uid#* }" == Running || "${uid#* }" == Failed ]] && break
    sleep 3
  done
  phase="${uid#* }" uid="${uid%% *}"
  echo "pod overhead: $(k -n "$NAMESPACE" get pod "$TEST_NAME" -o jsonpath='{.spec.overhead}' 2>/dev/null || true)" >&2
  [[ "$phase" == Running ]] || { result null "$(( $(date +%s) - started ))" /dev/null "the Pod never ran: $phase"; exit 2; }
  k -n "$NAMESPACE" exec "$SAMPLER" -- sh -c "POD_UID=$uid; $(sample_script)" >"$trace" 2>&1 &
  sampler_pid=$!
  # Writes, plus the time to fill RAM and to start.
  deadline=$(( $(date +%s) + WRITE_SECONDS + main * 20 + 300 ))
  while (( $(date +%s) < deadline )); do
    phase="$(k -n "$NAMESPACE" get pod "$TEST_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || echo gone)"
    [[ "$phase" == Running ]] || break
    log="$(k -n "$NAMESPACE" logs "$TEST_NAME" -c main --tail=3 2>/dev/null || true)"
    grep -q WRITES_DONE <<<"$log" && break
    sleep 5
  done
  kill "$sampler_pid" 2>/dev/null || true
  wait "$sampler_pid" 2>/dev/null || true
  cgroup_kills="$(awk '$1 ~ /^[0-9]+$/ { k = $3 } END { print k + 0 }' "$trace")"
  kills="$(kernel_vm_kills "$since")"
  reason="phase=$phase writes_done=$(grep -c WRITES_DONE <<<"${log:-}" || true) pod_oom_kills=$cgroup_kills kernel_vm_kills=${kills:-unread} mglru=${mglru:-unread} volume=$VOLUME writers=[$WRITERS] node_wide=no"
  short="$(shmem_short "$trace" "$main" "$second")"
  if [[ -n "$short" ]]; then
    result null "$(( $(date +%s) - started ))" "$trace" "$short: $reason"
    exit 2
  fi
  if [[ "$phase" == Running ]] && grep -q WRITES_DONE <<<"${log:-}" && [[ "$cgroup_kills" == 0 && "$kills" != [1-9]* ]]; then
    result true "$(( $(date +%s) - started ))" "$trace" "$reason"
    exit 0
  fi
  if [[ "$phase" == Running && "$cgroup_kills" == 0 && "$kills" != [1-9]* ]]; then
    result null "$(( $(date +%s) - started ))" "$trace" "timed out before the writes finished: $reason"
    exit 2
  fi
  result false "$(( $(date +%s) - started ))" "$trace" "$reason"
  exit 1
}

main() {
  if [[ "${1:-}" == --print ]]; then
    shift
    [[ "$#" == 3 ]] || die "usage: --print MAIN_GIB SECOND_GIB OVERHEAD"
    runtime_class_json '{"handler":"kata-clh","overhead":{"podFixed":{"cpu":"250m","memory":"1Gi"}},"scheduling":{}}' "$3"
    volume_json "$1" "$2"
    pod_json "$1" "$2" "${KILL_TEST_NODE:-the-sampler-node}"
    return
  fi
  [[ "$#" == 3 ]] || die "usage: MAIN_GIB SECOND_GIB OVERHEAD"
  [[ "$1" =~ ^[2-9]$|^[1-9][0-9]+$ && "$2" =~ ^[2-9]$|^[1-9][0-9]+$ ]] || die "sizes are whole GiB, at least 2"
  [[ "$3" =~ ^[1-9][0-9]*(Mi|Gi)$ ]] || die "the overhead looks like 512Mi or 1Gi"
  [[ "$VOLUME" == virtiofs || "$VOLUME" == block ]] || die "KILL_TEST_VOLUME is virtiofs or block"
  round "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
