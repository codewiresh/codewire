#!/usr/bin/env bash
# One round of the commodity overhead kill test (#3718; design
# 2026-11-01-commodity-workspace-direct-io §4), for kill-test-overhead-matrix.sh.
#
#   kill-test-round.sh MAIN_GIB SECOND_GIB OVERHEAD     run one round, print one JSON line
#   kill-test-round.sh --print MAIN_GIB SECOND_GIB OVERHEAD   the objects it would apply
#
# One test Pod alone on KILL_TEST_NODE, in a throwaway RuntimeClass that copies
# commodity's with this overhead. Each container holds all but 1 GiB of its limit in
# guest memory, so guest RAM is full; then buffered writers run on every writer path
# for KILL_TEST_WRITE_SECONDS. KILL_TEST_HOST_READ reads the test Pod's host cgroup
# from outside the cluster's Pods, as often as it answers: no Pod has host access
# (owner, 2026-11-02, #3718). On Dev, through Talos it answers about every 2 s per file.
#
# Prints: survived, seconds, peak_dirty_writeback_mib (the Pod cgroup's file_dirty +
# file_writeback), peak_host_processes_mib (its anon + kernel: the VMM's own memory,
# virtiofsd and the shim), peak_shmem_mib (all three sampled, so lower bounds),
# peak_cgroup_mib (the cgroup's exact memory.peak, null after a kill) and evidence. Guest RAM is shared memory,
# since the root filesystem is on virtio-fs, so it isn't in anon. A round whose shmem
# stays well short of the guest's holds says that's not so here, and is unknown.
# Exit 0 survived, 1 lost, 2 could not run or can't be read.
#
# Settings (environment):
#   KUBE_CONTEXT              cluster (default codewire-dev)
#   KILL_TEST_NAMESPACE       default codewire-runtime-probes
#   KILL_TEST_NODE            the node the test Pod runs on (required)
#   KILL_TEST_HOST_READ       a command that prints one file of that node, given its
#                             path as the last argument (required; on Dev
#                             `scripts/talos-access run CLUSTER admin -- --nodes NODE read`
#                             from infra, read-only)
#   KILL_TEST_VOLUME          block (default): a Block volume the guest formats; or
#                             virtiofs: a filesystem volume shared over virtio-fs
#   KILL_TEST_HANDLER         RuntimeClass handler (default: commodity's)
#   KILL_TEST_STORAGE_CLASS   default linstor-local
#   KILL_TEST_WRITERS         space-separated writer directories in the main container
#                             (default "/data /tmp /usr/local"; /data is the workspace)
#   KILL_TEST_WRITE_SECONDS   how long the writers run (default 120)
#   KILL_TEST_DMESG           optional command printing the node's kernel log, used to
#                             count host kills of the VM since the round began
#   KILL_TEST_WORKLOAD        fill (default): the holds and dd writers above; or real:
#                             the product's workspace shape on Block with a Go, Docker
#                             and Rust build (see real_pod_json); WRITE_SECONDS is
#                             then its budget (default 2400)
#   KILL_TEST_KEEP_TRACE      optional file to keep the host trace in (and, for
#                             the real workload, the workspace container's log beside it)
set -euo pipefail
umask 077

KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
NAMESPACE="${KILL_TEST_NAMESPACE:-codewire-runtime-probes}"
NODE="${KILL_TEST_NODE:-}"
HOST_READ="${KILL_TEST_HOST_READ:-}"
VOLUME="${KILL_TEST_VOLUME:-block}"
HANDLER="${KILL_TEST_HANDLER:-}"
STORAGE_CLASS="${KILL_TEST_STORAGE_CLASS:-linstor-local}"
WRITERS="${KILL_TEST_WRITERS:-/data /tmp /usr/local}"
WORKLOAD="${KILL_TEST_WORKLOAD:-fill}"
WRITE_SECONDS="${KILL_TEST_WRITE_SECONDS:-$([[ "$WORKLOAD" == real ]] && echo 2400 || echo 120)}"
DMESG="${KILL_TEST_DMESG:-}"
KEEP_TRACE="${KILL_TEST_KEEP_TRACE:-}"
# The product's workspace image, as the repository pins it: usually already on a
# runtime node, and it has sh and dd.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGE="$(sed -n 's/^pub const PUBLIC_IMAGE: &str = "\(.*\)";$/\1/p' "$ROOT/crates/codewire-workspace-image/src/pin.rs")"
readonly IMAGE
# The product's DinD image, as its template pins it.
DIND_IMAGE="$(sed -n 's/^pub const DEFAULT_DIND_IMAGE: &str = "\(.*\)";$/\1/p' "$ROOT/crates/codewire-orchestration/src/sandbox/template/mod.rs")"
readonly DIND_IMAGE
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
  [[ "$WORKLOAD" != real ]] || { real_pod_json "$@"; return; }
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

# The real workload (KILL_TEST_WORKLOAD=real): the product's workspace shape on a
# Block disk. A one-shot privileged init container is the only holder of the device:
# it formats a new disk, checks, mounts and grows it, seeds the image's home and the
# Docker data image onto it, and shares it through guest memory with Bidirectional
# propagation. The workspace container (root, unprivileged, as sudo gives a user) and
# DinD see it with HostToContainer at the product's paths; /usr/local stays on the
# root filesystem, which is the path measured. Each container first fills all but
# 1 GiB of its limit in guest memory and frees it: kata-clh doesn't reclaim freed
# guest pages, so guest RAM stays touched on the host while the build has the whole
# limit. The workload needs only the image and ghcr.io, which is all the probes
# namespace may reach.
real_mounter_script() {
  cat <<'SH'
set -eu
dev=/dev/cwws
fresh=0
if ! blkid "$dev" >/dev/null 2>&1; then
  mkfs.ext4 -q -E lazy_itable_init=1,lazy_journal_init=1 "$dev"
  fresh=1
fi
rc=0
e2fsck -f -p "$dev" || rc=$?
[ "$rc" -le 1 ]
mount -o noatime "$dev" /mnt/ws
resize2fs "$dev" >/dev/null 2>&1
if [ "$fresh" = 1 ]; then
  chown 1000:1000 /mnt/ws
  # A new workspace starts with the image's home: the Rust toolchain lives there.
  cp -a /home/codewire/. /mnt/ws/
  mkdir -p /mnt/ws/.codewire
  # As the product's DinD bootstrap leaves it: the workspace daemon refuses a group- or
  # world-writable ancestor of its session store.
  chown 1000:1000 /mnt/ws/.codewire
  chmod 0755 /mnt/ws/.codewire
  truncate -s "${DOCKER_DATA_GIB}G" /mnt/ws/.codewire/docker-data.ext4
  mkfs.ext4 -q -F -E lazy_itable_init=1,lazy_journal_init=1 /mnt/ws/.codewire/docker-data.ext4
fi
# The temp directory on the workspace disk, where the product puts it.
mkdir -p /mnt/ws/.codewire/tmp
chmod 1777 /mnt/ws/.codewire/tmp
mount --bind /mnt/ws/.codewire/tmp /mnt/tmp
echo "mounter mounted fresh=$fresh"
SH
}

# Each container holds all but 1 GiB of its limit and records "held want" MiB on the
# workspace; both hold at once before either frees, or the guest reuses one's freed
# pages for the other's fill and the host sees only the larger of the two. The
# workspace container holds anonymous memory, since a guest tmpfs may be capped
# below a large fill; DinD, which has no python, holds a small tmpfs fill.
real_wait_script() {
  cat <<'SH'
for _ in $(seq 1 150); do
  [ -e /workspace/.cw-kill-test-held-main ] && [ -e /workspace/.cw-kill-test-held-dind ] && break
  sleep 2
done
SH
}

real_dind_fill_script() {
  cat <<'SH'
want=$(( (LIMIT_GIB - 1) * 1024 ))
dd if=/dev/zero of=/hold/a bs=1M count="$want" 2>/dev/null
echo "$(du -sm /hold | cut -f1) $want" >"/workspace/.cw-kill-test-held-$NAME"
SH
  real_wait_script
  cat <<'SH'
rm -f /hold/a
echo "$NAME filled $(cat "/workspace/.cw-kill-test-held-$NAME") MiB (held, wanted) and freed it"
SH
}

real_main_fill_script() {
  cat <<'SH'
python3 - "$(( (LIMIT_GIB - 1) * 1024 ))" "$NAME" <<'PY'
import os, sys, time
want, name = int(sys.argv[1]), sys.argv[2]
hold = bytearray(want << 20)
hold[::4096] = b"\x01" * len(range(0, len(hold), 4096))
with open(f"/workspace/.cw-kill-test-held-{name}", "w") as f:
    f.write(f"{len(hold) >> 20} {want}\n")
for _ in range(150):
    if all(os.path.exists(f"/workspace/.cw-kill-test-held-{c}") for c in ("main", "dind")):
        break
    time.sleep(2)
PY
for c in main dind; do
  read -r held want <"/workspace/.cw-kill-test-held-$c" || { held=0; want=1; }
  echo "$c filled ${held} of ${want} MiB and freed it"
  if [ "$held" -lt $(( want * 95 / 100 )) ]; then
    echo "FILL_SHORT $c held $held of $want MiB"
    sleep 3600
  fi
done
SH
}

# DinD as the product runs it: a loop-mounted ext4 data image on the workspace disk.
real_dind_script() {
  real_dind_fill_script
  cat <<'SH'
mkdir -p /var/lib/docker
mount -o loop /workspace/.codewire/docker-data.ext4 /var/lib/docker
exec dockerd --host unix:///var/run/docker/docker.sock --group 1000 --data-root /var/lib/docker --storage-driver vfs
SH
}

# In order: Go (its tree unpacked into /usr/local as a package would be, then all of
# cmd rebuilt from it), a docker build, then Rust (its toolchain unpacked into
# /usr/local, then a crate built). Each step prints its start time, to match the
# host trace, then its result and wall time.
real_main_script() {
  real_main_fill_script
  cat <<'SH'
[ "$(findmnt -no FSTYPE /workspace)" = ext4 ] || { echo "$NAME: /workspace is not the workspace disk"; exit 1; }
work=/workspace/cw-kill-test
inst=/usr/local/cw-kill-test
mkdir -p "$work" "$inst"
step() {
  name="$1"
  shift
  started=$(date +%s)
  echo "STEP $name start $started"
  if "$@" >"$work/$name.log" 2>&1; then status=ok; else status=failed; fi
  echo "STEP $name $status $(( $(date +%s) - started ))s"
}
go_step() {
  tar -C /usr/local -cf - go | tar -C "$inst" -xf - &&
    GOROOT="$inst/go" GOCACHE="$work/gocache" CGO_ENABLED=0 "$inst/go/bin/go" install -a cmd/...
}
docker_step() {
  for _ in $(seq 1 90); do docker info >/dev/null 2>&1 && break; sleep 2; done
  ctx="$work/docker"
  rm -rf "$ctx"
  mkdir -p "$ctx"
  cp -a /usr/local/go "$ctx/go" &&
    tar -C / -c bin lib lib64 usr/bin usr/lib64 usr/lib/x86_64-linux-gnu etc 2>/dev/null | docker import - cw-kill-test-base &&
    printf '%s\n' 'FROM cw-kill-test-base' 'COPY go /usr/local/go' \
      'RUN mkdir -p /tmp && CGO_ENABLED=0 GOCACHE=/tmp/gocache /usr/local/go/bin/go build -a std && rm -rf /tmp/gocache' >"$ctx/Dockerfile" &&
    docker build --no-cache -t cw-kill-test-build "$ctx" &&
    docker rmi -f cw-kill-test-build cw-kill-test-base
}
rust_step() {
  export CARGO_HOME=/home/codewire/.cargo RUSTUP_HOME=/home/codewire/.rustup
  export PATH="$CARGO_HOME/bin:$PATH"
  mkdir -p "$inst/rustup" &&
    tar -C "$RUSTUP_HOME" -cf - toolchains | tar -C "$inst/rustup" -xf - &&
    rm -rf "$work/app" && cargo new --vcs none "$work/app" &&
    cd "$work/app" && CARGO_TARGET_DIR="$work/target" cargo build --release --offline
}
step go go_step
step docker docker_step
step rust rust_step
echo "USR_LOCAL_MIB $(du -sm "$inst" | cut -f1)"
echo "$NAME WRITES_DONE"
sleep 3600
SH
}

real_pod_json() { # MAIN_GIB SECOND_GIB NODE
  jq -n --arg name "$TEST_NAME" --arg ns "$NAMESPACE" --arg node "$3" \
    --arg image "$IMAGE" --arg dind "$DIND_IMAGE" --argjson main "$1" --argjson second "$2" \
    --arg mounter "$(real_mounter_script)" --arg workspace "$(real_main_script)" --arg docker "$(real_dind_script)" '
    def limits($cpu; $memory): {requests: {cpu: $cpu, memory: $memory}, limits: {cpu: $cpu, memory: $memory}};
    def seen($at): {name: "wsmnt", mountPath: $at, mountPropagation: "HostToContainer"};
    def tmp($at): {name: "wstmp", mountPath: $at, mountPropagation: "HostToContainer"};
    {
      apiVersion: "v1", kind: "Pod",
      metadata: {name: $name, namespace: $ns, labels: {"codewire.sh/test": $name}},
      spec: {
        runtimeClassName: $name, nodeSelector: {"kubernetes.io/hostname": $node},
        automountServiceAccountToken: false, restartPolicy: "Never",
        tolerations: [{operator: "Exists"}],
        initContainers: [{
          name: "mounter", image: $image, command: ["sh", "-c", $mounter],
          env: [{name: "DOCKER_DATA_GIB", value: "16"}],
          securityContext: {privileged: true, runAsUser: 0},
          resources: limits("1"; "512Mi"),
          volumeDevices: [{name: "ws", devicePath: "/dev/cwws"}],
          volumeMounts: [{name: "wsmnt", mountPath: "/mnt/ws", mountPropagation: "Bidirectional"},
                         {name: "wstmp", mountPath: "/mnt/tmp", mountPropagation: "Bidirectional"}]
        }],
        containers: [
          {name: "main", image: $image, command: ["sh", "-c", $workspace],
           env: [{name: "NAME", value: "main"}, {name: "LIMIT_GIB", value: "\($main)"},
                 {name: "HOME", value: "/home/codewire"},
                 {name: "DOCKER_HOST", value: "unix:///var/run/docker/docker.sock"}],
           securityContext: {runAsUser: 0},
           resources: limits("2"; "\($main)Gi"),
           volumeMounts: [seen("/workspace"), seen("/home/codewire"), tmp("/tmp"), tmp("/var/tmp"),
                          {name: "docker-sock", mountPath: "/var/run/docker"},
                          {name: "hold-main", mountPath: "/hold"}]},
          {name: "dind", image: $dind, command: ["sh", "-c", $docker],
           env: [{name: "NAME", value: "dind"}, {name: "LIMIT_GIB", value: "\($second)"}],
           securityContext: {privileged: true},
           resources: limits("2"; "\($second)Gi"),
           volumeMounts: [seen("/workspace"), tmp("/tmp"),
                          {name: "docker-sock", mountPath: "/var/run/docker"},
                          {name: "hold-dind", mountPath: "/hold"}]}
        ],
        volumes: [{name: "ws", persistentVolumeClaim: {claimName: $name}},
                  {name: "wsmnt", emptyDir: {medium: "Memory"}},
                  {name: "wstmp", emptyDir: {medium: "Memory"}},
                  # In guest memory, as the product has it: a socket does not cross virtio-fs.
                  {name: "docker-sock", emptyDir: {medium: "Memory"}},
                  {name: "hold-main", emptyDir: {medium: "Memory"}},
                  {name: "hold-dind", emptyDir: {medium: "Memory"}}]
      }
    }'
}

volume_json() { # MAIN_GIB SECOND_GIB
  # Room for every writer's eight 1 GiB files, the second container's and some slack.
  local paths; paths="$(wc -w <<<"$WRITERS")"
  # The real workload: the image's home, 16 GiB of Docker data and the builds.
  [[ "$WORKLOAD" != real ]] || paths=1
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

# One file of the node, through KILL_TEST_HOST_READ.
host_read() { # PATH
  bash -c "$HOST_READ \"\$1\"" host_read "$1" 2>/dev/null
}

# The Pod cgroup as often as the host read answers: file_dirty + file_writeback,
# anon + kernel, the oom_kill event count and shmem, as "dirty_wb host oom_kill shmem",
# then anon, kernel, file and the local clock; first its memory.max.
sample_cgroup() { # POD_UID
  local c="/sys/fs/cgroup/kubepods/burstable/pod$1" max stat events
  max="$(host_read "$c/memory.max")" || { c="/sys/fs/cgroup/kubepods/pod$1"; max="$(host_read "$c/memory.max")"; } ||
    { echo NO_CGROUP; return 2; }
  echo "CGROUP $c"
  echo "MEMORY_MAX $max"
  while stat="$(host_read "$c/memory.stat")" && events="$(host_read "$c/memory.events")"; do
    awk -v t="$(date +%s)" -v evs="$(tr '\n' ' ' <<<"$events")" '
      { v[$1] = $2 }
      END { n = split(evs, e, " "); for (i = 1; i < n; i += 2) ev[e[i]] = e[i + 1]
            M = 1048576
            printf "%d %d %d %d %d %d %d %d\n", (v["file_dirty"] + v["file_writeback"]) / M, (v["anon"] + v["kernel"]) / M, ev["oom_kill"], v["shmem"] / M,
              v["anon"] / M, v["kernel"] / M, v["file"] / M, t }' <<<"$stat"
  done
  echo CGROUP_GONE
}

peaks() { # TRACE -> "dirty_wb host shmem", or nulls
  awk '$1 ~ /^[0-9]+$/ { if ($1 > d) d = $1; if ($2 > h) h = $2; if ($4 > s) s = $4; n++ }
    END { if (n) printf "%d %d %d", d, h, s; else printf "null null null" }' "$1" 2>/dev/null || echo "null null null"
}

# The cgroup's exact high-water mark of all its memory (anon, kernel, file and shmem
# together), read once at the end; null when the cgroup is already gone, as after a
# kill. The sampled peaks above are lower bounds of their parts.
cgroup_peak_mib() { # TRACE
  local c peak
  c="$(awk '$1 == "CGROUP" { print $2; exit }' "$1" 2>/dev/null)"
  if [[ -n "$c" ]] && peak="$(host_read "$c/memory.peak")" && [[ "$peak" =~ ^[0-9]+$ ]]; then
    echo $(( peak / 1048576 ))
  else
    echo null
  fi
}

result() { # SURVIVED SECONDS TRACE EVIDENCE
  local dirty host shmem
  read -r dirty host shmem <<<"$(peaks "$3")"
  jq -cn --argjson survived "$1" --argjson seconds "$2" --arg evidence "$4" \
    --argjson dirty "$dirty" --argjson host "$host" --argjson shmem "$shmem" \
    --argjson cgroup "$(cgroup_peak_mib "$3")" \
    '{survived: $survived, seconds: $seconds, peak_dirty_writeback_mib: $dirty,
      peak_host_processes_mib: $host, peak_shmem_mib: $shmem, peak_cgroup_mib: $cgroup,
      evidence: $evidence}'
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
  local main="$1" second="$2" overhead="$3" node="$NODE" started since uid phase reader_pid
  local deadline log kills cgroup_kills mglru reason short running_after
  mglru="$(host_read /sys/kernel/mm/lru_gen/enabled | tail -1)"
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
  # From the Pod's create to Running: on a cold node, the image's unpack too.
  running_after=$(( $(date +%s) - started ))
  echo "pod overhead: $(k -n "$NAMESPACE" get pod "$TEST_NAME" -o jsonpath='{.spec.overhead}' 2>/dev/null || true)" >&2
  [[ "$phase" == Running ]] || { result null "$(( $(date +%s) - started ))" /dev/null "the Pod never ran: $phase"; exit 2; }
  sample_cgroup "$uid" >"$trace" 2>&1 &
  reader_pid=$!
  # Writes, plus the time to fill RAM and to start.
  deadline=$(( $(date +%s) + WRITE_SECONDS + main * 20 + 300 ))
  while (( $(date +%s) < deadline )); do
    phase="$(k -n "$NAMESPACE" get pod "$TEST_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || echo gone)"
    [[ "$phase" == Running ]] || break
    log="$(k -n "$NAMESPACE" logs "$TEST_NAME" -c main --tail=3 2>/dev/null || true)"
    grep -qE 'WRITES_DONE|FILL_SHORT' <<<"$log" && break
    sleep 5
  done
  kill "$reader_pid" 2>/dev/null || true
  wait "$reader_pid" 2>/dev/null || true
  cgroup_kills="$(awk '$1 ~ /^[0-9]+$/ { k = $3 } END { print k + 0 }' "$trace")"
  kills="$(kernel_vm_kills "$since")"
  reason="phase=$phase writes_done=$(grep -c WRITES_DONE <<<"${log:-}" || true) pod_oom_kills=$cgroup_kills kernel_vm_kills=${kills:-unread} mglru=${mglru:-unread} volume=$VOLUME handler=${HANDLER:-commodity} running_after=${running_after}s writers=[$WRITERS] node_wide=no"
  if [[ "$WORKLOAD" == real ]]; then
    # Each step's result and wall time, and what reached /usr/local.
    log="$(k -n "$NAMESPACE" logs "$TEST_NAME" -c main 2>/dev/null || true)"
    reason="workload=real steps=[$(grep -E '^(STEP [a-z]+ (ok|failed) |USR_LOCAL_MIB |FILL_SHORT |(main|dind) filled )' <<<"$log" | tr '\n' ' ' || true)] ${reason/ writers=\[$WRITERS\]/}"
    if [[ -n "$KEEP_TRACE" ]]; then
      { for c in mounter main dind; do echo "== $c"; k -n "$NAMESPACE" logs "$TEST_NAME" -c "$c" 2>&1 || true; done; } >"$KEEP_TRACE.logs" 2>&1
    fi
  fi
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
    pod_json "$1" "$2" "${NODE:-the-node}"
    return
  fi
  [[ "$#" == 3 ]] || die "usage: MAIN_GIB SECOND_GIB OVERHEAD"
  [[ "$1" =~ ^[2-9]$|^[1-9][0-9]+$ && "$2" =~ ^[2-9]$|^[1-9][0-9]+$ ]] || die "sizes are whole GiB, at least 2"
  [[ "$3" =~ ^[1-9][0-9]*(Mi|Gi)$ ]] || die "the overhead looks like 512Mi or 1Gi"
  [[ "$VOLUME" == virtiofs || "$VOLUME" == block ]] || die "KILL_TEST_VOLUME is virtiofs or block"
  [[ "$WORKLOAD" == fill || "$WORKLOAD" == real ]] || die "KILL_TEST_WORKLOAD is fill or real"
  [[ "$WORKLOAD" != real || "$VOLUME" == block ]] || die "the real workload runs on a Block volume"
  [[ -n "$IMAGE" && -n "$DIND_IMAGE" ]] || die "the workspace or DinD image pin wasn't found"
  [[ -n "$NODE" && -n "$HOST_READ" ]] || die "KILL_TEST_NODE and KILL_TEST_HOST_READ are required"
  round "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
