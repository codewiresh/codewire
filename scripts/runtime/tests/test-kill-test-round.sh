#!/usr/bin/env bash
# Offline contract for one kill-test round (#3718): the objects it would apply, and
# that it touches only its own.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROUND="$ROOT/scripts/runtime/dev/kill-test-round.sh"
fail() { printf 'test-kill-test-round: %s\n' "$*" >&2; exit 1; }

bash -n "$ROUND"
objects() { "$ROUND" --print "$@" | jq -s .; }

# Block is the default: what sets the values after cutover.
[[ "$("$ROUND" --print 4 2 1Gi | jq -s -r '.[1].spec.volumeMode')" == Block ]] || fail "block is not the default"

# virtio-fs: both containers write to the workspace volume; main also to /tmp and a
# root filesystem path. Each holds all but 1 GiB of its limit in guest memory.
all="$(KILL_TEST_VOLUME=virtiofs objects 8 4 512Mi)"
rc="$(jq '.[0]' <<<"$all")" pvc="$(jq '.[1]' <<<"$all")" pod="$(jq '.[2]' <<<"$all")"
[[ "$(jq -r '.overhead.podFixed.memory' <<<"$rc")" == 512Mi ]] || fail "overhead not applied"
[[ "$(jq -r '.overhead.podFixed.cpu' <<<"$rc")" == 250m ]] || fail "commodity's CPU overhead was not kept"
[[ "$(jq -r '.handler' <<<"$rc")" == kata-clh ]] || fail "handler not copied from commodity"
[[ "$(jq -r '.spec.volumeMode' <<<"$pvc")" == Filesystem ]] || fail "virtiofs volume mode"
[[ "$(jq -c '[.spec.containers[].resources.limits.memory]' <<<"$pod")" == '["8Gi","4Gi"]' ]] || fail "shape"
[[ "$(jq -r '.spec.runtimeClassName' <<<"$pod")" == cw-kill-test ]] || fail "the Pod doesn't use the throwaway class"
[[ "$(jq -r '.spec.containers[0].image' <<<"$pod")" =~ ^ghcr\.io/codewiresh/workspace@sha256:[0-9a-f]{64}$ ]] ||
  fail "the image is not the pinned workspace image"
[[ "$(jq -r '.spec.containers[0].env[] | select(.name == "WRITERS") | .value' <<<"$pod")" == "/data /tmp /usr/local" ]] ||
  fail "main writers"
[[ "$(jq -r '.spec.containers[1].env[] | select(.name == "WRITERS") | .value' <<<"$pod")" == "/data" ]] || fail "second writers"
[[ "$(jq -c '[.spec.volumes[] | select(.emptyDir.medium == "Memory") | .name]' <<<"$pod")" == '["hold-main","hold-second"]' ]] ||
  fail "memory holds"
script="$(jq -r '.spec.containers[0].command[2]' <<<"$pod")"
# shellcheck disable=SC2016
grep -F 'half=$(( (LIMIT_GIB - 1) * 512 ))' <<<"$script" >/dev/null || fail "the hold is not all but 1 GiB"
sh -n -c "$script" || fail "the container script is not valid sh"
jq -e '[.spec.containers[] | .securityContext.privileged // false] | any | not' <<<"$pod" >/dev/null ||
  fail "virtiofs runs privileged"

# The container script runs: it holds, writes to each path until told to stop, and
# says so. Stand-in commands keep it to this machine.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/hold" "$work/w1" "$work/w2"
cat >"$work/bin/dd" <<'SH'
#!/bin/sh
for a in "$@"; do case "$a" in of=*) : >"${a#of=}" ;; esac; done
echo "$*" >>"$CALLS"
SH
chmod 755 "$work/bin/dd"
run_script="$(sed -e "s|/hold/|$work/hold/|g" -e 's/^sleep 3600$//' <<<"$script")"
out="$(CALLS="$work/calls" PATH="$work/bin:$PATH" NAME=main LIMIT_GIB=3 MOUNT_BLOCK=0 WRITE_SECONDS=1 \
  WRITERS="$work/w1 $work/w2" sh -c "$run_script")"
grep -F 'main holding 2GiB' <<<"$out" >/dev/null || fail "no hold line: $out"
grep -F 'main WRITES_DONE' <<<"$out" >/dev/null || fail "no done line: $out"
grep -c 'count=1024' "$work/calls" | grep -qv '^0$' || fail "the hold wrote nothing"
[[ -d "$work/w1/cw-kill-test" && -d "$work/w2/cw-kill-test" ]] || fail "a writer path was not used"

# Block: the guest formats and mounts its own device; only that container is
# privileged, and the second container holds memory without a second mount.
all="$(KILL_TEST_VOLUME=block KILL_TEST_HANDLER=kata-clh-dio objects 16 4 1Gi)"
rc="$(jq '.[0]' <<<"$all")" pvc="$(jq '.[1]' <<<"$all")" pod="$(jq '.[2]' <<<"$all")"
[[ "$(jq -r '.handler' <<<"$rc")" == kata-clh-dio ]] || fail "the handler setting was ignored"
[[ "$(jq -r '.spec.volumeMode' <<<"$pvc")" == Block ]] || fail "block volume mode"
[[ "$(jq -r '.spec.containers[0].volumeDevices[0].devicePath' <<<"$pod")" == /dev/cwblk ]] || fail "block device"
[[ "$(jq -r '.spec.containers[0].securityContext.privileged' <<<"$pod")" == true ]] || fail "main not privileged on block"
[[ "$(jq -r '.spec.containers[1].securityContext.privileged // false' <<<"$pod")" == false ]] || fail "second privileged"
jq -e '[.spec.containers[1].volumeMounts[].name] | index("data") | not' <<<"$pod" >/dev/null || fail "second mounts the block volume"
[[ "$(jq -r '.spec.containers[0].env[] | select(.name == "MOUNT_BLOCK") | .value' <<<"$pod")" == 1 ]] || fail "no in-guest mount"

# Writer paths follow the setting, for wherever /tmp ends up.
pod="$(KILL_TEST_WRITERS="/data /workspace-tmp" objects 4 2 1Gi | jq '.[2]')"
[[ "$(jq -r '.spec.containers[0].env[] | select(.name == "WRITERS") | .value' <<<"$pod")" == "/data /workspace-tmp" ]] ||
  fail "writer setting"

# The guest's RAM must show as shmem, or the host-process figure means something else.
# shellcheck disable=SC1090
source "$ROUND"
printf '%s\n' '0 100 0 3000' '200 150 0 10500' >"$work/trace"
[[ -z "$(shmem_short "$work/trace" 8 4)" ]] || fail "a full guest was called short"
grep -F 'guest RAM may not be shared memory' <<<"$(shmem_short "$work/trace" 16 4)" >/dev/null || fail "a short shmem passed"
read -r dirty host shmem <<<"$(peaks "$work/trace")"
[[ "$dirty $host $shmem" == "200 150 10500" ]] || fail "peaks: $dirty $host $shmem"
[[ "$(peaks /nonexistent)" == "null null null" ]] || fail "an unread trace is not null"

# The kernel log: a failed or empty read is unread, never no kills.
kills_since() { DMESG="$1" kernel_vm_kills 2026-11-01T13:00:00; } # LOG-COMMAND
[[ "$(kills_since '')" == unread ]] || fail "no command read as no kills"
[[ "$(kills_since 'exit 1')" == unread ]] || fail "a failed read was counted"
[[ "$(kills_since true)" == unread ]] || fail "an empty read was counted"
log="printf '%s\n' '[2026-11-01T12:59:00.1Z]: out of memory: Killed process 1 (cloud-hyperviso)' '[2026-11-01T13:05:00.1Z]: out of memory: Killed process 2 (cloud-hyperviso)' '[2026-11-01T13:06:00.1Z]: out of memory: Killed process 3 (python3)'"
[[ "$(kills_since "$log")" == 1 ]] || fail "kills since the round: $(kills_since "$log")"
[[ "$(kills_since "echo '[2026-11-01T13:05:00.1Z]: nothing here'")" == 0 ]] || fail "a read log with no kills"

# Every mutating call names this tool's own objects.
# A whole round against a stand-in cluster: the VM is killed while it fills its RAM,
# before any write. The round still reports a loss with its peaks, and cleans up. The
# stand-in host read answers in the background, so the Pod fails only once it has been
# sampled: otherwise a slow runner kills it before it writes, and the round, rightly,
# can't read the VM (exit 2).
# The round calls these stand-ins and reads DMESG.
# shellcheck disable=SC2329,SC2034
round_with_kill() (
  set -euo pipefail # as the round runs on its own
  host_read() {
    local M=1048576 n
    case "$1" in
      /sys/kernel/mm/lru_gen/enabled) echo 0x0007 ;;
      /sys/fs/cgroup/kubepods/burstable/poduid-1/memory.max) echo 21474836480 ;;
      */memory.stat)
        n=$(( $(cat "$work/samples" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$work/samples"
        case "$n" in
          1) printf 'anon %d\nkernel %d\nshmem %d\nfile 0\nfile_dirty 0\nfile_writeback 0\n' $((200 * M)) $((100 * M)) $((18000 * M)) ;;
          2) printf 'anon %d\nkernel %d\nshmem %d\nfile 0\nfile_dirty 0\nfile_writeback 0\n' $((300 * M)) $((120 * M)) $((19000 * M)) ;;
          # The loop came round again, so the second sample's line is written:
          # only now may the Pod fail and the round stop the sampler (#4040).
          *) : >"$work/sampled"; return 1 ;;
        esac ;;
      */memory.events)
        if [[ "$(cat "$work/samples")" -ge 2 ]]; then printf 'oom 1\noom_kill 1\n'; else printf 'oom 0\noom_kill 0\n'; fi ;;
      *) return 1 ;;
    esac
  }
  k() {
    case "$*" in
      "get runtimeclass commodity -o json") echo '{"handler":"kata-clh","overhead":{"podFixed":{"cpu":"250m","memory":"1Gi"}},"scheduling":{}}' ;;
      *"apply -f -") cat >/dev/null ;;
      *"get pod cw-kill-test -o jsonpath={.metadata.uid} {.status.phase}") echo "uid-1 Running" ;;
      # Running until the sampler has written both samples, however slow the
      # runner: a fixed wait failed the Pod after one sample on a starved
      # runner (#4040). The round's own deadline bounds a sampler that never does.
      *"get pod cw-kill-test -o jsonpath={.status.phase}")
        if [[ -e "$work/sampled" ]]; then echo Failed; else command sleep 0.05; echo Running; fi ;;
      *" logs cw-kill-test "*) echo "main holding 15GiB" ;;
      *"delete "* | *"annotate "*) echo "$*" >>"$work/cleaned" ;;
    esac
  }
  sleep() { :; }
  DMESG='' NODE=node-a
  round 16 4 1Gi
)
: >"$work/cleaned"
rm -f "$work/sampled" "$work/samples"
set +e
out="$(round_with_kill 2>"$work/round.err")"
status=$?
set -e
[[ "$status" == 1 ]] || fail "a killed round exited $status: $(cat "$work/round.err")"
[[ "$(jq -c '[.survived, .peak_host_processes_mib, .peak_shmem_mib, .peak_cgroup_mib]' <<<"$out")" == '[false,420,19000,null]' ]] ||
  fail "a killed round's result: $out"
# A cgroup still there at the end gives its exact memory.peak.
printf 'CGROUP /sys/fs/cgroup/kubepods/burstable/poduid-2\nMEMORY_MAX 1\n' >"$work/trace-peak"
# The stand-in host read is called by cgroup_peak_mib.
# shellcheck disable=SC2329
[[ "$(host_read() { [[ "$1" == /sys/fs/cgroup/kubepods/burstable/poduid-2/memory.peak ]] && echo 6442450944; }; cgroup_peak_mib "$work/trace-peak")" == 6144 ]] ||
  fail "the cgroup peak wasn't read"
grep -F 'writes_done=0 pod_oom_kills=1 kernel_vm_kills=unread' <<<"$out" >/dev/null || fail "a killed round's evidence: $out"
grep -F 'delete runtimeclass cw-kill-test' "$work/cleaned" >/dev/null || fail "a killed round left its objects"

# shellcheck disable=SC2016
if grep -nE 'k( -n "\$NAMESPACE")? (delete|annotate|apply)' "$ROUND" | grep -vE 'TEST_NAME|k apply -f -' >/dev/null; then
  fail "it deletes or annotates something other than its own objects"
fi
grep -F 'readonly TEST_NAME=cw-kill-test' "$ROUND" >/dev/null || fail "the object name changed"
# No host name or address is written into the tool; the node comes from KILL_TEST_NODE.
if grep -nE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|servernet|hz-eu' "$ROUND" >/dev/null; then
  fail "a host name or address is in the tool"
fi

# The real workload: the product's shape on Block. Only the one-shot mounter holds the
# device; the workspace and DinD see the disk through propagation at the product's
# paths; /usr/local stays on the root filesystem; DinD is the pinned product image.
real="$(KILL_TEST_WORKLOAD=real objects 16 4 1Gi)"
pod="$(jq '.[2]' <<<"$real")"
[[ "$(jq -r '.[1].spec.volumeMode' <<<"$real")" == Block ]] || fail "real: not a Block volume"
[[ "$(jq -c '[.spec.initContainers[] | {name, dev: [.volumeDevices[]?.devicePath], privileged: .securityContext.privileged}]' <<<"$pod")" == '[{"name":"mounter","dev":["/dev/cwws"],"privileged":true}]' ]] ||
  fail "real: the mounter: $(jq -c .spec.initContainers <<<"$pod")"
[[ "$(jq '[.spec.containers[] | select(.volumeDevices)] | length' <<<"$pod")" == 0 ]] || fail "real: a workload container holds the device"
[[ "$(jq -c '[.spec.initContainers[0].volumeMounts[].mountPropagation] | unique' <<<"$pod")" == '["Bidirectional"]' ]] || fail "real: mounter propagation"
[[ "$(jq -r '[.spec.containers[0].volumeMounts[] | select(.name == "mnthome" or .name == "wstmp") | "\(.mountPath):\(.mountPropagation)"] | join(" ")' <<<"$pod")" == \
  "/workspace:HostToContainer /home/codewire:HostToContainer /tmp:HostToContainer /var/tmp:HostToContainer" ]] || fail "real: workspace mounts"
[[ "$(jq -r '.spec.volumes[] | select(.name == "docker-sock") | .emptyDir.medium' <<<"$pod")" == Memory ]] ||
  fail "real: the Docker socket is not in guest memory"
if jq -e '.spec.containers[].volumeMounts[] | select(.mountPath | startswith("/usr"))' <<<"$pod" >/dev/null; then
  fail "real: /usr is mounted over"
fi
[[ "$(jq -c '[.spec.containers[] | {name, privileged: (.securityContext.privileged // false), memory: .resources.limits.memory}]' <<<"$pod")" == \
  '[{"name":"main","privileged":false,"memory":"16Gi"},{"name":"dind","privileged":true,"memory":"4Gi"}]' ]] || fail "real: containers"
[[ "$(jq -r '.spec.containers[1].image' <<<"$pod")" =~ ^docker\.io/library/docker:[0-9.]+-dind@sha256:[0-9a-f]{64}$ ]] || fail "real: DinD image not the pin"
[[ "$(grep -c 'cw-kill-test-held-' <<<"$(real_main_script)")" -ge 2 && "$(grep -c 'cw-kill-test-held-' <<<"$(real_dind_script)")" -ge 2 ]] ||
  fail "real: the containers free their fills without waiting for each other"
grep -F 'FILL_SHORT' <<<"$(real_main_script)" >/dev/null || fail "real: a short fill goes unnoticed"
grep -F 'mount --bind /mnt/ws/.codewire/tmp /mnt/tmp' <<<"$(real_mounter_script)" >/dev/null ||
  fail "real: /tmp is not the product's temp directory on the workspace disk"
# shellcheck disable=SC2016
grep -F 'STEP $name start' <<<"$(real_main_script)" >/dev/null || fail "real: steps don't print their start"
[[ "$(grep -oE '^step [a-z]+' <<<"$(real_main_script)" | tr '\n' ' ')" == "step go step docker step rust " ]] || fail "real: step order"
if KILL_TEST_WORKLOAD=real KILL_TEST_VOLUME=virtiofs "$ROUND" 8 4 1Gi >/dev/null 2>&1; then fail "real ran on virtio-fs"; fi
if KILL_TEST_WORKLOAD=synthetic "$ROUND" 8 4 1Gi >/dev/null 2>&1; then fail "accepted an unknown workload"; fi

# Refusals before touching anything, including a round with no node or host read.
if KILL_TEST_HOST_READ='' KILL_TEST_NODE=node-a "$ROUND" 8 4 1Gi >/dev/null 2>&1; then fail "ran without a host read"; fi
if KILL_TEST_HOST_READ=true KILL_TEST_NODE='' "$ROUND" 8 4 1Gi >/dev/null 2>&1; then fail "ran without a node"; fi
if grep -nE 'hostPID|hostPath|exec .*cw-oom-sampler' "$ROUND" >/dev/null; then fail "it reads the host through a Pod"; fi
for bad in "1 2 1Gi" "8 4 1G" "8 x 1Gi"; do
  # shellcheck disable=SC2086
  if "$ROUND" $bad >/dev/null 2>&1; then fail "accepted $bad"; fi
done
if KILL_TEST_VOLUME=nfs "$ROUND" 8 4 1Gi >/dev/null 2>&1; then fail "accepted an unknown volume mode"; fi

echo "kill test round tests: ok"
