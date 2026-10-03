#!/usr/bin/env bash
# Qualified-host proof for the additive Linux Cloud Hypervisor spike. This
# script never acquires artifacts or selects another VMM: callers must stage
# the exact immutable inputs and lock before invoking it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly REQUIRED_CH_SHA256='448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc'
readonly REQUIRED_CH_SIZE='7062256'
readonly REQUIRED_KERNEL_RELEASE='6.18.48-codewire2'
readonly REQUIRED_KERNEL_PATH="vmlinuz-$REQUIRED_KERNEL_RELEASE"
readonly REQUIRED_KERNEL_SHA256='0087597973d655701cc01c313d08a534cd27134eec70061d2ae1e45165053eb5'
readonly REQUIRED_KERNEL_SIZE='9450496'
readonly REQUIRED_ARCH='x86_64'
readonly REQUIRED_CH_VERSION='v53.0'
readonly LINUX_SUN_PATH_BYTES=108

ARTIFACT_ROOT=''
ARTIFACT_LOCK=''
SMOKE_PARENT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
CPUS='1'
MEMORY_MIB='512'
CPUS_SET=0
MEMORY_MIB_SET=0
SMOKE_ROOT=''
STATE_ROOT=''
OUTSIDE_DISK=''
VM_ID=''
SMOKE_BIN=''
SMOKE_TIMEOUT_PID=''
SMOKE_TIMEOUT_START_TICKS=''

usage() {
  cat <<'USAGE' >&2
usage: smoke-local-vmm-cloud-hypervisor.sh \
  --artifact-root ABSOLUTE_PRIVATE_DIRECTORY \
  --artifact-lock ABSOLUTE_LOCK_FILE \
  [--cpus COUNT] \
  [--memory-mib MIB] \
  [--scratch-parent ABSOLUTE_DIRECTORY]

Runs the explicit Linux/x86_64 KVM qualification for codewire-local-vmm.
The artifact root must already contain the exact locked Cloud Hypervisor v53,
Linux 6.18.48 LTS kernel, and canonical static-musl initramfs. The command does
not download, extract, install, or fall back to Docker, QEMU, TCG, or another
VMM.
COUNT must be from 1 through 32 (default 1). MIB must be from 128 through
65536 (default 512). Both values are passed explicitly to the smoke driver.

The caller must provide:
  - a canonical, non-symlink artifact root owned by the current user, mode 0700;
  - a strict mode-0400 artifact lock in the same private staging parent;
  - locked artifacts owned by the current user with one link and exact modes
    (Cloud Hypervisor 0500; kernel and initramfs 0400).

The smoke creates disposable private state, runtime, and outside-Landlock roots
beneath --scratch-parent. It removes them after bounded cleanup succeeds and
preserves the exact root for diagnosis if cleanup cannot prove safe removal.
USAGE
}

log() {
  printf '[local-vmm-kvm-smoke] %s\n' "$*" >&2
}

die() {
  printf '[local-vmm-kvm-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_bounded_decimal() {
  local label="$1"
  local value="$2"
  local minimum="$3"
  local maximum="$4"
  local numeric
  [[ "$value" =~ ^[1-9][0-9]*$ && ${#value} -le ${#maximum} ]] ||
    die "$label must be a decimal integer from $minimum through $maximum"
  numeric=$((10#$value))
  (( numeric >= minimum && numeric <= maximum )) ||
    die "$label must be a decimal integer from $minimum through $maximum"
}

status_hex() {
  local field="$1"
  awk -v wanted="$field" '$1 == wanted ":" { print $2; found = 1 } END { if (!found) exit 1 }' \
    /proc/self/status
}

status_decimal() {
  local field="$1"
  awk -v wanted="$field" '$1 == wanted ":" { print $2; found = 1 } END { if (!found) exit 1 }' \
    /proc/self/status
}

process_start_ticks() {
  local pid="$1"
  local stat suffix
  local -a fields
  IFS= read -r stat <"/proc/$pid/stat" || return 1
  suffix="${stat##*) }"
  [[ "$suffix" != "$stat" ]] || return 1
  read -r -a fields <<<"$suffix"
  [[ "${#fields[@]}" -ge 20 && "${fields[19]}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${fields[19]}"
}

terminate_smoke_timeout() {
  local pid="$SMOKE_TIMEOUT_PID"
  local expected_start="$SMOKE_TIMEOUT_START_TICKS"
  local current_start=''
  [[ -n "$pid" ]] || return 0
  SMOKE_TIMEOUT_PID=''
  SMOKE_TIMEOUT_START_TICKS=''
  current_start="$(process_start_ticks "$pid" 2>/dev/null || true)"
  if [[ -n "$expected_start" && "$current_start" == "$expected_start" ]]; then
    kill -TERM -- "$pid" 2>/dev/null || true
  elif [[ -n "$current_start" ]]; then
    log "refusing to signal reused timeout PID $pid"
  fi
  wait "$pid" 2>/dev/null || true
}

handle_signal() {
  local status="$1"
  trap '' HUP INT TERM
  terminate_smoke_timeout
  exit "$status"
}

require_absolute_canonical_dir() {
  local label="$1"
  local path="$2"
  [[ "$path" == /* ]] || die "$label must be absolute: $path"
  [[ -d "$path" && ! -L "$path" ]] || die "$label must be a non-symlink directory: $path"
  [[ "$(realpath -e -- "$path")" == "$path" ]] || die "$label must be canonical: $path"
}

require_private_dir() {
  local label="$1"
  local path="$2"
  require_absolute_canonical_dir "$label" "$path"
  [[ "$(stat -c '%u' -- "$path")" == "$(id -u)" ]] || die "$label is not owned by this user"
  [[ "$(stat -c '%a' -- "$path")" == 700 ]] || die "$label must be mode 0700"
}

require_private_file() {
  local label="$1"
  local path="$2"
  local mode="$3"
  [[ "$path" == /* ]] || die "$label must be absolute: $path"
  [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular non-symlink file: $path"
  [[ "$(realpath -e -- "$path")" == "$path" ]] || die "$label must be canonical: $path"
  [[ "$(stat -c '%u' -- "$path")" == "$(id -u)" ]] || die "$label is not owned by this user"
  [[ "$(stat -c '%a' -- "$path")" == "$mode" ]] || die "$label must be mode 0$mode"
  [[ "$(stat -c '%h' -- "$path")" == 1 ]] || die "$label must have exactly one hard link"
}

require_unix_socket_capacity() {
  local path="$1"
  local LC_ALL=C
  (( ${#path} < LINUX_SUN_PATH_BYTES )) ||
    die 'scratch parent is too long for the local VMM Unix sockets'
}

lock_value() {
  local expression="$1"
  jq -er "$expression" "$ARTIFACT_LOCK"
}

validate_relative_artifact_path() {
  local label="$1"
  local relative="$2"
  local expected_mode="$3"
  local full
  [[ -n "$relative" && "$relative" != /* ]] || die "$label lock path must be non-empty and relative"
  [[ "$relative" != *','* && "$relative" != *'='* && "$relative" != *$'\n'* && "$relative" != *$'\r'* ]] ||
    die "$label lock path contains a forbidden Cloud Hypervisor parameter character"
  case "/$relative/" in
    */../*|*/./*|*//* ) die "$label lock path contains traversal or an empty component" ;;
  esac
  full="$ARTIFACT_ROOT/$relative"
  require_private_file "$label" "$full" "$expected_mode"
  case "$full" in
    "$ARTIFACT_ROOT"/*) ;;
    *) die "$label escaped the artifact root" ;;
  esac
  printf '%s\n' "$full"
}

verify_locked_artifact() {
  local label="$1"
  local object="$2"
  local expected_mode="$3"
  local required_sha="$4"
  local required_size="$5"
  local relative locked_sha locked_size full actual_sha actual_size
  relative="$(lock_value "$object.path | select(type == \"string\")")"
  locked_sha="$(lock_value "$object.sha256 | select(type == \"string\")")"
  locked_size="$(lock_value "$object.size | select(type == \"number\" and floor == .) | tostring")"
  [[ "$(lock_value "$object.architecture")" == "$REQUIRED_ARCH" ]] ||
    die "$label lock architecture is not $REQUIRED_ARCH"
  [[ "$locked_sha" =~ ^[0-9a-f]{64}$ ]] || die "$label lock SHA-256 is malformed"
  [[ "$locked_size" =~ ^[1-9][0-9]*$ ]] || die "$label lock size is invalid"
  [[ -z "$required_sha" || "$locked_sha" == "$required_sha" ]] ||
    die "$label lock digest is not the reviewed spike digest"
  [[ -z "$required_size" || "$locked_size" == "$required_size" ]] ||
    die "$label lock size is not the reviewed spike size"
  full="$(validate_relative_artifact_path "$label" "$relative" "$expected_mode")"
  actual_size="$(stat -c '%s' -- "$full")"
  [[ "$actual_size" == "$locked_size" ]] || die "$label size differs from its lock"
  actual_sha="$(sha256sum -- "$full" | awk '{print $1}')"
  [[ "$actual_sha" == "$locked_sha" ]] || die "$label digest differs from its lock"
  log "$label admitted path=$full dev=$(stat -c '%d' -- "$full") inode=$(stat -c '%i' -- "$full") size=$actual_size sha256=$actual_sha mode=0$expected_mode"
}

validate_artifact_lock() {
  local expected_keys
  local lock_parent artifact_parent
  require_private_dir 'artifact root' "$ARTIFACT_ROOT"
  require_private_file 'artifact lock' "$ARTIFACT_LOCK" 400
  [[ "$(stat -c '%s' -- "$ARTIFACT_LOCK")" -ge 1 && "$(stat -c '%s' -- "$ARTIFACT_LOCK")" -le 1048576 ]] ||
    die 'artifact lock must be from 1 byte through 1 MiB'
  lock_parent="$(dirname "$ARTIFACT_LOCK")"
  artifact_parent="$(dirname "$ARTIFACT_ROOT")"
  require_private_dir 'artifact staging parent' "$lock_parent"
  [[ "$lock_parent" == "$artifact_parent" ]] ||
    die 'artifact root and lock must share one private staging parent'
  jq -e 'type == "object"' "$ARTIFACT_LOCK" >/dev/null || die 'artifact lock is not a JSON object'
  expected_keys='["cloud_hypervisor","initramfs","kernel","schema_version"]'
  [[ "$(jq -c 'keys | sort' "$ARTIFACT_LOCK")" == "$expected_keys" ]] ||
    die 'artifact lock has missing or unknown top-level fields'
  [[ "$(lock_value '.schema_version')" == 1 ]] || die 'artifact lock schema is not version 1'
  [[ "$(lock_value '.cloud_hypervisor.version')" == "$REQUIRED_CH_VERSION" ]] ||
    die "Cloud Hypervisor lock does not pin $REQUIRED_CH_VERSION"
  [[ "$(lock_value '.kernel.path')" == "$REQUIRED_KERNEL_PATH" ]] ||
    die "kernel lock does not pin $REQUIRED_KERNEL_RELEASE"
  [[ "$(jq -c '.cloud_hypervisor | keys | sort' "$ARTIFACT_LOCK")" == '["architecture","path","sha256","size","version"]' ]] ||
    die 'Cloud Hypervisor lock has missing or unknown fields'
  local object
  for object in kernel initramfs; do
    [[ "$(jq -c --arg object "$object" '.[$object] | keys | sort' "$ARTIFACT_LOCK")" == '["architecture","path","sha256","size"]' ]] ||
      die "$object lock has missing or unknown fields"
  done
  verify_locked_artifact 'Cloud Hypervisor' '.cloud_hypervisor' 500 "$REQUIRED_CH_SHA256" "$REQUIRED_CH_SIZE"
  verify_locked_artifact 'kernel' '.kernel' 400 "$REQUIRED_KERNEL_SHA256" "$REQUIRED_KERNEL_SIZE"
  verify_locked_artifact 'initramfs' '.initramfs' 400 '' ''
}

cleanup() {
  local status=$?
  local cleanup_status=0
  local cleanup_log=''
  trap - EXIT HUP INT TERM
  terminate_smoke_timeout
  if [[ -n "$SMOKE_ROOT" && -d "$SMOKE_ROOT" && ! -L "$SMOKE_ROOT" ]]; then
    if [[ -n "$SMOKE_BIN" && -x "$SMOKE_BIN" && -n "$VM_ID" && -n "$STATE_ROOT" ]]; then
      cleanup_log="$SMOKE_ROOT/cleanup.log"
      if timeout --foreground --signal=TERM --kill-after=5s 30s \
          env -i PATH='/usr/bin:/bin' HOME="$SMOKE_ROOT/runtime-home" \
          TMPDIR="$SMOKE_ROOT/run" LC_ALL=C \
          "$SMOKE_BIN" cleanup \
            --artifact-root "$ARTIFACT_ROOT" \
            --artifact-lock "$ARTIFACT_LOCK" \
            --state-root "$STATE_ROOT" \
            --vm-id "$VM_ID" >"$cleanup_log" 2>&1; then
        :
      else
        cleanup_status=$?
        cat "$cleanup_log" >&2
      fi
    fi
    if [[ "$cleanup_status" -eq 0 ]]; then
      rm -rf -- "$SMOKE_ROOT"
    else
      printf '[local-vmm-kvm-smoke] cleanup preserved unresolved state at %s\n' \
        "$SMOKE_ROOT" >&2
    fi
  fi
  if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
    printf '[local-vmm-kvm-smoke] ERROR: bounded runner cleanup failed (status=%s)\n' \
      "$cleanup_status" >&2
    exit "$cleanup_status"
  fi
  exit "$status"
}

case "$-" in
  *x*) die 'shell tracing is enabled; rerun without set -x' ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-root)
      [[ $# -ge 2 && -z "$ARTIFACT_ROOT" ]] || { usage; exit 2; }
      ARTIFACT_ROOT="$2"
      shift 2
      ;;
    --artifact-lock)
      [[ $# -ge 2 && -z "$ARTIFACT_LOCK" ]] || { usage; exit 2; }
      ARTIFACT_LOCK="$2"
      shift 2
      ;;
    --scratch-parent)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      SMOKE_PARENT="$2"
      shift 2
      ;;
    --cpus)
      [[ $# -ge 2 && "$CPUS_SET" -eq 0 ]] || { usage; exit 2; }
      CPUS="$2"
      CPUS_SET=1
      shift 2
      ;;
    --memory-mib)
      [[ $# -ge 2 && "$MEMORY_MIB_SET" -eq 0 ]] || { usage; exit 2; }
      MEMORY_MIB="$2"
      MEMORY_MIB_SET=1
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -n "$ARTIFACT_ROOT" && -n "$ARTIFACT_LOCK" ]] || { usage; exit 2; }
require_bounded_decimal '--cpus' "$CPUS" 1 32
require_bounded_decimal '--memory-mib' "$MEMORY_MIB" 128 65536
readonly CPUS MEMORY_MIB
for tool in awk cargo cat chmod debugfs id jq mkdir mkfs.ext4 mktemp realpath setpriv sha256sum stat sync timeout tr truncate uname; do
  require_cmd "$tool"
done
[[ "$(uname -s)" == Linux ]] || die 'the Cloud Hypervisor smoke requires Linux'
[[ "$(uname -m)" == x86_64 ]] || die 'the locked spike artifacts require x86_64'
[[ "$(id -u)" != 0 ]] || die 'the Cloud Hypervisor smoke refuses root'
[[ -x /usr/bin/mkfs.ext4 ]] || die 'exact /usr/bin/mkfs.ext4 is unavailable'
[[ -x /usr/bin/sleep ]] || die 'exact /usr/bin/sleep is unavailable'
if [[ "${CODEWIRE_VMM_SMOKE_SANITIZED:-0}" != 1 ]] && {
    [[ "$(status_decimal NoNewPrivs)" != 1 ]] ||
      [[ ! "$(status_hex CapEff)" =~ ^0+$ ]] ||
      [[ ! "$(status_hex CapPrm)" =~ ^0+$ ]] ||
      [[ ! "$(status_hex CapInh)" =~ ^0+$ ]] ||
      [[ ! "$(status_hex CapAmb)" =~ ^0+$ ]];
  }; then
  export CODEWIRE_VMM_SMOKE_SANITIZED=1
  exec setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all -- "$0" \
    --artifact-root "$ARTIFACT_ROOT" \
    --artifact-lock "$ARTIFACT_LOCK" \
    --cpus "$CPUS" \
    --memory-mib "$MEMORY_MIB" \
    --scratch-parent "$SMOKE_PARENT"
fi
for field in CapEff CapPrm CapInh CapAmb; do
  [[ "$(status_hex "$field")" =~ ^0+$ ]] || die "$field must be empty"
done
[[ "$(status_decimal NoNewPrivs)" == 1 ]] || die 'NoNewPrivs must be set'
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || die '/dev/kvm is unavailable or unusable'
[[ -c /dev/vhost-vsock && -r /dev/vhost-vsock && -w /dev/vhost-vsock ]] ||
  die '/dev/vhost-vsock is unavailable or unusable'

require_absolute_canonical_dir 'scratch parent' "$SMOKE_PARENT"
validate_artifact_lock

TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh "$ROOT")"
readonly TARGET_DIR
log 'building exact-tree smoke driver offline (no artifact acquisition)'
(
  cd "$ROOT"
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --locked --offline \
    -p codewire-local-vmm --bin codewire-local-vmm-smoke
)
SMOKE_BIN="$TARGET_DIR/debug/codewire-local-vmm-smoke"
[[ -x "$SMOKE_BIN" ]] || die "smoke binary was not built: $SMOKE_BIN"

SMOKE_ROOT="$(mktemp -d "$SMOKE_PARENT/.cw.XXXXXX")"
chmod 0700 "$SMOKE_ROOT"
SMOKE_ROOT="$(realpath -e -- "$SMOKE_ROOT")"
trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM
STATE_ROOT="$SMOKE_ROOT/state"
OUTSIDE_ROOT="$SMOKE_ROOT/landlock-outside"
mkdir -m 0700 "$STATE_ROOT" "$SMOKE_ROOT/run" "$SMOKE_ROOT/runtime-home" "$OUTSIDE_ROOT"
VM_ID="$(tr -d '\n' </proc/sys/kernel/random/uuid)"
[[ "$VM_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] ||
  die 'kernel did not provide a valid random VM UUID'
require_unix_socket_capacity "$STATE_ROOT/vms/$VM_ID/api/api.sock"
require_unix_socket_capacity "$STATE_ROOT/vms/$VM_ID/vsock/vsock.sock"
STATE_FS_UUID="$(tr -d '\n' </proc/sys/kernel/random/uuid)"
[[ "$STATE_FS_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] ||
  die 'kernel did not provide a valid random state-disk UUID'
VM_DIR="$STATE_ROOT/vms/$VM_ID"
DISKS_DIR="$VM_DIR/disks"
mkdir -m 0700 "$STATE_ROOT/vms" "$VM_DIR" "$DISKS_DIR"
STATE_DISK="$DISKS_DIR/state.raw"
truncate -s 268435456 "$STATE_DISK"
chmod 0600 "$STATE_DISK"
/usr/bin/mkfs.ext4 -q -F -U "$STATE_FS_UUID" -L cw-state "$STATE_DISK"
sync -f "$STATE_DISK"
sync -f "$DISKS_DIR"
OUTSIDE_DISK="$OUTSIDE_ROOT/valid-ext4.raw"
truncate -s 268435456 "$OUTSIDE_DISK"
chmod 0600 "$OUTSIDE_DISK"
/usr/bin/mkfs.ext4 -q -F -U random -L cw-landlock-probe "$OUTSIDE_DISK"
sync -f "$OUTSIDE_DISK"
sync -f "$OUTSIDE_ROOT"

log "starting bounded KVM proof vm_id=$VM_ID cpus=$CPUS memory_mib=$MEMORY_MIB state_root=$STATE_ROOT run_root=$SMOKE_ROOT/run"
timeout --foreground --signal=TERM --kill-after=10s 240s \
  env -i PATH='/usr/bin:/bin' HOME="$SMOKE_ROOT/runtime-home" \
  TMPDIR="$SMOKE_ROOT/run" LC_ALL=C \
  "$SMOKE_BIN" run \
    --artifact-root "$ARTIFACT_ROOT" \
    --artifact-lock "$ARTIFACT_LOCK" \
    --state-root "$STATE_ROOT" \
    --vm-id "$VM_ID" \
    --outside-disk "$OUTSIDE_DISK" \
    --cpus "$CPUS" \
    --memory-mib "$MEMORY_MIB" &
SMOKE_TIMEOUT_PID=$!
if ! SMOKE_TIMEOUT_START_TICKS="$(process_start_ticks "$SMOKE_TIMEOUT_PID")"; then
  kill -TERM -- "$SMOKE_TIMEOUT_PID" 2>/dev/null || true
  wait "$SMOKE_TIMEOUT_PID" 2>/dev/null || true
  SMOKE_TIMEOUT_PID=''
  die 'could not capture the bounded timeout process identity'
fi
if wait "$SMOKE_TIMEOUT_PID"; then
  SMOKE_STATUS=0
else
  SMOKE_STATUS=$?
fi
SMOKE_TIMEOUT_PID=''
SMOKE_TIMEOUT_START_TICKS=''
if [[ "$SMOKE_STATUS" -ne 0 ]]; then
  BOOT_STAGE="$(env -i PATH='/usr/bin:/bin' LC_ALL=C \
    /usr/bin/debugfs -R 'cat codewire/boot-stage' "$STATE_DISK" 2>/dev/null || true)"
  if [[ "$BOOT_STAGE" =~ ^[a-z][a-z-]{0,31}$ ]]; then
    log "diagnostic guest.boot_stage=$BOOT_STAGE"
  else
    log 'diagnostic guest.boot_stage=unavailable'
  fi
  NETWORK_STATUS="$(env -i PATH='/usr/bin:/bin' LC_ALL=C \
    /usr/bin/debugfs -R 'cat codewire/network-status' "$STATE_DISK" 2>/dev/null || true)"
  case "$NETWORK_STATUS" in
    network-listening|network-peer-rejected|network-handshake-timeout|network-hello-read-failed|\
      network-hello-auth-failed|network-ack-write-failed|network-ready-read-failed|\
      network-ready-auth-failed|network-session-failed|network-authenticated)
      log "diagnostic guest.network_status=$NETWORK_STATUS"
      ;;
    *)
      log 'diagnostic guest.network_status=unavailable'
      ;;
  esac
  exit "$SMOKE_STATUS"
fi

log 'PASS: qualified Linux/KVM Cloud Hypervisor boundary'
