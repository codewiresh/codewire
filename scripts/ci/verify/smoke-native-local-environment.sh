#!/usr/bin/env bash
# Qualified-host product proof for the Linux native local environment. The
# caller supplies an exact built cw binary and already-staged immutable VMM
# artifacts; this script never downloads artifacts or selects a fallback VMM.
set -euo pipefail

readonly LINUX_SUN_PATH_BYTES=108
readonly LONGEST_SOCKET_SUFFIX='/engine/vms/00000000-0000-4000-8000-000000000000/vsock/vsock.sock'

CW_BIN=''
DATA_PLANE_SMOKE_BIN=''
STATE_PROBE_BIN=''
ARTIFACT_ROOT=''
ARTIFACT_LOCK=''
ORIGINAL_ARTIFACT_ROOT=''
ORIGINAL_ARTIFACT_LOCK=''
ADVANCED_ARTIFACT_ROOT=''
ADVANCED_ARTIFACT_LOCK=''
SMOKE_PARENT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
SMOKE_ROOT=''
SMOKE_HOME=''
STATE_ROOT=''
WORKSPACE=''
PLATFORM_CONFIG=''
TRIPWIRE=''
TRANSCRIPT=''
SOURCE_HOOK_MARKER=''
SOURCE_CREDENTIAL_MARKER=''
SOURCE_CONFIG_SHA256=''
GITEA_COMMIT='bcbae548ab2f4f0e407068aa8717cec341084d7a'
GITEA_README_SHA256='d4911db7bc817528fbcbaaf39e76851700084b65494dac1e29afb997867ac006'
GITHUB_COMMIT='93f68ba4abc9f6e222481265b9b759e71d332575'
GITHUB_README_SHA256='3661bce99f8eba5e48077eeddb4840f4404c1ceafbf200b9e8470bc7b4f22e50'
SCRATCH_MOUNT_OPTIONS=''
NAME='native-smoke'
COMMAND_INDEX=0
LAST_STDOUT=''
LAST_STDERR=''
ENV_CREATED=0
ALLOW_REGISTRY_EGRESS=0
CW_COMMAND_TIMEOUT_SECONDS=180

usage() {
  cat <<'USAGE' >&2
usage: smoke-native-local-environment.sh \
  --cw-bin ABSOLUTE_PATH \
  --data-plane-smoke-bin ABSOLUTE_PATH \
  --state-probe-bin ABSOLUTE_PATH \
  --artifact-root ABSOLUTE_PRIVATE_DIRECTORY \
  --artifact-lock ABSOLUTE_LOCK_FILE \
  [--scratch-parent ABSOLUTE_DIRECTORY]

Runs the built cw Linux/KVM native-environment product smoke with 2 vCPUs and
16 GiB of guest memory. The artifact root and lock must already contain the
exact Cloud Hypervisor, kernel, and product guest-root artifacts admitted by
codewire-local-vmm. Missing KVM, artifacts, or required tools fail nonzero.

The smoke uses an isolated HOME and short private native state root, poisons
the platform destination, installs Docker/Lima/QEMU tripwires, and creates
disposable multi-repository and filesystem-copy fixtures. Initial create
permits direct registry and Git egress; every later command receives dead proxy
endpoints. It proves digest-pinned OCI workspace execution, exact
credential-free git.example.invalid/GitHub preparation, independent copy preparation,
create/info, bounded daemon diagnostics and repair, bare run and shell, PTY
behavior, saved output and nonzero status, cached-runtime restart after the
installed artifact lock advances, offline disk/CPU/memory resize, supervisor
crash recovery, and journaled exact deletion cleanup.
USAGE
}

log() {
  printf '[native-local-environment-smoke] %s\n' "$*" >&2
}

die() {
  printf '[native-local-environment-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_absolute_canonical_dir() {
  local label="$1"
  local path="$2"
  [[ "$path" == /* ]] || die "$label must be absolute: $path"
  [[ -d "$path" && ! -L "$path" ]] || die "$label must be a non-symlink directory: $path"
  [[ "$(realpath -e -- "$path")" == "$path" ]] || die "$label must be canonical: $path"
}

require_absolute_canonical_file() {
  local label="$1"
  local path="$2"
  [[ "$path" == /* ]] || die "$label must be absolute: $path"
  [[ -f "$path" && ! -L "$path" ]] || die "$label must be a regular non-symlink file: $path"
  [[ "$(realpath -e -- "$path")" == "$path" ]] || die "$label must be canonical: $path"
}

case "$-" in
  *x*) die 'shell tracing is enabled; rerun without set -x' ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cw-bin)
      [[ $# -ge 2 && -z "$CW_BIN" ]] || { usage; exit 2; }
      CW_BIN="$2"
      shift 2
      ;;
    --data-plane-smoke-bin)
      [[ $# -ge 2 && -z "$DATA_PLANE_SMOKE_BIN" ]] || { usage; exit 2; }
      DATA_PLANE_SMOKE_BIN="$2"
      shift 2
      ;;
    --state-probe-bin)
      [[ $# -ge 2 && -z "$STATE_PROBE_BIN" ]] || { usage; exit 2; }
      STATE_PROBE_BIN="$2"
      shift 2
      ;;
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

[[ -n "$CW_BIN" && -n "$DATA_PLANE_SMOKE_BIN" && -n "$STATE_PROBE_BIN" && -n "$ARTIFACT_ROOT" && -n "$ARTIFACT_LOCK" ]] || {
  usage
  exit 2
}

for tool in awk cat chmod cp dirname e2fsck find findmnt git id jq ln mkdir mktemp python3 readlink realpath resize2fs rg script sha256sum sleep stat tail timeout touch tr uname; do
  require_cmd "$tool"
done
[[ "$(uname -s)" == Linux ]] || die 'the native local-environment smoke requires Linux'
[[ "$(uname -m)" == x86_64 ]] || die 'the current native artifact set requires x86_64'
[[ "$(id -u)" != 0 ]] || die 'the native local-environment smoke refuses root'
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || die '/dev/kvm is unavailable or unusable'
[[ -c /dev/vhost-vsock && -r /dev/vhost-vsock && -w /dev/vhost-vsock ]] ||
  die '/dev/vhost-vsock is unavailable or unusable'

require_absolute_canonical_file 'cw binary' "$CW_BIN"
[[ -x "$CW_BIN" ]] || die "cw binary is not executable: $CW_BIN"
require_absolute_canonical_file 'public data-plane smoke binary' "$DATA_PLANE_SMOKE_BIN"
[[ -x "$DATA_PLANE_SMOKE_BIN" ]] ||
  die "public data-plane smoke binary is not executable: $DATA_PLANE_SMOKE_BIN"
require_absolute_canonical_file 'native state probe binary' "$STATE_PROBE_BIN"
[[ -x "$STATE_PROBE_BIN" ]] ||
  die "native state probe binary is not executable: $STATE_PROBE_BIN"
[[ "$CW_BIN" =~ ^[-_./0-9A-Za-z]+$ ]] ||
  die 'cw binary path contains characters unsafe for the PTY smoke command'
require_absolute_canonical_dir 'artifact root' "$ARTIFACT_ROOT"
require_absolute_canonical_file 'artifact lock' "$ARTIFACT_LOCK"
[[ "$(dirname "$ARTIFACT_ROOT")" == "$(dirname "$ARTIFACT_LOCK")" ]] ||
  die 'artifact root and lock must share one staging parent'
require_absolute_canonical_dir 'scratch parent' "$SMOKE_PARENT"
if ! SCRATCH_MOUNT_OPTIONS="$(findmnt -nro OPTIONS -T "$SMOKE_PARENT")"; then
  die "cannot inspect scratch-parent mount options: $SMOKE_PARENT"
fi
case ",$SCRATCH_MOUNT_OPTIONS," in
  *,noexec,*)
    die 'scratch parent is mounted noexec; pass --scratch-parent on an executable filesystem'
    ;;
esac
ORIGINAL_ARTIFACT_ROOT="$ARTIFACT_ROOT"
ORIGINAL_ARTIFACT_LOCK="$ARTIFACT_LOCK"

SMOKE_ROOT="$(mktemp -d "$SMOKE_PARENT/.cwn.XXXXXX")"
chmod 0700 "$SMOKE_ROOT"
SMOKE_ROOT="$(realpath -e -- "$SMOKE_ROOT")"
SMOKE_HOME="$SMOKE_ROOT/h"
STATE_ROOT="$SMOKE_ROOT/s"
WORKSPACE="$SMOKE_ROOT/w"
PLATFORM_CONFIG="$SMOKE_ROOT/c"
TRIPWIRE="$SMOKE_ROOT/fallback-invoked"
TRANSCRIPT="$SMOKE_ROOT/transcript"
SOURCE_HOOK_MARKER="$SMOKE_ROOT/source-hook-invoked"
SOURCE_CREDENTIAL_MARKER="$SMOKE_ROOT/source-credential-helper-invoked"
mkdir -m 0700 "$SMOKE_HOME" "$STATE_ROOT" "$WORKSPACE" "$PLATFORM_CONFIG" "$SMOKE_ROOT/bin"
touch "$TRANSCRIPT"
chmod 0600 "$TRANSCRIPT"

(( ${#STATE_ROOT} + ${#LONGEST_SOCKET_SUFFIX} < LINUX_SUN_PATH_BYTES )) ||
  die 'scratch parent is too long for native VMM Unix sockets'

printf 'this is deliberately invalid platform JSON\n' >"$PLATFORM_CONFIG/config.json"
chmod 0600 "$PLATFORM_CONFIG/config.json"
mkdir -m 0700 "$SMOKE_HOME/.codewire"
cat >"$SMOKE_HOME/.codewire/local_instances.toml" <<'EOF'
[instances.legacy]
name = "legacy"
backend = "lima"
runtime_name = "cw-legacy"
repo_path = "/nonexistent/legacy"
workdir = "/workspace"
EOF
chmod 0600 "$SMOKE_HOME/.codewire/local_instances.toml"
LEGACY_SHA256="$(sha256sum "$SMOKE_HOME/.codewire/local_instances.toml" | awk '{print $1}')"

for fallback in docker limactl qemu-system-x86_64; do
  printf '#!/bin/sh\nprintf "%%s\\n" "%s" >>"%s"\nexit 97\n' \
    "$fallback" "$TRIPWIRE" >"$SMOKE_ROOT/bin/$fallback"
  chmod 0700 "$SMOKE_ROOT/bin/$fallback"
done

env -i PATH='/usr/bin:/bin' HOME="$SMOKE_HOME" LC_ALL=C \
  /usr/bin/git -C "$WORKSPACE" init -q
printf 'native workspace fixture\n' >"$WORKSPACE/README.md"
printf '#!/bin/sh\nprintf "native-workspace-ok\\n"\n' >"$WORKSPACE/hello.sh"
chmod 0755 "$WORKSPACE/hello.sh"
env -i PATH='/usr/bin:/bin' HOME="$SMOKE_HOME" LC_ALL=C \
  /usr/bin/git -C "$WORKSPACE" add README.md hello.sh
env -i PATH='/usr/bin:/bin' HOME="$SMOKE_HOME" LC_ALL=C \
  /usr/bin/git -C "$WORKSPACE" -c user.name='Codewire Smoke' \
    -c user.email='smoke@invalid.example' commit -q -m fixture
env -i PATH='/usr/bin:/bin' HOME="$SMOKE_HOME" LC_ALL=C \
  /usr/bin/git -C "$WORKSPACE" config credential.helper \
    "!touch '$SOURCE_CREDENTIAL_MARKER'"
env -i PATH='/usr/bin:/bin' HOME="$SMOKE_HOME" LC_ALL=C \
  /usr/bin/git -C "$WORKSPACE" remote add origin \
    'https://host-user:host-secret@example.invalid/codewire/smoke.git'
printf '#!/bin/sh\ntouch %q\n' "$SOURCE_HOOK_MARKER" >"$WORKSPACE/.git/hooks/post-checkout"
chmod 0700 "$WORKSPACE/.git/hooks/post-checkout"
SOURCE_CONFIG_SHA256="$(sha256sum "$WORKSPACE/.git/config" | awk '{print $1}')"
cat >"$WORKSPACE/codewire.yaml" <<EOF
version: 1
repositories:
  - source: https://git.example.invalid/supplychain.git
    revision: $GITEA_COMMIT
    destination: /workspace/gitea
  - source: https://github.com/noeljackson/method.git
    revision: $GITHUB_COMMIT
    destination: /workspace/github
working_directory: /workspace/github
EOF

cw_isolated() {
  (
    local -a proxy_environment=()
    if [[ "$ALLOW_REGISTRY_EGRESS" -eq 0 ]]; then
      proxy_environment=(
        HTTP_PROXY=http://127.0.0.1:1
        HTTPS_PROXY=http://127.0.0.1:1
        ALL_PROXY=http://127.0.0.1:1
        NO_PROXY=
      )
    fi
    cd "$WORKSPACE"
    env -i \
      PATH="$SMOKE_ROOT/bin:/usr/bin:/bin" \
      HOME="$SMOKE_HOME" \
      USER="$(id -un)" \
      LOGNAME="$(id -un)" \
      SHELL='/bin/sh' \
      TERM='xterm-256color' \
      LC_ALL=C \
      CW_CONFIG_DIR="$PLATFORM_CONFIG" \
      CODEWIRE_NATIVE_STATE_ROOT="$STATE_ROOT" \
      CODEWIRE_NATIVE_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
      CODEWIRE_NATIVE_ARTIFACT_LOCK="$ARTIFACT_LOCK" \
      CODEWIRE_SERVER_URL='http://127.0.0.1:1' \
      CODEWIRE_API_KEY='synthetic-platform-key-must-not-be-used' \
      "${proxy_environment[@]}" \
      /usr/bin/timeout --foreground --signal=TERM --kill-after=5s \
      "${CW_COMMAND_TIMEOUT_SECONDS}s" \
      "$CW_BIN" "$@"
  )
}

run_cw() {
  local stdout_file stderr_file
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stderr"
  if ! cw_isolated "$@" >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    tail -n 80 "$stderr_file" >&2
    die "cw command $COMMAND_INDEX failed: $*"
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  LAST_STDOUT="$stdout_file"
  LAST_STDERR="$stderr_file"
}

run_cw_expect_failure() {
  local stdout_file stderr_file
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stderr"
  if cw_isolated "$@" >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    die "cw command $COMMAND_INDEX unexpectedly succeeded: $*"
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  LAST_STDOUT="$stdout_file"
  LAST_STDERR="$stderr_file"
}

run_public_data_smoke() {
  local stdout_file stderr_file
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stderr"
  if ! env -i \
    PATH='/usr/bin:/bin' \
    HOME="$SMOKE_HOME" \
    USER="$(id -un)" \
    LOGNAME="$(id -un)" \
    SHELL='/bin/sh' \
    TERM='xterm-256color' \
    LC_ALL=C \
    /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 180s \
    "$DATA_PLANE_SMOKE_BIN" \
      --state-root "$STATE_ROOT" \
      --artifact-root "$ARTIFACT_ROOT" \
      --artifact-lock "$ARTIFACT_LOCK" \
      --cw-bin "$CW_BIN" \
      --target "$NAME" >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    tail -n 80 "$stderr_file" >&2
    die 'public Exec/File data-plane smoke failed'
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  [[ "$(cat "$stdout_file")" == 'codewire-local-public-data-smoke: PASS' ]] ||
    die 'public Exec/File data-plane smoke receipt drifted'
}

wait_for_pid_exit() {
  local pid="$1"
  for _attempt in {1..100}; do
    [[ ! -e "/proc/$pid" ]] && return 0
    sleep 0.05
  done
  return 1
}

wait_for_pid_death() {
  local pid="$1"
  local stat suffix state
  for _attempt in {1..100}; do
    [[ ! -r "/proc/$pid/stat" ]] && return 0
    stat="$(<"/proc/$pid/stat")"
    suffix="${stat##*) }"
    state="${suffix%% *}"
    [[ "$state" == Z || "$state" == X ]] && return 0
    sleep 0.05
  done
  return 1
}

wait_for_environment_state() {
  local expected="$1"
  for _attempt in {1..100}; do
    run_cw env info --local "$NAME" --output json
    if jq -e --arg expected "$expected" '.state == $expected' "$LAST_STDOUT" >/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

recorded_vmm_pid() {
  jq -er '.process.pid' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json"
}

kill_recorded_process() {
  local kind="$1"
  if [[ "$kind" == runner ]]; then
    env -i PATH='/usr/bin:/bin' LC_ALL=C \
      "$STATE_PROBE_BIN" kill-runner --state-root "$STATE_ROOT" --name "$NAME"
    return
  fi
  /usr/bin/env python3 - \
    "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json" \
    "$kind" <<'PY'
import json
import hashlib
import os
import signal
import sys

vmm_state, kind = sys.argv[1:]
if kind == "vmm":
    with open(vmm_state, "r", encoding="utf-8") as source:
        identity = json.load(source)["process"]
else:
    raise SystemExit("unknown process kind")

pid = identity["pid"]


def current_identity():
    with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as source:
        boot_id = source.read().strip()
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as source:
        stat = source.read()
    suffix = stat.rsplit(") ", 1)[1].split()
    executable_path = f"/proc/{pid}/exe"
    executable = os.readlink(executable_path)
    executable_stat = os.stat(executable_path)
    digest = hashlib.sha256()
    with open(executable_path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return (
        boot_id,
        int(suffix[19]),
        executable,
        (
            executable_stat.st_dev,
            executable_stat.st_ino,
            executable_stat.st_size,
            executable_stat.st_uid,
            executable_stat.st_mode,
            executable_stat.st_nlink,
        ),
        digest.hexdigest(),
    )


expected = (
    identity["boot_id"],
    identity["start_time_ticks"],
    identity["executable"],
    (
        identity["executable_file"]["device"],
        identity["executable_file"]["inode"],
        identity["executable_file"]["size"],
        identity["executable_file"]["uid"],
        identity["executable_file"]["mode"],
        identity["executable_file"]["links"],
    ),
    identity["executable_sha256"],
)
pidfd = os.pidfd_open(pid, 0)
try:
    if current_identity() != expected:
        raise SystemExit(f"persisted {kind} identity does not match the pidfd process")
    with open(f"/proc/self/fdinfo/{pidfd}", "r", encoding="ascii") as source:
        pidfd_pid = next(
            (line.removeprefix("Pid:\t").strip() for line in source if line.startswith("Pid:\t")),
            None,
        )
    if pidfd_pid != str(pid):
        raise SystemExit(f"pidfd target does not match the persisted {kind} PID")
    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
finally:
    os.close(pidfd)
print(pid)
PY
}

find_exact_supervisor_pid() {
  local proc pid
  local -a argv
  for proc in /proc/[0-9]*; do
    [[ "$(readlink -f "$proc/exe" 2>/dev/null || true)" == "$CW_BIN" ]] || continue
    argv=()
    mapfile -d '' -t argv <"$proc/cmdline" 2>/dev/null || continue
    [[ ${#argv[@]} -eq 8 ]] || continue
    if [[ "${argv[1]}" == '__native-supervisor' &&
          "${argv[2]}" == '--root' && "${argv[3]}" == "$STATE_ROOT" &&
          "${argv[4]}" == '--artifact-root' && "${argv[5]}" == "$ARTIFACT_ROOT" &&
          "${argv[6]}" == '--artifact-lock' && "${argv[7]}" == "$ARTIFACT_LOCK" ]]; then
      pid="${proc#/proc/}"
      printf '%s\n' "$pid"
      return 0
    fi
  done
  return 1
}

terminate_exact_supervisor() {
  local pid
  pid="$(find_exact_supervisor_pid)" || return 0
  if ! kill -TERM -- "$pid" 2>/dev/null; then
    find_exact_supervisor_pid >/dev/null 2>&1 && return 1
    return 0
  fi
  wait_for_pid_exit "$pid"
}

owned_processes() {
  local proc cmdline
  for proc in /proc/[0-9]*; do
    [[ -r "$proc/cmdline" ]] || continue
    cmdline="$(tr '\0' '\n' <"$proc/cmdline" 2>/dev/null || true)"
    if [[ "$cmdline" == *"$STATE_ROOT"* ]]; then
      printf '%s\n' "${proc#/proc/}"
    fi
  done
}

terminate_remaining_owned_processes() {
  local pid
  local -a pids=()
  mapfile -t pids < <(owned_processes)
  for pid in "${pids[@]}"; do
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    kill -KILL -- "$pid" 2>/dev/null || [[ ! -e "/proc/$pid" ]] || return 1
  done
  for pid in "${pids[@]}"; do
    wait_for_pid_death "$pid" || return 1
  done
}

native_database_value() {
  local field="$1"
  env -i PATH='/usr/bin:/bin' LC_ALL=C \
    "$STATE_PROBE_BIN" value "$field" --state-root "$STATE_ROOT" --name "$NAME"
}

wait_for_journal_complete() {
  for _attempt in {1..100}; do
    [[ "$(native_database_value journal_complete)" == yes ]] && return 0
    sleep 0.05
  done
  return 1
}

wait_for_replaced_runner_pid() {
  local previous_pid="$1"
  local candidate='unavailable'
  for _attempt in {1..100}; do
    candidate="$(native_database_value runner_pid)" || {
      log 'runner replacement observation could not read the persisted process identity'
      return 1
    }
    if [[ "$candidate" != "$previous_pid" && -d "/proc/$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
    sleep 0.05
  done
  log "runner replacement observation timed out: previous=$previous_pid observed=$candidate observed_live=$([[ -d "/proc/$candidate" ]] && printf yes || printf no)"
  return 1
}

copy_advanced_artifact() {
  local query="$1"
  local destination="$2"
  local mode="$3"
  local relative source
  relative="$(jq -er "$query | select(type == \"string\" and length > 0)" \
    "$ORIGINAL_ARTIFACT_LOCK")" || die "original artifact lock is missing $query"
  source="$(realpath -e -- "$ORIGINAL_ARTIFACT_ROOT/$relative")" ||
    die "original artifact path is unavailable: $relative"
  [[ "$source" == "$ORIGINAL_ARTIFACT_ROOT/"* && -f "$source" ]] ||
    die "original artifact escaped its root: $relative"
  cp -- "$source" "$ADVANCED_ARTIFACT_ROOT/$destination"
  chmod "$mode" "$ADVANCED_ARTIFACT_ROOT/$destination"
}

prepare_advanced_artifact_source() {
  local advanced_parent="$SMOKE_ROOT/a"
  ADVANCED_ARTIFACT_ROOT="$advanced_parent/artifacts"
  ADVANCED_ARTIFACT_LOCK="$advanced_parent/artifacts.lock.json"
  mkdir -m 0700 "$advanced_parent" "$ADVANCED_ARTIFACT_ROOT"
  copy_advanced_artifact '.cloud_hypervisor.path' 'advanced-cloud-hypervisor' 0500
  copy_advanced_artifact '.kernel.path' 'advanced-kernel' 0400
  copy_advanced_artifact '.initramfs.path' 'advanced-initramfs' 0400
  jq '
    .cloud_hypervisor.path = "advanced-cloud-hypervisor" |
    .kernel.path = "advanced-kernel" |
    .initramfs.path = "advanced-initramfs"
  ' "$ORIGINAL_ARTIFACT_LOCK" >"$ADVANCED_ARTIFACT_LOCK"
  chmod 0400 "$ADVANCED_ARTIFACT_LOCK"
  require_absolute_canonical_dir 'advanced artifact root' "$ADVANCED_ARTIFACT_ROOT"
  require_absolute_canonical_file 'advanced artifact lock' "$ADVANCED_ARTIFACT_LOCK"
  [[ "$(dirname "$ADVANCED_ARTIFACT_ROOT")" == "$(dirname "$ADVANCED_ARTIFACT_LOCK")" ]] ||
    die 'advanced artifact root and lock do not share one staging parent'
  [[ "$(sha256sum "$ADVANCED_ARTIFACT_LOCK" | awk '{print $1}')" != \
     "$(sha256sum "$ORIGINAL_ARTIFACT_LOCK" | awk '{print $1}')" ]] ||
    die 'advanced artifact lock did not change'
}

runtime_artifact_manifest_count() {
  find "$STATE_ROOT/engine/runtime-artifacts/generations" \
    -mindepth 1 -maxdepth 1 -type f -name '*.json' -printf '%f\n' |
    awk 'END { print NR }'
}

cleanup() {
  local status=$?
  local cleanup_status=0
  local diagnostic_runner_pid=''
  trap - EXIT HUP INT TERM
  ALLOW_REGISTRY_EGRESS=0
  CW_COMMAND_TIMEOUT_SECONDS=180
  if [[ "$ENV_CREATED" -eq 1 && ( -f "$STATE_ROOT/supervisor.db" || -f "$STATE_ROOT/state.json" ) ]]; then
    if [[ "$status" -eq 0 ]]; then
      log 'cleaning native environment after incomplete smoke'
      if ! cw_isolated env rm --local "$NAME" --yes >/dev/null 2>&1; then
        cleanup_status=1
      fi
    else
      log 'stopping exact native processes while preserving failed environment state'
      ENVIRONMENT_ID="${ENVIRONMENT_ID:-$(native_database_value environment_id 2>/dev/null || true)}"
      diagnostic_runner_pid="$(native_database_value runner_pid 2>/dev/null || true)"
      if [[ -n "$ENVIRONMENT_ID" && -n "$diagnostic_runner_pid" ]]; then
        kill_recorded_process runner >/dev/null 2>&1 || true
        wait_for_pid_death "$diagnostic_runner_pid" || cleanup_status=1
      fi
    fi
  fi
  if ! terminate_exact_supervisor; then
    cleanup_status=1
  fi
  if [[ "$status" -ne 0 ]] && ! terminate_remaining_owned_processes; then
    cleanup_status=1
  fi
  if [[ "$status" -eq 0 && "$cleanup_status" -eq 0 ]]; then
    rm -rf -- "$SMOKE_ROOT"
  else
    log "preserved diagnostic state at $SMOKE_ROOT"
  fi
  if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
    die 'bounded native environment cleanup failed'
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

log 'checking native and legacy local names cannot collide'
run_cw_expect_failure env create --local --name legacy --cpu 2 --memory 16Gi --path "$WORKSPACE"
rg -qF 'already exists in the legacy Docker/Lima state' "$LAST_STDERR" ||
  die 'native creation did not report the legacy-name collision'
[[ ! -e "$STATE_ROOT/state.json" && ! -e "$STATE_ROOT/supervisor.db" ]] ||
  die 'rejected native creation wrote native state'

log 'creating account-free 2-vCPU, 16-GiB native environment'
ALLOW_REGISTRY_EGRESS=1
CW_COMMAND_TIMEOUT_SECONDS=1500
run_cw env create --local --name "$NAME" --cpu 2 --memory 16Gi --path "$WORKSPACE" --output json
ALLOW_REGISTRY_EGRESS=0
CW_COMMAND_TIMEOUT_SECONDS=180
ENV_CREATED=1
jq -e '
  .name == "native-smoke" and
  .backend == "cloud-hypervisor" and
  .state == "running" and
  .selected == true and
  .cpu == 2 and
  .memory == "16Gi" and
  .working_directory == "/workspace/github" and
  .workspace_inputs == 2 and
  (.workspace_plan | test("^[0-9a-f]{64}$"))
' "$LAST_STDOUT" >/dev/null || die 'created native environment metadata drifted'
[[ ! -e "$SOURCE_HOOK_MARKER" ]] || die 'source Git hook ran during native clone preparation'
[[ ! -e "$SOURCE_CREDENTIAL_MARKER" ]] ||
  die 'source Git credential helper ran during native clone preparation'
printf 'host changed after environment creation\n' >"$WORKSPACE/README.md"
printf 'host-only untracked content\n' >"$WORKSPACE/host-only.txt"
run_cw env list --local --output json
jq -e '
  length == 2 and
  any(.[];
    .name == "native-smoke" and
    .placement == "local" and
    .selected == true and
    .state == "running" and
    .daemon_health == "ready"
  ) and
  any(.[];
    .name == "legacy" and
    .placement == "local" and
    .selected == false and
    .id == "cw-legacy"
  )
' "$LAST_STDOUT" >/dev/null || die 'native environment list metadata drifted'
[[ "$(stat -c '%a' "$STATE_ROOT")" == 700 ]] || die 'native state root is not mode 0700'
[[ "$(stat -c '%a' "$STATE_ROOT/supervisor.db")" == 600 ]] ||
  die 'native supervisor database is not mode 0600'
for sqlite_sidecar in "$STATE_ROOT/supervisor.db-wal" "$STATE_ROOT/supervisor.db-shm"; do
  [[ ! -e "$sqlite_sidecar" || "$(stat -c '%a' "$sqlite_sidecar")" == 600 ]] ||
    die "native supervisor database sidecar is not mode 0600: $sqlite_sidecar"
done
[[ "$(native_database_value contract)" == '1129797197:7:wal:ok' ]] ||
  die 'native supervisor database contract drifted'
wait_for_journal_complete ||
  die "initial create returned before its lifecycle journal became terminal: $(native_database_value journal_summary)"
[[ "$(native_database_value ownership)" == '64:6' ]] ||
  die 'native artifact generation or owned-object manifest was not recorded'
if ! ORIGINAL_ARTIFACT_GENERATION="$(native_database_value active_artifact_generation)"; then
  die 'active runtime artifact generation is missing'
fi
[[ "$ORIGINAL_ARTIFACT_GENERATION" =~ ^[0-9a-f]{64}$ ]] ||
  die 'active runtime artifact generation is not an exact SHA-256 identity'
if ! RUNNER_ARTIFACT_GENERATION="$(native_database_value runner_artifact_generation)"; then
  die 'initial runner artifact generation is missing'
fi
[[ "$RUNNER_ARTIFACT_GENERATION" == "$ORIGINAL_ARTIFACT_GENERATION" ]] ||
  die "initial runner artifact generation $RUNNER_ARTIFACT_GENERATION does not match active generation $ORIGINAL_ARTIFACT_GENERATION"
[[ -f "$STATE_ROOT/engine/runtime-artifacts/generations/$ORIGINAL_ARTIFACT_GENERATION.json" ]] ||
  die 'active runtime artifact generation manifest is missing'
[[ "$(runtime_artifact_manifest_count)" == 1 ]] ||
  die 'initial runtime artifact cache contains an unexpected generation'

ENVIRONMENT_ID="$(native_database_value environment_id)"
RUNNER_PID="$(native_database_value runner_pid)"
[[ -d "/proc/$RUNNER_PID" ]] || die 'persisted runner PID is not live'
[[ -d "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID" ]] || die 'owned VM state directory is missing'
[[ ! -e "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/seed/seed.raw" ]] ||
  die 'one-boot guest seed remained after readiness'
[[ -z "$(find "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/generations" -name setup.raw -print -quit)" ]] ||
  die 'credential-free one-boot setup pack remained after readiness'

log 'checking public Exec/File over the owner-only supervisor UDS'
run_public_data_smoke

log 'checking bounded public daemon status over the owner-only supervisor UDS'
run_cw env --local daemon status "$NAME" --output json
jq -e '
  .state == "ready" and
  .protocol_version == 1 and
  .minimum_protocol_version == 1 and
  (.daemon_version | type == "string" and length > 0) and
  .capabilities == [
    "attach.v1",
    "exec.v1",
    "files.v1",
    "health.v1",
    "pty.v1",
    "sessions.v1"
  ] and
  .message == "local environment daemon is ready" and
  .diagnostics == [{
    "name": "daemon",
    "healthy": true,
    "message": "local environment daemon is ready"
  }] and
  .pod_name == ""
' "$LAST_STDOUT" >/dev/null || die 'native daemon ready status drifted'

log 'checking read-only orphan inventory without adoption or cleanup'
ORPHAN_SENTINEL="$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/unknown-object"
printf 'do-not-adopt-or-delete\n' >"$ORPHAN_SENTINEL"
chmod 0600 "$ORPHAN_SENTINEL"
run_cw doctor local --output json
jq -e --arg path "$ORPHAN_SENTINEL" '
  .reclaimable_bytes >= 0 and
  any(.orphans[];
    .kind == "vm_tree" and
    .path == ($path | sub("/unknown-object$"; "")) and
    .reason == "unexpected_environment_object"
  )
' "$LAST_STDOUT" >/dev/null || die 'native doctor did not report the exact unknown VM object'
[[ "$(cat "$ORPHAN_SENTINEL")" == 'do-not-adopt-or-delete' ]] ||
  die 'native doctor mutated an orphan candidate'
rm -- "$ORPHAN_SENTINEL"
run_cw doctor local --output json
jq -e '.orphans == [] and .reclaimable_bytes == 0' "$LAST_STDOUT" >/dev/null ||
  die 'native doctor reported an orphan after the test object was removed'

log 'checking guest identity, live resources, workspace, and durable output'
# The quoted expression is evaluated by the guest shell, not this host script.
# shellcheck disable=SC2016
run_cw run --no-tty -- /bin/sh -lc \
  'printf "guest-cwd=%s\n" "$PWD"; printf "guest-pid1-comm="; cat /proc/1/comm; if readlink /proc/1/exe >/dev/null 2>&1; then printf "guest-pid1-exe=exposed\n"; else printf "guest-pid1-exe=confined\n"; fi; printf "guest-sealed-init="; /run/codewire-runtime/init identity; printf "guest-machine-id="; cat /etc/machine-id; awk "/^NoNewPrivs:/ { printf \"guest-no-new-privileges=%s\\n\", \$2 } /^CapEff:/ { printf \"guest-effective-capabilities=%s\\n\", \$2 }" /proc/self/status; printf "guest-cpus="; grep -c "^processor" /proc/cpuinfo; grep "^MemTotal:" /proc/meminfo; printf "workspace-node="; node --version; test -d /workspace/github/.git; test -d /workspace/gitea/.git; test -z "$(git -C /workspace/github status --porcelain=v1 --untracked-files=all)"; test -z "$(git -C /workspace/gitea status --porcelain=v1 --untracked-files=all)"; printf "guest-github-head="; git -C /workspace/github rev-parse HEAD; printf "guest-gitea-head="; git -C /workspace/gitea rev-parse HEAD; printf "guest-github-readme-sha="; sha256sum /workspace/github/README.md | cut -d " " -f 1; printf "guest-gitea-readme-sha="; sha256sum /workspace/gitea/README.md | cut -d " " -f 1; printf "guest-github-origin="; git -C /workspace/github config --local --get remote.origin.url; printf "guest-gitea-origin="; git -C /workspace/gitea config --local --get remote.origin.url; git -C /workspace/github config --local --list; git -C /workspace/gitea config --local --list; printf persistence-ok > /workspace/sentinel.txt'
rg -qF 'guest-cwd=/workspace/github' "$LAST_STDOUT" ||
  die 'session did not start in the configured repository working directory'
rg -qF 'guest-pid1-comm=init' "$LAST_STDOUT" ||
  die 'guest PID 1 does not have the sealed init process identity'
rg -qF 'guest-pid1-exe=confined' "$LAST_STDOUT" ||
  die 'guest PID 1 exposed its executable link to the workspace identity'
rg -q '^guest-sealed-init=CWIDENTITY1 vm_id=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12} generation=1$' "$LAST_STDOUT" ||
  die 'sealed Codewire init did not return the generation-bound VM identity'
EXPECTED_MACHINE_ID="${ENVIRONMENT_ID//-/}"
rg -qF "guest-machine-id=$EXPECTED_MACHINE_ID" "$LAST_STDOUT" ||
  die 'workspace inherited image machine identity instead of its environment identity'
rg -qF 'guest-no-new-privileges=1' "$LAST_STDOUT" ||
  die 'session did not execute through the no-new-privileges OCI boundary'
rg -qF 'guest-effective-capabilities=0000000000000000' "$LAST_STDOUT" ||
  die 'session retained capabilities across the OCI execution boundary'
rg -qF 'guest-cpus=2' "$LAST_STDOUT" || die 'guest did not observe exactly 2 vCPUs'
rg -q '^workspace-node=v[0-9]+\.' "$LAST_STDOUT" ||
  die 'session did not execute from the canonical Codewire workspace image'
rg -qF "guest-github-head=$GITHUB_COMMIT" "$LAST_STDOUT" ||
  die 'GitHub workspace does not identify the pinned commit'
rg -qF "guest-gitea-head=$GITEA_COMMIT" "$LAST_STDOUT" ||
  die 'git.example.invalid workspace does not identify the pinned commit'
rg -qF "guest-github-readme-sha=$GITHUB_README_SHA256" "$LAST_STDOUT" ||
  die 'GitHub workspace content drifted from the pinned commit'
rg -qF "guest-gitea-readme-sha=$GITEA_README_SHA256" "$LAST_STDOUT" ||
  die 'git.example.invalid workspace content drifted from the pinned commit'
rg -qF 'guest-github-origin=https://github.com/noeljackson/method.git' "$LAST_STDOUT" ||
  die 'GitHub workspace origin metadata is not the sanitized public source'
rg -qF 'guest-gitea-origin=https://git.example.invalid/supplychain.git' "$LAST_STDOUT" ||
  die 'git.example.invalid workspace origin metadata is not the sanitized public source'
if rg -qF 'host-secret' "$LAST_STDOUT" || rg -qF 'credential.helper' "$LAST_STDOUT" ||
   rg -qF "$WORKSPACE" "$LAST_STDOUT"; then
  die 'host Git credential or source-path metadata entered the guest clone'
fi
MEMORY_KIB="$(awk '$1 == "MemTotal:" { print $2 }' "$LAST_STDOUT")"
[[ "$MEMORY_KIB" =~ ^[0-9]+$ && "$MEMORY_KIB" -ge 15000000 && "$MEMORY_KIB" -le 17500000 ]] ||
  die "guest MemTotal is not consistent with 16 GiB: ${MEMORY_KIB:-missing} KiB"

log 'checking daemon logs contain only trusted lifecycle journal fields'
DAEMON_GUEST_SENTINEL='guest-output-must-not-enter-daemon-logs-1909'
run_cw run --no-tty -- /bin/sh -lc "printf '%s\\n' '$DAEMON_GUEST_SENTINEL'"
rg -qF "$DAEMON_GUEST_SENTINEL" "$LAST_STDOUT" || die 'guest diagnostic sentinel was not emitted'
run_cw env --local daemon logs "$NAME"
rg -q '^time_unix_ms=[0-9]+ operation=[0-9a-f-]{36} kind=create phase=completed checkpoint=8 stage=OPERATION_STAGE_[A-Z_]+ error=-$' "$LAST_STDOUT" ||
  die 'native daemon logs did not expose the trusted create journal record'
[[ "$(stat -c '%s' "$LAST_STDOUT")" -le 65536 ]] || die 'native daemon logs exceeded their public bound'
if rg -qF "$DAEMON_GUEST_SENTINEL" "$LAST_STDOUT"; then
  die 'guest command output entered native daemon logs'
fi

log 'checking interactive PTY shell through the selected native environment'
PTY_LOG="$SMOKE_ROOT/pty.log"
if ! (
  cd "$WORKSPACE"
  {
    printf 'test -t 0 && test -t 1 && printf "native-pty-ok\\n"\npwd\nexit\n'
    # Keep testing input sent before the shell banner, but allow the extra
    # runc console hop to return its output before the local detach chord.
    sleep 1
    printf '\002d'
  } |
    env -i \
      PATH="$SMOKE_ROOT/bin:/usr/bin:/bin" HOME="$SMOKE_HOME" USER="$(id -un)" \
      LOGNAME="$(id -un)" SHELL='/bin/sh' TERM='xterm-256color' LC_ALL=C \
      CW_CONFIG_DIR="$PLATFORM_CONFIG" CODEWIRE_NATIVE_STATE_ROOT="$STATE_ROOT" \
      CODEWIRE_NATIVE_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
      CODEWIRE_NATIVE_ARTIFACT_LOCK="$ARTIFACT_LOCK" \
      CODEWIRE_SERVER_URL='http://127.0.0.1:1' \
      CODEWIRE_API_KEY='synthetic-platform-key-must-not-be-used' \
      HTTP_PROXY='http://127.0.0.1:1' HTTPS_PROXY='http://127.0.0.1:1' \
      ALL_PROXY='http://127.0.0.1:1' NO_PROXY='' \
      /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 30s \
      /usr/bin/script -qefc "$CW_BIN shell" "$PTY_LOG"
) >"$SMOKE_ROOT/pty.stdout" 2>"$SMOKE_ROOT/pty.stderr"; then
  tail -n 80 "$SMOKE_ROOT/pty.stderr" >&2
  die 'interactive native shell failed'
fi
cat "$SMOKE_ROOT/pty.stdout" "$SMOKE_ROOT/pty.stderr" >>"$TRANSCRIPT"
rg -qF 'native-pty-ok' "$PTY_LOG" || die 'guest shell did not receive a PTY'
rg -qF '/workspace/github' "$PTY_LOG" ||
  die 'interactive shell did not start in the configured repository directory'

log 'checking nonzero status and saved session output'
run_cw_expect_failure run --no-tty -- /bin/sh -lc 'printf saved-nonzero; exit 42'
rg -qF 'saved-nonzero' "$LAST_STDOUT" || die 'nonzero session output was not returned'
rg -qF 'session exited with code 42' "$LAST_STDERR" || die 'guest exit code 42 was not propagated'
run_cw list --output json
SESSION_ID="$(jq -er '
  .[] |
  select(.command == ["/bin/sh", "-lc", "printf saved-nonzero; exit 42"]) |
  select(.state == "Exited" and .exit_code == 42 and .output_end_offset == 13) |
  .session_id
' "$LAST_STDOUT")" || die 'saved nonzero session record drifted'
run_cw logs "$NAME" "$SESSION_ID" --raw
[[ "$(cat "$LAST_STDOUT")" == 'saved-nonzero' ]] || die 'saved session output was not readable'

log 'checking stopped offline restart remains pinned after the installed artifact lock advances'
run_cw env stop --local "$NAME" --output json
jq -e '.state == "stopped"' "$LAST_STDOUT" >/dev/null || die 'native environment did not stop'
wait_for_journal_complete ||
  die 'native stop returned before its lifecycle journal became terminal'
STOPPED_RUNNER_PID="$(native_database_value runner_pid)"
STOPPED_SUPERVISOR_PID="$(find_exact_supervisor_pid)" ||
  die 'native supervisor process was not found before installed artifact advance'
kill -KILL -- "$STOPPED_SUPERVISOR_PID"
wait_for_pid_exit "$STOPPED_SUPERVISOR_PID" ||
  die 'killed supervisor process did not exit before installed artifact advance'
[[ "$(kill_recorded_process runner)" == "$STOPPED_RUNNER_PID" ]] ||
  die 'pidfd runner kill did not target the stopped persisted process identity'
wait_for_pid_death "$STOPPED_RUNNER_PID" ||
  die 'stopped runner remained live before installed artifact advance'
wait_for_journal_complete ||
  die 'committed lifecycle journal regressed after exact supervisor and runner death'
prepare_advanced_artifact_source
ARTIFACT_ROOT="$ADVANCED_ARTIFACT_ROOT"
ARTIFACT_LOCK="$ADVANCED_ARTIFACT_LOCK"
run_cw env start --local "$NAME" --output json
jq -e '.state == "running"' "$LAST_STDOUT" >/dev/null || die 'native environment did not restart'
REPLACEMENT_RUNNER_PID="$(native_database_value runner_pid)"
[[ "$REPLACEMENT_RUNNER_PID" != "$STOPPED_RUNNER_PID" && -d "/proc/$REPLACEMENT_RUNNER_PID" ]] ||
  die 'installed artifact advance did not produce a replacement live runner'
[[ "$(native_database_value active_artifact_generation)" == "$ORIGINAL_ARTIFACT_GENERATION" ]] ||
  die 'restart substituted the installed runtime for the environment-pinned generation'
[[ "$(native_database_value runner_artifact_generation)" == "$ORIGINAL_ARTIFACT_GENERATION" ]] ||
  die 'replacement runner did not use the environment-pinned runtime generation'
[[ "$(runtime_artifact_manifest_count)" == 1 ]] ||
  die 'restart admitted the advanced installed artifact lock unexpectedly'
[[ -f "$STATE_ROOT/engine/runtime-artifacts/generations/$ORIGINAL_ARTIFACT_GENERATION.json" ]] ||
  die 'restart removed the environment-pinned runtime generation manifest'
RUNNER_PID="$REPLACEMENT_RUNNER_PID"
run_cw run --no-tty -- /bin/sh -lc 'cat /workspace/sentinel.txt; git -C /workspace/github rev-parse HEAD; git -C /workspace/gitea rev-parse HEAD; cat /etc/machine-id'
rg -qF 'persistence-ok' "$LAST_STDOUT" ||
  die 'workspace sentinel did not survive cached-runtime restart'
rg -qF "$GITHUB_COMMIT" "$LAST_STDOUT" ||
  die 'GitHub workspace did not survive cached-runtime restart'
rg -qF "$GITEA_COMMIT" "$LAST_STDOUT" ||
  die 'git.example.invalid workspace did not survive cached-runtime restart'
rg -qF "$EXPECTED_MACHINE_ID" "$LAST_STDOUT" ||
  die 'environment-specific machine identity did not survive restart'

log 'checking exact runner adoption after supervisor crash'
SUPERVISOR_PID="$(find_exact_supervisor_pid)" || die 'native supervisor process was not found exactly'
kill -KILL -- "$SUPERVISOR_PID"
wait_for_pid_exit "$SUPERVISOR_PID" || die 'killed supervisor process did not exit'
[[ -d "/proc/$RUNNER_PID" ]] || die 'runner did not survive supervisor crash'
run_cw env info --local "$NAME" --output json
jq -e '.state == "running" and .cpu == 2 and .memory == "16Gi" and .disk == "20Gi"' "$LAST_STDOUT" >/dev/null ||
  die 'replacement supervisor did not reconcile the running environment'
[[ "$(native_database_value runner_pid)" == "$RUNNER_PID" ]] ||
  die 'replacement supervisor substituted a different runner'
run_public_data_smoke

log 'checking exact 2-vCPU, 16-GiB VMM death classification and daemon repair'
VMM_PID="$(recorded_vmm_pid)" || die 'persisted VMM process identity was not readable'
VMM_GENERATION="$(jq -er '.generation' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json")" ||
  die 'persisted VMM generation was not readable'
[[ "$(kill_recorded_process vmm)" == "$VMM_PID" ]] ||
  die 'pidfd VMM kill did not target the persisted process identity'
wait_for_pid_death "$VMM_PID" || die 'pidfd-signalled VMM process remained live'
wait_for_environment_state error ||
  die 'VMM death was not classified as an environment error'
wait_for_pid_exit "$VMM_PID" || die 'reconciled VMM process was not reaped'
run_cw env --local daemon status "$NAME" --output json
jq -e '
  .state == "unhealthy" and
  .protocol_version == 1 and
  .minimum_protocol_version == 1 and
  .capabilities == [] and
  .message == "local environment runtime requires repair" and
  .diagnostics == [{
    "name": "daemon",
    "healthy": false,
    "message": "local environment runtime requires repair"
  }] and
  .pod_name == ""
' "$LAST_STDOUT" >/dev/null || die 'native daemon error status drifted after exact VMM death'
run_cw env --local daemon repair "$NAME" --output json
jq -e '
  .replaced_pod_name == "" and
  .status.state == "ready" and
  .status.protocol_version == 1 and
  .status.minimum_protocol_version == 1 and
  .status.message == "local environment daemon is ready" and
  .status.pod_name == ""
' "$LAST_STDOUT" >/dev/null || die 'native daemon repair result drifted after exact VMM death'
RECOVERED_VMM_PID="$(recorded_vmm_pid)" || die 'restarted VMM identity was not readable'
[[ "$RECOVERED_VMM_PID" != "$VMM_PID" && -d "/proc/$RECOVERED_VMM_PID" ]] ||
  die 'VMM death recovery did not produce a new live VMM process'
RECOVERED_VMM_GENERATION="$(jq -er '.generation' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json")" ||
  die 'repaired VMM generation was not readable'
[[ "$RECOVERED_VMM_GENERATION" -eq $((VMM_GENERATION + 1)) ]] ||
  die 'daemon repair did not rotate the VMM generation exactly once'
[[ "$(native_database_value environment_id)" == "$ENVIRONMENT_ID" ]] ||
  die 'daemon repair changed the durable environment identity'
run_cw run --no-tty -- /bin/sh -lc \
  "cat /workspace/sentinel.txt; test \"\$(git -C /workspace/github rev-parse HEAD)\" = '$GITHUB_COMMIT'; test \"\$(git -C /workspace/gitea rev-parse HEAD)\" = '$GITEA_COMMIT'"
rg -qF 'persistence-ok' "$LAST_STDOUT" || die 'workspace did not survive exact VMM death'

log 'checking exact runner death, VMM parent-death containment, and recovery'
RUNNER_PID="$(native_database_value runner_pid)"
VMM_PID="$(recorded_vmm_pid)"
[[ "$(kill_recorded_process runner)" == "$RUNNER_PID" ]] ||
  die 'pidfd runner kill did not target the persisted process identity'
wait_for_pid_death "$RUNNER_PID" || die 'pidfd-signalled runner process remained live'
wait_for_pid_death "$VMM_PID" || die 'VMM remained live after its runner died'
wait_for_environment_state error ||
  die 'runner death was not classified as an environment error'
run_cw env --local daemon repair "$NAME" --output json
jq -e '.replaced_pod_name == "" and .status.state == "ready" and .status.pod_name == ""' \
  "$LAST_STDOUT" >/dev/null || die 'environment daemon did not repair after exact runner death'
RECOVERED_RUNNER_PID="$(wait_for_replaced_runner_pid "$RUNNER_PID")" ||
  die 'runner death recovery did not publish a new live runner process identity'
RECOVERED_VMM_PID="$(recorded_vmm_pid)"
[[ -d "/proc/$RECOVERED_RUNNER_PID" ]] ||
  die 'replacement runner exited before recovery verification completed'
[[ "$RECOVERED_VMM_PID" != "$VMM_PID" && -d "/proc/$RECOVERED_VMM_PID" ]] ||
  die 'runner death recovery did not produce a new live VMM process'
run_cw run --no-tty -- /bin/sh -lc \
  "cat /workspace/sentinel.txt; test \"\$(git -C /workspace/github rev-parse HEAD)\" = '$GITHUB_COMMIT'; test \"\$(git -C /workspace/gitea rev-parse HEAD)\" = '$GITEA_COMMIT'"
rg -qF 'persistence-ok' "$LAST_STDOUT" || die 'workspace did not survive exact runner death'
wait_for_journal_complete ||
  die 'native lifecycle journal contains a pending or partial operation'

log 'checking journaled offline disk growth and restart-applied CPU and memory'
run_cw env resize --local "$NAME" --cpu 3 --memory 12Gi --disk 21Gi --yes --force --output json
jq -e '
  .state == "running" and
  .cpu == 3 and
  .memory == "12Gi" and
  .disk == "21Gi"
' "$LAST_STDOUT" >/dev/null || die 'native resize result drifted'
[[ "$(stat -c '%s' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/disks/state.raw")" == 22548578304 ]] ||
  die 'native state disk file did not grow to 21 GiB'
[[ "$(native_database_value resize_operation)" == 'restart:completed:7' ]] ||
  die 'native resize journal did not commit all six effect checkpoints'
run_cw run --no-tty -- /bin/sh -lc \
  'printf "guest-cpus="; grep -c "^processor" /proc/cpuinfo; grep "^MemTotal:" /proc/meminfo; cat /workspace/sentinel.txt'
rg -qF 'guest-cpus=3' "$LAST_STDOUT" || die 'resized guest did not observe exactly 3 vCPUs'
rg -qF 'persistence-ok' "$LAST_STDOUT" || die 'workspace sentinel did not survive resize'
MEMORY_KIB="$(awk '$1 == "MemTotal:" { print $2 }' "$LAST_STDOUT")"
[[ "$MEMORY_KIB" =~ ^[0-9]+$ && "$MEMORY_KIB" -ge 11000000 && "$MEMORY_KIB" -le 13000000 ]] ||
  die "guest MemTotal is not consistent with 12 GiB after resize: ${MEMORY_KIB:-missing} KiB"
run_cw_expect_failure env resize --local "$NAME" --disk 20Gi --yes --output json
rg -qF 'disk shrink is not supported' "$LAST_STDERR" ||
  die 'native disk shrink did not fail with an actionable error'

log 'deleting the environment and proving complete owned-object cleanup'
run_cw env rm --local "$NAME" --yes
ENV_CREATED=0
DELETED_SUPERVISOR_PID="$(find_exact_supervisor_pid)" ||
  die 'per-user supervisor did not survive final environment deletion'
[[ "$(owned_processes)" == "$DELETED_SUPERVISOR_PID" ]] ||
  die 'a runner or VMM process remained after delete'
[[ "$(find "$STATE_ROOT" -type s -print)" == "$STATE_ROOT/supervisor.sock" ]] ||
  die 'final deletion did not retain exactly the per-user supervisor socket'
[[ -z "$(find "$STATE_ROOT/engine/vms" -mindepth 1 -print -quit)" ]] || die 'owned VM disk or state remained after delete'
[[ -z "$(find "$STATE_ROOT/engine/trash" -mindepth 1 -print -quit)" ]] ||
  die 'owned VM trash generation remained after delete'
[[ -z "$(find "$STATE_ROOT/engine/runtime-artifacts/generations" -mindepth 1 -print -quit)" ]] ||
  die 'runtime artifact generation remained after delete'
[[ -z "$(find "$STATE_ROOT/engine/runtime-artifacts/blobs" -mindepth 1 -print -quit)" ]] ||
  die 'runtime artifact blob remained after delete'
[[ -z "$(find "$STATE_ROOT/engine/content/blobs" -mindepth 1 -print -quit)" ]] ||
  die 'workspace image or repository content blob remained after delete'
[[ "$(native_database_value empty)" == yes ]] ||
  die 'native environment state entry remained after delete'
wait_for_journal_complete ||
  die 'native delete journal did not reach its final checkpoint'
[[ "$(cat "$WORKSPACE/README.md")" == 'host changed after environment creation' ]] ||
  die 'guest clone or environment deletion mutated the host Git worktree'
[[ "$(cat "$WORKSPACE/host-only.txt")" == 'host-only untracked content' ]] ||
  die 'host-only content changed during guest clone lifecycle'
[[ ! -e "$WORKSPACE/sentinel.txt" ]] ||
  die 'guest writes escaped the environment-owned clone into the host source'
[[ "$(sha256sum "$WORKSPACE/.git/config" | awk '{print $1}')" == "$SOURCE_CONFIG_SHA256" ]] ||
  die 'native clone preparation mutated the host Git configuration'
[[ -x "$WORKSPACE/.git/hooks/post-checkout" ]] ||
  die 'native clone lifecycle mutated the source Git hook'
[[ ! -e "$SOURCE_HOOK_MARKER" && ! -e "$SOURCE_CREDENTIAL_MARKER" ]] ||
  die 'source Git executable configuration ran during the native lifecycle'
run_cw doctor local --output json
jq -e '.orphans == [] and .reclaimable_bytes == 0' "$LAST_STDOUT" >/dev/null ||
  die 'native doctor reported owned state after exact deletion cleanup'

log 'checking explicit copy-mode path preparation is detached from the host'
NAME='native-copy-smoke'
WORKSPACE="$SMOKE_ROOT/copy-source"
mkdir -m 0700 "$WORKSPACE"
printf 'copy source before creation\n' >"$WORKSPACE/data.txt"
printf 'hidden copy content\n' >"$WORKSPACE/.hidden"
printf '#!/bin/sh\nprintf "copy-executable-ok\\n"\n' >"$WORKSPACE/tool.sh"
chmod 0755 "$WORKSPACE/tool.sh"
ln "$WORKSPACE/data.txt" "$WORKSPACE/hardlink.txt"
ln -s data.txt "$WORKSPACE/link.txt"
ALLOW_REGISTRY_EGRESS=1
CW_COMMAND_TIMEOUT_SECONDS=1500
run_cw env create --local --name "$NAME" --cpu 2 --memory 16Gi \
  --path "$WORKSPACE" --path-mode copy --output json
ALLOW_REGISTRY_EGRESS=0
CW_COMMAND_TIMEOUT_SECONDS=180
ENV_CREATED=1
jq -e '
  .name == "native-copy-smoke" and
  .backend == "cloud-hypervisor" and
  .state == "running" and
  .working_directory == "/workspace" and
  .workspace_inputs == 1 and
  (.workspace_plan | test("^[0-9a-f]{64}$"))
' "$LAST_STDOUT" >/dev/null || die 'copy-mode environment metadata drifted'
printf 'host changed after copy creation\n' >"$WORKSPACE/data.txt"
printf 'host-only after copy\n' >"$WORKSPACE/host-only.txt"
# The quoted expression is evaluated by the guest shell, not this host script.
# shellcheck disable=SC2016
run_cw run --no-tty -- /bin/sh -lc \
  'test ! -e .git; grep -qx "copy source before creation" data.txt; grep -qx "hidden copy content" .hidden; test "$(readlink link.txt)" = data.txt; test "$(stat -c %h data.txt)" = 1; test "$(stat -c %h hardlink.txt)" = 1; test ! -e host-only.txt; ./tool.sh; printf guest-copy-write > guest-only.txt'
rg -qF 'copy-executable-ok' "$LAST_STDOUT" ||
  die 'copy-mode executable content was unavailable in the guest'
[[ "$(cat "$WORKSPACE/data.txt")" == 'host changed after copy creation' ]] ||
  die 'copy-mode guest read or write mutated the selected host source'
[[ ! -e "$WORKSPACE/guest-only.txt" ]] ||
  die 'copy-mode guest write escaped into the selected host source'
run_cw env rm --local "$NAME" --yes
ENV_CREATED=0
[[ "$(cat "$WORKSPACE/data.txt")" == 'host changed after copy creation' ]] ||
  die 'copy-mode deletion mutated the selected host source'
[[ "$(cat "$WORKSPACE/host-only.txt")" == 'host-only after copy' ]] ||
  die 'copy-mode deletion mutated host-only content'
[[ ! -e "$WORKSPACE/guest-only.txt" ]] ||
  die 'copy-mode deletion synchronized guest state into the host source'
[[ "$(native_database_value empty)" == yes ]] ||
  die 'copy-mode environment state remained after deletion'
run_cw doctor local --output json
jq -e '.orphans == [] and .reclaimable_bytes == 0' "$LAST_STDOUT" >/dev/null ||
  die 'copy-mode deletion left native owned state'

[[ ! -e "$TRIPWIRE" ]] || die "a forbidden fallback was invoked: $(tr '\n' ' ' <"$TRIPWIRE")"
[[ "$(sha256sum "$SMOKE_HOME/.codewire/local_instances.toml" | awk '{print $1}')" == "$LEGACY_SHA256" ]] ||
  die 'pre-existing legacy local state changed'
if rg -qF 'synthetic-platform-key-must-not-be-used' "$TRANSCRIPT"; then
  die 'synthetic platform credential appeared in CLI output'
fi
terminate_exact_supervisor || die 'bounded supervisor teardown failed'
[[ -z "$(owned_processes)" ]] || die 'an owned process remained after bounded smoke teardown'

log 'PASS (Linux/KVM native cw product flow)'
