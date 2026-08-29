#!/usr/bin/env bash
# Qualified-host product proof for the Linux native local environment. The
# caller supplies an exact built cw binary and already-staged immutable VMM
# artifacts; this script never downloads artifacts or selects a fallback VMM.
set -euo pipefail

readonly LINUX_SUN_PATH_BYTES=108
readonly LONGEST_SOCKET_SUFFIX='/engine/vms/00000000-0000-4000-8000-000000000000/vsock/vsock.sock'

CW_BIN=''
ARTIFACT_ROOT=''
ARTIFACT_LOCK=''
SMOKE_PARENT="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
SMOKE_ROOT=''
SMOKE_HOME=''
STATE_ROOT=''
WORKSPACE=''
PLATFORM_CONFIG=''
TRIPWIRE=''
TRANSCRIPT=''
NAME='native-smoke'
COMMAND_INDEX=0
LAST_STDOUT=''
LAST_STDERR=''
ENV_CREATED=0

usage() {
  cat <<'USAGE' >&2
usage: smoke-native-local-environment.sh \
  --cw-bin ABSOLUTE_PATH \
  --artifact-root ABSOLUTE_PRIVATE_DIRECTORY \
  --artifact-lock ABSOLUTE_LOCK_FILE \
  [--scratch-parent ABSOLUTE_DIRECTORY]

Runs the built cw Linux/KVM native-environment product smoke with 2 vCPUs and
16 GiB of guest memory. The artifact root and lock must already contain the
exact Cloud Hypervisor, kernel, and product guest-root artifacts admitted by
codewire-local-vmm. Missing KVM, artifacts, or required tools fail nonzero.

The smoke uses an isolated HOME and short private native state root, poisons
all platform and proxy destinations, installs Docker/Lima/QEMU tripwires, and
creates a clean disposable Git fixture. It proves create/info, bare run and
shell, PTY behavior, saved output and nonzero status, stop/start persistence,
offline disk/CPU/memory resize, supervisor crash recovery, and journaled exact
deletion cleanup.
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

[[ -n "$CW_BIN" && -n "$ARTIFACT_ROOT" && -n "$ARTIFACT_LOCK" ]] || {
  usage
  exit 2
}

for tool in awk cat chmod dirname e2fsck find git id jq mkdir mktemp python3 readlink realpath resize2fs rg script sha256sum sleep stat tail timeout touch tr uname; do
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
[[ "$CW_BIN" =~ ^[-_./0-9A-Za-z]+$ ]] ||
  die 'cw binary path contains characters unsafe for the PTY smoke command'
require_absolute_canonical_dir 'artifact root' "$ARTIFACT_ROOT"
require_absolute_canonical_file 'artifact lock' "$ARTIFACT_LOCK"
[[ "$(dirname "$ARTIFACT_ROOT")" == "$(dirname "$ARTIFACT_LOCK")" ]] ||
  die 'artifact root and lock must share one staging parent'
require_absolute_canonical_dir 'scratch parent' "$SMOKE_PARENT"

SMOKE_ROOT="$(mktemp -d "$SMOKE_PARENT/.cwn.XXXXXX")"
chmod 0700 "$SMOKE_ROOT"
SMOKE_ROOT="$(realpath -e -- "$SMOKE_ROOT")"
SMOKE_HOME="$SMOKE_ROOT/h"
STATE_ROOT="$SMOKE_ROOT/s"
WORKSPACE="$SMOKE_ROOT/w"
PLATFORM_CONFIG="$SMOKE_ROOT/c"
TRIPWIRE="$SMOKE_ROOT/fallback-invoked"
TRANSCRIPT="$SMOKE_ROOT/transcript"
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
WORKSPACE_COMMIT="$(env -i PATH='/usr/bin:/bin' HOME="$SMOKE_HOME" LC_ALL=C \
  /usr/bin/git -C "$WORKSPACE" rev-parse HEAD)"

cw_isolated() {
  (
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
      HTTP_PROXY='http://127.0.0.1:1' \
      HTTPS_PROXY='http://127.0.0.1:1' \
      ALL_PROXY='http://127.0.0.1:1' \
      NO_PROXY='' \
      /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 180s \
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
  /usr/bin/env python3 - \
    "$STATE_ROOT/supervisor.db" \
    "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json" \
    "$NAME" \
    "$kind" <<'PY'
import json
import hashlib
import os
import signal
import sqlite3
import sys

database, vmm_state, name, kind = sys.argv[1:]
if kind == "runner":
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=1)
    try:
        row = connection.execute(
            "SELECT runner_json FROM environments WHERE name = ?", (name,)
        ).fetchone()
        if row is None or row[0] is None:
            raise SystemExit("runner identity is missing")
        identity = json.loads(row[0])["process"]
    finally:
        connection.close()
elif kind == "vmm":
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

native_database_value() {
  local field="$1"
  /usr/bin/env python3 - "$STATE_ROOT/supervisor.db" "$field" "$NAME" <<'PY'
import json
import sqlite3
import sys

database, field, name = sys.argv[1:]
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=1)
try:
    if field == "environment_id":
        row = connection.execute(
            "SELECT id FROM environments WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            raise SystemExit(1)
        print(row[0])
    elif field == "runner_pid":
        row = connection.execute(
            "SELECT runner_json FROM environments WHERE name = ?", (name,)
        ).fetchone()
        if row is None or row[0] is None:
            raise SystemExit(1)
        print(json.loads(row[0])["process"]["pid"])
    elif field == "empty":
        count = connection.execute("SELECT count(*) FROM environments").fetchone()[0]
        current = connection.execute(
            "SELECT current_environment_id FROM supervisor_settings WHERE singleton = 1"
        ).fetchone()[0]
        print("yes" if count == 0 and current is None else "no")
    elif field == "contract":
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        quick_check = connection.execute("PRAGMA quick_check(1)").fetchone()[0]
        print(f"{application_id}:{user_version}:{journal_mode}:{quick_check}")
    elif field == "resize_operation":
        row = connection.execute(
            "SELECT kind, phase, checkpoint FROM operations "
            "WHERE kind IN ('restart', 'grow_disk') ORDER BY created_unix_ms DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise SystemExit(1)
        print(f"{row[0]}:{row[1]}:{row[2]}")
    elif field == "journal_complete":
        expected = {
            "create": 6,
            "start": 5,
            "stop": 3,
            "restart": 7,
            "grow_disk": 7,
            "delete": 5,
            "reconcile": 2,
        }
        rows = connection.execute(
            "SELECT kind, phase, checkpoint FROM operations"
        ).fetchall()
        complete = bool(rows) and all(
            kind in expected and phase == "completed" and checkpoint == expected[kind]
            for kind, phase, checkpoint in rows
        )
        print("yes" if complete else "no")
    elif field == "ownership":
        row = connection.execute(
            "SELECT id, active_artifact_generation FROM environments WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            raise SystemExit(1)
        count = connection.execute(
            "SELECT count(*) FROM owned_objects WHERE environment_id = ?", (row[0],)
        ).fetchone()[0]
        generation = row[1] or ""
        print(f"{len(generation)}:{count}")
    else:
        raise SystemExit(2)
finally:
    connection.close()
PY
}

cleanup() {
  local status=$?
  local cleanup_status=0
  trap - EXIT HUP INT TERM
  if [[ "$ENV_CREATED" -eq 1 && ( -f "$STATE_ROOT/supervisor.db" || -f "$STATE_ROOT/state.json" ) ]]; then
    log 'cleaning native environment after incomplete smoke'
    if ! cw_isolated env rm --local "$NAME" --yes >/dev/null 2>&1; then
      cleanup_status=1
    fi
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
run_cw env create --local --name "$NAME" --cpu 2 --memory 16Gi --path "$WORKSPACE" --output json
ENV_CREATED=1
jq -e --arg commit "$WORKSPACE_COMMIT" '
  .name == "native-smoke" and
  .backend == "cloud-hypervisor" and
  .state == "running" and
  .selected == true and
  .cpu == 2 and
  .memory == "16Gi" and
  .workspace_commit == $commit
' "$LAST_STDOUT" >/dev/null || die 'created native environment metadata drifted'
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
[[ "$(native_database_value contract)" == '1129797197:1:wal:ok' ]] ||
  die 'native supervisor database contract drifted'
[[ "$(native_database_value ownership)" == '64:6' ]] ||
  die 'native artifact generation or owned-object manifest was not recorded'

ENVIRONMENT_ID="$(native_database_value environment_id)"
RUNNER_PID="$(native_database_value runner_pid)"
[[ -d "/proc/$RUNNER_PID" ]] || die 'persisted runner PID is not live'
[[ -d "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID" ]] || die 'owned VM state directory is missing'
[[ ! -e "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/seed/seed.raw" ]] ||
  die 'one-boot guest seed remained after readiness'

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
  'printf "guest-cwd=%s\n" "$PWD"; printf "guest-pid1="; readlink /proc/1/exe; printf "guest-cpus="; grep -c "^processor" /proc/cpuinfo; grep "^MemTotal:" /proc/meminfo; ./hello.sh; printf persistence-ok > /workspace/sentinel.txt'
rg -qF 'guest-cwd=/workspace' "$LAST_STDOUT" || die 'session did not start in /workspace'
rg -qF 'guest-pid1=/init' "$LAST_STDOUT" || die 'guest PID 1 is not the Codewire init entrypoint'
rg -qF 'guest-cpus=2' "$LAST_STDOUT" || die 'guest did not observe exactly 2 vCPUs'
rg -qF 'native-workspace-ok' "$LAST_STDOUT" || die 'clean Git workspace content is unavailable'
MEMORY_KIB="$(awk '$1 == "MemTotal:" { print $2 }' "$LAST_STDOUT")"
[[ "$MEMORY_KIB" =~ ^[0-9]+$ && "$MEMORY_KIB" -ge 15000000 && "$MEMORY_KIB" -le 17500000 ]] ||
  die "guest MemTotal is not consistent with 16 GiB: ${MEMORY_KIB:-missing} KiB"

log 'checking interactive PTY shell through the selected native environment'
PTY_LOG="$SMOKE_ROOT/pty.log"
if ! (
  cd "$WORKSPACE"
  printf 'test -t 0 && test -t 1 && printf "native-pty-ok\\n"\npwd\nexit\n\002d' |
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
rg -qF '/workspace' "$PTY_LOG" || die 'interactive shell did not start in /workspace'

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

log 'checking stop/start workspace persistence'
run_cw env stop --local "$NAME" --output json
jq -e '.state == "stopped"' "$LAST_STDOUT" >/dev/null || die 'native environment did not stop'
run_cw env start --local "$NAME" --output json
jq -e '.state == "running"' "$LAST_STDOUT" >/dev/null || die 'native environment did not restart'
run_cw run --no-tty -- /bin/sh -lc 'cat /workspace/sentinel.txt; ./hello.sh'
rg -qF 'persistence-ok' "$LAST_STDOUT" || die 'workspace sentinel did not survive stop/start'
rg -qF 'native-workspace-ok' "$LAST_STDOUT" || die 'workspace snapshot did not survive stop/start'

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

log 'checking exact runner adoption after supervisor crash'
SUPERVISOR_PID="$(find_exact_supervisor_pid)" || die 'native supervisor process was not found exactly'
kill -KILL -- "$SUPERVISOR_PID"
wait_for_pid_exit "$SUPERVISOR_PID" || die 'killed supervisor process did not exit'
[[ -d "/proc/$RUNNER_PID" ]] || die 'runner did not survive supervisor crash'
run_cw env info --local "$NAME" --output json
jq -e '.state == "running" and .cpu == 3 and .memory == "12Gi" and .disk == "21Gi"' "$LAST_STDOUT" >/dev/null ||
  die 'replacement supervisor did not reconcile the running environment'
[[ "$(native_database_value runner_pid)" == "$RUNNER_PID" ]] ||
  die 'replacement supervisor substituted a different runner'

log 'checking exact VMM death classification and normal lifecycle recovery'
VMM_PID="$(recorded_vmm_pid)" || die 'persisted VMM process identity was not readable'
[[ "$(kill_recorded_process vmm)" == "$VMM_PID" ]] ||
  die 'pidfd VMM kill did not target the persisted process identity'
wait_for_pid_death "$VMM_PID" || die 'pidfd-signalled VMM process remained live'
wait_for_environment_state error ||
  die 'VMM death was not classified as an environment error'
wait_for_pid_exit "$VMM_PID" || die 'reconciled VMM process was not reaped'
run_cw env start --local "$NAME" --output json
jq -e '.state == "running"' "$LAST_STDOUT" >/dev/null ||
  die 'environment did not restart after exact VMM death'
RECOVERED_VMM_PID="$(recorded_vmm_pid)" || die 'restarted VMM identity was not readable'
[[ "$RECOVERED_VMM_PID" != "$VMM_PID" && -d "/proc/$RECOVERED_VMM_PID" ]] ||
  die 'VMM death recovery did not produce a new live VMM process'
run_cw run --no-tty -- /bin/sh -lc 'cat /workspace/sentinel.txt; ./hello.sh'
rg -qF 'persistence-ok' "$LAST_STDOUT" || die 'workspace did not survive exact VMM death'
rg -qF 'native-workspace-ok' "$LAST_STDOUT" || die 'snapshot did not survive exact VMM death'

log 'checking exact runner death, VMM parent-death containment, and recovery'
RUNNER_PID="$(native_database_value runner_pid)"
VMM_PID="$(recorded_vmm_pid)"
[[ "$(kill_recorded_process runner)" == "$RUNNER_PID" ]] ||
  die 'pidfd runner kill did not target the persisted process identity'
wait_for_pid_death "$RUNNER_PID" || die 'pidfd-signalled runner process remained live'
wait_for_pid_death "$VMM_PID" || die 'VMM remained live after its runner died'
wait_for_environment_state error ||
  die 'runner death was not classified as an environment error'
run_cw env start --local "$NAME" --output json
jq -e '.state == "running"' "$LAST_STDOUT" >/dev/null ||
  die 'environment did not restart after exact runner death'
RECOVERED_RUNNER_PID="$(native_database_value runner_pid)"
RECOVERED_VMM_PID="$(recorded_vmm_pid)"
[[ "$RECOVERED_RUNNER_PID" != "$RUNNER_PID" && -d "/proc/$RECOVERED_RUNNER_PID" ]] ||
  die 'runner death recovery did not produce a new live runner process'
[[ "$RECOVERED_VMM_PID" != "$VMM_PID" && -d "/proc/$RECOVERED_VMM_PID" ]] ||
  die 'runner death recovery did not produce a new live VMM process'
run_cw run --no-tty -- /bin/sh -lc 'cat /workspace/sentinel.txt; ./hello.sh'
rg -qF 'persistence-ok' "$LAST_STDOUT" || die 'workspace did not survive exact runner death'
rg -qF 'native-workspace-ok' "$LAST_STDOUT" || die 'snapshot did not survive exact runner death'
[[ "$(native_database_value journal_complete)" == yes ]] ||
  die 'native lifecycle journal contains a pending or partial operation'

log 'deleting the environment and proving complete owned-object cleanup'
run_cw env rm --local "$NAME" --yes
ENV_CREATED=0
for _attempt in {1..100}; do
  [[ -z "$(owned_processes)" ]] && break
  sleep 0.05
done
[[ -z "$(owned_processes)" ]] || die 'an owned supervisor, runner, or VMM process remained after delete'
[[ -z "$(find "$STATE_ROOT" -type s -print -quit)" ]] || die 'an owned Unix socket remained after delete'
[[ -z "$(find "$STATE_ROOT/engine/vms" -mindepth 1 -print -quit)" ]] || die 'owned VM disk or state remained after delete'
[[ -z "$(find "$STATE_ROOT/engine/trash" -mindepth 1 -print -quit)" ]] ||
  die 'owned VM trash generation remained after delete'
[[ "$(native_database_value empty)" == yes ]] ||
  die 'native environment state entry remained after delete'
[[ "$(native_database_value journal_complete)" == yes ]] ||
  die 'native delete journal did not reach its final checkpoint'
run_cw doctor local --output json
jq -e '.orphans == [] and .reclaimable_bytes == 0' "$LAST_STDOUT" >/dev/null ||
  die 'native doctor reported owned state after exact deletion cleanup'
[[ ! -e "$TRIPWIRE" ]] || die "a forbidden fallback was invoked: $(tr '\n' ' ' <"$TRIPWIRE")"
[[ "$(sha256sum "$SMOKE_HOME/.codewire/local_instances.toml" | awk '{print $1}')" == "$LEGACY_SHA256" ]] ||
  die 'pre-existing legacy local state changed'
if rg -qF 'synthetic-platform-key-must-not-be-used' "$TRANSCRIPT"; then
  die 'synthetic platform credential appeared in CLI output'
fi

log 'PASS (Linux/KVM native cw product flow)'
