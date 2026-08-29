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
supervisor crash recovery, and exact deletion cleanup.
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

for tool in awk cat chmod dirname find git id jq mkdir mktemp readlink realpath rg script sha256sum sleep stat tail timeout touch tr uname; do
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

cleanup() {
  local status=$?
  local cleanup_status=0
  trap - EXIT HUP INT TERM
  if [[ "$ENV_CREATED" -eq 1 && -f "$STATE_ROOT/state.json" ]]; then
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
[[ ! -e "$STATE_ROOT/state.json" ]] || die 'rejected native creation wrote native state'

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
[[ "$(stat -c '%a' "$STATE_ROOT/state.json")" == 600 ]] || die 'native state is not mode 0600'

ENVIRONMENT_ID="$(jq -er --arg name "$NAME" '.environments[$name].id' "$STATE_ROOT/state.json")"
RUNNER_PID="$(jq -er --arg name "$NAME" '.environments[$name].runner.process.pid' "$STATE_ROOT/state.json")"
[[ -d "/proc/$RUNNER_PID" ]] || die 'persisted runner PID is not live'
[[ -d "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID" ]] || die 'owned VM state directory is missing'
[[ ! -e "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/seed/seed.raw" ]] ||
  die 'one-boot guest seed remained after readiness'

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

log 'checking exact runner adoption after supervisor crash'
SUPERVISOR_PID="$(find_exact_supervisor_pid)" || die 'native supervisor process was not found exactly'
kill -KILL -- "$SUPERVISOR_PID"
wait_for_pid_exit "$SUPERVISOR_PID" || die 'killed supervisor process did not exit'
[[ -d "/proc/$RUNNER_PID" ]] || die 'runner did not survive supervisor crash'
run_cw env info --local "$NAME" --output json
jq -e '.state == "running" and .cpu == 2 and .memory == "16Gi"' "$LAST_STDOUT" >/dev/null ||
  die 'replacement supervisor did not reconcile the running environment'
[[ "$(jq -er --arg name "$NAME" '.environments[$name].runner.process.pid' "$STATE_ROOT/state.json")" == "$RUNNER_PID" ]] ||
  die 'replacement supervisor substituted a different runner'

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
jq -e '.current == null and .environments == {}' "$STATE_ROOT/state.json" >/dev/null ||
  die 'native environment state entry remained after delete'
[[ ! -e "$TRIPWIRE" ]] || die "a forbidden fallback was invoked: $(tr '\n' ' ' <"$TRIPWIRE")"
[[ "$(sha256sum "$SMOKE_HOME/.codewire/local_instances.toml" | awk '{print $1}')" == "$LEGACY_SHA256" ]] ||
  die 'pre-existing legacy local state changed'
if rg -qF 'synthetic-platform-key-must-not-be-used' "$TRANSCRIPT"; then
  die 'synthetic platform credential appeared in CLI output'
fi

log 'PASS (Linux/KVM native cw product flow)'
