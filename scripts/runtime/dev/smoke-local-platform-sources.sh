#!/usr/bin/env bash
# Owner-operated Dev sources in a real Linux VM. No provider login or key import.
set -euo pipefail
[[ "$-" != *x* ]] || { printf 'shell tracing is unsupported\n' >&2; exit 1; }
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# Reuse public enrollment/project ownership helpers, not platform VM assertions.
LP_ARGUMENTS=("$@")
set --
# shellcheck disable=SC1091 # Guarded entrypoint; its arguments are intentionally empty.
source "$REPO_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
set -- "${LP_ARGUMENTS[@]}"
unset LP_ARGUMENTS

LOCAL_PLATFORM_ARTIFACT_ROOT="${LOCAL_PLATFORM_ARTIFACT_ROOT:-}"
LOCAL_PLATFORM_ARTIFACT_LOCK="${LOCAL_PLATFORM_ARTIFACT_LOCK:-}"
LOCAL_PLATFORM_IMAGE="${LOCAL_PLATFORM_IMAGE:-}"
LOCAL_PLATFORM_NETWORK_ID="${LOCAL_PLATFORM_NETWORK_ID:-}"
EXPECTED_CODEWIRE_ORGANIZATION_ID="${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}"
LP_RUNTIME=''
LP_HOME=''
LP_WORKSPACE=''
LP_CREATE_ATTEMPTED=0
LP_USER_ID=''
LP_GENERATION=0
LP_LOGIN_ATTEMPTED=0
LP_NETWORK_NODE_OWNED=0
LP_ENV=()

local_platform_usage() {
  cat <<'USAGE'
Usage: scripts/runtime/dev/smoke-local-platform-sources.sh --admin-oidc --cw-bin /absolute/normal/cw

Owner-operated Linux KVM acceptance against https://codewire-dev.sh. Uses one
disposable 2-vCPU/16-GiB local VM, synthetic application values and a newly
generated platform SSH key. No existing provider login or private key import.

Required environment:
  CODEWIRE_SERVER_URL=https://codewire-dev.sh
  EXPECTED_CODEWIRE_DEV_SERVER_URL=https://codewire-dev.sh
  EXPECTED_CODEWIRE_ADMIN_EMAIL    Exact authenticated account email
  EXPECTED_CODEWIRE_ORGANIZATION_ID Exact selected organization ID (32 lowercase hex)
  LOCAL_PLATFORM_ARTIFACT_ROOT     Absolute prepared native artifact directory
  LOCAL_PLATFORM_ARTIFACT_LOCK     Absolute matching native artifact lock
  LOCAL_PLATFORM_IMAGE             Published workspace registry@sha256:digest
  LOCAL_PLATFORM_NETWORK_ID        Optional existing Dev Mesh network ID. The
                                   smoke preserves the shared network and only
                                   revokes its exact owned environment node.
  XDG_RUNTIME_DIR                  Owner-only tmpfs runtime parent

The smoke starts a fresh normal cw login in private tmpfs and waits for the owner
to approve it. Existing login directories are rejected, never inspected. Cleanup
logs out that login and removes its files. Local VM state uses a temporary HOME;
cleanup failures retain only private diagnostic state and fail the acceptance.
USAGE
}

local_platform_parse() {
  while (($#)); do
    case "$1" in
      --admin-oidc) SMOKE_AUTH_MODE=admin-oidc; shift ;;
      --cw-bin) [[ $# -ge 2 ]] || die '--cw-bin requires a path'; CW_BIN="$2"; shift 2 ;;
      -h|--help) local_platform_usage; return 2 ;;
      *) die 'unsupported local/platform smoke option' ;;
    esac
  done
}

validate_local_platform_options() {
  [[ "$SMOKE_AUTH_MODE" == admin-oidc && -z "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" &&
     -n "$EXPECTED_CODEWIRE_ADMIN_EMAIL" && -n "$CW_BIN" ]] ||
    die 'local/platform smoke requires --admin-oidc, expected email and normal --cw-bin, without any saved login directory'
  [[ -z "${CODEWIRE_API_KEY:-}" && -z "${CODEWIRE_DEV_SMOKE_API_KEY:-}" &&
     "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == 0 && "$ALLOW_NON_DEV" == 0 &&
     "$CODEWIRE_SERVER_URL" == https://codewire-dev.sh &&
     "$EXPECTED_CODEWIRE_DEV_SERVER_URL" == "$CODEWIRE_SERVER_URL" ]] ||
    die 'local/platform smoke requires normal Dev OAuth, without API keys or alternate endpoints'
  [[ -z "$SMOKE_EXISTING_ENV_ID" && "$SMOKE_KEEP_ENV" == 0 &&
     ${#SMOKE_ONLY_PHASES[@]} == 0 && "$SMOKE_SKIP_KUBE" == 0 ]] ||
    die 'local/platform smoke owns one fresh local environment; existing/keep/only/skip flags are unsupported'
  [[ "$EXPECTED_CODEWIRE_ORGANIZATION_ID" =~ ^[0-9a-f]{32}$ &&
     "$EXPECTED_CODEWIRE_ORGANIZATION_ID" != 00000000000000000000000000000000 ]] ||
    die 'an exact expected Dev organization ID is required'
  [[ "$LOCAL_PLATFORM_IMAGE" =~ ^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$ ]] ||
    die 'LOCAL_PLATFORM_IMAGE must be the exact published workspace digest'
  [[ -z "$LOCAL_PLATFORM_NETWORK_ID" ||
    ( "$LOCAL_PLATFORM_NETWORK_ID" != *[[:space:]]* && ${#LOCAL_PLATFORM_NETWORK_ID} -le 128 ) ]] ||
    die 'LOCAL_PLATFORM_NETWORK_ID must be one exact non-whitespace network ID'
  local path
  for path in "$CW_BIN" "$LOCAL_PLATFORM_ARTIFACT_ROOT" "$LOCAL_PLATFORM_ARTIFACT_LOCK"; do
    [[ "$path" == /* && "$(realpath -e -- "$path")" == "$path" && ! -L "$path" ]] ||
      die 'CLI and artifact paths must be absolute and canonical'
  done
  [[ -f "$CW_BIN" && -x "$CW_BIN" && -d "$LOCAL_PLATFORM_ARTIFACT_ROOT" &&
     -f "$LOCAL_PLATFORM_ARTIFACT_LOCK" && -r "$LOCAL_PLATFORM_ARTIFACT_LOCK" ]] ||
    die 'normal CLI or matching native artifacts are unavailable'
}

local_platform_read_network_nodes() {
  local destination="$1"
  cw_with_timeout 30 network nodes --network "$LOCAL_PLATFORM_NETWORK_ID" \
    --org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" --output json >"$destination" || return 2
  # Invalid inventory is unknown, never evidence of absence or permission to
  # revoke a node. Validate before predicates whose false result means absent.
  jq -e --arg network "$LOCAL_PLATFORM_NETWORK_ID" '
    type == "array" and all(.[];
      type == "object" and .network_id == $network and
      (.name | type == "string" and length > 0) and
      (.connected | type == "boolean"))
  ' "$destination" >/dev/null || return 2
}

local_platform_validate_network() {
  [[ -n "$LOCAL_PLATFORM_NETWORK_ID" ]] || return 0
  cw_with_timeout 30 network list --org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" --output json \
    >"$TMPDIR_SMOKE/local-networks-before.json" || die 'cannot inspect the selected Dev Mesh network'
  jq -e --arg network "$LOCAL_PLATFORM_NETWORK_ID" --arg org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" '
    [.[] | select(.id == $network and .org_id == $org)] | length == 1
  ' "$TMPDIR_SMOKE/local-networks-before.json" >/dev/null ||
    die 'selected Dev Mesh network is absent, ambiguous or owned by another organization'
  local_platform_read_network_nodes "$TMPDIR_SMOKE/local-network-nodes-before.json" ||
    die 'cannot validate selected Dev Mesh membership before creation'
  jq -e --arg network "$LOCAL_PLATFORM_NETWORK_ID" --arg name "$SMOKE_NAME" '
    all(.[]; .network_id != $network or .name != $name)
  ' "$TMPDIR_SMOKE/local-network-nodes-before.json" >/dev/null ||
    die 'selected Dev Mesh network already contains the proposed environment node name'
}

local_platform_network_member() {
  local_platform_read_network_nodes "$TMPDIR_SMOKE/local-network-nodes.json" || return 2
  jq -e --arg network "$LOCAL_PLATFORM_NETWORK_ID" --arg name "$SMOKE_NAME" '
    [.[] | select(.network_id == $network and .name == $name and .connected == true)] | length == 1
  ' "$TMPDIR_SMOKE/local-network-nodes.json" >/dev/null
}

local_platform_network_node_present() {
  local_platform_read_network_nodes "$TMPDIR_SMOKE/local-network-cleanup-nodes.json" || return 2
  jq -e --arg network "$LOCAL_PLATFORM_NETWORK_ID" --arg name "$SMOKE_NAME" '
    any(.[]; .network_id == $network and .name == $name)
  ' "$TMPDIR_SMOKE/local-network-cleanup-nodes.json" >/dev/null
}

local_platform_network_node_absent() {
  local present_rc=0
  local_platform_network_node_present || present_rc=$?
  [[ "$present_rc" == 1 ]]
}

local_platform_wait_network_node_absent() {
  local deadline="$(( $(seconds_now) + 30 ))"
  while (( $(seconds_now) < deadline )); do
    if local_platform_network_node_absent; then return 0; fi
    sleep 1
  done
  return 1
}

local_platform_network_prove() {
  [[ -n "$LOCAL_PLATFORM_NETWORK_ID" ]] || return 0
  wait_until 'owned local Dev Mesh membership' "$(( $(seconds_now) + 60 ))" local_platform_network_member
  log 'selected-network membership proved; no remote transport path is claimed'
}

local_platform_set_network_args() {
  LP_NETWORK_ARGS=(--no-network)
  if [[ -n "$LOCAL_PLATFORM_NETWORK_ID" ]]; then
    LP_NETWORK_ARGS=(--network "$LOCAL_PLATFORM_NETWORK_ID")
  fi
}

local_platform_bind_network_attempt() {
  [[ -n "$LOCAL_PLATFORM_NETWORK_ID" ]] || return 0
  # Validation has proved this exact node name absent. Any later appearance is
  # owned by this create attempt, including a partial enrollment on failure.
  LP_NETWORK_NODE_OWNED=1
}

local_platform_cw() {
  local duration="$1"; shift
  (
    cd "$LP_WORKSPACE"
    env -i "${LP_ENV[@]}" timeout --foreground --kill-after=5s "$duration" \
      "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"
  )
}

local_platform_binding() {
  local project="$1" previous="$2"
  cw_with_timeout 30 env info --local "$SMOKE_NAME" --output json \
    >"$TMPDIR_SMOKE/local-environment.json" 2>"$TMPDIR_SMOKE/local-info.err" || return 1
  jq -e --arg id "$ENV_ID" --arg project "$project" \
    --arg profile "platform:id:$PROVIDER_SSH_PROFILE_ID" --arg reference "user/$PROVIDER_SSH_PROFILE_NAME" \
    --arg server "$CODEWIRE_SERVER_URL" --arg org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" \
    --arg user "$LP_USER_ID" --argjson previous "$previous" '
    .id == $id and .backend == "cloud-hypervisor" and .state == "running" and
    .cpu == 2 and .memory == "16Gi" and .generation == ($previous + 1) and
    .source_selection.credentials == {profile:$profile,reference:$reference,revision:1} and
    (.source_selection.secrets.project // "") == $project and
    (.source_selection.secrets.user // null) == null and
    (.source_selection.secrets.organization // false) == false and
    .source_selection.platform == {server_url:$server,organization_id:$org,user_id:$user}
  ' "$TMPDIR_SMOKE/local-environment.json" >/dev/null
}

local_platform_guest_check() {
  local expected="$1"
  # Only a synthetic digest enters argv or saved setup intent, never its value.
  cat <<SCRIPT
set -eu
test "\$CW_DEV_PRECEDENCE" = ordinary-config
test "\$(cat /workspace/.cw-app-smoke/install-count)" = 1
test "\$(cat /workspace/.cw-app-smoke/preserved)" = workspace-preserved
if test '$expected' = absent; then test "\${DATABASE_URL+x}" != x; else
  test "\$(printf %s "\$DATABASE_URL" | sha256sum | cut -d ' ' -f 1)" = '$expected'
fi
attempt=0
while test "\$(cat /workspace/.cw-app-smoke/startup-sha 2>/dev/null || true)" != '$expected'; do
  attempt=\$((attempt + 1)); test "\$attempt" -lt 100; sleep 0.1
done
python3 - <<'PY'
import json
from pathlib import Path
root = Path('/home/codewire/.codewire')
# The pinned native workspace passes ordinary values directly to its launcher;
# unlike platform placement it never persists an environment.json file.
assert not (root / 'environment.json').exists()
sessions = list((root / 'daemon' / 'sessions').glob('*/session.json'))
assert sessions, 'managed session metadata is missing'
for path in sessions:
    session = json.loads(path.read_text())
    assert all(value.split('=', 1)[0] not in ('DATABASE_URL', 'CW_DEV_PRECEDENCE') for value in session['env'])
PY
printf 'application-secret-check-ok\\n'
SCRIPT
}

local_platform_application_phase() {
  local phase="$1" project="$2" expected="$3" guest command receipt
  local_platform_binding "$project" "$LP_GENERATION" || die 'local VM source/profile/authority binding drifted'
  LP_GENERATION="$(jq -er .generation "$TMPDIR_SMOKE/local-environment.json")"
  guest="$(local_platform_guest_check "$expected")"
  cw_with_timeout 60 run --no-tty -- /bin/sh -c "$guest" \
    >"$TMPDIR_SMOKE/local-app-$phase.out" 2>"$TMPDIR_SMOKE/local-app-$phase.err" ||
    die 'platform application projection failed in the local VM'
  grep -qx application-secret-check-ok "$TMPDIR_SMOKE/local-app-$phase.out" || die 'local application receipt is missing'
  # cw needs terminal stdin to read its initial size. Redirect cw's stdout
  # inside that host PTY so attach is noninteractive and propagates the guest
  # exit status, rather than waiting for the interactive detach chord.
  printf -v command '%q ' "$CW_BIN" --server "$CODEWIRE_SERVER_URL" run --tty -- \
    /bin/sh -c "set -eu; test -t 0; test -t 1; $guest"
  printf -v receipt '%q' "$TMPDIR_SMOKE/local-pty-$phase.log"
  command+=" >$receipt"
  if ! (
    cd "$LP_WORKSPACE"
    env -i "${LP_ENV[@]}" timeout --foreground --kill-after=5s 60 \
      script -qefc "$command" /dev/null </dev/null
  ) >"$TMPDIR_SMOKE/local-pty-$phase.out" 2>"$TMPDIR_SMOKE/local-pty-$phase.err"; then
    die 'platform application projection failed in a local PTY'
  fi
  grep -Eq $'^application-secret-check-ok\r?$' "$TMPDIR_SMOKE/local-pty-$phase.log" ||
    die 'local PTY application receipt is missing'
}

local_platform_ssh_prove() {
  cw_with_timeout 30 run --no-tty -- /bin/bash "$PROVIDER_SSH_SCRIPT" public-host-key \
    >"$TMPDIR_SMOKE/local-host-key" 2>"$TMPDIR_SMOKE/local-host-key.err" || die 'cannot obtain local fixture host trust'
  local host_key
  host_key="$(cat "$TMPDIR_SMOKE/local-host-key")"
  [[ "$host_key" =~ ^\[127\.0\.0\.1\]:22222\ ssh-ed25519\ [A-Za-z0-9+/]+={0,2}$ ]] || die 'invalid fixture host trust'
  cw_with_timeout 120 run --no-tty -- /bin/bash "$PROVIDER_SSH_SCRIPT" prove "$host_key" \
    >"$TMPDIR_SMOKE/local-ssh.out" 2>"$TMPDIR_SMOKE/local-ssh.err" || die 'local VM platform-backed stock SSH proof failed'
  grep -qx stock-ssh-workload-proved "$TMPDIR_SMOKE/local-ssh.out" || die 'stock SSH receipt is missing'
}

local_platform_ssh_revoke() {
  local host_key session_id
  host_key="$(cat "$TMPDIR_SMOKE/local-host-key")"
  cw_with_timeout 30 run --no-tty --detach --output json -- \
    /bin/bash "$PROVIDER_SSH_SCRIPT" wait-revoked "$host_key" >"$TMPDIR_SMOKE/local-waiter.json" ||
    die 'cannot admit the local revocation probe'
  session_id="$(jq -er 'select(.state == "Running") | .session_id | select(type == "string" and length > 0)' \
    "$TMPDIR_SMOKE/local-waiter.json")" || die 'local revocation probe was not acknowledged'
  wait_until 'local revocation probe ready' "$(( $(seconds_now) + 30 ))" provider_ssh_waiter_ready "$session_id"
  cw_with_timeout 30 credentials --platform revoke "id:$PROVIDER_SSH_CREDENTIAL_ID" --output json \
    >"$TMPDIR_SMOKE/local-revoked.json" || die 'cannot revoke the owned platform SSH identity'
  jq -e --arg id "$PROVIDER_SSH_CREDENTIAL_ID" 'length == 1 and .[0].id == $id and
    .[0].status == "CREDENTIAL_STATUS_REVOKED" and .[0].revocationGeneration == "2"' \
    "$TMPDIR_SMOKE/local-revoked.json" >/dev/null || die 'platform revocation acknowledgement drifted'
  printf 'revoked\n' >"$TMPDIR_SMOKE/local-revoked-trigger"
  cw_with_timeout 30 env cp --local "$TMPDIR_SMOKE/local-revoked-trigger" \
    "$SMOKE_NAME:/workspace/.cw-ssh-smoke/revoked-trigger" >"$TMPDIR_SMOKE/local-trigger.out" ||
    die 'cannot signal the admitted local workload'
  wait_until 'local fresh SSH denial' "$(( $(seconds_now) + 30 ))" provider_ssh_waiter_complete "$session_id"
  cw_with_timeout 30 logs "$ENV_ID" "$session_id" --raw >"$TMPDIR_SMOKE/local-denial.out" || die 'cannot read local denial receipt'
  grep -qx stock-ssh-workload-revoked "$TMPDIR_SMOKE/local-denial.out" || die 'local fresh signing denial was not proved'
  if cw_with_timeout 30 run --no-tty -- /bin/true >"$TMPDIR_SMOKE/local-denied-launch.out" \
      2>"$TMPDIR_SMOKE/local-denied-launch.err"; then
    die 'revoked platform profile permitted a new local launch'
  fi
  [[ ! -s "$TMPDIR_SMOKE/local-denied-launch.out" &&
    "$(tail -n 1 "$TMPDIR_SMOKE/local-denied-launch.err")" == \
      'session reached terminal state Failed without an exit code: environment launch denied or expired' ]] ||
    die 'new local launch failed for an unrelated reason'
}

local_platform_stop_owners() {
  # pidfds bind signals to the observed process, not a possibly recycled PID.
  # Only exact supervisor/authority argv may be signalled. Unexpected leftover
  # VMM/runner processes fail cleanup and retain their state for diagnosis.
  python3 - "$CW_BIN" "$LP_HOME" "$LP_RUNTIME" "$LOCAL_PLATFORM_ARTIFACT_ROOT" \
    "$LOCAL_PLATFORM_ARTIFACT_LOCK" "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" <<'PY'
import os
from pathlib import Path
import select
import signal
import sys

binary, home, runtime, artifacts, lock, config = sys.argv[1:]
assert home and runtime
expected = [
    ['__native-supervisor', '--root', home + '/.codewire/native-v1',
     '--artifact-root', artifacts, '--artifact-lock', lock, '--mesh-data-dir', home + '/.codewire',
     '--platform-config-dir', config, '--credential-authority-root', home + '/.codewire/credentials-v1'],
    ['__local-credential-authority', '--root', home + '/.codewire/credentials-v1'],
]
failed = False
def retire(proc):
    global failed
    descriptor = None
    try:
        descriptor = os.pidfd_open(int(proc.name))
        argv = (proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        if (proc.stat().st_uid != os.getuid() or os.readlink(proc / 'exe') != binary or
                [os.fsdecode(arg) for arg in argv[1:]] not in expected):
            return False
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        if not poller.poll(10000):
            failed = True
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            if not poller.poll(5000):
                failed = True
        return True
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
for proc in Path('/proc').iterdir():
    if proc.name.isdecimal():
        retire(proc)
# A supervisor shutting down may have started its authority after the first
# enumeration. Retire that exact late owner too, but record an unclean shutdown.
for proc in Path('/proc').iterdir():
    if proc.name.isdecimal() and retire(proc):
        failed = True
for proc in Path('/proc').iterdir():
    if not proc.name.isdecimal() or int(proc.name) == os.getpid():
        continue
    try:
        argv = (proc / 'cmdline').read_bytes().split(b'\0')
        if any(arg.startswith(os.fsencode(root)) for arg in argv for root in (home, runtime)):
            failed = True
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        continue
sys.exit(1 if failed else 0)
PY
}

local_platform_cleanup() {
  local rc=$? cleanup_rc=0 resolved=''
  trap - EXIT INT TERM HUP
  if [[ "$LP_CREATE_ATTEMPTED" == 1 ]]; then
    if cw_with_timeout 30 env list --local --output json >"$TMPDIR_SMOKE/local-cleanup-environments.json" 2>/dev/null &&
        jq -e 'type == "array"' "$TMPDIR_SMOKE/local-cleanup-environments.json" >/dev/null; then
      if jq -e --arg name "$SMOKE_NAME" 'any(.[]; .name == $name)' "$TMPDIR_SMOKE/local-cleanup-environments.json" >/dev/null; then
        resolved="$(provider_ssh_metadata_id "$TMPDIR_SMOKE/local-cleanup-environments.json" "$SMOKE_NAME")" || rc=1
        if [[ -n "$resolved" && ( -z "$ENV_ID" || "$ENV_ID" == "$resolved" ) ]]; then
          cw_with_timeout 180 env rm --local --yes "$resolved" >"$TMPDIR_SMOKE/local-cleanup.out" 2>&1 || rc=1
        else rc=1; fi
      fi
      cw_with_timeout 30 env list --local --output json >"$TMPDIR_SMOKE/local-cleanup-environments.json" 2>/dev/null &&
        jq -e --arg name "$SMOKE_NAME" --arg id "$ENV_ID" 'type == "array" and all(.[]; .name != $name and .id != $id)' \
          "$TMPDIR_SMOKE/local-cleanup-environments.json" >/dev/null || rc=1
    else rc=1; fi
  fi
  if [[ "$LP_NETWORK_NODE_OWNED" == 1 ]]; then
    local network_node_rc=0
    local_platform_network_node_present || network_node_rc=$?
    if [[ "$network_node_rc" == 0 ]]; then
      if ! cw_with_timeout 30 network revoke --network "$LOCAL_PLATFORM_NETWORK_ID" \
        --org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" "$SMOKE_NAME" \
        >"$TMPDIR_SMOKE/local-network-revoke.out" 2>"$TMPDIR_SMOKE/local-network-revoke.err"; then
        rc=1
      else
        local_platform_wait_network_node_absent || rc=1
      fi
    elif [[ "$network_node_rc" != 1 ]]; then
      rc=1
    fi
  fi
  cleanup_provider_ssh_profile || rc=1
  cleanup_provider_ssh_credential || rc=1
  # Only project cleanup is reused: this entrypoint never created a platform VM.
  ( ENV_ID=''; cleanup_application_secrets ) || rc=1
  local_platform_stop_owners || { rc=1; cleanup_rc=1; }
  if [[ "$LP_LOGIN_ATTEMPTED" == 1 ]]; then
    cw_with_timeout 30 logout >"$TMPDIR_SMOKE/local-logout.out" 2>"$TMPDIR_SMOKE/local-logout.err" || rc=1
    # Auth files are not diagnostic evidence, even if VM cleanup failed.
    if [[ "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" == "$LP_RUNTIME/login" &&
          -d "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" && ! -L "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" ]]; then
      rm -rf -- "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR"
    else rc=1; fi
  fi
  if [[ -n "$LP_RUNTIME" ]]; then
    if [[ "$cleanup_rc" == 0 && "$LP_RUNTIME" == */.cwlp-?????? && -d "$LP_RUNTIME" && ! -L "$LP_RUNTIME" &&
          "$(stat -c %u "$LP_RUNTIME")" == "$(id -u)" ]]; then
      rm -rf -- "$LP_RUNTIME"
    else
      rc=1
      log "retained private local runtime for failed cleanup: $LP_RUNTIME"
    fi
  fi
  if [[ "$rc" == 0 ]]; then
    assert_application_artifacts_redacted "$TMPDIR_SMOKE"/*.json "$TMPDIR_SMOKE"/*.out "$TMPDIR_SMOKE"/*.err \
      "$TMPDIR_SMOKE"/local-pty-*.log || rc=1
  fi
  if [[ "$rc" == 0 ]]; then
    [[ "$LP_HOME" == "$TMPDIR_SMOKE/native-home" && -d "$LP_HOME" && ! -L "$LP_HOME" &&
      "$(stat -c %u "$LP_HOME")" == "$(id -u)" ]] || exit 1
    rm -rf -- "$LP_HOME"
    log 'PASS: local Linux VM with actual Dev application sources and platform SSH, transitions and cleanup'
  else
    log "local/platform smoke incomplete; private evidence retained at $TMPDIR_SMOKE"
  fi
  exit "$rc"
}

main() {
  local parse_rc=0
  local_platform_parse "$@" || parse_rc=$?
  [[ "$parse_rc" != 2 ]] || return 0
  local command runtime_parent="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  for command in jq sha256sum script findmnt realpath timeout python3; do require_cmd "$command"; done
  validate_local_platform_options
  [[ "$(uname -s)" == Linux && "$(id -u)" != 0 && -r /dev/kvm && -w /dev/kvm ]] || die 'Linux owner KVM access is required'
  [[ "$(realpath -e -- "$runtime_parent")" == "$runtime_parent" &&
     "$(stat -c '%u:%a' "$runtime_parent")" == "$(id -u):700" &&
     "$(findmnt -nro FSTYPE -T "$runtime_parent")" == tmpfs ]] || die 'private tmpfs XDG runtime parent is required'
  mkdir -p "$SMOKE_TMP_PARENT"
  TMPDIR_SMOKE="$(mktemp -d "$SMOKE_TMP_PARENT/codewire-runtime-smoke.XXXXXX")"
  LP_HOME="$TMPDIR_SMOKE/native-home"; LP_WORKSPACE="$LP_HOME/workspace"
  mkdir -m 700 "$LP_HOME" "$LP_WORKSPACE"
  LP_RUNTIME="$(mktemp -d "$runtime_parent/.cwlp-XXXXXX")"
  CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$LP_RUNTIME/login"
  mkdir -m 700 "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR"
  LP_ENV=(PATH=/usr/bin:/bin "HOME=$LP_HOME" "USER=$(id -un)" "LOGNAME=$(id -un)"
    SHELL=/bin/bash TERM=xterm-256color LC_ALL=C "CW_CONFIG_DIR=$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR"
    "CODEWIRE_NATIVE_STATE_ROOT=$LP_HOME/.codewire/native-v1"
    "CODEWIRE_LOCAL_CREDENTIAL_ROOT=$LP_HOME/.codewire/credentials-v1"
    "CODEWIRE_NATIVE_ARTIFACT_ROOT=$LOCAL_PLATFORM_ARTIFACT_ROOT" "CODEWIRE_NATIVE_ARTIFACT_LOCK=$LOCAL_PLATFORM_ARTIFACT_LOCK"
    "XDG_RUNTIME_DIR=$LP_RUNTIME" "DBUS_SESSION_BUS_ADDRESS=unix:path=$LP_RUNTIME/no-owner-bus")
  cw() { local_platform_cw 180 "$@"; }
  cw_with_timeout() { local_platform_cw "$@"; }
  trap local_platform_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  # Even identity checks use the isolated HOME and explicit config; never call
  # the ambient prepare_cli wrapper before isolation has been established.
  LP_LOGIN_ATTEMPTED=1
  cw_with_timeout 600 login --org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" || die 'fresh owner-operated Dev login failed'
  validate_admin_oauth_config "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR"
  assert_admin_oauth_principal
  LP_USER_ID="$(jq -er .id "$TMPDIR_SMOKE/admin-whoami.json")"
  [[ "$(awk '$1 == "ID:" {print $2}' "$TMPDIR_SMOKE/admin-current-organization.out")" == "$EXPECTED_CODEWIRE_ORGANIZATION_ID" ]] ||
    die 'fresh OAuth login selected a different organization'
  [[ "$(awk '$1 == "Role:" {print $2}' "$TMPDIR_SMOKE/admin-current-organization.out")" == owner ]] ||
    die 'fresh OAuth login must own the selected disposable-test organization'
  local_platform_journey
}

local_platform_journey() {
  SMOKE_NAME="local-platform-$(tr -d '-' </proc/sys/kernel/random/uuid)"
  cw_with_timeout 30 env list --local --output json >"$TMPDIR_SMOKE/local-before.json"
  jq -e --arg name "$SMOKE_NAME" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/local-before.json" >/dev/null || die 'local environment name collision'
  local_platform_validate_network
  prepare_provider_ssh
  prepare_application_secrets
  jq --slurpfile provider "$PROVIDER_SSH_DOCUMENT" --arg image "$LOCAL_PLATFORM_IMAGE" '
    .image=$image | .credentials=$provider[0].credentials |
    .install_command += "; " + $provider[0].install_command |
    .startup_script += "; " + $provider[0].startup_script
  ' "$APP_SECRET_DOCUMENT" >"$LP_WORKSPACE/codewire.yaml"
  LP_CREATE_ATTEMPTED=1
  local -a LP_NETWORK_ARGS=()
  local_platform_set_network_args
  local_platform_bind_network_attempt
  cw_with_timeout 1500 env create --local --name "$SMOKE_NAME" --cpu 2 --memory 16GB --no-docker "${LP_NETWORK_ARGS[@]}" \
    --path "$LP_WORKSPACE" --path-mode copy --file codewire.yaml --yes --output json \
    >"$TMPDIR_SMOKE/local-create.json" 2>"$TMPDIR_SMOKE/local-create.err" || die 'local VM with platform sources failed to start'
  ENV_ID="$(jq -er '.id | select(. != "00000000-0000-0000-0000-000000000000" and
    test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))' "$TMPDIR_SMOKE/local-create.json")"
  cw_with_timeout 30 use --local "$ENV_ID" >"$TMPDIR_SMOKE/local-use.out"
  local_platform_network_prove
  local_platform_application_phase a "platform:id:${APP_SECRET_IDS[0]}" "${APP_SECRET_HASHES[0]}"
  local_platform_ssh_prove
  cw_with_timeout 300 env update --local "$ENV_ID" --secrets "platform:id:${APP_SECRET_IDS[1]}" --yes --output json \
    >"$TMPDIR_SMOKE/local-update.json" 2>"$TMPDIR_SMOKE/local-update.err" || die 'platform source replacement in the local VM failed'
  local_platform_application_phase b "platform:id:${APP_SECRET_IDS[1]}" "${APP_SECRET_HASHES[1]}"
  cw_with_timeout 300 env update --local "$ENV_ID" --clear-secrets --yes --output json \
    >"$TMPDIR_SMOKE/local-clear.json" 2>"$TMPDIR_SMOKE/local-clear.err" || die 'local platform-source clear failed'
  local_platform_application_phase clear '' absent
  local_platform_ssh_prove
  local_platform_ssh_revoke
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
