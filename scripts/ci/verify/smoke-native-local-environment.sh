#!/usr/bin/env bash
# Qualified-host product proof for the Linux native local environment. The
# caller supplies an exact built cw binary and already-staged immutable VMM
# artifacts; this script never downloads artifacts or selects a fallback VMM.
set -euo pipefail

readonly LINUX_SUN_PATH_BYTES=108
readonly LONGEST_SOCKET_SUFFIX='/engine/vms/00000000-0000-4000-8000-000000000000/vsock/vsock.sock'
# PrivateProviderHome plus the selected SSH agent's fixed socket name.
readonly SSH_AGENT_SOCKET_SUFFIX='/.codewire-provider-login-00000000-0000-4000-8000-000000000000/a'
SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
SOURCE_ROOT="$(cd -- "$SCRIPT_DIRECTORY/../../.." && pwd -P)"
readonly SOURCE_ROOT
readonly STOCK_SSH_WORKLOAD_SOURCE="$SCRIPT_DIRECTORY/stock-ssh-workload.sh"

CW_BIN=''
MESH_BIN=''
DERP_BIN=''
DATA_PLANE_SMOKE_BIN=''
CREDENTIAL_BRIDGE_SMOKE_BIN=''
STATE_PROBE_BIN=''
WORKSPACE_IMAGE_IMPORT_BIN=''
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
MOUNT_SOURCE=''
DIRECT_RO_SOURCE=''
DIRECT_RW_SOURCE=''
DIRECT_OUTSIDE_SOURCE=''
REPOSITORY_SKILL_SOURCE=''
DIRECT_SKILL_SOURCE=''
USER_SKILL_SOURCE=''
INITIAL_SKILL_SNAPSHOT=''
PLATFORM_CONFIG=''
TRIPWIRE=''
TRANSCRIPT=''
SOURCE_HOOK_MARKER=''
SOURCE_CREDENTIAL_MARKER=''
SOURCE_CONFIG_SHA256=''
HOST_PORT=''
MESH_PORT=''
DERP_PORT=''
DOCKER_HOST_PORT=''
MESH_NETWORK='native-smoke-network'
MESH_ORGANIZATION_ID=''
GITEA_COMMIT='bcbae548ab2f4f0e407068aa8717cec341084d7a'
GITEA_README_SHA256='d4911db7bc817528fbcbaaf39e76851700084b65494dac1e29afb997867ac006'
GITHUB_COMMIT='93f68ba4abc9f6e222481265b9b759e71d332575'
GITHUB_README_SHA256='3661bce99f8eba5e48077eeddb4840f4404c1ceafbf200b9e8470bc7b4f22e50'
WORKSPACE_IMAGE='ghcr.io/codewiresh/workspace@sha256:fa5d2fa61bb03b0e9181915b57ce5f2f8fa053eec8b7c6a950ecaadf93bc3645'
DOCKER_PUBLIC_IMAGE='ghcr.io/stargz-containers/alpine@sha256:237e28761b771d41d0b841bacfe39f4a49d30b1c8dfecc90aef09b68d86ebc99'
SCRATCH_MOUNT_OPTIONS=''
NAME='native-smoke'
COMMAND_INDEX=0
LAST_STDOUT=''
LAST_STDERR=''
ENV_CREATED=0
MESH_STARTED=0
ALLOW_REGISTRY_EGRESS=0
CW_COMMAND_TIMEOUT_SECONDS=180
MANAGED_CREDENTIAL_BROKER=0
MANAGED_AGENT_SESSIONS=0
MANAGED_AGENT_CW_IMAGE_RECEIPT=''
MANAGED_AGENT_CW_IMAGE_RECEIPT_SEEN=0
MANAGED_AGENT_UPDATE=0
MANAGED_AGENT_UPDATE_RUNTIME_LOCK=''
MANAGED_AGENT_UPDATE_IMAGE_RECEIPT=''
MANAGED_AGENT_UPDATE_SHA256=''
MANAGED_AGENT_UPDATE_RUNTIME_SEEN=0
MANAGED_AGENT_UPDATE_IMAGE_SEEN=0
MANAGED_AGENT_UPDATE_SHA_SEEN=0
MANAGED_AGENT_UPDATE_A_LOCK=''
MANAGED_AGENT_UPDATE_A_SHA256=''
CREDENTIAL_ROOT=''
CREDENTIAL_PROFILE_NAME='native-broker'
CREDENTIAL_ID=''
CREDENTIAL_CANARY=''
CREDENTIAL_REFRESH_CANARY=''
GITHUB_CREDENTIAL_ID=''
GITHUB_CREDENTIAL_CANARY=''
OPENAI_CREDENTIAL_ID=''
OPENAI_CREDENTIAL_CANARY=''
ANTHROPIC_CREDENTIAL_ID=''
ANTHROPIC_CREDENTIAL_CANARY=''
SSH_CREDENTIAL_ID=''
SSH_PUBLIC_KEY=''
SSH_PUBLIC_KEY_FINGERPRINT=''
WORKLOAD_SECRET_CANARY=''
APP_SECRET_PROJECT_A='native-app-a'
APP_SECRET_PROJECT_B='native-app-b'
APP_SECRET_UNSELECTED_PROJECT='native-app-unselected-canary'
APP_SECRET_PROJECT_A_ID=''
APP_SECRET_PROJECT_B_ID=''
APP_SECRET_CANARY_A=''
APP_SECRET_CANARY_B=''
APP_SECRET_SHA_A=''
APP_SECRET_SHA_B=''
APP_SECRET_USER_ONLY_CANARY=''
APP_SECRET_USER_COLLISION_CANARY=''
APP_SECRET_USER_PRECEDENCE_CANARY=''
APP_SECRET_USER_ONLY_SHA=''
APP_SECRET_USER_COLLISION_SHA=''
KEYRING_ROOT=''
KEYRING_RUNTIME=''
KEYRING_RUNTIME_PARENT=''
KEYRING_CONFIG=''
KEYRING_DATA=''
KEYRING_CONTROL=''
KEYRING_DBUS_ADDRESS=''
KEYRING_DBUS_PID=''
KEYRING_DAEMON_PID=''
CREATE_ACCESS_ARGS=()
CREATE_DOCKER_ARGS=()
DIRECT_SHARE_PIDS=()

usage() {
  cat <<'USAGE' >&2
usage: smoke-native-local-environment.sh \
  --cw-bin ABSOLUTE_PATH \
  --mesh-bin ABSOLUTE_PATH \
  --derp-bin ABSOLUTE_PATH \
  --data-plane-smoke-bin ABSOLUTE_PATH \
  --credential-bridge-smoke-bin ABSOLUTE_PATH \
  --state-probe-bin ABSOLUTE_PATH \
  --artifact-root ABSOLUTE_PRIVATE_DIRECTORY \
  --artifact-lock ABSOLUTE_LOCK_FILE \
  [--managed-credential-broker] \
  [--managed-agent-sessions --managed-agent-cw-image-receipt ABSOLUTE_IMAGE_RECEIPT] \
  [--managed-agent-update-runtime-lock ABSOLUTE_B_LOCK \
   --managed-agent-update-cw-image-receipt ABSOLUTE_B_IMAGE_RECEIPT \
   --managed-agent-update-cw-sha256 B_CW_SHA256] \
  [--workspace-image-import-bin ABSOLUTE_PATH] \
  [--scratch-parent ABSOLUTE_DIRECTORY]

Runs the built cw Linux/KVM native-environment product smoke with 2 vCPUs and
16 GiB of guest memory. The artifact root and lock must already contain the
exact Cloud Hypervisor, virtiofsd, kernel, and product guest-root artifacts
admitted by codewire-local-vmm. Missing KVM, artifacts, or required tools fail
nonzero.

The smoke uses an isolated HOME and short private native state root, poisons
the platform destination, installs Docker/Lima/QEMU tripwires, starts an
isolated standalone Codewire Mesh/DERP pair, and creates disposable mixed
repository/copy-mount and implicit filesystem-copy fixtures. Initial create
permits direct registry and Git egress; every later command receives dead proxy
endpoints. It proves digest-pinned OCI workspace execution, exact
credential-free git.example.invalid/GitHub preparation, independent copy preparation,
create/info, loopback-only host-port publication, bounded daemon diagnostics and
repair, stock Codex 0.157.0 over the synthetic credential bridge, bare run and
shell, PTY behavior, saved output and nonzero status,
cached-runtime restart after the installed artifact lock advances, offline
disk/CPU/memory resize, supervisor crash recovery, Mesh attachment and typed
transport-loss recovery, and journaled exact deletion cleanup.

With --managed-credential-broker, it instead runs the focused protected-store
product proof. That mode requires a specially featured cw binary named exactly
cw-local-credential-broker-smoke, an isolated Secret Service implementation,
and a private tmpfs-backed XDG runtime. It also requires
--workspace-image-import-bin and the exact local image receipt produced by
verify-workspace-image.sh in this clean source tree. The importer verifies and
pins that same OCI artifact in the fresh synthetic supervisor; no image override,
registry publication or live package installation is used. Normal builds cannot
load this synthetic-only input. It enrolls synthetic Codex and GitHub
OAuth identities, OpenAI and Anthropic API keys, and one generated SSH identity
through the public commands;
it never contacts any provider or reads the desktop session keyring or an
ambient provider home.
It also selects synthetic local personal and project application scopes for
install, startup, managed exec, and PTY sessions; replaces and clears them
through confirmed source updates; and proves installed-root, workspace, and
skill preservation.
Application values are intentionally child-visible, unlike provider credentials.

With --managed-agent-sessions and a source-bound readonly cw runtime image receipt,
the same protected-broker environment additionally runs actual pinned guest
Codex and Claude managed conversations before the existing revocation proof.
It requires native acknowledgement, follow-up/resume, held-turn controls,
guest tool execution, same-VM parent continuation, history/wait and cleanup.
This mode retains the exact workspace-image and private credential-store gates.
The three update inputs additionally select the running-VM A-to-B-to-A journey.
They require both managed modes. Host and both asset identities are admitted
before allocating scratch; the same journey repeats admission and preserves
every existing managed-session assertion before revocation and cleanup.
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
    --mesh-bin)
      [[ $# -ge 2 && -z "$MESH_BIN" ]] || { usage; exit 2; }
      MESH_BIN="$2"
      shift 2
      ;;
    --derp-bin)
      [[ $# -ge 2 && -z "$DERP_BIN" ]] || { usage; exit 2; }
      DERP_BIN="$2"
      shift 2
      ;;
    --data-plane-smoke-bin)
      [[ $# -ge 2 && -z "$DATA_PLANE_SMOKE_BIN" ]] || { usage; exit 2; }
      DATA_PLANE_SMOKE_BIN="$2"
      shift 2
      ;;
    --credential-bridge-smoke-bin)
      [[ $# -ge 2 && -z "$CREDENTIAL_BRIDGE_SMOKE_BIN" ]] || { usage; exit 2; }
      CREDENTIAL_BRIDGE_SMOKE_BIN="$2"
      shift 2
      ;;
    --state-probe-bin)
      [[ $# -ge 2 && -z "$STATE_PROBE_BIN" ]] || { usage; exit 2; }
      STATE_PROBE_BIN="$2"
      shift 2
      ;;
    --workspace-image-import-bin)
      [[ $# -ge 2 && -z "$WORKSPACE_IMAGE_IMPORT_BIN" ]] || { usage; exit 2; }
      WORKSPACE_IMAGE_IMPORT_BIN="$2"
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
    --managed-credential-broker)
      [[ "$MANAGED_CREDENTIAL_BROKER" -eq 0 ]] || { usage; exit 2; }
      MANAGED_CREDENTIAL_BROKER=1
      shift
      ;;
    --managed-agent-sessions)
      [[ "$MANAGED_AGENT_SESSIONS" -eq 0 ]] || { usage; exit 2; }
      MANAGED_AGENT_SESSIONS=1
      shift
      ;;
    --managed-agent-cw-image-receipt)
      [[ $# -ge 2 && -n "$2" && "$MANAGED_AGENT_CW_IMAGE_RECEIPT_SEEN" -eq 0 ]] || { usage; exit 2; }
      MANAGED_AGENT_CW_IMAGE_RECEIPT_SEEN=1
      MANAGED_AGENT_CW_IMAGE_RECEIPT="$2"
      shift 2
      ;;
    --managed-agent-update-runtime-lock)
      [[ $# -ge 2 && "$MANAGED_AGENT_UPDATE_RUNTIME_SEEN" -eq 0 ]] || { usage; exit 2; }
      MANAGED_AGENT_UPDATE_RUNTIME_SEEN=1
      MANAGED_AGENT_UPDATE_RUNTIME_LOCK="$2"
      shift 2
      ;;
    --managed-agent-update-cw-image-receipt)
      [[ $# -ge 2 && "$MANAGED_AGENT_UPDATE_IMAGE_SEEN" -eq 0 ]] || { usage; exit 2; }
      MANAGED_AGENT_UPDATE_IMAGE_SEEN=1
      MANAGED_AGENT_UPDATE_IMAGE_RECEIPT="$2"
      shift 2
      ;;
    --managed-agent-update-cw-sha256)
      [[ $# -ge 2 && "$MANAGED_AGENT_UPDATE_SHA_SEEN" -eq 0 ]] || { usage; exit 2; }
      MANAGED_AGENT_UPDATE_SHA_SEEN=1
      MANAGED_AGENT_UPDATE_SHA256="$2"
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

[[ -n "$CW_BIN" && -n "$MESH_BIN" && -n "$DERP_BIN" && -n "$DATA_PLANE_SMOKE_BIN" && -n "$CREDENTIAL_BRIDGE_SMOKE_BIN" && -n "$STATE_PROBE_BIN" && -n "$ARTIFACT_ROOT" && -n "$ARTIFACT_LOCK" ]] || {
  usage
  exit 2
}

if (( MANAGED_AGENT_UPDATE_RUNTIME_SEEN + MANAGED_AGENT_UPDATE_IMAGE_SEEN + MANAGED_AGENT_UPDATE_SHA_SEEN > 0 )); then
  [[ "$MANAGED_AGENT_UPDATE_RUNTIME_SEEN" -eq 1 && "$MANAGED_AGENT_UPDATE_IMAGE_SEEN" -eq 1 &&
     "$MANAGED_AGENT_UPDATE_SHA_SEEN" -eq 1 && -n "$MANAGED_AGENT_UPDATE_RUNTIME_LOCK" &&
     -n "$MANAGED_AGENT_UPDATE_IMAGE_RECEIPT" && "$MANAGED_AGENT_UPDATE_SHA256" =~ ^[0-9a-f]{64}$ &&
     "$MANAGED_CREDENTIAL_BROKER" -eq 1 && "$MANAGED_AGENT_SESSIONS" -eq 1 &&
     -n "$MANAGED_AGENT_CW_IMAGE_RECEIPT" ]] || { usage; exit 2; }
  MANAGED_AGENT_UPDATE=1
fi

for tool in awk base64 cat chmod cp dirname e2fsck find findmnt git id jq ln mkdir mktemp python3 readlink realpath resize2fs rg script sha256sum sleep stat tail timeout touch tr uname; do
  require_cmd "$tool"
done
if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  [[ -n "$WORKSPACE_IMAGE_IMPORT_BIN" ]] || die 'managed smoke requires --workspace-image-import-bin'
  require_absolute_canonical_file 'workspace image importer' "$WORKSPACE_IMAGE_IMPORT_BIN"
  [[ -x "$WORKSPACE_IMAGE_IMPORT_BIN" ]] || die 'workspace image importer is not executable'
  for tool in busctl dbus-daemon gnome-keyring-daemon secret-tool; do
    require_cmd "$tool"
  done
  require_absolute_canonical_file 'stock SSH workload fixture' "$STOCK_SSH_WORKLOAD_SOURCE"
elif [[ -n "$WORKSPACE_IMAGE_IMPORT_BIN" ]]; then
  die 'workspace image importer is only available in managed synthetic mode'
fi
if [[ "$MANAGED_AGENT_SESSIONS" -eq 1 ]]; then
  [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 && -n "$MANAGED_AGENT_CW_IMAGE_RECEIPT" ]] ||
    die 'managed agent sessions require protected-broker mode and a boot cw image receipt'
  require_absolute_canonical_file 'managed cw runtime image receipt' "$MANAGED_AGENT_CW_IMAGE_RECEIPT"
  require_absolute_canonical_file 'managed native journey' "$SOURCE_ROOT/scripts/dev/test-cli-native-managed.py"
elif [[ -n "$MANAGED_AGENT_CW_IMAGE_RECEIPT" ]]; then
  die 'cw runtime image receipt requires --managed-agent-sessions'
fi
[[ "$(uname -s)" == Linux ]] || die 'the native local-environment smoke requires Linux'
[[ "$(uname -m)" == x86_64 ]] || die 'the current native artifact set requires x86_64'
[[ "$(id -u)" != 0 ]] || die 'the native local-environment smoke refuses root'
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || die '/dev/kvm is unavailable or unusable'
[[ -c /dev/vhost-vsock && -r /dev/vhost-vsock && -w /dev/vhost-vsock ]] ||
  die '/dev/vhost-vsock is unavailable or unusable'

require_absolute_canonical_file 'cw binary' "$CW_BIN"
[[ -x "$CW_BIN" ]] || die "cw binary is not executable: $CW_BIN"
require_absolute_canonical_file 'Mesh binary' "$MESH_BIN"
[[ -x "$MESH_BIN" ]] || die "Mesh binary is not executable: $MESH_BIN"
require_absolute_canonical_file 'DERP binary' "$DERP_BIN"
[[ -x "$DERP_BIN" ]] || die "DERP binary is not executable: $DERP_BIN"
if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 && "${CW_BIN##*/}" != cw-local-credential-broker-smoke ]]; then
  die 'managed credential-broker smoke requires cw-local-credential-broker-smoke'
fi
require_absolute_canonical_file 'public data-plane smoke binary' "$DATA_PLANE_SMOKE_BIN"
[[ -x "$DATA_PLANE_SMOKE_BIN" ]] ||
  die "public data-plane smoke binary is not executable: $DATA_PLANE_SMOKE_BIN"
require_absolute_canonical_file 'Codex credential-bridge smoke binary' "$CREDENTIAL_BRIDGE_SMOKE_BIN"
[[ -x "$CREDENTIAL_BRIDGE_SMOKE_BIN" ]] ||
  die "Codex credential-bridge smoke binary is not executable: $CREDENTIAL_BRIDGE_SMOKE_BIN"
require_absolute_canonical_file 'native state probe binary' "$STATE_PROBE_BIN"
[[ -x "$STATE_PROBE_BIN" ]] ||
  die "native state probe binary is not executable: $STATE_PROBE_BIN"
[[ "$CW_BIN" =~ ^[-_./0-9A-Za-z]+$ ]] ||
  die 'cw binary path contains characters unsafe for the PTY smoke command'
require_absolute_canonical_dir 'artifact root' "$ARTIFACT_ROOT"
require_absolute_canonical_file 'artifact lock' "$ARTIFACT_LOCK"
[[ "$(dirname "$ARTIFACT_ROOT")" == "$(dirname "$ARTIFACT_LOCK")" ]] ||
  die 'artifact root and lock must share one staging parent'
[[ "$(stat -c %a -- "$ARTIFACT_LOCK")" == 400 ]] || die 'artifact lock must have mode 0400'
for artifact in cloud_hypervisor virtiofsd kernel initramfs; do
  artifact_path="$(jq -er --arg artifact "$artifact" '.[$artifact].path' "$ARTIFACT_LOCK")" ||
    die "artifact lock has no $artifact path"
  artifact_path="$ARTIFACT_ROOT/$artifact_path"
  require_absolute_canonical_file "$artifact artifact" "$artifact_path"
  [[ "$artifact_path" == "$ARTIFACT_ROOT/"* ]] || die 'artifact escaped its staging root'
  case "$artifact" in cloud_hypervisor|virtiofsd) artifact_mode=500 ;; *) artifact_mode=400 ;; esac
  [[ "$(stat -c %a -- "$artifact_path")" == "$artifact_mode" ]] ||
    die "$artifact artifact must have mode 0$artifact_mode"
done
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

admit_native_managed_update_assets() {
  local admission
  MANAGED_AGENT_UPDATE_A_LOCK="$(dirname -- "$ORIGINAL_ARTIFACT_LOCK")/cw-runtime.lock.json"
  require_absolute_canonical_file 'managed A runtime lock' "$MANAGED_AGENT_UPDATE_A_LOCK"
  require_absolute_canonical_file 'managed B runtime lock' "$MANAGED_AGENT_UPDATE_RUNTIME_LOCK"
  require_absolute_canonical_file 'managed B cw image receipt' "$MANAGED_AGENT_UPDATE_IMAGE_RECEIPT"
  require_absolute_canonical_file 'managed native update journey' "$SOURCE_ROOT/scripts/dev/test-cli-native-update.py"
  if ! admission="$(env -i PATH='/usr/bin:/bin' HOME="$HOME" USER="$(id -un)" LOGNAME="$(id -un)" \
    LC_ALL=C PYTHONDONTWRITEBYTECODE=1 \
    python3 "$SOURCE_ROOT/scripts/dev/test-cli-native-update.py" --admit-only \
      --cw "$CW_BIN" --runtime-a "$MANAGED_AGENT_UPDATE_A_LOCK" \
      --image-a "$MANAGED_AGENT_CW_IMAGE_RECEIPT" \
      --runtime-b "$MANAGED_AGENT_UPDATE_RUNTIME_LOCK" --image-b "$MANAGED_AGENT_UPDATE_IMAGE_RECEIPT" \
      --sha256-b "$MANAGED_AGENT_UPDATE_SHA256")"; then
    die 'native managed update asset admission failed before scratch allocation'
  fi
  jq -e --arg pin "$MANAGED_AGENT_UPDATE_SHA256" '
    .status == "admitted" and .proof == "asset-admission-only" and
    .harness == "scripts/dev/test-cli-native-update.py" and .vm_journey_started == false and
    (.assets.A.identity.sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
    .assets.B.identity.sha256 == $pin
  ' <<<"$admission" >/dev/null || die 'native managed update admission receipt drifted'
  MANAGED_AGENT_UPDATE_A_SHA256="$(jq -er '.assets.A.identity.sha256' <<<"$admission")"
}

if [[ "$MANAGED_AGENT_UPDATE" -eq 1 ]]; then
  admit_native_managed_update_assets
fi

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
CREDENTIAL_ROOT="$SMOKE_HOME/.codewire/credentials-v1"
KEYRING_ROOT="$SMOKE_ROOT/keyring"
KEYRING_CONFIG="$KEYRING_ROOT/config"
KEYRING_DATA="$KEYRING_ROOT/data"
KEYRING_CONTROL="$KEYRING_ROOT/control"
if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  KEYRING_RUNTIME_PARENT="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  require_absolute_canonical_dir 'XDG runtime parent' "$KEYRING_RUNTIME_PARENT"
  [[ "$(stat -c '%u' "$KEYRING_RUNTIME_PARENT")" == "$(id -u)" &&
     "$(stat -c '%a' "$KEYRING_RUNTIME_PARENT")" == 700 ]] ||
    die 'XDG runtime parent must be private and owned by the smoke user'
  [[ "$(findmnt -nro FSTYPE -T "$KEYRING_RUNTIME_PARENT")" == tmpfs ]] ||
    die 'XDG runtime parent must be backed by tmpfs'
  # Leave room for the broker-owned provider home and SSH agent socket. The
  # former descriptive prefix exceeded sockaddr_un even under /run/user/1000.
  KEYRING_RUNTIME_TEMPLATE="$KEYRING_RUNTIME_PARENT/.cwn-XXXXXX"
  (( ${#KEYRING_RUNTIME_TEMPLATE} + ${#SSH_AGENT_SOCKET_SUFFIX} < LINUX_SUN_PATH_BYTES )) ||
    die 'XDG runtime parent is too long for the private SSH agent socket'
  KEYRING_RUNTIME="$(mktemp -d "$KEYRING_RUNTIME_TEMPLATE")"
  chmod 0700 "$KEYRING_RUNTIME"
  KEYRING_RUNTIME="$(realpath -e -- "$KEYRING_RUNTIME")"
  KEYRING_DBUS_ADDRESS="unix:path=$KEYRING_RUNTIME/bus"
fi
mkdir -m 0700 "$SMOKE_HOME" "$STATE_ROOT" "$WORKSPACE" "$PLATFORM_CONFIG" "$SMOKE_ROOT/bin"
if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  workspace_input="$(env -i PATH='/usr/bin:/bin' HOME="$SMOKE_HOME" LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 python3 "$SCRIPT_DIRECTORY/workspace-image-artifact.py" \
    native-input "$SOURCE_ROOT" "$SOURCE_ROOT/.tmp/codewire-workspace-image-verification.json")" ||
    die 'no matching verified workspace OCI artifact; run verify-workspace-image.sh first'
  workspace_archive="$(jq -er '.path' <<<"$workspace_input")"
  workspace_archive_sha="$(jq -er '.sha256' <<<"$workspace_input")"
  workspace_archive_size="$(jq -er '.size' <<<"$workspace_input")"
  workspace_source_digest="$(jq -er '.source_digest' <<<"$workspace_input")"
  imported_image="$(env -i PATH='/usr/bin:/bin' HOME="$SMOKE_HOME" LC_ALL=C \
    "$WORKSPACE_IMAGE_IMPORT_BIN" --archive "$workspace_archive" \
    --archive-sha256 "$workspace_archive_sha" --archive-size "$workspace_archive_size" \
    --source-digest "$workspace_source_digest" --state-root "$STATE_ROOT")" ||
    die 'verified workspace OCI import failed'
  [[ "$imported_image" == "registry.invalid/codewire/workspace@$workspace_source_digest" ]] ||
    die 'workspace OCI importer returned a different image identity'
  WORKSPACE_IMAGE="$imported_image"
  log "using the exact locally verified workspace OCI artifact: $workspace_source_digest"
fi
touch "$TRANSCRIPT"
chmod 0600 "$TRANSCRIPT"

(( ${#STATE_ROOT} + ${#LONGEST_SOCKET_SUFFIX} < LINUX_SUN_PATH_BYTES )) ||
  die 'scratch parent is too long for native VMM Unix sockets'

printf 'this is deliberately invalid platform JSON\n' >"$PLATFORM_CONFIG/config.json"
chmod 0600 "$PLATFORM_CONFIG/config.json"
mkdir -m 0700 "$SMOKE_HOME/.codewire"

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
mapfile -t LOCAL_PORTS < <(
  /usr/bin/env python3 - <<'PY'
import os
import socket

lower = 20_000
upper = 29_999
span = upper - lower + 1
start = lower + (os.getpid() % span)
listeners = []
for offset in range(span):
    port = lower + ((start - lower + offset) % span)
    listener = None
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", port))
    except OSError:
        if listener is not None:
            listener.close()
        continue
    listeners.append(listener)
    if len(listeners) == 4:
        break
if len(listeners) != 4:
    raise SystemExit("fewer than four loopback ports are free in the native smoke range")
for listener in listeners:
    print(listener.getsockname()[1])
PY
)
[[ ${#LOCAL_PORTS[@]} -eq 4 ]] || die 'failed to select four loopback smoke ports'
HOST_PORT="${LOCAL_PORTS[0]}"
MESH_PORT="${LOCAL_PORTS[1]}"
DERP_PORT="${LOCAL_PORTS[2]}"
DOCKER_HOST_PORT="${LOCAL_PORTS[3]}"
for port in "$HOST_PORT" "$MESH_PORT" "$DERP_PORT" "$DOCKER_HOST_PORT"; do
  [[ "$port" =~ ^[0-9]+$ ]] || die 'failed to select a loopback smoke port'
done
MOUNT_SOURCE="$SMOKE_ROOT/m"
mkdir -m 0700 "$MOUNT_SOURCE" "$MOUNT_SOURCE/nested"
printf 'copy mount before creation\n' >"$MOUNT_SOURCE/data.txt"
printf 'hidden copy mount content\n' >"$MOUNT_SOURCE/.hidden"
printf 'nested copy mount content\n' >"$MOUNT_SOURCE/nested/file.txt"
printf '#!/bin/sh\nprintf "copy-mount-executable-ok\\n"\n' >"$MOUNT_SOURCE/tool.sh"
chmod 0755 "$MOUNT_SOURCE/tool.sh"
cat >"$MOUNT_SOURCE/docker-smoke.sh" <<'DOCKER_SMOKE'
#!/bin/sh
set -eu

host_port="$1"
public_image="$2"
root=/workspace/docker-smoke
context="$root/context"
rm -rf -- "$root"
mkdir -p "$context"
cp /run/codewire-runtime/init "$context/init"
chmod 0755 "$context/init"
cat >"$context/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY init /init
ENTRYPOINT ["/init", "docker-fixture"]
DOCKERFILE
cat >"$root/compose.yaml" <<'COMPOSE'
services:
  fixture:
    image: codewire-native-smoke:1913
COMPOSE

test -S /var/run/docker.sock
test "$(stat -Lc '%u:%g:%a' /var/run/docker.sock)" = "0:$(id -g):660"
test ! -S /run/containerd/containerd.sock
test "$(docker info --format '{{.DockerRootDir}}|{{.Driver}}')" = '/var/lib/docker|overlay2'
docker version >/dev/null
docker compose version >/dev/null
docker build --network=none --quiet -t codewire-native-smoke:1913 "$context" >/dev/null
test "$(docker run --rm codewire-native-smoke:1913 emit docker-run-ok)" = docker-run-ok
test "$(docker run --rm --privileged -v /:/host:ro codewire-native-smoke:1913 assert-boundary)" = docker-privileged-boundary-ok
test "$(docker compose -p codewire-native-smoke -f "$root/compose.yaml" run --rm fixture emit docker-compose-ok)" = docker-compose-ok
docker volume create codewire-native-smoke-volume >/dev/null
docker run --rm -v codewire-native-smoke-volume:/data codewire-native-smoke:1913 \
  write-volume generation-one
docker run -d --name codewire-native-smoke-port -p "${host_port}:8080" \
  codewire-native-smoke:1913 serve 8080 >/dev/null
for attempt in $(seq 1 100); do
  if response="$(curl -fsS "http://127.0.0.1:${host_port}/")" &&
     test "$response" = docker-port-local; then
    break
  fi
  test "$attempt" -lt 100 || exit 91
  sleep 0.05
done
docker pull "$public_image" >/dev/null
docker image inspect "$public_image" >/dev/null
docker image rm "$public_image" >/dev/null
if docker pull ghcr.io/codewiresh/private-native-docker-smoke:1913 \
  >"$root/private-pull.stdout" 2>"$root/private-pull.stderr"; then
  exit 92
fi
test -s "$root/private-pull.stderr"
rm -f "$root/private-pull.stdout" "$root/private-pull.stderr"
mkdir -p "$HOME/.docker"
chmod 0700 "$HOME/.docker"
auth="$(printf '%s' 'synthetic-user:synthetic-token' | base64 | tr -d '\n')"
printf '{"auths":{"registry.invalid":{"auth":"%s"}}}\n' "$auth" >"$HOME/.docker/config.json"
chmod 0600 "$HOME/.docker/config.json"
unset auth
printf '%s\n' docker-build-run-compose-ok docker-public-private-policy-ok \
  docker-user-auth-visible-ok docker-vm-port-local-ok docker-privileged-boundary-ok
DOCKER_SMOKE
chmod 0755 "$MOUNT_SOURCE/docker-smoke.sh"
ln "$MOUNT_SOURCE/data.txt" "$MOUNT_SOURCE/hardlink.txt"
ln -s nested/file.txt "$MOUNT_SOURCE/link.txt"
REPOSITORY_SKILL_SOURCE="$MOUNT_SOURCE/.agents/skills/repo-smoke"
USER_SKILL_SOURCE="$SMOKE_HOME/.codewire/skills/user-smoke"
mkdir -p "$REPOSITORY_SKILL_SOURCE/scripts" "$USER_SKILL_SOURCE"
chmod 0700 \
  "$MOUNT_SOURCE/.agents" "$MOUNT_SOURCE/.agents/skills" "$REPOSITORY_SKILL_SOURCE" \
  "$REPOSITORY_SKILL_SOURCE/scripts" \
  "$SMOKE_HOME/.codewire/skills" "$USER_SKILL_SOURCE"
printf '%s\n' 'repository skill generation one' >"$REPOSITORY_SKILL_SOURCE/SKILL.md"
printf '#!/bin/sh\nprintf "skill-executable-ok\\n"\n' >"$REPOSITORY_SKILL_SOURCE/scripts/verify.sh"
chmod 0755 "$REPOSITORY_SKILL_SOURCE/scripts/verify.sh"
printf '%s\n' 'user skill generation one' >"$USER_SKILL_SOURCE/SKILL.md"
DIRECT_RO_SOURCE="$SMOKE_ROOT/direct-ro"
DIRECT_RW_SOURCE="$SMOKE_ROOT/direct-rw"
DIRECT_OUTSIDE_SOURCE="$SMOKE_ROOT/direct-outside"
mkdir -m 0700 "$DIRECT_RO_SOURCE" "$DIRECT_RW_SOURCE" "$DIRECT_OUTSIDE_SOURCE"
printf 'direct read-only before creation\n' >"$DIRECT_RO_SOURCE/data.txt"
printf 'direct read-write before creation\n' >"$DIRECT_RW_SOURCE/data.txt"
printf 'direct outside must remain isolated\n' >"$DIRECT_OUTSIDE_SOURCE/data.txt"
ln -s "$DIRECT_OUTSIDE_SOURCE/data.txt" "$DIRECT_RO_SOURCE/outside.txt"
ln -s "$DIRECT_OUTSIDE_SOURCE/data.txt" "$DIRECT_RW_SOURCE/outside.txt"
DIRECT_SKILL_SOURCE="$DIRECT_RO_SOURCE/.agents/skills/direct-smoke"
mkdir -p "$DIRECT_SKILL_SOURCE"
chmod 0700 "$DIRECT_RO_SOURCE/.agents" "$DIRECT_RO_SOURCE/.agents/skills" "$DIRECT_SKILL_SOURCE"
printf '%s\n' 'direct skill generation one' >"$DIRECT_SKILL_SOURCE/SKILL.md"
cat >"$WORKSPACE/codewire.yaml" <<EOF
version: 1
image: $WORKSPACE_IMAGE
repositories:
  - source: https://git.example.invalid/supplychain.git
    revision: $GITEA_COMMIT
    destination: /workspace/gitea
  - source: https://github.com/noeljackson/method.git
    revision: $GITHUB_COMMIT
    destination: /workspace/github
mounts:
  - source: ../m
    destination: /workspace/fixtures
    mode: copy
  - source: ../direct-ro
    destination: /workspace/direct-ro
    mode: direct
    read_only: true
  - source: ../direct-rw
    destination: /workspace/direct-rw
    mode: direct
    read_only: false
working_directory: /workspace/github
agents:
  tools: [codex, claude-code]
skills:
  - source: repository
    path: fixtures/.agents/skills/repo-smoke
    agents: [codex, claude-code]
  - source: repository
    path: direct-ro/.agents/skills/direct-smoke
    agents: [codex]
  - source: user
    name: user-smoke
    agents: [codex]
ports:
  - host_port: $HOST_PORT
    guest_port: 3000
EOF

cw_isolated() {
  (
    local -a proxy_environment=()
    local -a credential_environment=()
    if [[ "$ALLOW_REGISTRY_EGRESS" -eq 0 ]]; then
      proxy_environment=(
        HTTP_PROXY=http://127.0.0.1:1
        HTTPS_PROXY=http://127.0.0.1:1
        ALL_PROXY=http://127.0.0.1:1
        'NO_PROXY=127.0.0.1,localhost'
      )
    fi
    if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
      credential_environment=(CODEWIRE_LOCAL_CREDENTIAL_ROOT="$CREDENTIAL_ROOT")
      if [[ -n "$KEYRING_DBUS_PID" && -n "$KEYRING_DAEMON_PID" ]]; then
        credential_environment+=(
          XDG_RUNTIME_DIR="$KEYRING_RUNTIME"
          DBUS_SESSION_BUS_ADDRESS="$KEYRING_DBUS_ADDRESS"
        )
      fi
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
      "${credential_environment[@]}" \
      "${proxy_environment[@]}" \
      /usr/bin/timeout --foreground --signal=TERM --kill-after=5s \
      "${CW_COMMAND_TIMEOUT_SECONDS}s" \
      "$CW_BIN" "$@"
  )
}

run_cw_connect_synthetic_codex() {
  local stdout_file stderr_file
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stderr"
  if ! cw_isolated credentials --local connect codex \
    --name native-broker-codex >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    tail -n 80 "$stderr_file" >&2
    die 'connecting the synthetic local Codex credential failed'
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  LAST_STDOUT="$stdout_file"
  LAST_STDERR="$stderr_file"
}

run_cw_connect_synthetic_github() {
  local stdout_file stderr_file
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stderr"
  if ! cw_isolated credentials --local connect github \
    --name native-broker-github >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    tail -n 80 "$stderr_file" >&2
    die 'connecting the synthetic local GitHub credential failed'
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  LAST_STDOUT="$stdout_file"
  LAST_STDERR="$stderr_file"
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

run_named_reader_smoke() {
  local parent_name='native-reader-parent' reader_name='native-reader'
  local input='native-reader-ack' parent_id reader_id

  log 'checking named non-PTY input ACK, wait, restart identity, and known-clean stop'
  run_cw run --detach --no-tty --name "$parent_name" --output json -- /bin/true
  parent_id="$(jq -er '.session_id | select(type == "string" and length > 0)' "$LAST_STDOUT")" ||
    die 'named reader parent did not return a canonical identity'
  run_cw wait "$parent_name" --timeout 30s --output json
  jq -e --arg id "$parent_id" --arg name "$parent_name" '
    .session.session_id == $id and .session.name == $name and
    .session.parent_session_id == "" and .session.pty == false and
    .session.state == "Exited" and .session.exit_code == 0 and
    .session.cleanup_unknown == false and .output == "" and .eof == true
  ' "$LAST_STDOUT" >/dev/null || die 'named reader parent completion was not confirmed'

  # Bound the detached guest process as well as each host-side cw command.
  # shellcheck disable=SC2016 # This variable belongs to the guest process.
  run_cw run --detach --no-tty --name "$reader_name" --parent "$parent_name" \
    --output json -- timeout --signal=TERM --kill-after=5s 60s /bin/sh -c \
    'set -eu; IFS= read -r value; printf "native-reader:%s\n" "$value"'
  reader_id="$(jq -er '.session_id | select(type == "string" and length > 0)' "$LAST_STDOUT")" ||
    die 'named non-PTY reader did not return a canonical identity'
  jq -e --arg id "$reader_id" --arg name "$reader_name" --arg parent "$parent_id" '
    .session_id == $id and .session_id != $parent and .name == $name and
    .parent_session_id == $parent and .pty == false and .state == "Running"
  ' "$LAST_STDOUT" >/dev/null || die 'named reader launch or canonical parent drifted'

  run_cw send "$reader_name" "$input"
  rg -qxF "Input written to $reader_id" "$LAST_STDOUT" ||
    die 'named reader input ACK did not resolve to its canonical identity'
  run_cw wait "$reader_name" --timeout 30s --output json
  jq -e --arg id "$reader_id" --arg name "$reader_name" --arg parent "$parent_id" \
    --arg output "native-reader:$input"$'\n' '
    .session.session_id == $id and .session.name == $name and
    .session.parent_session_id == $parent and .session.pty == false and
    .session.state == "Exited" and .session.exit_code == 0 and
    .session.cleanup_unknown == false and .output == $output and
    .eof == true and .history_gap == false
  ' "$LAST_STDOUT" >/dev/null || die 'named reader wait did not confirm input, zero exit, output, and EOF'

  run_cw restart "$reader_name" --output json
  jq -e --arg id "$reader_id" --arg name "$reader_name" --arg parent "$parent_id" '
    length == 1 and (.[0] |
      .session_id == $id and .name == $name and .parent_session_id == $parent and
      .pty == false and .state == "Running" and .exit_code == null)
  ' "$LAST_STDOUT" >/dev/null || die 'reader restart changed its identity, name, parent, or run state'
  run_cw stop "$reader_name" --output json
  jq -e --arg id "$reader_id" --arg name "$reader_name" --arg parent "$parent_id" '
    length == 1 and (.[0] |
      .session_id == $id and .name == $name and .parent_session_id == $parent and
      .pty == false and .state == "Stopped" and .cleanup_unknown == false)
  ' "$LAST_STDOUT" >/dev/null || die 'reader stop did not return its terminal known-clean record'
  run_cw list --output json
  jq -e --arg id "$reader_id" --arg name "$reader_name" --arg parent "$parent_id" '
    [.[] | select(.name == $name)] |
    length == 1 and (.[0] |
      .session_id == $id and .parent_session_id == $parent and
      .pty == false and .state == "Stopped" and .cleanup_unknown == false)
  ' "$LAST_STDOUT" >/dev/null || die 'reader terminal known-clean record was not retained'
}

assert_current_target_cleared() {
  if rg -qF 'could not save the current local target' "$LAST_STDERR"; then
    die 'last environment deletion failed to clear the current target'
  fi
  run_cw current --verbose
  rg -q '^Target: +local$' "$LAST_STDOUT" ||
    die 'last environment deletion retained a stale current target'
}

run_cw_with_secret_stdin() {
  local secret_value="$1"
  shift
  local stdout_file stderr_file
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stderr"
  if ! printf '%s\n' "$secret_value" | cw_isolated "$@" >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    tail -n 80 "$stderr_file" >&2
    die "cw secret-stdin command $COMMAND_INDEX failed: $*"
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

run_cw_disruptive() {
  local stdout_file stderr_file
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stderr"
  if cw_isolated "$@" >"$stdout_file" 2>"$stderr_file"; then
    :
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  LAST_STDOUT="$stdout_file"
  LAST_STDERR="$stderr_file"
}

start_smoke_mesh() {
  run_cw mesh up \
    --binary "$MESH_BIN" \
    --derp-binary "$DERP_BIN" \
    --base-url "http://127.0.0.1:$MESH_PORT" \
    --listen "127.0.0.1:$MESH_PORT" \
    --derp-url "http://127.0.0.1:$DERP_PORT" \
    --derp-listen "127.0.0.1:$DERP_PORT" \
    --output json
  jq -e \
    --arg mesh_url "http://127.0.0.1:$MESH_PORT" \
    --arg derp_url "http://127.0.0.1:$DERP_PORT" '
      .started == true and
      .base_url == $mesh_url and
      .derp.url == $derp_url and
      (.pid | type == "number" and . > 0) and
      (.derp.pid | type == "number" and . > 0)
    ' "$LAST_STDOUT" >/dev/null || die 'standalone Mesh startup metadata drifted'
  MESH_STARTED=1
}

stop_smoke_mesh() {
  run_cw mesh down --output json
  jq -e '.stopped == true and .state == "stopped"' "$LAST_STDOUT" >/dev/null ||
    die 'standalone Mesh shutdown metadata drifted'
  MESH_STARTED=0
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
      --mesh-data-dir "$SMOKE_HOME/.codewire" \
      --platform-config-dir "$PLATFORM_CONFIG" \
      --credential-authority-root "$CREDENTIAL_ROOT" \
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

run_docker_persistence_smoke() {
  local marker="$1"
  # shellcheck disable=SC2016 # Expressions are evaluated inside the guest.
  run_cw run --no-tty -- /bin/sh -c '
    set -eu
    test "$(docker info --format "{{.DockerRootDir}}|{{.Driver}}")" = "/var/lib/docker|overlay2"
    docker image inspect codewire-native-smoke:1913 >/dev/null
    test "$(docker run --rm -v codewire-native-smoke-volume:/data codewire-native-smoke:1913 read-volume)" = generation-one
    node -e "
      const fs = require(\"node:fs\");
      const config = JSON.parse(fs.readFileSync(process.env.HOME + \"/.docker/config.json\", \"utf8\"));
      const auth = config.auths?.[\"registry.invalid\"]?.auth;
      process.exit(Buffer.from(auth ?? \"\", \"base64\").toString(\"utf8\") === \"synthetic-user:synthetic-token\" ? 0 : 1);
    "
    printf "%s\n" "$1"
  ' docker-persistence "$marker"
  rg -qxF "$marker" "$LAST_STDOUT" || die "Docker persistence marker drifted: $marker"
}

run_codex_credential_bridge_smoke() {
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
    "$CREDENTIAL_BRIDGE_SMOKE_BIN" \
      --state-root "$STATE_ROOT" \
      --artifact-root "$ARTIFACT_ROOT" \
      --artifact-lock "$ARTIFACT_LOCK" \
      --mesh-data-dir "$SMOKE_HOME/.codewire" \
      --platform-config-dir "$PLATFORM_CONFIG" \
      --credential-authority-root "$CREDENTIAL_ROOT" \
      --cw-bin "$CW_BIN" \
      --target "$NAME" >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    tail -n 80 "$stderr_file" >&2
    die 'stock Codex credential-bridge smoke failed'
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  [[ "$(cat "$stdout_file")" == 'codewire-local-codex-bridge-smoke: PASS' ]] ||
    die 'stock Codex credential-bridge smoke receipt drifted'
}

prepare_application_secret_fixture() {
  local project phase boot_id
  boot_id="$(tr -d '-' </proc/sys/kernel/random/boot_id)"
  APP_SECRET_CANARY_A="cwappfirst$boot_id"
  APP_SECRET_CANARY_B="cwappsecond$boot_id"
  APP_SECRET_USER_ONLY_CANARY="cwpersonalonly$boot_id"
  APP_SECRET_USER_COLLISION_CANARY="cwpersonalwins$boot_id"
  APP_SECRET_USER_PRECEDENCE_CANARY="cwpersonalconfigloses$boot_id"
  APP_SECRET_SHA_A="$(printf '%s' "$APP_SECRET_CANARY_A" | sha256sum | cut -d ' ' -f 1)"
  APP_SECRET_SHA_B="$(printf '%s' "$APP_SECRET_CANARY_B" | sha256sum | cut -d ' ' -f 1)"
  APP_SECRET_USER_ONLY_SHA="$(printf '%s' "$APP_SECRET_USER_ONLY_CANARY" | sha256sum | cut -d ' ' -f 1)"
  APP_SECRET_USER_COLLISION_SHA="$(printf '%s' "$APP_SECRET_USER_COLLISION_CANARY" | sha256sum | cut -d ' ' -f 1)"
  [[ "$APP_SECRET_SHA_A" =~ ^[0-9a-f]{64}$ && "$APP_SECRET_SHA_B" =~ ^[0-9a-f]{64}$ &&
     "$APP_SECRET_USER_ONLY_SHA" =~ ^[0-9a-f]{64}$ &&
     "$APP_SECRET_USER_COLLISION_SHA" =~ ^[0-9a-f]{64}$ &&
     "$APP_SECRET_SHA_A" != "$APP_SECRET_SHA_B" &&
     "$APP_SECRET_USER_ONLY_SHA" != "$APP_SECRET_USER_COLLISION_SHA" ]] ||
    die 'application fixture digests are invalid'
  for project in "$APP_SECRET_PROJECT_A" "$APP_SECRET_PROJECT_B"; do
    run_cw secrets --local projects create "$project"
    run_cw_with_secret_stdin stored-project-precedence-must-lose \
      secrets --local --project "$project" set CW_NATIVE_PRECEDENCE
    run_cw_with_secret_stdin "stored-$project-collision-must-lose" \
      secrets --local --project "$project" set CW_NATIVE_SCOPE_COLLISION
  done
  run_cw_with_secret_stdin "$APP_SECRET_CANARY_A" \
    secrets --local --project "$APP_SECRET_PROJECT_A" set DATABASE_URL
  run_cw_with_secret_stdin selected-a-only \
    secrets --local --project "$APP_SECRET_PROJECT_A" set CW_NATIVE_APP_A_ONLY
  run_cw_with_secret_stdin "$APP_SECRET_CANARY_B" \
    secrets --local --project "$APP_SECRET_PROJECT_B" set DATABASE_URL
  run_cw_with_secret_stdin selected-b-only \
    secrets --local --project "$APP_SECRET_PROJECT_B" set CW_NATIVE_APP_B_ONLY
  run_cw_with_secret_stdin "$APP_SECRET_USER_ONLY_CANARY" \
    secrets --local --user set CW_NATIVE_PERSONAL_ONLY
  run_cw_with_secret_stdin "$APP_SECRET_USER_COLLISION_CANARY" \
    secrets --local --user set CW_NATIVE_SCOPE_COLLISION
  run_cw_with_secret_stdin "$APP_SECRET_USER_PRECEDENCE_CANARY" \
    secrets --local --user set CW_NATIVE_PRECEDENCE
  run_cw secrets --local projects list --output json
  APP_SECRET_PROJECT_A_ID="$(jq -er --arg name "$APP_SECRET_PROJECT_A" \
    '.[] | select(.name == $name) | .id | select(test("^[0-9a-f-]{36}$"))' "$LAST_STDOUT")"
  APP_SECRET_PROJECT_B_ID="$(jq -er --arg name "$APP_SECRET_PROJECT_B" \
    '.[] | select(.name == $name) | .id | select(test("^[0-9a-f-]{36}$"))' "$LAST_STDOUT")"
  for project in "$APP_SECRET_PROJECT_A" "$APP_SECRET_PROJECT_B"; do
    run_cw secrets --local --project "$project" list --output json
    jq -e 'length == 4 and any(.[]; .key == "DATABASE_URL") and
      any(.[]; .key == "CW_NATIVE_SCOPE_COLLISION") and
      all(.[]; (keys | sort) == ["created_at", "key", "updated_at"]) and
      (tostring | contains("cwapp") | not)' "$LAST_STDOUT" >/dev/null ||
      die 'selected application project metadata is not key-only'
  done
  run_cw secrets --local --user list --output json
  jq -e '
    length == 3 and
    any(.[]; .key == "CW_NATIVE_PERSONAL_ONLY") and
    any(.[]; .key == "CW_NATIVE_SCOPE_COLLISION") and
    any(.[]; .key == "CW_NATIVE_PRECEDENCE") and
    all(.[]; (keys | sort) == ["created_at", "key", "updated_at"]) and
    (tostring | contains("cwpersonal") | not)
  ' "$LAST_STDOUT" >/dev/null || die 'selected personal application metadata is not key-only'
  cat >"$MOUNT_SOURCE/app-secrets-install.sh" <<'APP_INSTALL'
#!/bin/sh
set -eu
test -n "${DATABASE_URL:-}"
test "$(printf '%s' "$DATABASE_URL" | sha256sum | cut -d ' ' -f 1)" = "$1"
test "$(printf '%s' "$CW_NATIVE_PERSONAL_ONLY" | sha256sum | cut -d ' ' -f 1)" = "$2"
test "$(printf '%s' "$CW_NATIVE_SCOPE_COLLISION" | sha256sum | cut -d ' ' -f 1)" = "$3"
test "$CW_NATIVE_PRECEDENCE" = explicit-project-environment
test -z "${CW_NATIVE_SMOKE_SECRET+x}"
count=0
if test -f /workspace/native-app-install-count; then count=$(cat /workspace/native-app-install-count); fi
count=$((count + 1))
printf '%s\n' "$count" > /workspace/native-app-install-count
mkdir -p "$HOME/.local/bin"
cat >"$HOME/.local/bin/native-app-installed" <<'INSTALLED_TOOL'
#!/bin/sh
printf '%s\n' app-installed-tool-ok
INSTALLED_TOOL
chmod 0755 "$HOME/.local/bin/native-app-installed"
printf '%s\n' app-install-secret-ok > /workspace/native-app-install-proof
/bin/bash /workspace/fixtures/stock-ssh-workload.sh install \
  /workspace/fixtures/native-ssh-public-key.pub
APP_INSTALL
  cat >"$MOUNT_SOURCE/app-secrets-startup.sh" <<'APP_STARTUP'
#!/bin/sh
set -eu
test "$CW_NATIVE_PRECEDENCE" = explicit-project-environment
test -z "${CW_NATIVE_SMOKE_SECRET+x}"
if test -n "${DATABASE_URL+x}" && test -n "${CW_NATIVE_PERSONAL_ONLY+x}" &&
   test -n "${CW_NATIVE_SCOPE_COLLISION+x}"; then
  printf '%s:%s:%s\n' \
    "$(printf '%s' "$DATABASE_URL" | sha256sum | cut -d ' ' -f 1)" \
    "$(printf '%s' "$CW_NATIVE_PERSONAL_ONLY" | sha256sum | cut -d ' ' -f 1)" \
    "$(printf '%s' "$CW_NATIVE_SCOPE_COLLISION" | sha256sum | cut -d ' ' -f 1)" \
    > /workspace/native-app-startup-proof
else
  test -z "${DATABASE_URL+x}"
  test -z "${CW_NATIVE_PERSONAL_ONLY+x}"
  test -z "${CW_NATIVE_SCOPE_COLLISION+x}"
  printf '%s\n' absent > /workspace/native-app-startup-proof
fi
/bin/bash /workspace/fixtures/stock-ssh-workload.sh startup
APP_STARTUP
  cat >"$MOUNT_SOURCE/app-secrets-check.sh" <<'APP_CHECK'
#!/bin/sh
set -eu
expected=$1
personal_expected=$2
collision_expected=$3
phase=$4
assert_app() {
  label=$1
  shift
  if ! "$@"; then
    printf 'application assertion failed: %s (phase %s)\n' "$label" "$phase" >&2
    exit 1
  fi
}
assert_app ambient-absent test -z "${CW_NATIVE_SMOKE_SECRET+x}"
assert_app explicit-project-precedence test "$CW_NATIVE_PRECEDENCE" = explicit-project-environment
assert_app install-ran-once test "$(cat /workspace/native-app-install-count)" = 1
assert_app install-proof-preserved test "$(cat /workspace/native-app-install-proof)" = app-install-secret-ok
assert_app installed-tool-preserved test "$("$HOME/.local/bin/native-app-installed")" = app-installed-tool-ok
assert_app workspace-write-preserved test "$(cat /workspace/native-app-workspace-proof)" = app-workspace-preserved
case "$phase" in
  a)
    assert_app selected-a-present test "${CW_NATIVE_APP_A_ONLY-}" = selected-a-only
    assert_app unselected-b-absent test -z "${CW_NATIVE_APP_B_ONLY+x}"
    ;;
  b)
    assert_app selected-b-present test "${CW_NATIVE_APP_B_ONLY-}" = selected-b-only
    assert_app old-a-absent test -z "${CW_NATIVE_APP_A_ONLY+x}"
    ;;
  clear)
    assert_app cleared-database-absent test -z "${DATABASE_URL+x}"
    assert_app cleared-a-absent test -z "${CW_NATIVE_APP_A_ONLY+x}"
    assert_app cleared-b-absent test -z "${CW_NATIVE_APP_B_ONLY+x}"
    assert_app cleared-personal-only-absent test -z "${CW_NATIVE_PERSONAL_ONLY+x}"
    assert_app cleared-scope-collision-absent test -z "${CW_NATIVE_SCOPE_COLLISION+x}"
    ;;
  *) exit 76 ;;
esac
if test "$phase" != clear; then
  assert_app selected-database-matches test "$(printf '%s' "${DATABASE_URL-}" | sha256sum | cut -d ' ' -f 1)" = "$expected"
  assert_app personal-only-matches test "$(printf '%s' "${CW_NATIVE_PERSONAL_ONLY-}" | sha256sum | cut -d ' ' -f 1)" = "$personal_expected"
  assert_app personal-beats-project test "$(printf '%s' "${CW_NATIVE_SCOPE_COLLISION-}" | sha256sum | cut -d ' ' -f 1)" = "$collision_expected"
fi
startup_expected=absent
if test "$phase" != clear; then
  startup_expected="$expected:$personal_expected:$collision_expected"
fi
attempt=0
while test "$(cat /workspace/native-app-startup-proof 2>/dev/null || true)" != "$startup_expected"; do
  attempt=$((attempt + 1))
  assert_app startup-current-generation test "$attempt" -lt 100
  sleep 0.05
done
printf '%s\n' app-managed-exec-ok
APP_CHECK
  cp -- "$STOCK_SSH_WORKLOAD_SOURCE" "$MOUNT_SOURCE/stock-ssh-workload.sh"
  chmod 0755 "$MOUNT_SOURCE/stock-ssh-workload.sh" \
    "$MOUNT_SOURCE/app-secrets-install.sh" "$MOUNT_SOURCE/app-secrets-startup.sh" \
    "$MOUNT_SOURCE/app-secrets-check.sh"
  cat >>"$WORKSPACE/codewire.yaml" <<EOF
environment:
  CW_NATIVE_PRECEDENCE: explicit-project-environment
install_command: /bin/sh /workspace/fixtures/app-secrets-install.sh $APP_SECRET_SHA_A $APP_SECRET_USER_ONLY_SHA $APP_SECRET_USER_COLLISION_SHA
startup_script: /bin/sh /workspace/fixtures/app-secrets-startup.sh
EOF
  # Only hashes and fixed receipts enter scripts/YAML/output. The selected app
  # values are intentionally child-visible; this is not a provider-hiding proof.
  for phase in "$APP_SECRET_CANARY_A" "$APP_SECRET_CANARY_B" \
    "$APP_SECRET_USER_ONLY_CANARY" "$APP_SECRET_USER_COLLISION_CANARY" \
    "$APP_SECRET_USER_PRECEDENCE_CANARY"; do
    if rg -qF "$phase" "$WORKSPACE/codewire.yaml" "$MOUNT_SOURCE"/app-secrets-*.sh; then
      die 'application value entered a checked launch fixture instead of protected storage'
    fi
  done
}

run_application_secret_pty() {
  local expected="$1" personal_expected="$2" collision_expected="$3" phase="$4" pty_log attempt
  pty_log="$SMOKE_ROOT/app-pty-$phase.log"
  if ! (
    cd "$WORKSPACE"
    {
      printf 'test -t 0 && test -t 1 && /bin/sh /workspace/fixtures/app-secrets-check.sh %s %s %s %s && printf "app-secret-pty-ok\\n" || exit 77\nexit\n' \
        "$expected" "$personal_expected" "$collision_expected" "$phase"
      # Keep the checked-in PTY/detach path, but wait for the exact guest
      # receipt instead of guessing when the console hop has completed.
      for ((attempt = 0; attempt < 400; attempt++)); do
        if rg -q $'^app-secret-pty-ok\r?$' "$pty_log" 2>/dev/null; then
          printf '\002d' || true
          exit 0
        fi
        sleep 0.05
      done
      exit 1
    } | env -i PATH="$SMOKE_ROOT/bin:/usr/bin:/bin" HOME="$SMOKE_HOME" USER="$(id -un)" \
      LOGNAME="$(id -un)" SHELL='/bin/sh' TERM='xterm-256color' LC_ALL=C \
      CW_CONFIG_DIR="$PLATFORM_CONFIG" CODEWIRE_NATIVE_STATE_ROOT="$STATE_ROOT" \
      CODEWIRE_NATIVE_ARTIFACT_ROOT="$ARTIFACT_ROOT" CODEWIRE_NATIVE_ARTIFACT_LOCK="$ARTIFACT_LOCK" \
      CODEWIRE_LOCAL_CREDENTIAL_ROOT="$CREDENTIAL_ROOT" XDG_RUNTIME_DIR="$KEYRING_RUNTIME" \
      DBUS_SESSION_BUS_ADDRESS="$KEYRING_DBUS_ADDRESS" CODEWIRE_SERVER_URL='http://127.0.0.1:1' \
      CODEWIRE_API_KEY='synthetic-platform-key-must-not-be-used' \
      HTTP_PROXY='http://127.0.0.1:1' HTTPS_PROXY='http://127.0.0.1:1' ALL_PROXY='http://127.0.0.1:1' \
      NO_PROXY='127.0.0.1,localhost' /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 30s \
      /usr/bin/script -qefc "$CW_BIN shell" "$pty_log"
  ) >"$SMOKE_ROOT/app-pty-$phase.stdout" 2>"$SMOKE_ROOT/app-pty-$phase.stderr"; then
    tail -n 80 "$SMOKE_ROOT/app-pty-$phase.stderr" >&2
    die 'application projection PTY proof failed'
  fi
  cat "$SMOKE_ROOT/app-pty-$phase.stdout" "$SMOKE_ROOT/app-pty-$phase.stderr" >>"$TRANSCRIPT"
  rg -q $'^app-secret-pty-ok\r?$' "$pty_log" || die 'PTY did not confirm the current application projection'
}

run_application_secret_smoke() {
  local built root_generation root_file root_identity generation expected phase project_id journal
  log 'checking selected application keys during install, startup, managed exec, PTY, restart, and clear'
  built="$(native_database_value built_workspace_identity)"
  [[ "$built" =~ ^[0-9a-f]{64}:[0-9a-f]{64}$ ]] || die 'built workspace identity is unavailable'
  # The build record identifies OCI/setup intent. The disk's storage generation
  # also binds the immutable skill seed, so read the runner's admitted identity.
  root_generation="$(jq -er '.root_generation | select(test("^[0-9a-f]{64}$"))' \
    "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json")"
  root_file="$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/generations/$root_generation/root.raw"
  root_identity="$(stat -c '%d:%i:%s' "$root_file")"
  run_cw run --no-tty -- /bin/sh -lc 'printf "%s\n" app-workspace-preserved > /workspace/native-app-workspace-proof'
  generation="$(jq -er '.generation' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json")"
  for phase in a b clear; do
    case "$phase" in
      a) expected="$APP_SECRET_SHA_A"; project_id="$APP_SECRET_PROJECT_A_ID" ;;
      b)
        expected="$APP_SECRET_SHA_B"; project_id="$APP_SECRET_PROJECT_B_ID"
        journal="$(native_database_value journal_summary)"
        run_cw_expect_failure env update --local "$NAME" --secrets "local:$APP_SECRET_PROJECT_B" \
          --user-secrets local --output json
        [[ "$(jq -er '.generation' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json")" == "$generation" &&
           "$(native_database_value journal_summary)" == "$journal" ]] ||
          die 'unconfirmed source update changed the running generation or admitted an operation'
        run_cw env update --local "$NAME" --secrets "local:$APP_SECRET_PROJECT_B" \
          --user-secrets local --yes --output json
        assert_previous_direct_share_processes_gone
        assert_direct_share_processes
        generation=$((generation + 1))
        ;;
      clear)
        expected=absent; project_id=''
        run_cw env update --local "$NAME" --clear-secrets --yes --output json
        assert_previous_direct_share_processes_gone
        assert_direct_share_processes
        generation=$((generation + 1))
        ;;
    esac
    run_cw env info --local "$NAME" --output json
    jq -e --argjson generation "$generation" --arg id "$ENVIRONMENT_ID" --arg project "$project_id" \
      --arg skills "$INITIAL_SKILL_SNAPSHOT" '
      .id == $id and .generation == $generation and .state == "running" and
      .access_profile == "user/native-broker" and .access_profile_revision == 4 and
      .source_selection.credentials.reference == "user/native-broker" and
      .source_selection.credentials.revision == 4 and
      (.source_selection.secrets.project // "") == (if $project == "" then "" else "local:id:" + $project end) and
      (if $project == "" then .source_selection.secrets.user == null
       else .source_selection.secrets.user == "local" end) and
      (.source_selection.secrets.organization // false) == false and
      .skill_snapshot == $skills and .skill_snapshot_generation == 1
    ' "$LAST_STDOUT" >/dev/null || die 'source update changed an unrelated pin or did not replace the exact source'
    [[ "$(native_database_value built_workspace_identity)" == "$built" &&
       "$(jq -er '.root_generation' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json")" == "$root_generation" &&
       "$(stat -c '%d:%i:%s' "$root_file")" == "$root_identity" ]] ||
      die 'source-only update rebuilt the installed root or changed immutable setup/skill intent'
    run_cw run --no-tty -- /bin/sh /workspace/fixtures/app-secrets-check.sh \
      "$expected" "$APP_SECRET_USER_ONLY_SHA" "$APP_SECRET_USER_COLLISION_SHA" "$phase"
    rg -qxF app-managed-exec-ok "$LAST_STDOUT" || die 'managed exec did not receive the exact current application keys'
    # shellcheck disable=SC2016 # These variables belong to the guest command.
    run_cw run --no-tty --env DATABASE_URL=explicit-command-database -- /bin/sh -lc \
      'test "$DATABASE_URL" = explicit-command-database'
    run_application_secret_pty \
      "$expected" "$APP_SECRET_USER_ONLY_SHA" "$APP_SECRET_USER_COLLISION_SHA" "$phase"
    if [[ "$phase" != a ]]; then
      [[ "$(native_database_value source_operation)" == 'update_environment_sources:completed:10' ]] ||
        die 'source update did not complete its exact durable operation'
    fi
  done
  # Per-command environment remains an explicit override, independent of the
  # stored source or canonical project environment.
  # shellcheck disable=SC2016 # These variables belong to the guest command.
  run_cw run --no-tty --env CW_NATIVE_PRECEDENCE=explicit-command-environment -- /bin/sh -lc \
    'test "$CW_NATIVE_PRECEDENCE" = explicit-command-environment'
  [[ ! -e "$KEYRING_RUNTIME/codewire/workload-secrets-v1" ]] ||
    die 'application source updates created a second durable delivery store'
  if rg -qF "$APP_SECRET_CANARY_A" "$TRANSCRIPT" || rg -qF "$APP_SECRET_CANARY_B" "$TRANSCRIPT"; then
    die 'application smoke accidentally printed a selected value'
  fi
  for expected in "$APP_SECRET_USER_ONLY_CANARY" "$APP_SECRET_USER_COLLISION_CANARY" \
    "$APP_SECRET_USER_PRECEDENCE_CANARY"; do
    if rg -qF "$expected" "$TRANSCRIPT"; then
      die 'personal application smoke accidentally printed a selected value'
    fi
  done
}

run_managed_credential_broker_smoke() {
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
    /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 300s \
    "$CREDENTIAL_BRIDGE_SMOKE_BIN" \
      --state-root "$STATE_ROOT" \
      --artifact-root "$ARTIFACT_ROOT" \
      --artifact-lock "$ARTIFACT_LOCK" \
      --mesh-data-dir "$SMOKE_HOME/.codewire" \
      --platform-config-dir "$PLATFORM_CONFIG" \
      --credential-authority-root "$CREDENTIAL_ROOT" \
      --cw-bin "$CW_BIN" \
      --target "$NAME" \
      --managed-broker \
      --credential-id "$CREDENTIAL_ID" \
      --openai-credential-id "$OPENAI_CREDENTIAL_ID" \
      --anthropic-credential-id "$ANTHROPIC_CREDENTIAL_ID" \
      --ssh-credential-id "$SSH_CREDENTIAL_ID" \
      >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    tail -n 80 "$stderr_file" >&2
    die 'managed local credential-broker product smoke failed'
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  [[ "$(cat "$stdout_file")" == 'codewire-local-codex-bridge-smoke: PASS (managed broker)' ]] ||
    die 'managed local credential-broker smoke receipt drifted'
}

run_native_managed_agent_smoke() {
  local stdout_file stderr_file journey expected_harness
  local -a journey_args
  journey="$SOURCE_ROOT/scripts/dev/test-cli-native-managed.py"
  expected_harness='scripts/dev/test-cli-native-managed.py'
  journey_args=(--cw "$CW_BIN" --environment "$ENVIRONMENT_ID")
  if [[ "$MANAGED_AGENT_UPDATE" -eq 1 ]]; then
    journey="$SOURCE_ROOT/scripts/dev/test-cli-native-update.py"
    expected_harness='scripts/dev/test-cli-native-update.py'
    journey_args+=(--runtime-a "$MANAGED_AGENT_UPDATE_A_LOCK" --image-a "$MANAGED_AGENT_CW_IMAGE_RECEIPT"
      --sha256-a "$MANAGED_AGENT_UPDATE_A_SHA256" --runtime-b "$MANAGED_AGENT_UPDATE_RUNTIME_LOCK"
      --image-b "$MANAGED_AGENT_UPDATE_IMAGE_RECEIPT" --sha256-b "$MANAGED_AGENT_UPDATE_SHA256"
      --vm-state "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json"
      --runner-socket "$STATE_ROOT/runners/$ENVIRONMENT_ID.sock")
  else
    journey_args+=(--cw-image-receipt "$MANAGED_AGENT_CW_IMAGE_RECEIPT")
  fi
  journey_args+=(--codex-model codewire-synthetic --claude-model claude-sonnet-4-6)
  COMMAND_INDEX=$((COMMAND_INDEX + 1))
  stdout_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stdout"
  stderr_file="$SMOKE_ROOT/command-$COMMAND_INDEX.stderr"
  if ! env -i \
    PATH='/usr/bin:/bin' HOME="$SMOKE_HOME" USER="$(id -un)" LOGNAME="$(id -un)" \
    SHELL='/bin/sh' TERM='xterm-256color' LC_ALL=C \
    CW_CONFIG_DIR="$PLATFORM_CONFIG" \
    CODEWIRE_NATIVE_STATE_ROOT="$STATE_ROOT" \
    CODEWIRE_NATIVE_ARTIFACT_ROOT="$ARTIFACT_ROOT" \
    CODEWIRE_NATIVE_ARTIFACT_LOCK="$ARTIFACT_LOCK" \
    CODEWIRE_LOCAL_CREDENTIAL_ROOT="$CREDENTIAL_ROOT" \
    XDG_RUNTIME_DIR="$KEYRING_RUNTIME" DBUS_SESSION_BUS_ADDRESS="$KEYRING_DBUS_ADDRESS" \
    CODEWIRE_SERVER_URL='http://127.0.0.1:1' \
    CODEWIRE_API_KEY='synthetic-platform-key-must-not-be-used' \
    HTTP_PROXY='http://127.0.0.1:1' HTTPS_PROXY='http://127.0.0.1:1' \
    ALL_PROXY='http://127.0.0.1:1' NO_PROXY='127.0.0.1,localhost' \
    PYTHONDONTWRITEBYTECODE=1 \
    /usr/bin/timeout --foreground --signal=TERM --kill-after=10s 1220s \
    python3 "$journey" "${journey_args[@]}" \
      >"$stdout_file" 2>"$stderr_file"; then
    cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
    cat "$stdout_file" >&2
    tail -n 30 "$stderr_file" >&2
    die 'native managed agent session journey failed'
  fi
  cat "$stdout_file" "$stderr_file" >>"$TRANSCRIPT"
  jq -e --arg harness "$expected_harness" '.status == "passed" and
    .harness == $harness and .mode == "protected-broker-actual-agents" and
    (.missing_acceptance | length) == 0 and (.cleanup_errors | length) == 0' \
    "$stdout_file" >/dev/null || die 'native managed agent journey receipt drifted'
  log 'native managed agent session journey passed'
}

wait_for_pid_exit() {
  local pid="$1"
  # Match the direct VMM gate's 15-second process-identity termination bound.
  for _attempt in {1..300}; do
    [[ ! -e "/proc/$pid" ]] && return 0
    sleep 0.05
  done
  return 1
}

wait_for_pid_death() {
  local pid="$1"
  local stat suffix state
  for _attempt in {1..300}; do
    [[ ! -r "/proc/$pid/stat" ]] && return 0
    stat="$(<"/proc/$pid/stat")"
    suffix="${stat##*) }"
    state="${suffix%% *}"
    [[ "$state" == Z || "$state" == X ]] && return 0
    sleep 0.05
  done
  return 1
}

exact_isolated_process() {
  local pid="$1"
  local executable="$2"
  local marker="$3"
  local argument
  local -a argv=()
  [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]] || return 1
  [[ "$(stat -c '%u' "/proc/$pid" 2>/dev/null || true)" == "$(id -u)" ]] || return 1
  [[ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" == "$(readlink -f "$executable")" ]] ||
    return 1
  mapfile -d '' -t argv <"/proc/$pid/cmdline" 2>/dev/null || return 1
  for argument in "${argv[@]}"; do
    [[ "$argument" == "$marker" ]] && return 0
  done
  return 1
}

wait_for_exact_isolated_process() {
  local pid="$1"
  local executable="$2"
  local marker="$3"
  for _attempt in {1..100}; do
    exact_isolated_process "$pid" "$executable" "$marker" && return 0
    [[ -d "/proc/$pid" ]] || return 1
    sleep 0.01
  done
  return 1
}

stop_exact_isolated_process() {
  local pid="$1"
  local executable="$2"
  local marker="$3"
  [[ -n "$pid" ]] || return 0
  [[ -d "/proc/$pid" ]] || return 0
  exact_isolated_process "$pid" "$executable" "$marker" || return 1
  kill -TERM -- "$pid" 2>/dev/null || return 1
  if ! wait_for_pid_death "$pid"; then
    exact_isolated_process "$pid" "$executable" "$marker" || return 1
    kill -KILL -- "$pid" 2>/dev/null || return 1
    wait_for_pid_death "$pid" || return 1
  fi
  wait "$pid" 2>/dev/null || true
}

keyring_service_ready() {
  /usr/bin/busctl --address="$KEYRING_DBUS_ADDRESS" --no-pager \
    status org.freedesktop.secrets >/dev/null 2>&1
}

start_isolated_keyring() {
  mkdir -m 0700 \
    "$KEYRING_ROOT" "$KEYRING_CONFIG" "$KEYRING_DATA" "$KEYRING_CONTROL"
  [[ -d "$KEYRING_RUNTIME" && ! -L "$KEYRING_RUNTIME" &&
     "$(stat -c '%u' "$KEYRING_RUNTIME")" == "$(id -u)" &&
     "$(stat -c '%a' "$KEYRING_RUNTIME")" == 700 &&
     "$(findmnt -nro FSTYPE -T "$KEYRING_RUNTIME")" == tmpfs ]] ||
    die 'isolated keyring runtime is not a private tmpfs directory'
  env -i PATH='/usr/bin:/bin' LC_ALL=C XDG_RUNTIME_DIR="$KEYRING_RUNTIME" \
    /usr/bin/dbus-daemon --session --address="$KEYRING_DBUS_ADDRESS" \
      --nofork --nopidfile >"$KEYRING_ROOT/dbus.stdout" 2>"$KEYRING_ROOT/dbus.stderr" &
  KEYRING_DBUS_PID=$!
  wait_for_exact_isolated_process \
    "$KEYRING_DBUS_PID" /usr/bin/dbus-daemon "--address=$KEYRING_DBUS_ADDRESS" ||
    die 'isolated D-Bus process identity drifted'
  for _attempt in {1..200}; do
    /usr/bin/busctl --address="$KEYRING_DBUS_ADDRESS" --no-pager \
      status org.freedesktop.DBus >/dev/null 2>&1 && break
    [[ -d "/proc/$KEYRING_DBUS_PID" ]] || break
    sleep 0.05
  done
  if ! /usr/bin/busctl --address="$KEYRING_DBUS_ADDRESS" --no-pager \
    status org.freedesktop.DBus >/dev/null 2>&1; then
    tail -n 40 "$KEYRING_ROOT/dbus.stderr" >&2
    die 'isolated D-Bus did not become ready'
  fi

  printf '%s' 'codewire-local-smoke-keyring-password' | env -i PATH='/usr/bin:/bin' LC_ALL=C \
    XDG_RUNTIME_DIR="$KEYRING_RUNTIME" \
    XDG_CONFIG_HOME="$KEYRING_CONFIG" \
    XDG_DATA_HOME="$KEYRING_DATA" \
    DBUS_SESSION_BUS_ADDRESS="$KEYRING_DBUS_ADDRESS" \
    /usr/bin/gnome-keyring-daemon --foreground --unlock --components=secrets \
      --control-directory="$KEYRING_CONTROL" \
      >"$KEYRING_ROOT/keyring.stdout" 2>"$KEYRING_ROOT/keyring.stderr" &
  KEYRING_DAEMON_PID=$!
  wait_for_exact_isolated_process \
    "$KEYRING_DAEMON_PID" /usr/bin/gnome-keyring-daemon \
    "--control-directory=$KEYRING_CONTROL" ||
    die 'isolated keyring process identity drifted'
  for _attempt in {1..200}; do
    keyring_service_ready && break
    [[ -d "/proc/$KEYRING_DAEMON_PID" ]] || break
    sleep 0.05
  done
  if ! keyring_service_ready; then
    tail -n 40 "$KEYRING_ROOT/keyring.stderr" >&2
    die 'isolated Secret Service did not become ready'
  fi
}

stop_isolated_keyring() {
  local failed=0
  stop_exact_isolated_process \
    "$KEYRING_DAEMON_PID" /usr/bin/gnome-keyring-daemon \
    "--control-directory=$KEYRING_CONTROL" || failed=1
  KEYRING_DAEMON_PID=''
  stop_exact_isolated_process \
    "$KEYRING_DBUS_PID" /usr/bin/dbus-daemon "--address=$KEYRING_DBUS_ADDRESS" || failed=1
  KEYRING_DBUS_PID=''
  [[ "$failed" -eq 0 ]]
}

remove_isolated_keyring_runtime() {
  local expected_prefix
  [[ -n "$KEYRING_RUNTIME" ]] || return 0
  expected_prefix="$KEYRING_RUNTIME_PARENT/.cwn-"
  [[ -n "$KEYRING_RUNTIME_PARENT" && "$KEYRING_RUNTIME" == "$expected_prefix"* &&
     "${KEYRING_RUNTIME#"$expected_prefix"}" =~ ^[[:alnum:]]{6}$ &&
     -d "$KEYRING_RUNTIME" && ! -L "$KEYRING_RUNTIME" &&
     "$(stat -c '%u' "$KEYRING_RUNTIME")" == "$(id -u)" ]] || return 1
  rm -rf -- "$KEYRING_RUNTIME"
  KEYRING_RUNTIME=''
  KEYRING_DBUS_ADDRESS=''
}

secret_tool_isolated() {
  env -i PATH='/usr/bin:/bin' LC_ALL=C \
    XDG_RUNTIME_DIR="$KEYRING_RUNTIME" \
    DBUS_SESSION_BUS_ADDRESS="$KEYRING_DBUS_ADDRESS" \
    /usr/bin/secret-tool "$@"
}

find_exact_credential_authority_pid() {
  local proc pid
  local -a argv
  for proc in /proc/[0-9]*; do
    [[ "$(readlink -f "$proc/exe" 2>/dev/null || true)" == "$CW_BIN" ]] || continue
    [[ "$(stat -c '%u' "$proc" 2>/dev/null || true)" == "$(id -u)" ]] || continue
    argv=()
    mapfile -d '' -t argv <"$proc/cmdline" 2>/dev/null || continue
    [[ ${#argv[@]} -eq 4 ]] || continue
    if [[ "${argv[1]}" == '__local-credential-authority' &&
          "${argv[2]}" == '--root' && "${argv[3]}" == "$CREDENTIAL_ROOT" ]]; then
      pid="${proc#/proc/}"
      printf '%s\n' "$pid"
      return 0
    fi
  done
  return 1
}

shutdown_credential_authority() {
  local pid
  if ! pid="$(find_exact_credential_authority_pid)"; then
    [[ ! -e "$CREDENTIAL_ROOT/authority.sock" ]]
    return
  fi
  if ! cw_isolated __local-credential-authority-probe \
    --root "$CREDENTIAL_ROOT" --shutdown >/dev/null 2>&1; then
    return 1
  fi
  wait_for_pid_death "$pid" || return 1
  [[ ! -e "$CREDENTIAL_ROOT/authority.sock" ]]
}

terminate_exact_credential_authority() {
  local pid
  shutdown_credential_authority && return 0
  pid="$(find_exact_credential_authority_pid)" || return 1
  kill -TERM -- "$pid" 2>/dev/null || return 1
  if ! wait_for_pid_death "$pid"; then
    [[ "$(find_exact_credential_authority_pid)" == "$pid" ]] || return 1
    kill -KILL -- "$pid" 2>/dev/null || return 1
    wait_for_pid_death "$pid" || return 1
  fi
  [[ ! -e "$CREDENTIAL_ROOT/authority.sock" ]]
}

scan_for_credential_canary() {
  local label="$1"
  local canary="$2"
  local report="$SMOKE_ROOT/canary-scan-$label.report"
  if ! printf '%s' "$canary" | /usr/bin/python3 -c '
import errno
import os
import stat
import sys

needle = sys.stdin.buffer.read()
root = os.fsencode(sys.argv[1])
if len(needle) < 16 or not os.path.isabs(root):
    raise SystemExit(2)

def allocated_ranges(descriptor, size):
    if not hasattr(os, "SEEK_DATA"):
        yield 0, size
        return
    offset = 0
    while offset < size:
        try:
            data = os.lseek(descriptor, offset, os.SEEK_DATA)
        except OSError as error:
            if error.errno == errno.ENXIO:
                return
            if error.errno in (errno.EINVAL, errno.ENOTSUP):
                yield 0, size
                return
            raise
        hole = os.lseek(descriptor, data, os.SEEK_HOLE)
        yield data, min(hole, size)
        offset = max(hole, data + 1)

def contains(descriptor, start, end):
    carry = b""
    offset = start
    while offset < end:
        chunk = os.pread(descriptor, min(1024 * 1024, end - offset), offset)
        if not chunk:
            return False
        combined = carry + chunk
        if needle in combined:
            return True
        carry = combined[-(len(needle) - 1):]
        offset += len(chunk)
    return False

found = []
for directory, directories, files in os.walk(root, followlinks=False):
    directories[:] = [
        name for name in directories
        if not os.path.islink(os.path.join(directory, name))
    ]
    for name in files:
        path = os.path.join(directory, name)
        metadata = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            continue
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            if any(contains(descriptor, start, end) for start, end in allocated_ranges(descriptor, metadata.st_size)):
                found.append(os.fsdecode(os.path.relpath(path, root)))
        finally:
            os.close(descriptor)
for path in found:
    print(path)
raise SystemExit(1 if found else 0)
' "$SMOKE_ROOT" >"$report"; then
    tail -n 20 "$report" >&2
    die "synthetic $label canary entered durable smoke state"
  fi
  [[ ! -s "$report" ]] || die "$label canary scanner emitted unexpected output"
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
    [[ ${#argv[@]} -eq 14 ]] || continue
    if [[ "${argv[1]}" == '__native-supervisor' &&
          "${argv[2]}" == '--root' && "${argv[3]}" == "$STATE_ROOT" &&
          "${argv[4]}" == '--artifact-root' && "${argv[5]}" == "$ARTIFACT_ROOT" &&
          "${argv[6]}" == '--artifact-lock' && "${argv[7]}" == "$ARTIFACT_LOCK" &&
          "${argv[8]}" == '--mesh-data-dir' && "${argv[9]}" == "$SMOKE_HOME/.codewire" &&
          "${argv[10]}" == '--platform-config-dir' && "${argv[11]}" == "$PLATFORM_CONFIG" &&
          "${argv[12]}" == '--credential-authority-root' &&
          "${argv[13]}" == "$SMOKE_HOME/.codewire/credentials-v1" ]]; then
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
    if [[ "$cmdline" == *"$STATE_ROOT"* ||
          ( "$MANAGED_CREDENTIAL_BROKER" -eq 1 && "$cmdline" == *"$CREDENTIAL_ROOT"* ) ]]; then
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
  copy_advanced_artifact '.virtiofsd.path' 'advanced-virtiofsd' 0500
  copy_advanced_artifact '.kernel.path' 'advanced-kernel' 0400
  copy_advanced_artifact '.initramfs.path' 'advanced-initramfs' 0400
  jq '
    .cloud_hypervisor.path = "advanced-cloud-hypervisor" |
    .virtiofsd.path = "advanced-virtiofsd" |
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

assert_direct_share_processes() {
  local generation_manifest virtiofsd_sha256 virtiofsd_executable index source socket pid_file pid
  local no_new_privileges effective_capabilities seccomp_mode argument host_uid host_gid
  local -a argv=()
  generation_manifest="$STATE_ROOT/engine/runtime-artifacts/generations/$ORIGINAL_ARTIFACT_GENERATION.json"
  virtiofsd_sha256="$(jq -er '.virtiofsd.sha256 | select(test("^[0-9a-f]{64}$"))' \
    "$generation_manifest")" || die 'cached runtime generation is missing virtiofsd'
  virtiofsd_executable="$(realpath -e -- \
    "$STATE_ROOT/engine/runtime-artifacts/blobs/x-$virtiofsd_sha256")" ||
    die 'cached virtiofsd executable is unavailable'
  host_uid="$(id -u)"
  host_gid="$(id -g)"
  DIRECT_SHARE_PIDS=()
  for index in 00 01; do
    if [[ "$index" == 00 ]]; then
      source="$DIRECT_RO_SOURCE"
    else
      source="$DIRECT_RW_SOURCE"
    fi
    socket="$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/fs/$index.sock"
    pid_file="$socket.pid"
    [[ -S "$socket" && "$(stat -c '%a' "$socket")" == 600 ]] ||
      die "direct-share socket $index is absent or not private"
    [[ -f "$pid_file" && ! -L "$pid_file" && "$(stat -c '%a' "$pid_file")" == 600 ]] ||
      die "direct-share PID file $index is absent or not private"
    pid="$(tr -d '[:space:]' <"$pid_file")"
    [[ "$pid" =~ ^[0-9]+$ ]] || die "direct-share PID $index is invalid"
    exact_isolated_process "$pid" "$virtiofsd_executable" "/proc/self/fd/3/" ||
      die "direct-share process $index identity or fixed descriptor argument drifted"
    [[ "$(readlink -f "/proc/$pid/fd/3")" == "$source" ]] ||
      die "direct-share process $index does not hold the admitted source descriptor"
    argv=()
    mapfile -d '' -t argv <"/proc/$pid/cmdline" ||
      die "direct-share process $index command line is unreadable"
    for argument in "${argv[@]}"; do
      [[ "$argument" != *"$DIRECT_RO_SOURCE"* && "$argument" != *"$DIRECT_RW_SOURCE"* ]] ||
        die "direct-share process $index leaked a host source path into argv"
    done
    printf '%s\n' "${argv[@]}" | grep -Fxq "squash-guest:0:$host_uid:4294967295" ||
      die "direct-share process $index omitted its unprivileged UID translation"
    printf '%s\n' "${argv[@]}" | grep -Fxq "squash-guest:0:$host_gid:4294967295" ||
      die "direct-share process $index omitted its unprivileged GID translation"
    no_new_privileges="$(awk '$1 == "NoNewPrivs:" { print $2 }' "/proc/$pid/status")"
    effective_capabilities="$(awk '$1 == "CapEff:" { print $2 }' "/proc/$pid/status")"
    seccomp_mode="$(awk '$1 == "Seccomp:" { print $2 }' "/proc/$pid/status")"
    [[ "$no_new_privileges" == 1 && "$effective_capabilities" == 0000000000000000 &&
       "$seccomp_mode" == 2 ]] ||
      die "direct-share process $index confinement status drifted"
    DIRECT_SHARE_PIDS+=("$pid")
  done
}

assert_previous_direct_share_processes_gone() {
  local pid
  for pid in "${DIRECT_SHARE_PIDS[@]}"; do
    wait_for_pid_death "$pid" || die "direct-share process $pid survived VM stop"
  done
  DIRECT_SHARE_PIDS=()
}

assert_direct_share_processes_stopped() {
  assert_previous_direct_share_processes_gone
  [[ -z "$(find "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/fs" -mindepth 1 -print -quit)" ]] ||
    die 'direct-share runtime endpoints remained after VM stop'
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
  if [[ "$ENV_CREATED" -eq 1 && -f "$STATE_ROOT/supervisor.db" ]]; then
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
  if [[ "$MESH_STARTED" -eq 1 ]]; then
    if ! cw_isolated mesh down --output json >/dev/null 2>&1; then
      cleanup_status=1
    else
      MESH_STARTED=0
    fi
  fi
  if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]] && ! terminate_exact_credential_authority; then
    cleanup_status=1
  fi
  if [[ "$status" -ne 0 ]] && ! terminate_remaining_owned_processes; then
    cleanup_status=1
  fi
  if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]] && ! stop_isolated_keyring; then
    cleanup_status=1
  fi
  if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]] && ! remove_isolated_keyring_runtime; then
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

if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  log 'checking the specially named synthetic-broker build before creating protected material'
  run_cw __local-credential-broker-synthetic-smoke-check
  [[ "$(cat "$LAST_STDOUT")" == 'codewire-local-credential-broker-synthetic-smoke:v1' ]] ||
    die 'synthetic credential-broker build marker drifted'
fi

log 'starting isolated standalone Mesh and selecting the smoke network'
start_smoke_mesh
MESH_OWNER_CONTEXT="$SMOKE_HOME/.codewire/mesh_owner.json"
[[ -f "$MESH_OWNER_CONTEXT" && ! -L "$MESH_OWNER_CONTEXT" ]] ||
  die 'standalone Mesh did not write its credential-free owner projection'
[[ "$(stat -c '%a' "$MESH_OWNER_CONTEXT")" == 600 ]] ||
  die 'standalone Mesh owner projection is not mode 0600'
jq -e \
  --arg mesh_url "http://127.0.0.1:$MESH_PORT" '
    .schema_version == 1 and
    .auth_source == "standalone_local" and
    .mesh_url == $mesh_url and
    (.organization_id | type == "string" and length > 0) and
    .selected_network == null and
    .auto_connect == false
  ' "$MESH_OWNER_CONTEXT" >/dev/null || die 'standalone Mesh owner projection drifted'
if rg -qi 'token|secret|credential|api[_-]?key' "$MESH_OWNER_CONTEXT"; then
  die 'credential material or a credential field entered the Mesh owner projection'
fi
MESH_ORGANIZATION_ID="$(jq -er '.organization_id' "$MESH_OWNER_CONTEXT")"
run_cw network create "$MESH_NETWORK" --org "$MESH_ORGANIZATION_ID"
rg -qF "Network \"$MESH_NETWORK\" created and selected" "$LAST_STDERR" ||
  die 'standalone smoke network was not selected'
run_cw network use "$MESH_NETWORK" --auto-connect
rg -qF 'new environments connect automatically' "$LAST_STDERR" ||
  die 'standalone smoke network did not enable automatic attachment'
jq -e --arg network "$MESH_NETWORK" '
  .selected_network == $network and .auto_connect == true
' \
  "$MESH_OWNER_CONTEXT" >/dev/null || die 'selected network did not reach the owner projection'
run_cw mesh status --output json
jq -e --arg network "$MESH_NETWORK" --arg mesh_url "http://127.0.0.1:$MESH_PORT" '
  .configured == true and
  .mesh_url == $mesh_url and
  .selected_network == $network and
  .auto_connect == true and
  .local.state == "running" and
  .local.derp.state == "running"
' "$LAST_STDOUT" >/dev/null || die 'standalone Mesh status drifted after default selection'

if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  log 'starting a private D-Bus and Secret Service instance'
  start_isolated_keyring
  CREDENTIAL_CANARY="cwlocalbroker$(tr -d '-' </proc/sys/kernel/random/boot_id)"
  CREDENTIAL_REFRESH_CANARY="cwlocalrefresh$(tr -d '-' </proc/sys/kernel/random/boot_id)"
  GITHUB_CREDENTIAL_CANARY="ghu_cwlocalgithub$(tr -d '-' </proc/sys/kernel/random/boot_id)"
  OPENAI_CREDENTIAL_CANARY="cwlocalopenai$(tr -d '-' </proc/sys/kernel/random/boot_id)"
  ANTHROPIC_CREDENTIAL_CANARY="cwlocalanthropic$(tr -d '-' </proc/sys/kernel/random/boot_id)"
  WORKLOAD_SECRET_CANARY="cwworkload$(tr -d '-' </proc/sys/kernel/random/boot_id)"
  [[ ${#CREDENTIAL_CANARY} -ge 16 && ${#CREDENTIAL_CANARY} -le 256 &&
     "$CREDENTIAL_CANARY" =~ ^[A-Za-z0-9._-]+$ ]] ||
    die 'generated credential canary is invalid'
  [[ ${#CREDENTIAL_REFRESH_CANARY} -ge 16 && ${#CREDENTIAL_REFRESH_CANARY} -le 256 &&
     "$CREDENTIAL_REFRESH_CANARY" =~ ^[A-Za-z0-9._-]+$ ]] ||
    die 'generated credential refresh canary is invalid'
  [[ ${#GITHUB_CREDENTIAL_CANARY} -ge 16 && ${#GITHUB_CREDENTIAL_CANARY} -le 256 &&
     "$GITHUB_CREDENTIAL_CANARY" =~ ^[A-Za-z0-9._-]+$ ]] ||
    die 'generated GitHub credential canary is invalid'
  [[ ${#OPENAI_CREDENTIAL_CANARY} -ge 16 && ${#OPENAI_CREDENTIAL_CANARY} -le 256 &&
     "$OPENAI_CREDENTIAL_CANARY" =~ ^[A-Za-z0-9._-]+$ ]] ||
    die 'generated OpenAI credential canary is invalid'
  [[ ${#ANTHROPIC_CREDENTIAL_CANARY} -ge 16 && ${#ANTHROPIC_CREDENTIAL_CANARY} -le 256 &&
     "$ANTHROPIC_CREDENTIAL_CANARY" =~ ^[A-Za-z0-9._-]+$ ]] ||
    die 'generated Anthropic credential canary is invalid'
  [[ ${#WORKLOAD_SECRET_CANARY} -ge 16 && ${#WORKLOAD_SECRET_CANARY} -le 256 &&
     "$WORKLOAD_SECRET_CANARY" =~ ^[A-Za-z0-9._-]+$ ]] ||
    die 'generated workload-secret canary is invalid'
  log 'enrolling synthetic protected Codex/GitHub OAuth, OpenAI/Anthropic API-key, and generated SSH credentials through public commands'
  run_cw_connect_synthetic_codex
  run_cw_connect_synthetic_github
  run_cw_with_secret_stdin "$OPENAI_CREDENTIAL_CANARY" \
    credentials --local add openai --name native-broker-openai
  run_cw_with_secret_stdin "$ANTHROPIC_CREDENTIAL_CANARY" \
    credentials --local add anthropic --name native-broker-anthropic
  run_cw credentials --local generate ssh --name native-broker-ssh
  run_cw secrets --local projects create "$APP_SECRET_UNSELECTED_PROJECT"
  run_cw_with_secret_stdin "$WORKLOAD_SECRET_CANARY" \
    secrets --local --project "$APP_SECRET_UNSELECTED_PROJECT" set CW_NATIVE_SMOKE_SECRET
  run_cw secrets --local --project "$APP_SECRET_UNSELECTED_PROJECT" list --output json
  jq -e '
    length == 1 and
    (.[0] | keys | sort) == ["created_at", "key", "updated_at"] and
    .[0].key == "CW_NATIVE_SMOKE_SECRET" and
    (tostring | contains("cwworkload") | not)
  ' "$LAST_STDOUT" >/dev/null || die 'unselected workload-secret inventory was not key-only'
  run_cw secrets --local --user list --output json
  jq -e 'length == 0' "$LAST_STDOUT" >/dev/null ||
    die 'local personal-secret store was not empty before its selected fixture'
  run_cw credentials --local list --output json
  jq -e '
    length == 5 and
    ([.[] | select(.provider == "github")] | length) == 1 and
    any(.[];
      .placement == "local" and
      .owner == "user/local-user" and
      .provider == "openai" and
      .authentication_kind == "oauth" and
      .name == "native-broker-codex" and
      .account_hint == "native-smoke@example.test" and
      .status == "active" and
      .revocation_generation == 1 and
      .protected_store_persistence == "operating_system" and
      .cleanup_pending == false
    ) and
    any(.[];
      .placement == "local" and
      .owner == "user/local-user" and
      .provider == "github" and
      .authentication_kind == "oauth" and
      .name == "native-broker-github" and
      .account_hint == null and
      .status == "active" and
      .revocation_generation == 1 and
      .protected_store_persistence == "operating_system" and
      .cleanup_pending == false
    ) and
    any(.[];
      .placement == "local" and
      .owner == "user/local-user" and
      .provider == "openai" and
      .authentication_kind == "api_key" and
      .name == "native-broker-openai" and
      .account_hint == null and
      .status == "active" and
      .revocation_generation == 1 and
      .protected_store_persistence == "operating_system" and
      .cleanup_pending == false
    ) and
    any(.[];
      .placement == "local" and
      .owner == "user/local-user" and
      .provider == "anthropic" and
      .authentication_kind == "api_key" and
      .name == "native-broker-anthropic" and
      .account_hint == null and
      .status == "active" and
      .revocation_generation == 1 and
      .protected_store_persistence == "operating_system" and
      .cleanup_pending == false
    ) and
    any(.[];
      .placement == "local" and
      .owner == "user/local-user" and
      .provider == "ssh" and
      .authentication_kind == "ssh_key" and
      .name == "native-broker-ssh" and
      .account_hint == null and
      .expires_at_unix == null and
      (.ssh_public_key | keys | sort) == ["fingerprint", "openssh"] and
      (.ssh_public_key.openssh | test("^ssh-(ed25519|rsa) [A-Za-z0-9+/]+={0,2}$")) and
      (.ssh_public_key.fingerprint | test("^SHA256:[A-Za-z0-9+/]+={0,2}$")) and
      .status == "active" and
      .revocation_generation == 1 and
      .protected_store_persistence == "operating_system" and
      .cleanup_pending == false
    )
  ' "$LAST_STDOUT" >/dev/null || die 'synthetic protected credential metadata drifted'
  CREDENTIAL_ID="$(jq -er '.[] | select(.provider == "openai" and .authentication_kind == "oauth" and .name == "native-broker-codex") | .id | select(test("^[0-9a-f-]{36}$"))' "$LAST_STDOUT")" ||
    die 'synthetic protected credential ID is invalid'
  GITHUB_CREDENTIAL_ID="$(jq -er '.[] | select(.provider == "github" and .authentication_kind == "oauth" and .name == "native-broker-github") | .id | select(test("^[0-9a-f-]{36}$"))' "$LAST_STDOUT")" ||
    die 'synthetic protected GitHub credential ID is invalid'
  OPENAI_CREDENTIAL_ID="$(jq -er '.[] | select(.provider == "openai" and .authentication_kind == "api_key" and .name == "native-broker-openai") | .id | select(test("^[0-9a-f-]{36}$"))' "$LAST_STDOUT")" ||
    die 'synthetic protected OpenAI credential ID is invalid'
  ANTHROPIC_CREDENTIAL_ID="$(jq -er '.[] | select(.provider == "anthropic" and .authentication_kind == "api_key" and .name == "native-broker-anthropic") | .id | select(test("^[0-9a-f-]{36}$"))' "$LAST_STDOUT")" ||
    die 'synthetic protected Anthropic credential ID is invalid'
  SSH_CREDENTIAL_ID="$(jq -er '.[] | select(.provider == "ssh" and .authentication_kind == "ssh_key" and .name == "native-broker-ssh") | .id | select(test("^[0-9a-f-]{36}$"))' "$LAST_STDOUT")" ||
    die 'synthetic protected SSH credential ID is invalid'
  SSH_PUBLIC_KEY="$(jq -er --arg id "$SSH_CREDENTIAL_ID" '.[] | select(.id == $id) | .ssh_public_key.openssh' "$LAST_STDOUT")" ||
    die 'synthetic protected SSH public key is invalid'
  SSH_PUBLIC_KEY_FINGERPRINT="$(jq -er --arg id "$SSH_CREDENTIAL_ID" '.[] | select(.id == $id) | .ssh_public_key.fingerprint' "$LAST_STDOUT")" ||
    die 'synthetic protected SSH public-key fingerprint is invalid'
  printf '%s\n' "$SSH_PUBLIC_KEY" >"$MOUNT_SOURCE/native-ssh-public-key.pub"
  chmod 0600 "$MOUNT_SOURCE/native-ssh-public-key.pub"
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" set codex "id:$CREDENTIAL_ID"
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" get --output json
  jq -e --arg credential "$CREDENTIAL_ID" '
    length == 1 and .[0].revision == 1 and
    (.[0].entries | keys) == ["codex"] and .[0].entries.codex == $credential
  ' "$LAST_STDOUT" >/dev/null ||
    die 'first profile set did not create exactly revision one'
  # GitHub is the one account connection, automatically included in grants;
  # it cannot be selected or stored as a profile entry.
  run_cw_expect_failure credentials --local --profile "$CREDENTIAL_PROFILE_NAME" set github "id:$GITHUB_CREDENTIAL_ID"
  rg -qF 'every profile includes your one GitHub connection' "$LAST_STDERR" ||
    die 'profile GitHub selection did not refuse with singleton connection guidance'
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" get --output json
  jq -e --arg credential "$CREDENTIAL_ID" '
    length == 1 and .[0].revision == 1 and
    (.[0].entries | keys) == ["codex"] and .[0].entries.codex == $credential
  ' "$LAST_STDOUT" >/dev/null ||
    die 'refused GitHub profile selection changed profile revision or entries'
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" set openai "id:$OPENAI_CREDENTIAL_ID"
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" get --output json
  jq -e --arg credential "$CREDENTIAL_ID" --arg openai "$OPENAI_CREDENTIAL_ID" '
    length == 1 and .[0].revision == 2 and
    (.[0].entries | keys) == ["codex", "openai"] and
    .[0].entries.codex == $credential and .[0].entries.openai == $openai
  ' "$LAST_STDOUT" >/dev/null ||
    die 'second profile set did not create exactly revision two'
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" set anthropic "id:$ANTHROPIC_CREDENTIAL_ID"
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" get --output json
  jq -e --arg credential "$CREDENTIAL_ID" \
    --arg openai "$OPENAI_CREDENTIAL_ID" --arg anthropic "$ANTHROPIC_CREDENTIAL_ID" '
    length == 1 and
    .[0].placement == "local" and
    .[0].owner == "user/local-user" and
    .[0].name == "native-broker" and
    .[0].revision == 3 and
    (.[0].entries | keys) == ["anthropic", "codex", "openai"] and
    .[0].entries.codex == $credential and
    .[0].entries.openai == $openai and
    .[0].entries.anthropic == $anthropic
  ' "$LAST_STDOUT" >/dev/null || die 'third profile set did not create exact revision three'
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" set ssh "id:$SSH_CREDENTIAL_ID"
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" get --output json
  jq -e --arg credential "$CREDENTIAL_ID" \
    --arg openai "$OPENAI_CREDENTIAL_ID" --arg anthropic "$ANTHROPIC_CREDENTIAL_ID" \
    --arg ssh "$SSH_CREDENTIAL_ID" '
    length == 1 and
    .[0].placement == "local" and
    .[0].owner == "user/local-user" and
    .[0].name == "native-broker" and
    .[0].revision == 4 and
    (.[0].entries | keys) == ["anthropic", "codex", "openai", "ssh"] and
    .[0].entries.codex == $credential and
    .[0].entries.openai == $openai and
    .[0].entries.anthropic == $anthropic and
    .[0].entries.ssh == $ssh
  ' "$LAST_STDOUT" >/dev/null || die 'synthetic access profile metadata drifted'
  run_cw credentials --local list --output json
  jq -e --arg github "$GITHUB_CREDENTIAL_ID" '
    [.[] | select(.provider == "github")] |
    length == 1 and .[0].id == $github and
    .[0].authentication_kind == "oauth" and .[0].status == "active" and
    .[0].revocation_generation == 1 and
    .[0].protected_store_persistence == "operating_system" and
    .[0].cleanup_pending == false
  ' "$LAST_STDOUT" >/dev/null || die 'profile selection changed the account GitHub connection'
  prepare_application_secret_fixture
  CREATE_ACCESS_ARGS=(--profile "local:user/$CREDENTIAL_PROFILE_NAME" \
    --secrets "local:$APP_SECRET_PROJECT_A" --user-secrets local --yes)
fi

if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  log 'creating a broker-bound 2-vCPU, 16-GiB native environment'
  CREATE_DOCKER_ARGS=(--no-docker)
  EXPECTED_OWNED_OBJECT_COUNT=6
else
  log 'creating account-free 2-vCPU, 16-GiB native environment'
  CREATE_DOCKER_ARGS=(--docker-disk 1Gi)
  EXPECTED_OWNED_OBJECT_COUNT=7
fi
ALLOW_REGISTRY_EGRESS=1
CW_COMMAND_TIMEOUT_SECONDS=1500
run_cw env create --local --name "$NAME" --cpu 2 --memory 16GB \
  --path "$WORKSPACE" "${CREATE_ACCESS_ARGS[@]}" "${CREATE_DOCKER_ARGS[@]}" --output json
ALLOW_REGISTRY_EGRESS=0
CW_COMMAND_TIMEOUT_SECONDS=180
ENV_CREATED=1
jq -e --arg listen "127.0.0.1:$HOST_PORT" --arg network "$MESH_NETWORK" '
  .name == "native-smoke" and
  .backend == "cloud-hypervisor" and
  .state == "running" and
  .selected == true and
  .cpu == 2 and
  .memory == "16Gi" and
  .working_directory == "/workspace/github" and
  .workspace_inputs == 5 and
  .skill_count == 3 and
  .skill_snapshot_generation == 1 and
  (.skill_snapshot | test("^[0-9a-f]{64}$")) and
  .network == $network and
  (has("error_code") | not) and
  .ports == [{"listen": $listen, "guest_port": 3000}] and
  (.workspace_plan | test("^[0-9a-f]{64}$"))
' "$LAST_STDOUT" >/dev/null || die 'created native environment metadata drifted'
if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  jq -e 'has("docker_disk") | not' "$LAST_STDOUT" >/dev/null ||
    die 'Docker-disabled broker environment metadata drifted'
else
  jq -e '.docker_disk == "1Gi"' "$LAST_STDOUT" >/dev/null ||
    die 'native Docker disk metadata drifted'
fi
INITIAL_SKILL_SNAPSHOT="$(jq -er '.skill_snapshot | select(test("^[0-9a-f]{64}$"))' "$LAST_STDOUT")" ||
  die 'created native environment omitted its immutable skill snapshot identity'
rg -qF 'direct mounts let guest root inspect every file' "$LAST_STDERR" ||
  die 'native creation did not present the direct-share guest-root warning'
rg -qF 'Read-write grants let guest root modify or delete that host content' "$LAST_STDERR" ||
  die 'native creation did not present the direct-share write warning'
if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  jq -e '
    .access_profile == "user/native-broker" and
    .access_profile_revision == 4
  ' "$LAST_STDOUT" >/dev/null || die 'created native environment access profile drifted'
fi
[[ ! -e "$SOURCE_HOOK_MARKER" ]] || die 'source Git hook ran during native clone preparation'
[[ ! -e "$SOURCE_CREDENTIAL_MARKER" ]] ||
  die 'source Git credential helper ran during native clone preparation'
printf 'host changed after environment creation\n' >"$WORKSPACE/README.md"
printf 'host-only untracked content\n' >"$WORKSPACE/host-only.txt"
printf 'copy mount host changed after creation\n' >"$MOUNT_SOURCE/data.txt"
printf 'copy mount host-only content\n' >"$MOUNT_SOURCE/host-only.txt"
printf '%s\n' 'repository skill generation two' >"$REPOSITORY_SKILL_SOURCE/SKILL.md"
printf '%s\n' 'direct skill generation two' >"$DIRECT_SKILL_SOURCE/SKILL.md"
printf '%s\n' 'user skill generation two' >"$USER_SKILL_SOURCE/SKILL.md"
printf 'direct read-only host changed after creation\n' >"$DIRECT_RO_SOURCE/data.txt"
run_cw env list --local --output json
jq -e '
  length == 1 and
  (.[0] |
    .name == "native-smoke" and
    .placement == "local" and
    .selected == true and
    .state == "running" and
    .daemon_health == "ready")
' "$LAST_STDOUT" >/dev/null || die 'native environment list metadata drifted'
run_cw use --local "$NAME"
rg -qxF 'Current target set to native-smoke.' "$LAST_STDERR" ||
  die 'native environment selection output drifted'
run_cw current
rg -qxF 'native-smoke  network: native-smoke-network' "$LAST_STDOUT" ||
  die 'native current-target output drifted'
[[ "$(stat -c '%a' "$STATE_ROOT")" == 700 ]] || die 'native state root is not mode 0700'
[[ "$(stat -c '%a' "$STATE_ROOT/supervisor.db")" == 600 ]] ||
  die 'native supervisor database is not mode 0600'
for sqlite_sidecar in "$STATE_ROOT/supervisor.db-wal" "$STATE_ROOT/supervisor.db-shm"; do
  [[ ! -e "$sqlite_sidecar" || "$(stat -c '%a' "$sqlite_sidecar")" == 600 ]] ||
    die "native supervisor database sidecar is not mode 0600: $sqlite_sidecar"
done
[[ "$(native_database_value contract)" == '1129797197:12:wal:ok' ]] ||
  die 'native supervisor database contract drifted'
wait_for_journal_complete ||
  die "initial create returned before its lifecycle journal became terminal: $(native_database_value journal_summary)"
[[ "$(native_database_value ownership)" == "64:$EXPECTED_OWNED_OBJECT_COUNT" ]] ||
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
if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  [[ ! -e "$KEYRING_RUNTIME/codewire/workload-secrets-v1" ]] ||
    die 'application selection created a second durable delivery store'
  # shellcheck disable=SC2016 # This variable belongs to the guest environment.
  run_cw run --no-tty -- /bin/sh -lc 'test -z "${CW_NATIVE_SMOKE_SECRET+x}"'
fi

log 'checking confined live read-only and acknowledged read-write direct shares'
assert_direct_share_processes
run_cw run --no-tty -- /bin/sh -lc \
  'set -eu; grep -qx "direct read-only host changed after creation" /workspace/direct-ro/data.txt; grep -qx "direct read-write before creation" /workspace/direct-rw/data.txt; if cat /workspace/direct-ro/outside.txt >/dev/null 2>&1; then exit 81; fi; if printf forbidden > /workspace/direct-ro/guest-write.txt 2>/dev/null; then exit 82; fi; test ! -e /workspace/direct-ro/guest-write.txt; printf "direct guest write\n" > /workspace/direct-rw/guest-write.txt; if printf forbidden > /workspace/direct-rw/outside.txt 2>/dev/null; then exit 83; fi'
[[ "$(cat "$DIRECT_RW_SOURCE/guest-write.txt")" == 'direct guest write' ]] ||
  die 'acknowledged direct read-write guest change did not reach the selected host source'
[[ ! -e "$DIRECT_RO_SOURCE/guest-write.txt" ]] ||
  die 'read-only direct share changed its selected host source'
[[ "$(cat "$DIRECT_OUTSIDE_SOURCE/data.txt")" == 'direct outside must remain isolated' ]] ||
  die 'direct-share symlink access mutated unselected host content'

if [[ "$MANAGED_CREDENTIAL_BROKER" -eq 1 ]]; then
  run_application_secret_smoke
  if [[ "$MANAGED_AGENT_SESSIONS" -eq 1 ]]; then
    log 'checking actual pinned guest managed sessions and parent continuation'
    run_native_managed_agent_smoke
  fi
  log 'checking protected injection, redaction, denial, broker recovery, revocation, and audit'
  run_managed_credential_broker_smoke
  run_cw credentials --local get "id:$CREDENTIAL_ID" --output json
  jq -e '
    length == 1 and
    .[0].status == "revoked" and
    .[0].revocation_generation == 2 and
    .[0].protected_store_persistence == "operating_system" and
    .[0].cleanup_pending == false
  ' "$LAST_STDOUT" >/dev/null || die 'synthetic credential revocation metadata drifted'
  run_cw credentials --local get "id:$SSH_CREDENTIAL_ID" --output json
  jq -e --arg key "$SSH_PUBLIC_KEY" --arg fingerprint "$SSH_PUBLIC_KEY_FINGERPRINT" '
    length == 1 and
    .[0].provider == "ssh" and
    .[0].authentication_kind == "ssh_key" and
    .[0].status == "revoked" and
    .[0].revocation_generation == 2 and
    .[0].ssh_public_key.openssh == $key and
    .[0].ssh_public_key.fingerprint == $fingerprint and
    .[0].protected_store_persistence == "operating_system" and
    .[0].cleanup_pending == false
  ' "$LAST_STDOUT" >/dev/null || die 'synthetic SSH revocation metadata drifted'

  log 'stopping the VM before scanning all durable test-owned state'
  run_cw env stop --local "$NAME" --output json
  jq -e '.state == "stopped"' "$LAST_STDOUT" >/dev/null ||
    die 'broker-bound native environment did not stop'
  wait_for_journal_complete ||
    die 'broker-bound native stop returned before its lifecycle journal became terminal'
  assert_direct_share_processes_stopped
  # The preceding scenario deliberately revoked the selected credential and
  # killed its authority. Detach that now-unusable profile through the public
  # API before the independent offline/direct-share lifecycle scenario.
  run_cw env update --local "$NAME" --clear-profile --yes --output json
  jq -e '
    .state == "stopped" and
    .access_profile == null and
    .access_profile_revision == null and
    .source_selection.credentials == null
  ' "$LAST_STDOUT" >/dev/null || die 'revoked profile remained selected after clear'
  wait_for_journal_complete ||
    die 'stopped profile clear did not finish its lifecycle journal'
  printf 'direct read-only offline host change\n' >"$DIRECT_RO_SOURCE/restart.txt"
  printf 'direct read-write offline host change\n' >"$DIRECT_RW_SOURCE/restart.txt"
  log 'checking offline restart reopens the exact direct-share roots'
  run_cw env start --local "$NAME" --output json
  jq -e '.state == "running"' "$LAST_STDOUT" >/dev/null ||
    die 'broker-bound native environment did not restart'
  assert_direct_share_processes
  # shellcheck disable=SC2016 # SSH_AUTH_SOCK belongs to the guest environment.
  run_cw run --no-tty -- /bin/sh -lc \
    'set -eu; test -z "${SSH_AUTH_SOCK+x}"; grep -qx "direct read-only offline host change" /workspace/direct-ro/restart.txt; grep -qx "direct read-write offline host change" /workspace/direct-rw/restart.txt; grep -qx "direct guest write" /workspace/direct-rw/guest-write.txt; printf "direct restarted guest write\n" > /workspace/direct-rw/restarted.txt'
  [[ "$(cat "$DIRECT_RW_SOURCE/restarted.txt")" == 'direct restarted guest write' ]] ||
    die 'restarted direct read-write share was not live'
  # Keep the fixture through the preceding restart so the unchanged startup
  # script remains valid. Retire it only before the final stop and deletion.
  run_cw run --no-tty -- /bin/bash /workspace/fixtures/stock-ssh-workload.sh cleanup
  rg -qxF stock-ssh-workload-cleaned "$LAST_STDOUT" || die 'stock SSH fixture cleanup failed'
  run_cw env stop --local "$NAME" --output json
  jq -e '.state == "stopped"' "$LAST_STDOUT" >/dev/null ||
    die 'restarted broker-bound native environment did not stop'
  wait_for_journal_complete ||
    die 'restarted broker-bound native stop did not finish its journal'
  assert_direct_share_processes_stopped
  scan_for_credential_canary before-delete-access-token "$CREDENTIAL_CANARY"
  scan_for_credential_canary before-delete-refresh-token "$CREDENTIAL_REFRESH_CANARY"
  scan_for_credential_canary before-delete-github-token "$GITHUB_CREDENTIAL_CANARY"
  scan_for_credential_canary before-delete-openai-key "$OPENAI_CREDENTIAL_CANARY"
  scan_for_credential_canary before-delete-anthropic-key "$ANTHROPIC_CREDENTIAL_CANARY"
  scan_for_credential_canary before-delete-workload-secret "$WORKLOAD_SECRET_CANARY"

  log 'deleting the environment, profile, credentials, and protected-store entries'
  run_cw env rm --local "$NAME" --yes
  ENV_CREATED=0
  assert_current_target_cleared
  [[ -d "$DIRECT_RO_SOURCE" && -d "$DIRECT_RW_SOURCE" ]] ||
    die 'environment deletion removed a direct-share host root'
  [[ "$(cat "$DIRECT_RW_SOURCE/guest-write.txt")" == 'direct guest write' &&
     "$(cat "$DIRECT_RW_SOURCE/restarted.txt")" == 'direct restarted guest write' ]] ||
    die 'environment deletion changed acknowledged direct-share host content'
  run_cw credentials --local --profile "$CREDENTIAL_PROFILE_NAME" delete --yes
  run_cw credentials --local delete "id:$CREDENTIAL_ID" --yes
  run_cw credentials --local delete "id:$GITHUB_CREDENTIAL_ID" --yes
  run_cw credentials --local delete "id:$OPENAI_CREDENTIAL_ID" --yes
  run_cw credentials --local delete "id:$ANTHROPIC_CREDENTIAL_ID" --yes
  run_cw credentials --local delete "id:$SSH_CREDENTIAL_ID" --yes
  run_cw secrets --local --user delete CW_NATIVE_PERSONAL_ONLY
  run_cw secrets --local --user delete CW_NATIVE_SCOPE_COLLISION
  run_cw secrets --local --user delete CW_NATIVE_PRECEDENCE
  run_cw secrets --local projects delete "$APP_SECRET_PROJECT_A" --yes
  run_cw secrets --local projects delete "$APP_SECRET_PROJECT_B" --yes
  run_cw secrets --local projects delete "$APP_SECRET_UNSELECTED_PROJECT" --yes
  run_cw secrets --local projects list --output json
  jq -e 'length == 0' "$LAST_STDOUT" >/dev/null ||
    die 'synthetic application projects remained after deletion'
  run_cw secrets --local --user list --output json
  jq -e 'length == 0' "$LAST_STDOUT" >/dev/null ||
    die 'synthetic workload-secret metadata remained after deletion'
  run_cw credentials --local list --output json
  jq -e 'length == 0' "$LAST_STDOUT" >/dev/null ||
    die 'synthetic credential metadata remained after deletion'
  run_cw credentials --local profiles list --output json
  jq -e 'length == 0' "$LAST_STDOUT" >/dev/null ||
    die 'synthetic access profile remained after deletion'
  keyring_service_ready || die 'isolated Secret Service exited before deletion proof'
  if secret_tool_isolated lookup \
    application codewire \
    service sh.codewire.credentials \
    entry "local/credentials/$CREDENTIAL_ID/material-v1" \
    >/dev/null 2>"$SMOKE_ROOT/deleted-keyring-entry.stderr"; then
    die 'synthetic protected-store entry remained after credential deletion'
  fi
  if secret_tool_isolated lookup \
    application codewire \
    service sh.codewire.credentials \
    entry "local/credentials/$GITHUB_CREDENTIAL_ID/material-v1" \
    >/dev/null 2>"$SMOKE_ROOT/deleted-github-keyring-entry.stderr"; then
    die 'synthetic GitHub protected-store entry remained after credential deletion'
  fi
  if secret_tool_isolated lookup \
    application codewire \
    service sh.codewire.credentials \
    entry "local/credentials/$OPENAI_CREDENTIAL_ID/material-v1" \
    >/dev/null 2>"$SMOKE_ROOT/deleted-openai-keyring-entry.stderr"; then
    die 'synthetic OpenAI protected-store entry remained after credential deletion'
  fi
  if secret_tool_isolated lookup \
    application codewire \
    service sh.codewire.credentials \
    entry "local/credentials/$ANTHROPIC_CREDENTIAL_ID/material-v1" \
    >/dev/null 2>"$SMOKE_ROOT/deleted-anthropic-keyring-entry.stderr"; then
    die 'synthetic Anthropic protected-store entry remained after credential deletion'
  fi
  if secret_tool_isolated lookup \
    application codewire \
    service sh.codewire.credentials \
    entry "local/credentials/$SSH_CREDENTIAL_ID/material-v1" \
    >/dev/null 2>"$SMOKE_ROOT/deleted-ssh-keyring-entry.stderr"; then
    die 'synthetic SSH protected-store entry remained after credential deletion'
  fi
  scan_for_credential_canary after-delete-access-token "$CREDENTIAL_CANARY"
  scan_for_credential_canary after-delete-refresh-token "$CREDENTIAL_REFRESH_CANARY"
  scan_for_credential_canary after-delete-github-token "$GITHUB_CREDENTIAL_CANARY"
  scan_for_credential_canary after-delete-openai-key "$OPENAI_CREDENTIAL_CANARY"
  scan_for_credential_canary after-delete-anthropic-key "$ANTHROPIC_CREDENTIAL_CANARY"
  scan_for_credential_canary after-delete-workload-secret "$WORKLOAD_SECRET_CANARY"
  unset CREDENTIAL_CANARY
  unset CREDENTIAL_REFRESH_CANARY
  unset GITHUB_CREDENTIAL_CANARY
  unset OPENAI_CREDENTIAL_CANARY
  unset ANTHROPIC_CREDENTIAL_CANARY
  unset WORKLOAD_SECRET_CANARY
  unset SSH_PUBLIC_KEY SSH_PUBLIC_KEY_FINGERPRINT
  unset APP_SECRET_CANARY_A APP_SECRET_CANARY_B
  unset APP_SECRET_USER_ONLY_CANARY APP_SECRET_USER_COLLISION_CANARY
  unset APP_SECRET_USER_PRECEDENCE_CANARY

  [[ ! -e "$TRIPWIRE" ]] ||
    die "a forbidden fallback was invoked: $(tr '\n' ' ' <"$TRIPWIRE")"
  terminate_exact_credential_authority || die 'bounded credential-authority teardown failed'
  terminate_exact_supervisor || die 'bounded supervisor teardown failed'
  [[ -z "$(owned_processes)" ]] ||
    die 'a native runtime or credential process remained after bounded teardown'
  stop_isolated_keyring || die 'bounded isolated keyring teardown failed'
  log 'PASS (Linux/KVM isolated protected credential-broker product flow)'
  exit 0
fi

run_named_reader_smoke

log 'checking public Exec/File over the owner-only supervisor UDS'
run_public_data_smoke

log 'checking binary file transfer through cw and the public supervisor FileService'
CW_UPLOAD="$SMOKE_ROOT/cw-upload.bin"
CW_DOWNLOAD="$SMOKE_ROOT/cw-download.bin"
/usr/bin/env python3 - "$CW_UPLOAD" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_bytes(bytes(range(256)) * 257 + b"\x00codewire-cp\xff")
PY
CW_UPLOAD_SHA256="$(sha256sum "$CW_UPLOAD" | cut -d' ' -f1)"
run_cw env cp --local "$CW_UPLOAD" "$NAME:/workspace/cw-upload.bin"
run_cw run --no-tty -- /bin/sh -lc \
  "test \"\$(sha256sum /workspace/cw-upload.bin | cut -d' ' -f1)\" = '$CW_UPLOAD_SHA256'"
run_cw env cp --local "$NAME:/workspace/cw-upload.bin" "$CW_DOWNLOAD"
cmp "$CW_UPLOAD" "$CW_DOWNLOAD" || die 'cw binary file transfer changed content'

log 'checking codewire.yaml loopback host-port publication through the native VM'
HOST_PORT_SERVER='const net=require("node:net");const server=net.createServer((socket)=>{const chunks=[];socket.on("data",(chunk)=>chunks.push(chunk));socket.on("end",()=>{const request=Buffer.concat(chunks).toString("utf8");socket.end(request==="codewire-host-port-request"?"codewire-host-port-response":"unexpected-request",()=>server.close());});});server.listen(3000,"0.0.0.0",()=>process.stdout.write("codewire-host-port-ready\n"));'
run_cw run --detach --no-tty --output json -- node -e "$HOST_PORT_SERVER"
HOST_PORT_SESSION_ID="$(jq -er '.session_id | select(type == "string" and length > 0)' "$LAST_STDOUT")" ||
  die 'host-port guest session did not return an identity'
HOST_PORT_SESSION_READY=0
for _attempt in {1..200}; do
  run_cw logs "$NAME" "$HOST_PORT_SESSION_ID" --raw
  if rg -qxF 'codewire-host-port-ready' "$LAST_STDOUT"; then
    HOST_PORT_SESSION_READY=1
    break
  fi
  sleep 0.05
done
[[ "$HOST_PORT_SESSION_READY" -eq 1 ]] ||
  die 'host-port guest listener did not become ready'
if ! /usr/bin/env python3 - "$HOST_PORT" \
  >"$SMOKE_ROOT/host-port.stdout" 2>"$SMOKE_ROOT/host-port.stderr" <<'PY'
import socket
import sys

port = int(sys.argv[1])
request = b"codewire-host-port-request"
expected = b"codewire-host-port-response"
with socket.create_connection(("127.0.0.1", port), timeout=2) as stream:
    stream.settimeout(2)
    stream.sendall(request)
    stream.shutdown(socket.SHUT_WR)
    response = bytearray()
    while chunk := stream.recv(4096):
        response.extend(chunk)
if bytes(response) != expected:
    raise SystemExit(f"unexpected host-port response: {bytes(response)!r}")
print("codewire-native-host-port: PASS")
PY
then
  cat "$SMOKE_ROOT/host-port.stdout" "$SMOKE_ROOT/host-port.stderr" >>"$TRANSCRIPT"
  tail -n 80 "$SMOKE_ROOT/host-port.stderr" >&2
  die 'native host-port round trip failed'
fi
cat "$SMOKE_ROOT/host-port.stdout" "$SMOKE_ROOT/host-port.stderr" >>"$TRANSCRIPT"
[[ "$(cat "$SMOKE_ROOT/host-port.stdout")" == 'codewire-native-host-port: PASS' ]] ||
  die 'native host-port receipt drifted'
HOST_PORT_SESSION_EXITED=0
for _attempt in {1..100}; do
  run_cw list --output json
  if jq -e --arg session_id "$HOST_PORT_SESSION_ID" '
    any(.[];
      .session_id == $session_id and
      .state == "Exited" and
      .exit_code == 0
    )
  ' "$LAST_STDOUT" >/dev/null; then
    HOST_PORT_SESSION_EXITED=1
    break
  fi
  sleep 0.05
done
[[ "$HOST_PORT_SESSION_EXITED" -eq 1 ]] ||
  die 'host-port guest session did not exit successfully'

log 'checking stock Codex 0.157.0 over the synthetic guest credential bridge'
run_codex_credential_bridge_smoke

log 'checking bounded public daemon status over the owner-only supervisor UDS'
run_cw env --local daemon status "$NAME" --output json
jq -e '
  .state == "ready" and
  .protocol_version == 1 and
  .minimum_protocol_version == 1 and
  (.daemon_version | type == "string" and length > 0) and
  .capabilities == [
    "attach.v1",
    "credential_bridge.v1",
    "exec.v1",
    "files.v1",
    "health.v1",
    "pty.v1",
    "session_input.v1",
    "session_metadata.v1",
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
  'printf "guest-cwd=%s\n" "$PWD"; printf "guest-pid1-comm="; cat /proc/1/comm; if readlink /proc/1/exe >/dev/null 2>&1; then printf "guest-pid1-exe=exposed\n"; else printf "guest-pid1-exe=confined\n"; fi; printf "guest-sealed-init="; /run/codewire-runtime/init identity; printf "guest-machine-id="; cat /etc/machine-id; awk "/^NoNewPrivs:/ { printf \"guest-no-new-privileges=%s\\n\", \$2 } /^CapEff:/ { printf \"guest-effective-capabilities=%s\\n\", \$2 }" /proc/self/status; printf "guest-cpus="; grep -c "^processor" /proc/cpuinfo; grep "^MemTotal:" /proc/meminfo; printf "workspace-node="; node --version; test -d /workspace/github/.git; test -d /workspace/gitea/.git; test -z "$(git -C /workspace/github status --porcelain=v1 --untracked-files=all)"; test -z "$(git -C /workspace/gitea status --porcelain=v1 --untracked-files=all)"; grep -qx "copy mount before creation" /workspace/fixtures/data.txt; grep -qx "hidden copy mount content" /workspace/fixtures/.hidden; grep -qx "nested copy mount content" /workspace/fixtures/nested/file.txt; test "$(readlink /workspace/fixtures/link.txt)" = nested/file.txt; test "$(stat -c %h /workspace/fixtures/data.txt)" = 1; test "$(stat -c %h /workspace/fixtures/hardlink.txt)" = 1; test ! -e /workspace/fixtures/host-only.txt; /workspace/fixtures/tool.sh; grep -qx "repository skill generation one" "$CODEX_HOME/skills/repo-smoke/SKILL.md"; grep -qx "repository skill generation one" "$HOME/.claude/skills/repo-smoke/SKILL.md"; "$CODEX_HOME/skills/repo-smoke/scripts/verify.sh"; grep -qx "direct skill generation one" "$CODEX_HOME/skills/direct-smoke/SKILL.md"; grep -qx "user skill generation one" "$CODEX_HOME/skills/user-smoke/SKILL.md"; test ! -e "$HOME/.codex/skills/repo-smoke"; if printf forbidden >"$CODEX_HOME/skills/repo-smoke/SKILL.md" 2>/dev/null; then exit 84; fi; grep -qx "repository skill generation one" "$CODEX_HOME/skills/repo-smoke/SKILL.md"; printf guest-copy-mount-write > /workspace/fixtures/guest-only.txt; printf "guest-github-head="; git -C /workspace/github rev-parse HEAD; printf "guest-gitea-head="; git -C /workspace/gitea rev-parse HEAD; printf "guest-github-readme-sha="; sha256sum /workspace/github/README.md | cut -d " " -f 1; printf "guest-gitea-readme-sha="; sha256sum /workspace/gitea/README.md | cut -d " " -f 1; printf "guest-github-origin="; git -C /workspace/github config --local --get remote.origin.url; printf "guest-gitea-origin="; git -C /workspace/gitea config --local --get remote.origin.url; git -C /workspace/github config --local --list; git -C /workspace/gitea config --local --list; printf persistence-ok > /workspace/sentinel.txt'
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
rg -qF 'copy-mount-executable-ok' "$LAST_STDOUT" ||
  die 'explicit copy mount executable content was unavailable in the guest'
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
   rg -qF "$WORKSPACE" "$LAST_STDOUT" || rg -qF "$MOUNT_SOURCE" "$LAST_STDOUT"; then
  die 'host Git credential or source-path metadata entered the guest clone'
fi
MEMORY_KIB="$(awk '$1 == "MemTotal:" { print $2 }' "$LAST_STDOUT")"
[[ "$MEMORY_KIB" =~ ^[0-9]+$ && "$MEMORY_KIB" -ge 15000000 && "$MEMORY_KIB" -le 17500000 ]] ||
  die "guest MemTotal is not consistent with 16 GiB: ${MEMORY_KIB:-missing} KiB"

DOCKER_DISK_PATH="$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/disks/docker.raw"
[[ -f "$DOCKER_DISK_PATH" && ! -L "$DOCKER_DISK_PATH" ]] ||
  die 'dedicated Docker data disk is not an exact regular file'
[[ "$(stat -c '%s' "$DOCKER_DISK_PATH")" == 1073741824 ]] ||
  die 'dedicated Docker data disk is not exactly 1 GiB'
[[ "$(stat -c '%d:%i' "$DOCKER_DISK_PATH")" != \
   "$(stat -c '%d:%i' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/disks/state.raw")" ]] ||
  die 'Docker and workspace state disks share an inode'

log 'checking private guest Docker build, run, Compose, pulls, and VM-only publication'
CW_COMMAND_TIMEOUT_SECONDS=900
run_cw run --no-tty -- /workspace/fixtures/docker-smoke.sh \
  "$DOCKER_HOST_PORT" "$DOCKER_PUBLIC_IMAGE"
CW_COMMAND_TIMEOUT_SECONDS=180
for marker in docker-build-run-compose-ok docker-public-private-policy-ok \
  docker-user-auth-visible-ok docker-vm-port-local-ok docker-privileged-boundary-ok; do
  rg -qxF "$marker" "$LAST_STDOUT" || die "guest Docker marker drifted: $marker"
done
if /usr/bin/env python3 - "$DOCKER_HOST_PORT" <<'PY'
import socket
import sys

try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1)
except OSError:
    raise SystemExit(1)
raise SystemExit(0)
PY
then
  die 'docker -p escaped the VM through an unadmitted host port'
fi
run_cw run --no-tty -- docker rm -f codewire-native-smoke-port
[[ ! -e "$WORKSPACE/.docker/config.json" && ! -e "$MOUNT_SOURCE/.docker/config.json" ]] ||
  die 'guest-visible Docker login state escaped into a selected host source'

log 'checking bounded Docker logs and recoverable block and inode exhaustion'
CW_COMMAND_TIMEOUT_SECONDS=900
# shellcheck disable=SC2016 # Expressions are evaluated inside the guest.
run_cw run --no-tty -- /bin/sh -lc '
  set -eu
  docker volume create codewire-native-smoke-bytes >/dev/null
  test "$(docker run --rm --log-driver=none -v codewire-native-smoke-bytes:/data codewire-native-smoke:1913 fill-bytes)" = docker-byte-enospc-ok
  docker volume rm codewire-native-smoke-bytes >/dev/null
  docker volume create codewire-native-smoke-inodes >/dev/null
  test "$(docker run --rm --log-driver=none -v codewire-native-smoke-inodes:/data codewire-native-smoke:1913 fill-inodes)" = docker-inode-enospc-ok
  docker volume rm codewire-native-smoke-inodes >/dev/null
  docker run --name codewire-native-smoke-log codewire-native-smoke:1913 spam-log 41943040 >/dev/null
  log_bytes="$(docker logs codewire-native-smoke-log | wc -c)"
  test "$log_bytes" -gt 0
  test "$log_bytes" -le 33554432
  docker rm codewire-native-smoke-log >/dev/null
  test "$(cat /workspace/sentinel.txt)" = persistence-ok
  docker info >/dev/null
  printf "%s\n" docker-byte-enospc-ok docker-inode-enospc-ok docker-log-bound-ok
'
for marker in docker-byte-enospc-ok docker-inode-enospc-ok docker-log-bound-ok; do
  rg -qxF "$marker" "$LAST_STDOUT" || die "Docker exhaustion marker drifted: $marker"
done
[[ "$(stat -c '%s' "$DOCKER_DISK_PATH")" == 1073741824 ]] ||
  die 'Docker exhaustion changed the dedicated data disk boundary'

log 'checking explicit native restart and persistent workspace identity'
PRE_RESTART_VMM_PID="$(recorded_vmm_pid)"
PRE_RESTART_GENERATION="$(jq -er '.generation' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json")"
run_cw env restart --local "$NAME" --output json
jq -e '.name == "native-smoke" and .state == "running"' "$LAST_STDOUT" >/dev/null ||
  die 'explicit native restart did not return the running environment'
wait_for_journal_complete ||
  die 'explicit native restart returned before its lifecycle journal became terminal'
POST_RESTART_VMM_PID="$(recorded_vmm_pid)"
POST_RESTART_GENERATION="$(jq -er '.generation' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/state.json")"
[[ "$POST_RESTART_VMM_PID" != "$PRE_RESTART_VMM_PID" &&
   -d "/proc/$POST_RESTART_VMM_PID" ]] ||
  die 'explicit native restart did not replace the VMM process'
[[ "$POST_RESTART_GENERATION" -eq "$((PRE_RESTART_GENERATION + 1))" ]] ||
  die 'explicit native restart did not advance exactly one VM generation'
run_cw run --no-tty -- /bin/sh -lc \
  'printf "sentinel="; cat /workspace/sentinel.txt; printf "\nmachine-id="; cat /etc/machine-id'
rg -qxF 'sentinel=persistence-ok' "$LAST_STDOUT" ||
  die 'workspace sentinel did not survive explicit native restart'
rg -qxF "machine-id=$EXPECTED_MACHINE_ID" "$LAST_STDOUT" ||
  die 'environment identity did not survive explicit native restart'
run_docker_persistence_smoke docker-explicit-restart-persistence-ok

log 'checking explicit offline immutable skill refresh and read-only reprojection'
# Refreshing the snapshot can materialize a new OCI root generation. Retain the
# same bounded budget as the preceding guest storage workloads for that rebuild.
run_cw env refresh-skills --local "$NAME" --output json
CW_COMMAND_TIMEOUT_SECONDS=180
jq -e --arg prior "$INITIAL_SKILL_SNAPSHOT" '
  .name == "native-smoke" and
  .state == "running" and
  .skill_count == 3 and
  .skill_snapshot_generation == 2 and
  (.skill_snapshot | test("^[0-9a-f]{64}$")) and
  .skill_snapshot != $prior
' "$LAST_STDOUT" >/dev/null || die 'refreshed native skill snapshot metadata drifted'
# The quoted expression is evaluated by the guest shell, not this host script.
# shellcheck disable=SC2016
run_cw run --no-tty -- /bin/sh -lc \
  'set -eu; grep -qx "repository skill generation two" "$CODEX_HOME/skills/repo-smoke/SKILL.md"; grep -qx "repository skill generation two" "$HOME/.claude/skills/repo-smoke/SKILL.md"; grep -qx "direct skill generation two" "$CODEX_HOME/skills/direct-smoke/SKILL.md"; grep -qx "user skill generation two" "$CODEX_HOME/skills/user-smoke/SKILL.md"; if printf forbidden >"$CODEX_HOME/skills/user-smoke/SKILL.md" 2>/dev/null; then exit 85; fi; grep -qx "user skill generation two" "$CODEX_HOME/skills/user-smoke/SKILL.md"'
[[ "$(cat "$REPOSITORY_SKILL_SOURCE/SKILL.md")" == 'repository skill generation two' &&
   "$(cat "$DIRECT_SKILL_SOURCE/SKILL.md")" == 'direct skill generation two' &&
   "$(cat "$USER_SKILL_SOURCE/SKILL.md")" == 'user skill generation two' ]] ||
  die 'skill refresh mutated a selected host skill source'

log 'checking daemon logs contain only trusted lifecycle journal fields'
DAEMON_GUEST_SENTINEL='guest-output-must-not-enter-daemon-logs-1909'
run_cw run --no-tty -- /bin/sh -lc "printf '%s\\n' '$DAEMON_GUEST_SENTINEL'"
rg -qF "$DAEMON_GUEST_SENTINEL" "$LAST_STDOUT" || die 'guest diagnostic sentinel was not emitted'
run_cw env --local daemon logs "$NAME"
rg -q '^time_unix_ms=[0-9]+ operation=[0-9a-f-]{36} kind=create phase=completed checkpoint=9 stage=OPERATION_STAGE_[A-Z_]+ error=-$' "$LAST_STDOUT" ||
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
      ALL_PROXY='http://127.0.0.1:1' NO_PROXY='127.0.0.1,localhost' \
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
assert_direct_share_processes_stopped
printf 'direct read-only offline host change\n' >"$DIRECT_RO_SOURCE/restart.txt"
printf 'direct read-write offline host change\n' >"$DIRECT_RW_SOURCE/restart.txt"
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
assert_direct_share_processes
run_cw run --no-tty -- /bin/sh -lc 'set -eu; cat /workspace/sentinel.txt; cat /workspace/fixtures/guest-only.txt; grep -qx "copy mount before creation" /workspace/fixtures/data.txt; test ! -e /workspace/fixtures/host-only.txt; grep -qx "direct read-only offline host change" /workspace/direct-ro/restart.txt; grep -qx "direct read-write offline host change" /workspace/direct-rw/restart.txt; grep -qx "direct guest write" /workspace/direct-rw/guest-write.txt; printf "direct restarted guest write\n" > /workspace/direct-rw/restarted.txt; git -C /workspace/github rev-parse HEAD; git -C /workspace/gitea rev-parse HEAD; cat /etc/machine-id'
rg -qF 'persistence-ok' "$LAST_STDOUT" ||
  die 'workspace sentinel did not survive cached-runtime restart'
rg -qF 'guest-copy-mount-write' "$LAST_STDOUT" ||
  die 'explicit copy mount guest state did not survive cached-runtime restart'
rg -qF "$GITHUB_COMMIT" "$LAST_STDOUT" ||
  die 'GitHub workspace did not survive cached-runtime restart'
rg -qF "$GITEA_COMMIT" "$LAST_STDOUT" ||
  die 'git.example.invalid workspace did not survive cached-runtime restart'
rg -qF "$EXPECTED_MACHINE_ID" "$LAST_STDOUT" ||
  die 'environment-specific machine identity did not survive restart'
[[ "$(cat "$DIRECT_RW_SOURCE/restarted.txt")" == 'direct restarted guest write' ]] ||
  die 'restarted direct read-write share was not live'
run_docker_persistence_smoke docker-runtime-generation-persistence-ok

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

log 'checking typed Mesh transport loss and repair through normal CLI status'
stop_smoke_mesh
wait_for_environment_state error ||
  die 'coordinator loss was not classified as an environment error'
jq -e --arg network "$MESH_NETWORK" '
  .state == "error" and
  .network == $network and
  .error_code == "mesh_transport_exit"
' "$LAST_STDOUT" >/dev/null || die 'typed Mesh transport failure did not reach CLI status'
run_cw env --local daemon status "$NAME" --output json
jq -e '
  .state == "unhealthy" and
  .message == "local environment runtime requires repair"
' "$LAST_STDOUT" >/dev/null || die 'daemon status remained healthy after Mesh transport loss'
start_smoke_mesh
jq -e --arg network "$MESH_NETWORK" '
  .selected_network == $network and .auto_connect == true
' \
  "$MESH_OWNER_CONTEXT" >/dev/null || die 'Mesh restart lost the selected network projection'
run_cw env --local daemon repair "$NAME" --output json
jq -e '
  .replaced_pod_name == "" and
  .status.state == "ready" and
  .status.message == "local environment daemon is ready"
' "$LAST_STDOUT" >/dev/null || die 'native daemon did not repair after Mesh transport loss'
run_cw env info --local "$NAME" --output json
jq -e --arg network "$MESH_NETWORK" '
  .state == "running" and
  .network == $network and
  (has("error_code") | not)
' "$LAST_STDOUT" >/dev/null || die 'Mesh repair did not clear the typed runtime failure'
RUNNER_PID="$(native_database_value runner_pid)"

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
run_docker_persistence_smoke docker-vmm-recovery-persistence-ok

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
run_docker_persistence_smoke docker-runner-recovery-persistence-ok
wait_for_journal_complete ||
  die 'native lifecycle journal contains a pending or partial operation'

log 'checking privileged nested Docker ownership remains confined to the guest'
VMM_PID="$(recorded_vmm_pid)" || die 'persisted VMM process identity was not readable'
run_cw_disruptive run --no-tty -- docker run --rm --privileged --pid=host \
  codewire-native-smoke:1913 crash-dockerd
wait_for_environment_state error ||
  die 'guest-local dockerd crash was not classified as an environment error'
wait_for_pid_death "$VMM_PID" || die 'VMM remained live after guest-local dockerd crashed'
run_cw env --local daemon status "$NAME" --output json
jq -e '.state == "unhealthy" and .message == "local environment runtime requires repair"' \
  "$LAST_STDOUT" >/dev/null || die 'daemon remained healthy after guest-local dockerd crashed'
run_cw env --local daemon repair "$NAME" --output json
jq -e '.replaced_pod_name == "" and .status.state == "ready"' "$LAST_STDOUT" >/dev/null ||
  die 'environment daemon did not repair after guest-local dockerd crashed'
RECOVERED_VMM_PID="$(recorded_vmm_pid)" || die 'repaired Docker VMM identity was not readable'
[[ "$RECOVERED_VMM_PID" != "$VMM_PID" && -d "/proc/$RECOVERED_VMM_PID" ]] ||
  die 'Docker crash recovery did not produce a new live VMM process'
# shellcheck disable=SC2016 # Read the persistent file inside the guest.
run_cw run --no-tty -- /bin/sh -lc 'test "$(cat /workspace/sentinel.txt)" = persistence-ok'
run_docker_persistence_smoke docker-crash-persistence-ok

log 'checking journaled offline disk growth and restart-applied CPU and memory'
run_cw env resize --local "$NAME" --cpu 3 --memory 12GB --disk 21GB --yes --force --output json
jq -e '
  .state == "running" and
  .cpu == 3 and
  .memory == "12Gi" and
  .disk == "21Gi"
' "$LAST_STDOUT" >/dev/null || die 'native resize result drifted'
[[ "$(stat -c '%s' "$STATE_ROOT/engine/vms/$ENVIRONMENT_ID/disks/state.raw")" == 22548578304 ]] ||
  die 'native state disk file did not grow to 21 GiB'
[[ "$(native_database_value resize_operation)" == 'restart:completed:9' ]] ||
  die 'native resize journal did not commit all nine effect checkpoints'
run_cw run --no-tty -- /bin/sh -lc \
  'printf "guest-cpus="; grep -c "^processor" /proc/cpuinfo; grep "^MemTotal:" /proc/meminfo; cat /workspace/sentinel.txt'
rg -qF 'guest-cpus=3' "$LAST_STDOUT" || die 'resized guest did not observe exactly 3 vCPUs'
rg -qF 'persistence-ok' "$LAST_STDOUT" || die 'workspace sentinel did not survive resize'
MEMORY_KIB="$(awk '$1 == "MemTotal:" { print $2 }' "$LAST_STDOUT")"
[[ "$MEMORY_KIB" =~ ^[0-9]+$ && "$MEMORY_KIB" -ge 11000000 && "$MEMORY_KIB" -le 13000000 ]] ||
  die "guest MemTotal is not consistent with 12 GiB after resize: ${MEMORY_KIB:-missing} KiB"
run_docker_persistence_smoke docker-resize-persistence-ok
run_cw_expect_failure env resize --local "$NAME" --disk 20Gi --yes --output json
rg -qF 'disk shrink is not supported' "$LAST_STDERR" ||
  die 'native disk shrink did not fail with an actionable error'

log 'deleting the environment and proving complete owned-object cleanup'
run_cw env rm --local "$NAME" --yes
ENV_CREATED=0
assert_current_target_cleared
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
[[ "$(cat "$MOUNT_SOURCE/data.txt")" == 'copy mount host changed after creation' ]] ||
  die 'explicit copy mount guest read or write mutated the selected host source'
[[ "$(cat "$MOUNT_SOURCE/host-only.txt")" == 'copy mount host-only content' ]] ||
  die 'explicit copy mount deletion mutated host-only content'
[[ ! -e "$MOUNT_SOURCE/guest-only.txt" ]] ||
  die 'explicit copy mount guest writes escaped or synchronized into the host source'
[[ -d "$DIRECT_RO_SOURCE" && -d "$DIRECT_RW_SOURCE" ]] ||
  die 'environment deletion removed a direct-share host root'
[[ ! -e "$DIRECT_RO_SOURCE/guest-write.txt" ]] ||
  die 'read-only direct-share host content changed during the lifecycle'
[[ "$(cat "$DIRECT_RW_SOURCE/guest-write.txt")" == 'direct guest write' &&
   "$(cat "$DIRECT_RW_SOURCE/restarted.txt")" == 'direct restarted guest write' ]] ||
  die 'environment deletion changed acknowledged direct-share host content'
[[ "$(cat "$DIRECT_OUTSIDE_SOURCE/data.txt")" == 'direct outside must remain isolated' ]] ||
  die 'direct-share lifecycle changed unselected host content'
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
run_cw env create --local --name "$NAME" --cpu 2 --memory 16GB \
  --path "$WORKSPACE" --path-mode copy --no-network --no-docker --output json
ALLOW_REGISTRY_EGRESS=0
CW_COMMAND_TIMEOUT_SECONDS=180
ENV_CREATED=1
jq -e '
  .name == "native-copy-smoke" and
  .backend == "cloud-hypervisor" and
  .state == "running" and
  (has("docker_disk") | not) and
  .working_directory == "/workspace" and
  .workspace_inputs == 1 and
  (.workspace_plan | test("^[0-9a-f]{64}$"))
' "$LAST_STDOUT" >/dev/null || die 'copy-mode environment metadata drifted'
COPY_ENVIRONMENT_ID="$(native_database_value environment_id)"
[[ ! -e "$STATE_ROOT/engine/vms/$COPY_ENVIRONMENT_ID/disks/docker.raw" ]] ||
  die 'Docker-disabled environment created a Docker data disk'
printf 'host changed after copy creation\n' >"$WORKSPACE/data.txt"
printf 'host-only after copy\n' >"$WORKSPACE/host-only.txt"
# The quoted expression is evaluated by the guest shell, not this host script.
# shellcheck disable=SC2016
run_cw run --no-tty -- /bin/sh -lc \
  'test ! -e .git; test ! -S /var/run/docker.sock; if docker info >/dev/null 2>&1; then exit 86; fi; grep -qx "copy source before creation" data.txt; grep -qx "hidden copy content" .hidden; test "$(readlink link.txt)" = data.txt; test "$(stat -c %h data.txt)" = 1; test "$(stat -c %h hardlink.txt)" = 1; test ! -e host-only.txt; ./tool.sh; printf guest-copy-write > guest-only.txt'
rg -qF 'copy-executable-ok' "$LAST_STDOUT" ||
  die 'copy-mode executable content was unavailable in the guest'
[[ "$(cat "$WORKSPACE/data.txt")" == 'host changed after copy creation' ]] ||
  die 'copy-mode guest read or write mutated the selected host source'
[[ ! -e "$WORKSPACE/guest-only.txt" ]] ||
  die 'copy-mode guest write escaped into the selected host source'
run_cw env rm --local "$NAME" --yes
ENV_CREATED=0
assert_current_target_cleared
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
stop_smoke_mesh
[[ ! -e "$MESH_OWNER_CONTEXT" ]] || die 'Mesh owner projection remained after Mesh shutdown'

[[ ! -e "$TRIPWIRE" ]] || die "a forbidden fallback was invoked: $(tr '\n' ' ' <"$TRIPWIRE")"
if rg -qF 'synthetic-platform-key-must-not-be-used' "$TRANSCRIPT"; then
  die 'synthetic platform credential appeared in CLI output'
fi
terminate_exact_supervisor || die 'bounded supervisor teardown failed'
[[ -z "$(owned_processes)" ]] || die 'an owned process remained after bounded smoke teardown'

log 'PASS (Linux/KVM native cw product flow)'
