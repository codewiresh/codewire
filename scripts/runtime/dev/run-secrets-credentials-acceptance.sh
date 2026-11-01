#!/usr/bin/env bash
# Compose the existing bounded #1922 acceptance journeys without weakening
# their individual auth, topology, evidence, or cleanup contracts.
set -uo pipefail
# The exact setsid PID/process-group identity below requires non-job-control
# launch semantics even if the invoking shell exported unusual Bash options.
set +m

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

readonly -a JOURNEYS=(
  native-local
  local-platform
  dev-application-all-scopes
  dev-provider-ssh
  local-platform-mesh
  live-codex
  live-github
  live-openai
  live-anthropic
  initial-private-checkout
  dev-initial-private-checkout
)

ACCEPTANCE_NORMAL_CW_BIN="${ACCEPTANCE_NORMAL_CW_BIN:-}"
ACCEPTANCE_SYNTHETIC_CW_BIN="${ACCEPTANCE_SYNTHETIC_CW_BIN:-}"
ACCEPTANCE_NATIVE_DATA_PLANE_SMOKE_BIN="${ACCEPTANCE_NATIVE_DATA_PLANE_SMOKE_BIN:-}"
ACCEPTANCE_NATIVE_CREDENTIAL_BRIDGE_SMOKE_BIN="${ACCEPTANCE_NATIVE_CREDENTIAL_BRIDGE_SMOKE_BIN:-}"
ACCEPTANCE_NATIVE_STATE_PROBE_BIN="${ACCEPTANCE_NATIVE_STATE_PROBE_BIN:-}"
ACCEPTANCE_NATIVE_WORKSPACE_IMAGE_IMPORT_BIN="${ACCEPTANCE_NATIVE_WORKSPACE_IMAGE_IMPORT_BIN:-}"
ACCEPTANCE_NATIVE_ARTIFACT_ROOT="${ACCEPTANCE_NATIVE_ARTIFACT_ROOT:-}"
ACCEPTANCE_NATIVE_ARTIFACT_LOCK="${ACCEPTANCE_NATIVE_ARTIFACT_LOCK:-}"
ACCEPTANCE_NATIVE_SCRATCH_PARENT="${ACCEPTANCE_NATIVE_SCRATCH_PARENT:-}"
ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR="${ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR:-}"

SELECTED_JOURNEY=""
ACTIVE_JOURNEY=""
ACTIVE_PID=""
ACTIVE_PGID=""
SUMMARY_PRINTED=0
STOP_AFTER_FAILURE=0
declare -A JOURNEY_STATUS=()
declare -A JOURNEY_REASON=()

usage() {
  cat <<'USAGE'
Usage: scripts/runtime/dev/run-secrets-credentials-acceptance.sh [--only JOURNEY]

Runs fixed checked-in #1922 journeys serially and reports each final child exit.
One failed child stops the matrix because its cleanup state is unknown. Retry an
individual journey with --only. Available journeys:
  native-local
  local-platform
  dev-application-all-scopes
  dev-provider-ssh
  local-platform-mesh
  live-codex                (Linux local VM; fresh Codex device approval required)
  live-github               (Linux local VM; fresh GitHub device approval required)
  live-openai               (Linux local VM; fresh API key and explicit model required)
  live-anthropic            (Linux local VM; fresh Anthropic API key input required)
  initial-private-checkout   (Linux local VM with generated platform SSH)
  dev-initial-private-checkout (Dev; dedicated enrolled automated account only)

Required input names:
  ACCEPTANCE_NORMAL_CW_BIN
  ACCEPTANCE_SYNTHETIC_CW_BIN
  ACCEPTANCE_NATIVE_DATA_PLANE_SMOKE_BIN
  ACCEPTANCE_NATIVE_CREDENTIAL_BRIDGE_SMOKE_BIN
  ACCEPTANCE_NATIVE_STATE_PROBE_BIN
  ACCEPTANCE_NATIVE_WORKSPACE_IMAGE_IMPORT_BIN
  ACCEPTANCE_NATIVE_ARTIFACT_ROOT
  ACCEPTANCE_NATIVE_ARTIFACT_LOCK
  ACCEPTANCE_NATIVE_SCRATCH_PARENT
  ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR
  DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE  Optional dedicated test-user automation
  DEV_SMOKE_BROWSER_AUTH_BUN_BIN         Required with browser automation
  DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN    Required with browser automation
  LOCAL_PLATFORM_ARTIFACT_ROOT
  LOCAL_PLATFORM_ARTIFACT_LOCK
  LOCAL_PLATFORM_IMAGE
  LOCAL_PLATFORM_MESH_PROBE_BIN
  LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN
  DEV_CHECKOUT_WORKSPACE_IMAGE  Existing immutable workspace registry@sha256:digest
  CODEWIRE_SERVER_URL
  EXPECTED_CODEWIRE_DEV_SERVER_URL
  EXPECTED_CODEWIRE_ADMIN_EMAIL
  EXPECTED_CODEWIRE_ADMIN_USER_ID
  EXPECTED_CODEWIRE_ORGANIZATION_ID
  KUBECONFIG
  KUBE_CONTEXT
  CODEWIRE_DEV_CLUSTER  Dev cluster pin (dev-initial-private-checkout)
  CODEWIRE_DEV_KUBE_SERVER
  CODEWIRE_DEV_KUBE_TLS_SERVER_NAME
  CODEWIRE_DEV_KUBE_CA_SHA256
  CODEWIRE_SERVER_NAMESPACE
  SANDBOX_NAMESPACE
  EXPECTED_NODE
  EXPECTED_TAILNET_PATH_TRANSPORT
  EXPECTED_TAILNET_PEER_RELAY_ENDPOINT
  EXPECTED_UDP_RELAY_BIND_ADDRS
  EXPECTED_UDP_RELAY_ALLOCATOR_URL
  EXPECTED_TAILNET_DIRECT_UDP_LB_IP
  EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE
  EXPECTED_RUNTIME_TRANSPORT_REGION
  XDG_RUNTIME_DIR
  SMOKE_TMP_PARENT
  LOCAL_PLATFORM_OPENAI_MODEL (live-openai only: exact accessible model snapshot)

The default matrix requires fresh Codewire/Codex approvals, fresh OpenAI/Anthropic
API-key input through cw's protected prompt, and an explicit OpenAI model. It remains
INCOMPLETE while any required journey is absent.
This runner never reads credential material, captures child output, or accepts an
arbitrary command. See docs/dev/SECRETS-AND-CREDENTIALS.md for required inputs.
USAGE
}

die() {
  printf '[secrets-credentials-acceptance] ERROR: %s\n' "$*" >&2
  exit 2
}

journey_exists() {
  local expected="$1" journey
  for journey in "${JOURNEYS[@]}"; do
    [[ "$journey" != "$expected" ]] || return 0
  done
  return 1
}

while (($#)); do
  case "$1" in
    --only)
      [[ $# -ge 2 && -z "$SELECTED_JOURNEY" ]] || die '--only requires exactly one journey'
      journey_exists "$2" || die "unknown journey: $2"
      SELECTED_JOURNEY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$-" in *x*) die 'shell tracing is unsupported' ;; esac

selected() {
  [[ -z "$SELECTED_JOURNEY" || "$SELECTED_JOURNEY" == "$1" ]]
}

canonical_executable() {
  local path="$1"
  [[ "$path" == /* && -f "$path" && -x "$path" && ! -L "$path" ]] || return 1
  [[ "$(realpath -e -- "$path" 2>/dev/null)" == "$path" ]]
}

canonical_file() {
  local path="$1"
  [[ "$path" == /* && -f "$path" && ! -L "$path" ]] || return 1
  [[ "$(realpath -e -- "$path" 2>/dev/null)" == "$path" ]]
}

canonical_directory() {
  local path="$1"
  [[ "$path" == /* && -d "$path" && ! -L "$path" ]] || return 1
  [[ "$(realpath -e -- "$path" 2>/dev/null)" == "$path" ]]
}

normal_cli_ready() {
  canonical_executable "$ACCEPTANCE_NORMAL_CW_BIN" &&
    [[ "${ACCEPTANCE_NORMAL_CW_BIN##*/}" != cw-local-credential-broker-smoke ]]
}

owner_runtime_ready() {
  local runtime_parent="${XDG_RUNTIME_DIR:-}"
  canonical_directory "$runtime_parent" &&
    [[ "$(stat -c '%u:%a' -- "$runtime_parent")" == "$(id -u):700" &&
       "$(findmnt -nro FSTYPE -T "$runtime_parent")" == tmpfs ]] &&
    canonical_directory "${SMOKE_TMP_PARENT:-}"
}

native_local_ready() {
  canonical_executable "$ACCEPTANCE_SYNTHETIC_CW_BIN" &&
    [[ "${ACCEPTANCE_SYNTHETIC_CW_BIN##*/}" == cw-local-credential-broker-smoke ]] &&
    canonical_executable "$ACCEPTANCE_NATIVE_DATA_PLANE_SMOKE_BIN" &&
    canonical_executable "$ACCEPTANCE_NATIVE_CREDENTIAL_BRIDGE_SMOKE_BIN" &&
    canonical_executable "$ACCEPTANCE_NATIVE_STATE_PROBE_BIN" &&
    canonical_executable "$ACCEPTANCE_NATIVE_WORKSPACE_IMAGE_IMPORT_BIN" &&
    canonical_directory "$ACCEPTANCE_NATIVE_ARTIFACT_ROOT" &&
    canonical_file "$ACCEPTANCE_NATIVE_ARTIFACT_LOCK" &&
    canonical_directory "$ACCEPTANCE_NATIVE_SCRATCH_PARENT"
}

local_platform_ready() {
  normal_cli_ready && owner_runtime_ready &&
    canonical_directory "${LOCAL_PLATFORM_ARTIFACT_ROOT:-}" &&
    canonical_file "${LOCAL_PLATFORM_ARTIFACT_LOCK:-}" &&
    [[ -n "${LOCAL_PLATFORM_IMAGE:-}" && -n "${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}" &&
       -n "${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}" ]]
}

local_platform_mesh_ready() {
  local_platform_ready && canonical_executable "${LOCAL_PLATFORM_MESH_PROBE_BIN:-}"
}

dev_topology_ready() {
  local name
  normal_cli_ready && owner_runtime_ready && canonical_file "${KUBECONFIG:-}" || return 1
  for name in CODEWIRE_SERVER_URL EXPECTED_CODEWIRE_DEV_SERVER_URL KUBE_CONTEXT \
      CODEWIRE_SERVER_NAMESPACE SANDBOX_NAMESPACE EXPECTED_NODE \
      EXPECTED_TAILNET_PEER_RELAY_ENDPOINT EXPECTED_UDP_RELAY_BIND_ADDRS \
      EXPECTED_UDP_RELAY_ALLOCATOR_URL EXPECTED_TAILNET_DIRECT_UDP_LB_IP \
      EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE EXPECTED_RUNTIME_TRANSPORT_REGION; do
    [[ -n "${!name:-}" ]] || return 1
  done
}

dev_application_all_scopes_ready() {
  normal_cli_ready && owner_runtime_ready &&
    [[ -n "${CODEWIRE_SERVER_URL:-}" && -n "${EXPECTED_CODEWIRE_DEV_SERVER_URL:-}" ]]
}

dev_initial_checkout_ready() {
  normal_cli_ready && owner_runtime_ready && canonical_file "${KUBECONFIG:-}" &&
    canonical_file "${DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE:-}" &&
    canonical_executable "${DEV_SMOKE_BROWSER_AUTH_BUN_BIN:-}" &&
    canonical_executable "${DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN:-}" &&
    [[ "${CODEWIRE_SERVER_URL:-}" == https://codewire-dev.sh &&
       "${EXPECTED_CODEWIRE_DEV_SERVER_URL:-}" == https://codewire-dev.sh &&
       -n "${KUBE_CONTEXT:-}" && -n "${SANDBOX_NAMESPACE:-}" &&
       -n "${CODEWIRE_DEV_CLUSTER:-}" && -n "${CODEWIRE_DEV_KUBE_SERVER:-}" &&
       -n "${CODEWIRE_DEV_KUBE_TLS_SERVER_NAME:-}" && -n "${CODEWIRE_DEV_KUBE_CA_SHA256:-}" &&
       "${DEV_CHECKOUT_WORKSPACE_IMAGE:-}" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]
}

dev_checkout_identity_ready() {
  # This is public source admission, not a caller-selected expected tuple.
  # The child separately proves the freshly authenticated principal/ownership.
  jq -es --arg user "${EXPECTED_CODEWIRE_ADMIN_USER_ID:-}" \
    --arg org "${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}" \
    --arg email "${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}" '
      length == 1 and (.[0] |
        keys == ["email","organizationId","status","userId","version"] and
        .version == 1 and .status == "enrolled" and
        .email == "hello@codewire.sh" and .email == $email and
        .userId == $user and .organizationId == $org and
        ([.userId,.organizationId] | all(type == "string" and
          test("^[0-9a-f]{32}$") and . != "00000000000000000000000000000000")))
    ' "$ROOT/scripts/runtime/dev/testdata/acceptance-identity.json" >/dev/null 2>&1
}

provider_oauth_config_ready() {
  local config_dir="$ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR"
  local runtime_parent="${XDG_RUNTIME_DIR:-}"
  canonical_directory "$config_dir" &&
    [[ "$config_dir" == "$runtime_parent"/* &&
       "$(stat -c '%u:%a' -- "$config_dir")" == "$(id -u):700" ]]
}

readiness_reason() {
  local journey="$1"
  case "$journey" in
    native-local)
      native_local_ready || { printf '%s' 'explicit synthetic CLI/native artifact inputs unavailable'; return 1; }
      ;;
    local-platform)
      local_platform_ready || { printf '%s' 'explicit normal CLI/local platform inputs unavailable'; return 1; }
      ;;
    local-platform-mesh)
      local_platform_mesh_ready || { printf '%s' 'explicit normal CLI/local platform/Mesh inputs unavailable'; return 1; }
      ;;
    dev-application-all-scopes)
      dev_application_all_scopes_ready || {
        printf '%s' 'explicit normal CLI/Dev API inputs unavailable'; return 1;
      }
      [[ -n "${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}" &&
         -n "${EXPECTED_CODEWIRE_ADMIN_USER_ID:-}" &&
         -n "${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}" ]] || {
        printf '%s' 'exact all-scope identity inputs unavailable'; return 1;
      }
      ;;
    dev-provider-ssh)
      dev_topology_ready || { printf '%s' 'explicit normal CLI/actual Dev topology inputs unavailable'; return 1; }
      [[ -n "${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}" ]] || {
        printf '%s' 'exact owner email unavailable'; return 1;
      }
      if [[ -n "${DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE:-}" ]]; then
        [[ -z "$ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR" &&
           -n "${EXPECTED_CODEWIRE_ADMIN_USER_ID:-}" &&
           -n "${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}" ]] || {
          printf '%s' 'browser automation requires exact identities without a saved OAuth directory'; return 1;
        }
      elif ! provider_oauth_config_ready; then
        printf '%s' 'explicit canonical fresh provider-SSH OAuth directory unavailable'; return 1;
      fi
      ;;
    live-codex|live-anthropic|live-github)
      local_platform_ready || { printf '%s' 'explicit normal CLI/local platform inputs unavailable'; return 1; }
      ;;
    live-openai)
      local_platform_ready || { printf '%s' 'explicit normal CLI/local platform inputs unavailable'; return 1; }
      [[ "${LOCAL_PLATFORM_OPENAI_MODEL:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || {
        printf '%s' 'explicit bounded LOCAL_PLATFORM_OPENAI_MODEL unavailable'; return 1;
      }
      ;;
    initial-private-checkout)
      if ! { local_platform_ready && canonical_executable "${LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN:-}"; }; then
        printf '%s' 'explicit normal CLI/local platform/checkout fixture inputs unavailable'; return 1;
      fi
      ;;
    dev-initial-private-checkout)
      dev_initial_checkout_ready || {
        printf '%s' 'explicit normal CLI/dedicated Dev checkout inputs unavailable'; return 1;
      }
      dev_checkout_identity_ready || {
        printf '%s' 'dedicated Dev checkout identity is not source-admitted'; return 1;
      }
      ;;
  esac
  return 0
}

start_isolated_child() {
  setsid env --default-signal=HUP --default-signal=INT --default-signal=TERM -i \
    PATH=/usr/bin:/bin \
    HOME=/nonexistent \
    USER="$(id -un)" \
    LOGNAME="$(id -un)" \
    SHELL=/bin/bash \
    TERM=dumb \
    LC_ALL=C \
    "$@" <&0 &
  ACTIVE_PID="$!"
  # A non-job-control asynchronous external command is not a process-group
  # leader, so setsid(1) makes this exact PID the new session/group leader.
  ACTIVE_PGID="$ACTIVE_PID"
}

start_fixed_child() {
  local journey="$1"
  local -a browser_auth_env=(
    "DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE=${DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE:-}"
    "DEV_SMOKE_BROWSER_AUTH_BUN_BIN=${DEV_SMOKE_BROWSER_AUTH_BUN_BIN:-}"
    "DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN=${DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN:-}"
  )
  case "$journey" in
    native-local)
      start_isolated_child \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
        GITHUB_SERVER_URL="${GITHUB_SERVER_URL:-}" \
        CODEWIRE_FORGEJO_FIXTURE_REPOSITORY="${CODEWIRE_FORGEJO_FIXTURE_REPOSITORY:-}" \
        "$ROOT/scripts/ci/verify/smoke-native-local-environment.sh" \
        --cw-bin "$ACCEPTANCE_SYNTHETIC_CW_BIN" \
        --data-plane-smoke-bin "$ACCEPTANCE_NATIVE_DATA_PLANE_SMOKE_BIN" \
        --credential-bridge-smoke-bin "$ACCEPTANCE_NATIVE_CREDENTIAL_BRIDGE_SMOKE_BIN" \
        --state-probe-bin "$ACCEPTANCE_NATIVE_STATE_PROBE_BIN" \
        --artifact-root "$ACCEPTANCE_NATIVE_ARTIFACT_ROOT" \
        --artifact-lock "$ACCEPTANCE_NATIVE_ARTIFACT_LOCK" \
        --managed-credential-broker \
        --workspace-image-import-bin "$ACCEPTANCE_NATIVE_WORKSPACE_IMAGE_IMPORT_BIN" \
        --scratch-parent "$ACCEPTANCE_NATIVE_SCRATCH_PARENT"
      ;;
    local-platform|initial-private-checkout|live-codex|live-anthropic|live-openai|live-github)
      local -a checkout_env=() checkout_args=()
      if [[ "$journey" == initial-private-checkout ]]; then
        checkout_env=("LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN=${LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN:-}")
        checkout_args=(--initial-private-checkout)
      elif [[ "$journey" == live-github ]]; then
        checkout_args=(--live-github)
      elif [[ "$journey" == live-codex ]]; then
        checkout_args=(--live-codex)
      elif [[ "$journey" == live-anthropic ]]; then
        checkout_args=(--live-anthropic)
      elif [[ "$journey" == live-openai ]]; then
        checkout_env=("LOCAL_PLATFORM_OPENAI_MODEL=$LOCAL_PLATFORM_OPENAI_MODEL")
        checkout_args=(--live-openai)
      fi
      start_isolated_child "${browser_auth_env[@]}" \
        "${checkout_env[@]}" \
        CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_DEV_SERVER_URL="${EXPECTED_CODEWIRE_DEV_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_ADMIN_EMAIL="${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}" \
        EXPECTED_CODEWIRE_ADMIN_USER_ID="${EXPECTED_CODEWIRE_ADMIN_USER_ID:-}" \
        EXPECTED_CODEWIRE_ORGANIZATION_ID="${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}" \
        LOCAL_PLATFORM_ARTIFACT_ROOT="${LOCAL_PLATFORM_ARTIFACT_ROOT:-}" \
        LOCAL_PLATFORM_ARTIFACT_LOCK="${LOCAL_PLATFORM_ARTIFACT_LOCK:-}" \
        LOCAL_PLATFORM_IMAGE="${LOCAL_PLATFORM_IMAGE:-}" \
        LOCAL_PLATFORM_DISPOSABLE_NETWORK=0 \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
        SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-}" \
        "$ROOT/scripts/runtime/dev/smoke-local-platform-sources.sh" \
          --admin-oidc --cw-bin "$ACCEPTANCE_NORMAL_CW_BIN" "${checkout_args[@]}"
      ;;
    dev-application-all-scopes)
      start_isolated_child "${browser_auth_env[@]}" \
        CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_DEV_SERVER_URL="${EXPECTED_CODEWIRE_DEV_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_ADMIN_EMAIL="${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}" \
        EXPECTED_CODEWIRE_ADMIN_USER_ID="${EXPECTED_CODEWIRE_ADMIN_USER_ID:-}" \
        EXPECTED_CODEWIRE_ORGANIZATION_ID="${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
        SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-}" \
        "$ROOT/scripts/ci/verify/runtime-dev-commodity-smoke.sh" \
          --admin-oidc --cw-bin "$ACCEPTANCE_NORMAL_CW_BIN" \
          --only application-secrets-all-scopes
      ;;
    dev-provider-ssh)
      start_isolated_child "${browser_auth_env[@]}" \
        CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_DEV_SERVER_URL="${EXPECTED_CODEWIRE_DEV_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_ADMIN_EMAIL="${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}" \
        EXPECTED_CODEWIRE_ADMIN_USER_ID="${EXPECTED_CODEWIRE_ADMIN_USER_ID:-}" \
        EXPECTED_CODEWIRE_ORGANIZATION_ID="${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}" \
        KUBECONFIG="${KUBECONFIG:-}" \
        KUBE_CONTEXT="${KUBE_CONTEXT:-}" \
        CODEWIRE_SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-}" \
        SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-}" \
        EXPECTED_NODE="${EXPECTED_NODE:-}" \
        EXPECTED_TAILNET_PATH_TRANSPORT="${EXPECTED_TAILNET_PATH_TRANSPORT:-peer_relay}" \
        EXPECTED_TAILNET_PEER_RELAY_ENDPOINT="${EXPECTED_TAILNET_PEER_RELAY_ENDPOINT:-}" \
        EXPECTED_UDP_RELAY_BIND_ADDRS="${EXPECTED_UDP_RELAY_BIND_ADDRS:-}" \
        EXPECTED_UDP_RELAY_ALLOCATOR_URL="${EXPECTED_UDP_RELAY_ALLOCATOR_URL:-}" \
        EXPECTED_TAILNET_DIRECT_UDP_LB_IP="${EXPECTED_TAILNET_DIRECT_UDP_LB_IP:-}" \
        EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE="${EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE:-}" \
        EXPECTED_RUNTIME_TRANSPORT_REGION="${EXPECTED_RUNTIME_TRANSPORT_REGION:-}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
        SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-}" \
        CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR" \
        "$ROOT/scripts/ci/verify/runtime-dev-commodity-smoke.sh" \
          --admin-oidc --cw-bin "$ACCEPTANCE_NORMAL_CW_BIN" --only provider-ssh
      ;;
    dev-initial-private-checkout)
      start_isolated_child "${browser_auth_env[@]}" \
        CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_DEV_SERVER_URL="${EXPECTED_CODEWIRE_DEV_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_ADMIN_EMAIL="${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}" \
        EXPECTED_CODEWIRE_ADMIN_USER_ID="${EXPECTED_CODEWIRE_ADMIN_USER_ID:-}" \
        EXPECTED_CODEWIRE_ORGANIZATION_ID="${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}" \
        KUBECONFIG="${KUBECONFIG:-}" KUBE_CONTEXT="${KUBE_CONTEXT:-}" \
        CODEWIRE_DEV_CLUSTER="${CODEWIRE_DEV_CLUSTER:-}" \
        CODEWIRE_DEV_KUBE_SERVER="${CODEWIRE_DEV_KUBE_SERVER:-}" \
        CODEWIRE_DEV_KUBE_TLS_SERVER_NAME="${CODEWIRE_DEV_KUBE_TLS_SERVER_NAME:-}" \
        CODEWIRE_DEV_KUBE_CA_SHA256="${CODEWIRE_DEV_KUBE_CA_SHA256:-}" \
        SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-}" \
        DEV_CHECKOUT_WORKSPACE_IMAGE="${DEV_CHECKOUT_WORKSPACE_IMAGE:-}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-}" \
        "$ROOT/scripts/runtime/dev/smoke-dev-initial-private-checkout.sh" \
          --cw-bin "$ACCEPTANCE_NORMAL_CW_BIN"
      ;;
    local-platform-mesh)
      start_isolated_child "${browser_auth_env[@]}" \
        CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_DEV_SERVER_URL="${EXPECTED_CODEWIRE_DEV_SERVER_URL:-}" \
        EXPECTED_CODEWIRE_ADMIN_EMAIL="${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}" \
        EXPECTED_CODEWIRE_ADMIN_USER_ID="${EXPECTED_CODEWIRE_ADMIN_USER_ID:-}" \
        EXPECTED_CODEWIRE_ORGANIZATION_ID="${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}" \
        LOCAL_PLATFORM_ARTIFACT_ROOT="${LOCAL_PLATFORM_ARTIFACT_ROOT:-}" \
        LOCAL_PLATFORM_ARTIFACT_LOCK="${LOCAL_PLATFORM_ARTIFACT_LOCK:-}" \
        LOCAL_PLATFORM_IMAGE="${LOCAL_PLATFORM_IMAGE:-}" \
        LOCAL_PLATFORM_DISPOSABLE_NETWORK=1 \
        LOCAL_PLATFORM_MESH_PROBE_BIN="${LOCAL_PLATFORM_MESH_PROBE_BIN:-}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
        SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-}" \
        "$ROOT/scripts/runtime/dev/smoke-local-platform-sources.sh" \
          --admin-oidc --cw-bin "$ACCEPTANCE_NORMAL_CW_BIN" --application-only
      ;;
    *) return 1 ;;
  esac
}

print_summary() {
  local journey
  [[ "$SUMMARY_PRINTED" == 0 ]] || return
  SUMMARY_PRINTED=1
  printf '[secrets-credentials-acceptance] summary\n'
  for journey in "${JOURNEYS[@]}"; do
    selected "$journey" || continue
    printf '[secrets-credentials-acceptance] %-30s %s' "$journey" "${JOURNEY_STATUS[$journey]:-NOT RUN}"
    if [[ -n "${JOURNEY_REASON[$journey]:-}" ]]; then
      printf ' (%s)' "${JOURNEY_REASON[$journey]}"
    fi
    printf '\n'
  done
}

# shellcheck disable=SC2329 # Reached through the signal-trap entrypoint.
mark_remaining_after_signal() {
  local journey
  for journey in "${JOURNEYS[@]}"; do
    selected "$journey" || continue
    [[ -n "${JOURNEY_STATUS[$journey]:-}" ]] || {
      JOURNEY_STATUS[$journey]='NOT RUN'
      JOURNEY_REASON[$journey]='runner interrupted after exact child cleanup wait'
    }
  done
}

# shellcheck disable=SC2329 # Invoked by the fixed HUP/INT/TERM traps below.
forward_signal() {
  local signal="$1" exit_code child_rc=0
  case "$signal" in HUP) exit_code=129 ;; INT) exit_code=130 ;; TERM) exit_code=143 ;; esac
  trap '' HUP INT TERM
  if [[ -n "$ACTIVE_PID" ]]; then
    if ! kill -s "$signal" -- "-$ACTIVE_PGID" 2>/dev/null; then
      # The signal may win the narrow interval before setsid(1) establishes
      # the private group. The launcher PID is still exact and runner-owned.
      kill -s "$signal" "$ACTIVE_PID" 2>/dev/null || true
    fi
    wait "$ACTIVE_PID" || child_rc=$?
    JOURNEY_STATUS[$ACTIVE_JOURNEY]='INTERRUPTED'
    JOURNEY_REASON[$ACTIVE_JOURNEY]="signal $signal; child final exit $child_rc after wait"
    ACTIVE_PID=""
    ACTIVE_PGID=""
  fi
  mark_remaining_after_signal
  print_summary
  printf '[secrets-credentials-acceptance] selected/full acceptance: NOT CLAIMED\n'
  exit "$exit_code"
}

trap 'forward_signal HUP' HUP
trap 'forward_signal INT' INT
trap 'forward_signal TERM' TERM

for journey in "${JOURNEYS[@]}"; do
  selected "$journey" || continue
  if [[ "$STOP_AFTER_FAILURE" == 1 ]]; then
    JOURNEY_STATUS[$journey]='NOT RUN'
    JOURNEY_REASON[$journey]='prior child failed; cleanup state unknown'
    continue
  fi
  reason=""
  if ! reason="$(readiness_reason "$journey")"; then
    JOURNEY_STATUS[$journey]='NOT RUN'
    JOURNEY_REASON[$journey]="$reason"
    continue
  fi
  ACTIVE_JOURNEY="$journey"
  ACTIVE_PID=""
  if ! start_fixed_child "$journey"; then
    JOURNEY_STATUS[$journey]='NOT RUN'
    JOURNEY_REASON[$journey]='checked-in child is unavailable'
    continue
  fi
  child_rc=0
  wait "$ACTIVE_PID" || child_rc=$?
  ACTIVE_PID=""
  ACTIVE_PGID=""
  if [[ "$child_rc" == 0 ]]; then
    JOURNEY_STATUS[$journey]='PASS'
  else
    JOURNEY_STATUS[$journey]='FAIL'
    JOURNEY_REASON[$journey]="child exit $child_rc; cleanup state unknown"
    STOP_AFTER_FAILURE=1
  fi
done

print_summary

result=0
for journey in "${JOURNEYS[@]}"; do
  selected "$journey" || continue
  [[ "${JOURNEY_STATUS[$journey]:-NOT RUN}" == PASS ]] || result=1
done

if [[ -n "$SELECTED_JOURNEY" && "$result" == 0 ]]; then
  printf '[secrets-credentials-acceptance] selected result: PASS; full acceptance: NOT CLAIMED\n'
else
  printf '[secrets-credentials-acceptance] aggregate result: INCOMPLETE; full acceptance: NOT CLAIMED\n'
fi
exit "$result"
