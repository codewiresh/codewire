#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-}"
EXPECTED_CODEWIRE_DEV_SERVER_URL="${EXPECTED_CODEWIRE_DEV_SERVER_URL:-}"
SMOKE_NAME="${SMOKE_NAME:-commodity-$(date -u +%Y%m%d%H%M%S)}"
SMOKE_IMAGE="${SMOKE_IMAGE:-workspace}"
SMOKE_TTL="${SMOKE_TTL:-2h}"
SMOKE_CPU="${SMOKE_CPU:-2000}"
SMOKE_MEMORY="${SMOKE_MEMORY:-4096}"
SMOKE_DISK="${SMOKE_DISK:-10}"
SMOKE_ISOLATION_TIER="${SMOKE_ISOLATION_TIER:-standard}"
SMOKE_TIMEOUT_SECONDS="${SMOKE_TIMEOUT_SECONDS:-900}"
SMOKE_KEEP_ENV="${SMOKE_KEEP_ENV:-0}"
SMOKE_SKIP_KUBE="${SMOKE_SKIP_KUBE:-0}"
SMOKE_SKIP_DOCKER="${SMOKE_SKIP_DOCKER:-0}"
SMOKE_SKIP_SSH="${SMOKE_SKIP_SSH:-0}"
SMOKE_TAILNET_DEBUG="${SMOKE_TAILNET_DEBUG:-0}"
SMOKE_DERP_FALLBACK="${SMOKE_DERP_FALLBACK:-1}"
SMOKE_PEER_RELAY_MATRIX="${SMOKE_PEER_RELAY_MATRIX:-0}"
SMOKE_TAILNET_DIRECT_WAIT="${SMOKE_TAILNET_DIRECT_WAIT:-20s}"
SMOKE_TAILNET_PEER_TIMEOUT="${SMOKE_TAILNET_PEER_TIMEOUT:-30s}"
SMOKE_TAILNET_DIAL_TIMEOUT="${SMOKE_TAILNET_DIAL_TIMEOUT:-60s}"
SMOKE_EXEC_TIMEOUT="${SMOKE_EXEC_TIMEOUT:-900}"
SMOKE_SSH_TIMEOUT="${SMOKE_SSH_TIMEOUT:-90}"
SMOKE_SSH_CONNECT_TIMEOUT="${SMOKE_SSH_CONNECT_TIMEOUT:-60}"
SMOKE_SSH_LOG_LEVEL="${SMOKE_SSH_LOG_LEVEL:-ERROR}"
SMOKE_TAILNET_DOCTOR_TIMEOUT="${SMOKE_TAILNET_DOCTOR_TIMEOUT:-180}"
SMOKE_DOCKER_STRESS="${SMOKE_DOCKER_STRESS:-0}"
SMOKE_DOCKER_STRESS_ITERATIONS="${SMOKE_DOCKER_STRESS_ITERATIONS:-3}"
SMOKE_DOCKER_POSTGRES_ROWS="${SMOKE_DOCKER_POSTGRES_ROWS:-0}"
SMOKE_DOCKER_LARGE_IMAGE="${SMOKE_DOCKER_LARGE_IMAGE:-python:3.12-slim}"
SMOKE_DOCKER_LARGE_IMAGE_MAX_SECONDS="${SMOKE_DOCKER_LARGE_IMAGE_MAX_SECONDS:-180}"
SMOKE_DOCKER_EGRESS_SMALL_URL="${SMOKE_DOCKER_EGRESS_SMALL_URL:-https://speed.cloudflare.com/__down?bytes=102400}"
SMOKE_DOCKER_EGRESS_LARGE_URL="${SMOKE_DOCKER_EGRESS_LARGE_URL:-https://speed.cloudflare.com/__down?bytes=10485760}"
SMOKE_DOCKER_OOM_STRESS="${SMOKE_DOCKER_OOM_STRESS:-1}"
SMOKE_APP_PREVIEW="${SMOKE_APP_PREVIEW:-0}"
SMOKE_APP_PREVIEW_PORT="${SMOKE_APP_PREVIEW_PORT:-8080}"
SMOKE_APP_PREVIEW_LABEL="${SMOKE_APP_PREVIEW_LABEL:-app}"
SMOKE_RESIZE_GUEST="${SMOKE_RESIZE_GUEST:-0}"
SMOKE_RESIZE_GUEST_CPU_DELTA="${SMOKE_RESIZE_GUEST_CPU_DELTA:-1000}"
SMOKE_RESIZE_GUEST_MEMORY_DELTA="${SMOKE_RESIZE_GUEST_MEMORY_DELTA:-2048}"
SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-$ROOT/.tmp}"
SMOKE_ARTIFACT_DIR="${SMOKE_ARTIFACT_DIR:-}"
SMOKE_CW_BUILD_TIMEOUT="${SMOKE_CW_BUILD_TIMEOUT:-600s}"
SMOKE_EXISTING_ENV_ID="${SMOKE_EXISTING_ENV_ID:-}"
SMOKE_COLLECT_FAILURE_DIAGNOSTICS="${SMOKE_COLLECT_FAILURE_DIAGNOSTICS:-1}"
SMOKE_PACKET_DIAGNOSTICS="${SMOKE_PACKET_DIAGNOSTICS:-0}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-}"
CODEWIRE_SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
EXPECTED_RUNTIME_CLASS="${EXPECTED_RUNTIME_CLASS:-commodity}"
EXPECTED_DOCKER_MODE="${EXPECTED_DOCKER_MODE:-guest-dind}"
EXPECTED_DAEMON_IMAGE="${EXPECTED_DAEMON_IMAGE:-}"
EXPECTED_DIND_IMAGE="${EXPECTED_DIND_IMAGE:-}"
EXPECTED_NODE="${EXPECTED_NODE:-}"
EXPECTED_NODE_KATA_LABEL="${EXPECTED_NODE_KATA_LABEL:-katacontainers.io/kata-runtime}"
EXPECTED_NODE_KATA_VALUE="${EXPECTED_NODE_KATA_VALUE:-true}"
EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB="${EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB:-500}"
EXPECTED_STUN_HOST="${EXPECTED_STUN_HOST:-}"
EXPECTED_STUN_PORT="${EXPECTED_STUN_PORT:-3478}"
EXPECTED_TAILNET_DIRECT_UDP_LB_IP="${EXPECTED_TAILNET_DIRECT_UDP_LB_IP:-}"
EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE="${EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE:-}"
EXPECTED_TAILNET_PEER_RELAY_ENDPOINT="${EXPECTED_TAILNET_PEER_RELAY_ENDPOINT:-}"
EXPECTED_UDP_RELAY_BIND_ADDRS="${EXPECTED_UDP_RELAY_BIND_ADDRS:-}"
REQUIRE_TAILNET_PATH_PROBE="${REQUIRE_TAILNET_PATH_PROBE:-0}"
EXPECTED_TAILNET_PATH_TRANSPORT="${EXPECTED_TAILNET_PATH_TRANSPORT:-direct_udp}"
EXPECTED_KATA_AGENT_POLICY_ANNOTATION="${EXPECTED_KATA_AGENT_POLICY_ANNOTATION:-0}"
EXPECTED_KATA_COCO_INIT_DATA_ANNOTATION="${EXPECTED_KATA_COCO_INIT_DATA_ANNOTATION:-0}"
EXPECTED_KATA_COCO_KBS_URL="${EXPECTED_KATA_COCO_KBS_URL:-}"
EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI="${EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI:-}"
EXPECTED_KATA_COCO_TEST_RESOURCE_URI="${EXPECTED_KATA_COCO_TEST_RESOURCE_URI:-}"
EXPECTED_KATA_COCO_TEST_RESOURCE_PATH="${EXPECTED_KATA_COCO_TEST_RESOURCE_PATH:-}"
EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT="${EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT:-}"
EXPECTED_CODEWIRE_SMOKE_USER_EMAIL="${EXPECTED_CODEWIRE_SMOKE_USER_EMAIL:-}"
EXPECTED_CODEWIRE_ADMIN_EMAIL="${EXPECTED_CODEWIRE_ADMIN_EMAIL:-}"
EXPECTED_CODEWIRE_ADMIN_USER_ID="${EXPECTED_CODEWIRE_ADMIN_USER_ID:-}"
EXPECTED_CODEWIRE_ORGANIZATION_ID="${EXPECTED_CODEWIRE_ORGANIZATION_ID:-}"
CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="${CODEWIRE_ADMIN_OAUTH_CONFIG_DIR:-}"
DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE="${DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE:-}"
DEV_SMOKE_BROWSER_AUTH_BUN_BIN="${DEV_SMOKE_BROWSER_AUTH_BUN_BIN:-}"
DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN="${DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN:-}"
readonly CODEWIRE_DEV_SMOKE_ORG_SLUG="codewire-dev-smoke"
readonly CODEWIRE_DEV_SMOKE_API_KEY_NAME="runtime-dev-commodity-smoke"
ALLOW_NON_DEV="${ALLOW_NON_DEV:-0}"
ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE="${ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE:-0}"
CW_BIN="${CW_BIN:-}"
SMOKE_AUTH_MODE="api-key"

ENV_ID=""
TMPDIR_SMOKE=""
CLAIM_NAME=""
POD_NAME=""
SMOKE_LAST_WAIT_DETAIL=""
SMOKE_FAILURE_DIAGNOSTICS_CAPTURED=0
SMOKE_PACKET_CAPTURE_PID=""
SMOKE_PACKET_CAPTURE_RAW=""
SMOKE_PACKET_CAPTURE_ERROR=""
SMOKE_PACKET_CAPTURE_SUMMARY=""
SMOKE_PACKET_CAPTURE_STATUS=""
SMOKE_PACKET_CAPTURE_UNAVAILABLE=0
COCO_REST_ISOLATION_STATUS=""
COCO_REST_ISOLATION_CURL_EXIT=""
COCO_REST_ISOLATION_EVIDENCE_SOURCE=""
COCO_REST_ISOLATION_RECEIPT=""
declare -a SMOKE_ONLY_PHASES=()
declare -a APP_SECRET_PROJECTS=() APP_SECRET_IDS=() APP_SECRET_VALUES=() APP_SECRET_HASHES=()
declare -a APP_SECRET_USER_ATTEMPTS=() APP_SECRET_ORG_ATTEMPTS=() APP_SECRET_ALL_KEYS=()
declare -a APP_SECRET_ALL_HASHES_A=() APP_SECRET_ALL_HASHES_B=() APP_SECRET_ALL_HASHES_CLEAR=()
declare -a SMOKE_OAUTH_ENV=()
APP_SECRET_DOCUMENT=""
APP_SECRET_CREATE_ATTEMPTED=0
APP_SECRET_ALL_SCOPES=0
APP_WORKSPACE_MARKER_SHA256=""
APP_RESTART_WITNESS_SESSION_ID=""
GUEST_NPROC=""
GUEST_MEMTOTAL_KIB=""
SMOKE_OAUTH_LOGIN_ATTEMPTED=0
SMOKE_OAUTH_LOGIN_DIR=""
SMOKE_OAUTH_RUNTIME_PARENT=""
SMOKE_OAUTH_RUNTIME_DIR=""

# shellcheck source=scripts/runtime/dev/provider-ssh-smoke.sh
source "$ROOT/scripts/runtime/dev/provider-ssh-smoke.sh"

usage() {
  cat <<'USAGE'
Usage:
  CODEWIRE_DEV_SMOKE_API_KEY=... scripts/runtime/dev/smoke-dev-commodity.sh [options]

For local runs, prefer:
  scripts/runtime/dev/with-dev-smoke-auth.sh scripts/runtime/dev/smoke-dev-commodity.sh [options]

Options:
  --name NAME              Environment name (default: commodity-<utc timestamp>)
  --cw-bin PATH            Use an existing cw binary instead of building one
  --existing-env ID        Reuse an existing environment instead of creating one.
                           The environment is always kept.
  --admin-oidc             Use the saved native OIDC login for an admin-only
                           acceptance run. API keys are rejected in this mode.
  --only PHASE             Run only one smoke phase; repeatable. Phases:
                           kube, exec, coco, docker, doctor, ssh,
                           tailnet-ssh, derp-ssh, websocket-ssh,
                           host-key, app-preview, resize-guest,
                           host-key proves the daemon presents the host
                           key the platform recorded, refuses a changed
                           key, and rotates it on stop and start.
                           application-secrets,
                           application-secrets-all-scopes, provider-ssh
                           resize-guest requires a fresh disposable env; see
                           SMOKE_RESIZE_GUEST.
                           application-secrets requires the dedicated smoke
                           API key, a fresh disposable env and Kubernetes checks.
                           It tests project application secrets, not personal
                           secrets or outbound provider SSH.
                           application-secrets-all-scopes is the sole phase in
                           a fresh --admin-oidc login for an isolated owner
                           account/org with initially empty shared scopes.
                           provider-ssh is owner-operated --admin-oidc with an
                           explicit login directory and expected email; it creates
                           only a disposable generated SSH identity/profile/env.
  --keep                   Keep the environment after the smoke
  --skip-kube              Skip Kubernetes shape assertions
  --skip-docker            Skip Docker/compose/Postgres guest smoke
  --skip-ssh               Skip tailnet/websocket SSH smoke
  --include-derp-fallback  Force an additional DERP relay tailnet SSH check
  --skip-derp-fallback     Skip the forced DERP relay tailnet SSH check
  --timeout-seconds N      Environment/Kubernetes wait budget (default: 900)
  -h, --help               Show this help

Environment:
  CODEWIRE_SERVER_URL      Required API endpoint for the selected environment
  EXPECTED_CODEWIRE_DEV_SERVER_URL
                           Required dev endpoint safety assertion
  CODEWIRE_DEV_SMOKE_API_KEY
                           Required by default; copied to CODEWIRE_API_KEY for cw
  CODEWIRE_API_KEY         Accepted only with ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=1
  CODEWIRE_ADMIN_OAUTH_CONFIG_DIR
                           Native cw login directory for --admin-oidc.
                           Defaults to ~/.config/cw.
  EXPECTED_CODEWIRE_ADMIN_EMAIL
                           Optional exact email assertion for --admin-oidc.
  EXPECTED_CODEWIRE_ADMIN_USER_ID
                           Exact 32-hex account ID for all-scope acceptance.
  EXPECTED_CODEWIRE_ORGANIZATION_ID
                           Exact owned 32-hex org ID for all-scope acceptance.
  KUBECONFIG               Optional; defaults to ~/src/infra/kubeconfig-oidc.yaml when present
  KUBE_CONTEXT             Optional; if unset, prefers codewire-dev, then default, then current-context
  SANDBOX_NAMESPACE        Required sandbox namespace when Kubernetes checks run
  CODEWIRE_SERVER_NAMESPACE
                           Required namespace containing codewire-derp/coordinator
  SMOKE_TMP_PARENT         Defaults to repo .tmp so built cw can run on noexec /tmp
  SMOKE_ARTIFACT_DIR       Optional directory for value-blind failure evidence
                           suitable for CI artifact upload. Full pod logs and
                           credentials are never copied there.
  SMOKE_CW_BUILD_TIMEOUT   Defaults to 600s when CW_BIN is not provided
  SMOKE_ISOLATION_TIER    Product isolation tier requested at environment
                           creation. Defaults to standard; the confidential
                           wrapper sets confidential explicitly.
  SMOKE_TAILNET_DEBUG      Defaults to 0; when set to 1, captures
                           CW_DEBUG_TAILNET output for tailnet SSH.
                           Path assertions are made by cw doctor tailnet.
  SMOKE_DERP_FALLBACK      Defaults to 1; forces an additional tailnet SSH
                           check with CW_DERP_ONLY=1 and
                           TS_DEBUG_NEVER_DIRECT_UDP=1, expecting
                           transport=derp_relay
  SMOKE_PEER_RELAY_MATRIX  Defaults to 0; when set to 1, the same live
                           environment must also pass a doctor probe and SSH
                           leg with peer direct UDP endpoints suppressed,
                           proving the shared UDP relay path before cleanup
  SMOKE_TAILNET_DIRECT_WAIT
                           Defaults to 20s; passed to cw as
                           CW_TAILNET_DIRECT_WAIT so direct UDP or peer relay
                           can settle before DERP fallback evidence is captured.
                           Set longer values for explicit direct-UDP proof.
  SMOKE_TAILNET_PEER_TIMEOUT
                           Defaults to 30s; passed to cw doctor tailnet and
                           cw shell while waiting for coordinator peer and
                           DERP readiness.
  SMOKE_TAILNET_DIAL_TIMEOUT
                           Defaults to 60s; passed to cw shell as
                           CW_TAILNET_DIAL_TIMEOUT for the final tailnet TCP
                           stream dial after path setup.
  SMOKE_TAILNET_DOCTOR_TIMEOUT
                           Defaults to 180s; outer timeout for the concurrent
                           direct and forced-DERP cw doctor probes.
  SMOKE_SSH_CONNECT_TIMEOUT
                           Defaults to 60; OpenSSH ConnectTimeout in seconds.
                           Increase when SMOKE_TAILNET_DIRECT_WAIT is longer.
  SMOKE_SSH_LOG_LEVEL      Defaults to ERROR. Set DEBUG3 for focused SSH
                           transport debugging.
  SMOKE_DOCKER_STRESS      Defaults to 0; enables heavier Kata/CLH container stress checks
  SMOKE_DOCKER_STRESS_ITERATIONS
                           Defaults to 3 when stress is enabled
  SMOKE_DOCKER_POSTGRES_ROWS
                           Optional row-count load for the guest Postgres smoke
  SMOKE_DOCKER_LARGE_IMAGE Optional large image for stress cold-start check
  SMOKE_DOCKER_EGRESS_SMALL_URL / SMOKE_DOCKER_EGRESS_LARGE_URL
                           URLs used for guest Docker egress checks
  SMOKE_DOCKER_OOM_STRESS  Defaults to 1 when SMOKE_DOCKER_STRESS=1
  SMOKE_APP_PREVIEW        Defaults to 0; when set to 1, writes and starts a
                           tiny HTTP service in /workspace, registers it with
                           cw ports --publish, fetches its preview URL, removes the
                           port, and verifies the preview no longer serves it
  SMOKE_APP_PREVIEW_PORT   Defaults to 8080
  SMOKE_APP_PREVIEW_LABEL  Defaults to app
  SMOKE_RESIZE_GUEST       Defaults to 0; when set to 1, grows the fresh
                           environment's CPU and memory with restart consent
                           after the other checks, then requires the guest to
                           show them: nproc must cover the new CPU limit and
                           MemTotal must grow by at least 90% of the memory
                           increase. Catches a resize that changes only cgroup
                           limits inside a VM sized at start (#2266).
  SMOKE_RESIZE_GUEST_CPU_DELTA
                           Defaults to 1000; CPU increase in millicores
  SMOKE_RESIZE_GUEST_MEMORY_DELTA
                           Defaults to 2048; memory increase in MiB
  SMOKE_COLLECT_FAILURE_DIAGNOSTICS
                           Defaults to 1. On failure, captures Kubernetes
                           claim/template/pod/event/log evidence into the
                           smoke evidence directory before deleting the env.
  SMOKE_PACKET_DIAGNOSTICS
                           Defaults to 0. Set to 1 only for the admitted
                           host-network diagnostic. Captures route metadata and
                           UDP headers for the configured peer relay without payload.
  EXPECTED_DAEMON_IMAGE    Optional exact assertion for the daemon image the
                           workspace Pod mounts (SANDBOX_DAEMON_IMAGE)
  EXPECTED_DOCKER_MODE     Expected workspace Docker mode. Defaults to
                           guest-dind, expecting workspace+dind containers.
                           Set none for focused KBS/CoCo proofs that do not
                           exercise Docker.
  EXPECTED_DIND_IMAGE      Optional exact image assertion for the dind support
                           container in the workspace pod
  EXPECTED_NODE            Optional exact node assertion
  EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB
                           Minimum allocatable ephemeral-storage for the
                           scheduled runtime node. Defaults to 500; set 0 to skip.
  EXPECTED_STUN_HOST       Expected public STUN host in the tailnet doctor's
                           DERP map
  EXPECTED_STUN_PORT       Expected public STUN port in that DERP map
  EXPECTED_TAILNET_PATH_TRANSPORT
                           Expected CW_DEBUG_TAILNET path-probe transport.
                           Defaults to empty, accepting any reachable tailnet
                           path. Set to direct_udp for explicit #182 proof or
                           peer_relay for the #257 no-NodePort relay proof.
                           Non-any tailnet SSH checks also pass this to cw as
                           CW_TAILNET_EXPECTED_TRANSPORT before dialing.
  EXPECTED_TAILNET_PEER_RELAY_ENDPOINT
                           Required configured endpoint when
                           EXPECTED_TAILNET_PATH_TRANSPORT=peer_relay.
  EXPECTED_UDP_RELAY_BIND_ADDRS
                           Accepted for wrapper compatibility; the daemon
                           receives relay endpoints from its access grant.
	  REQUIRE_TAILNET_PATH_PROBE
	                           Defaults to 0; with SMOKE_TAILNET_DEBUG=1, requires
	                           cw shell --stdio to emit a path probe line even when
	                           no exact transport is required.
	  EXPECTED_KATA_AGENT_POLICY_ANNOTATION
	                           Defaults to 0; set to 1 when commodity templates
	                           must carry Codewire-owned Kata Agent Policy.
	  EXPECTED_KATA_COCO_INIT_DATA_ANNOTATION
	                           Defaults to 0; set to 1 when dev node Kata config
	                           allows the CoCo init-data policy annotation.
  EXPECTED_KATA_COCO_KBS_URL
                           Optional; when set, decoded init-data must carry
                           aa.toml/cdh.toml with this KBS URL.
  EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI
                           Optional; when set, the workspace pod plus
                           the SandboxTemplate must carry CoCo kernel params
                           for guest registry auth via this KBS resource URI.
  EXPECTED_KATA_COCO_TEST_RESOURCE_URI
                           Optional; commodity fetches this non-sensitive KBS
                           resource through guest CDH REST. Confidential uses
                           the path only to prove that REST listener is absent.
  EXPECTED_KATA_COCO_TEST_RESOURCE_PATH
                           Deprecated compatibility input; ignored by the
                           current CoCo resource-boundary smoke path.
  EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT
                           Optional commodity-only expected resource content.
  EXPECTED_CODEWIRE_SMOKE_USER_EMAIL
                           Optional authenticated-user email assertion
USAGE
}

log() {
  printf '[runtime-smoke] %s\n' "$*" >&2
}

die() {
  printf '[runtime-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

assert_managed_run_stderr() {
  # cw's launch acknowledgement is separate from workload output. Accept only
  # silence or one exact acknowledgement, including its terminating newline.
  python3 - "$1" <<'PY'
import pathlib
import re
import sys
data = pathlib.Path(sys.argv[1]).read_bytes()
pattern = rb"Launched session session-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n"
sys.exit(0 if data == b"" or re.fullmatch(pattern, data) else 1)
PY
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

require_uint() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an unsigned integer, got '$value'"
}

require_bool01() {
  local name="$1"
  local value="$2"
  [[ "$value" == "0" || "$value" == "1" ]] || die "$name must be 0 or 1, got '$value'"
}

quantity_to_bytes() {
  local quantity="$1"
  local number suffix

  if [[ "$quantity" =~ ^([0-9]+)(Ki|Mi|Gi|Ti|Pi|Ei|K|M|G|T|P|E)?$ ]]; then
    number="${BASH_REMATCH[1]}"
    suffix="${BASH_REMATCH[2]:-}"
    case "$suffix" in
      "") printf '%s\n' "$number" ;;
      Ki) printf '%s\n' "$((number * 1024))" ;;
      Mi) printf '%s\n' "$((number * 1024 * 1024))" ;;
      Gi) printf '%s\n' "$((number * 1024 * 1024 * 1024))" ;;
      Ti) printf '%s\n' "$((number * 1024 * 1024 * 1024 * 1024))" ;;
      Pi) printf '%s\n' "$((number * 1024 * 1024 * 1024 * 1024 * 1024))" ;;
      Ei) printf '%s\n' "$((number * 1024 * 1024 * 1024 * 1024 * 1024 * 1024))" ;;
      K) printf '%s\n' "$((number * 1000))" ;;
      M) printf '%s\n' "$((number * 1000 * 1000))" ;;
      G) printf '%s\n' "$((number * 1000 * 1000 * 1000))" ;;
      T) printf '%s\n' "$((number * 1000 * 1000 * 1000 * 1000))" ;;
      P) printf '%s\n' "$((number * 1000 * 1000 * 1000 * 1000 * 1000))" ;;
      E) printf '%s\n' "$((number * 1000 * 1000 * 1000 * 1000 * 1000 * 1000))" ;;
    esac
    return 0
  fi

  die "unsupported Kubernetes quantity: $quantity"
}

expect_tailnet_peer_relay() {
  [[ "$EXPECTED_TAILNET_PATH_TRANSPORT" == "peer_relay" || "$EXPECTED_TAILNET_PATH_TRANSPORT" == "udp_relay" ]]
}

expect_tailnet_direct_udp() {
  [[ "$EXPECTED_TAILNET_PATH_TRANSPORT" == "direct_udp" ]]
}

while (($# > 0)); do
  case "$1" in
    --name)
      [[ $# -ge 2 ]] || die "--name requires a value"
      SMOKE_NAME="$2"
      shift 2
      ;;
    --cw-bin)
      [[ $# -ge 2 ]] || die "--cw-bin requires a value"
      CW_BIN="$2"
      shift 2
      ;;
    --existing-env)
      [[ $# -ge 2 ]] || die "--existing-env requires a value"
      SMOKE_EXISTING_ENV_ID="$2"
      shift 2
      ;;
    --admin-oidc)
      SMOKE_AUTH_MODE="admin-oidc"
      shift
      ;;
    --only)
      [[ $# -ge 2 ]] || die "--only requires a phase"
      case "$2" in
        kube|exec|coco|docker|doctor|ssh|tailnet-ssh|derp-ssh|websocket-ssh|host-key|app-preview|resize-guest|application-secrets|application-secrets-all-scopes|provider-ssh)
          SMOKE_ONLY_PHASES+=("$2")
          ;;
        *)
          die "unknown --only phase: $2"
          ;;
      esac
      shift 2
      ;;
    --keep)
      SMOKE_KEEP_ENV=1
      shift
      ;;
    --skip-kube)
      SMOKE_SKIP_KUBE=1
      shift
      ;;
    --skip-docker)
      SMOKE_SKIP_DOCKER=1
      shift
      ;;
    --skip-ssh)
      SMOKE_SKIP_SSH=1
      shift
      ;;
    --include-derp-fallback|--derp-fallback)
      SMOKE_DERP_FALLBACK=1
      shift
      ;;
    --skip-derp-fallback)
      SMOKE_DERP_FALLBACK=0
      shift
      ;;
    --timeout-seconds)
      [[ $# -ge 2 ]] || die "--timeout-seconds requires a value"
      SMOKE_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

cleanup() {
  local rc=$?
  stop_peer_relay_packet_diagnostics || true
  if [[ "$rc" != "0" ]]; then
    collect_failure_diagnostics "failure" || true
  fi
  if [[ -n "$PROVIDER_SSH_CREDENTIAL_NAME" ]]; then
    cleanup_provider_ssh || rc=1
  elif ((${#APP_SECRET_PROJECTS[@]} > 0 || ${#APP_SECRET_USER_ATTEMPTS[@]} > 0 || ${#APP_SECRET_ORG_ATTEMPTS[@]} > 0 || APP_SECRET_CREATE_ATTEMPTED == 1)); then
    if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
      (cleanup_application_secrets) || rc=1
    else
      cleanup_application_secrets || rc=1
    fi
  elif [[ -n "$ENV_ID" && "$SMOKE_KEEP_ENV" != "1" && -x "${CW_BIN:-}" ]]; then
    log "deleting smoke environment $ENV_ID"
    "$CW_BIN" --server "$CODEWIRE_SERVER_URL" rm --yes "$ENV_ID" >/dev/null 2>&1 || true
  elif [[ -n "$ENV_ID" && "$SMOKE_KEEP_ENV" == "1" ]]; then
    log "kept smoke environment $ENV_ID"
  fi
  if [[ "$SMOKE_OAUTH_LOGIN_ATTEMPTED" == 1 ]]; then
    cleanup_fresh_oauth_login || rc=1
  fi
  if [[ "$rc" != "0" && -n "$TMPDIR_SMOKE" && -d "$TMPDIR_SMOKE" ]]; then
    log "kept failed-smoke evidence directory $TMPDIR_SMOKE"
  elif [[ -n "$TMPDIR_SMOKE" && -d "$TMPDIR_SMOKE" && "$SMOKE_KEEP_ENV" != "1" ]]; then
    rm -rf "$TMPDIR_SMOKE"
  elif [[ -n "$TMPDIR_SMOKE" && -d "$TMPDIR_SMOKE" ]]; then
    log "kept evidence directory $TMPDIR_SMOKE"
  fi
  exit "$rc"
}

handle_signal() {
  local signal="$1"
  trap - INT TERM
  case "$signal" in
    INT) exit 130 ;;
    TERM) exit 143 ;;
    *) exit 1 ;;
  esac
}

split_peer_relay_endpoint() {
  local endpoint="$1"
  local relay_ip relay_port octet
  local -a octets

  [[ "$endpoint" == *:* ]] || \
    die "packet diagnostics require an IPv4 peer relay endpoint"
  relay_ip="${endpoint%:*}"
  relay_port="${endpoint##*:}"
  [[ "$relay_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ \
    && "$relay_port" =~ ^[0-9]+$ \
    && "$relay_port" -ge 1 \
    && "$relay_port" -le 65535 ]] || \
    die "packet diagnostics require an IPv4 peer relay endpoint"
  IFS=. read -r -a octets <<<"$relay_ip"
  for octet in "${octets[@]}"; do
    [[ "$octet" -le 255 ]] || \
      die "packet diagnostics require an IPv4 peer relay endpoint"
  done
  printf '%s\t%s\n' "$relay_ip" "$relay_port"
}

sanitize_peer_relay_packet_headers() {
  local raw_file="$1"
  local output_file="$2"
  local relay_ip="$3"
  local relay_port="$4"

  awk -v endpoint="${relay_ip}.${relay_port}" '
    $5 == "IP" && $7 == ">" {
      source = $6
      destination = $8
      sub(/:$/, "", destination)
      if (destination == endpoint) {
        direction = "outbound"
      } else if (source == endpoint) {
        direction = "inbound"
      } else {
        next
      }
      packet_length = 0
      for (i = 9; i <= NF; i++) {
        if ($i == "length" && (i + 1) <= NF && $(i + 1) ~ /^[0-9]+$/) {
          packet_length = $(i + 1)
          break
        }
      }
      printf "timestamp=%sT%s interface=%s direction=%s source=%s destination=%s protocol=UDP length=%d\n",
        $1, $2, $3, direction, source, destination, packet_length
    }
  ' "$raw_file" >"$output_file"
}

summarize_peer_relay_packet_headers() {
  local raw_file="$1"
  local relay_ip="$2"
  local relay_port="$3"
  local route_file="$4"
  local output_file="$5"
  local staged_headers="$6"
  local outbound inbound

  sanitize_peer_relay_packet_headers \
    "$raw_file" "$staged_headers" "$relay_ip" "$relay_port"
  outbound="$(awk '$0 ~ / direction=outbound / { count++ } END { print count + 0 }' \
    "$staged_headers")"
  inbound="$(awk '$0 ~ / direction=inbound / { count++ } END { print count + 0 }' \
    "$staged_headers")"
  jq -n \
    --slurpfile route "$route_file" \
    --arg relay_ip "$relay_ip" \
    --argjson relay_port "$relay_port" \
    --argjson outbound "$outbound" \
    --argjson inbound "$inbound" \
    '{
      relay: {ip: $relay_ip, port: $relay_port, protocol: "UDP"},
      route: $route[0],
      packets: {outbound: $outbound, inbound: $inbound}
    }' >"$output_file"
}

classify_peer_relay_packet_capture_error() {
  local error_file="$1"

  if grep -Eqi 'permission denied|operation not permitted|not permitted to capture|do not have permission' \
      "$error_file"; then
    printf 'permission_denied\n'
  elif grep -Eqi 'not supported|unsupported|does not support' "$error_file"; then
    printf 'unsupported\n'
  elif grep -Eqi 'no such device|device not found|cannot find device' "$error_file"; then
    printf 'device_unavailable\n'
  elif grep -Eqi 'syntax error|parse error|invalid filter' "$error_file"; then
    printf 'filter_invalid\n'
  else
    printf 'startup_failed\n'
  fi
}

record_peer_relay_packet_capture_unavailable() {
  local error_file="$1"
  local output_file="$2"
  local exit_code="$3"
  local failure_class

  failure_class="$(classify_peer_relay_packet_capture_error "$error_file")"
  jq -n \
    --arg state "unavailable" \
    --arg failure_class "$failure_class" \
    --argjson exit_code "$exit_code" \
    '{
      state: $state,
      failure_class: $failure_class,
      exit_code: $exit_code,
      payload_captured: false
    }' >"$output_file"
}

start_peer_relay_packet_diagnostics() {
  local relay_ip relay_port endpoint_parts route_file staged_headers
  local capture_exit=0

  require_bool01 SMOKE_PACKET_DIAGNOSTICS "$SMOKE_PACKET_DIAGNOSTICS"
  [[ "$SMOKE_PACKET_DIAGNOSTICS" == "1" ]] || return 0
  expect_tailnet_peer_relay || \
    die "packet diagnostics require EXPECTED_TAILNET_PATH_TRANSPORT=peer_relay"
  [[ -n "$SMOKE_ARTIFACT_DIR" ]] || \
    die "SMOKE_PACKET_DIAGNOSTICS requires SMOKE_ARTIFACT_DIR"
  require_cmd ip
  require_cmd jq
  require_cmd tcpdump

  endpoint_parts="$(split_peer_relay_endpoint "$EXPECTED_TAILNET_PEER_RELAY_ENDPOINT")"
  IFS=$'\t' read -r relay_ip relay_port <<<"$endpoint_parts"
  mkdir -p "$SMOKE_ARTIFACT_DIR"
  route_file="$SMOKE_ARTIFACT_DIR/peer-relay-route.json"
  staged_headers="$SMOKE_ARTIFACT_DIR/peer-relay-packet-headers.log"
  SMOKE_PACKET_CAPTURE_RAW="$TMPDIR_SMOKE/peer-relay-packet-headers.raw"
  SMOKE_PACKET_CAPTURE_ERROR="$TMPDIR_SMOKE/peer-relay-packet-headers.err"
  SMOKE_PACKET_CAPTURE_SUMMARY="$SMOKE_ARTIFACT_DIR/peer-relay-packet-summary.json"
  SMOKE_PACKET_CAPTURE_STATUS="$SMOKE_ARTIFACT_DIR/peer-relay-packet-capture.json"

  ip -j route get "$relay_ip" \
    | jq -e --arg destination "$relay_ip" '
        .[0]
        | {
            destination: (.dst // $destination),
            interface: .dev,
            source: (.prefsrc // .src),
            gateway: (.gateway // null)
          }
        | select(
            (.interface | type == "string" and length > 0)
            and (.source | type == "string" and length > 0)
          )
      ' >"$route_file"

  # Linux cooked v2 (20) + IPv4 (20) + UDP (8) headers exactly; no UDP payload.
  tcpdump -i any -Q inout -nn -tttt -l -s 48 \
    "host $relay_ip and udp port $relay_port" \
    >"$SMOKE_PACKET_CAPTURE_RAW" 2>"$SMOKE_PACKET_CAPTURE_ERROR" &
  SMOKE_PACKET_CAPTURE_PID="$!"
  sleep 1
  if ! kill -0 "$SMOKE_PACKET_CAPTURE_PID" 2>/dev/null; then
    set +e
    wait "$SMOKE_PACKET_CAPTURE_PID" 2>/dev/null
    capture_exit="$?"
    set -e
    SMOKE_PACKET_CAPTURE_PID=""
    record_peer_relay_packet_capture_unavailable \
      "$SMOKE_PACKET_CAPTURE_ERROR" \
      "$SMOKE_PACKET_CAPTURE_STATUS" \
      "$capture_exit"
    rm -f "$SMOKE_PACKET_CAPTURE_RAW" "$SMOKE_PACKET_CAPTURE_ERROR"
    SMOKE_PACKET_CAPTURE_RAW=""
    SMOKE_PACKET_CAPTURE_ERROR=""
    SMOKE_PACKET_CAPTURE_UNAVAILABLE=1
    log "local peer-relay packet capture unavailable; continuing doctor for external exact-tuple observation"
    return 0
  fi
  : >"$staged_headers"
  jq -n \
    '{state: "active", payload_captured: false}' \
    >"$SMOKE_PACKET_CAPTURE_STATUS"
  log "started header-only peer-relay packet diagnostic"
}

stop_peer_relay_packet_diagnostics() {
  local relay_ip relay_port endpoint_parts staged_headers outbound

  [[ -n "$SMOKE_PACKET_CAPTURE_PID" ]] || return 0
  kill -INT "$SMOKE_PACKET_CAPTURE_PID" 2>/dev/null || true
  wait "$SMOKE_PACKET_CAPTURE_PID" 2>/dev/null || true
  SMOKE_PACKET_CAPTURE_PID=""

  endpoint_parts="$(split_peer_relay_endpoint "$EXPECTED_TAILNET_PEER_RELAY_ENDPOINT")"
  IFS=$'\t' read -r relay_ip relay_port <<<"$endpoint_parts"
  staged_headers="$SMOKE_ARTIFACT_DIR/peer-relay-packet-headers.log"
  summarize_peer_relay_packet_headers \
    "$SMOKE_PACKET_CAPTURE_RAW" \
    "$relay_ip" \
    "$relay_port" \
    "$SMOKE_ARTIFACT_DIR/peer-relay-route.json" \
    "$SMOKE_PACKET_CAPTURE_SUMMARY" \
    "$staged_headers"
  rm -f "$SMOKE_PACKET_CAPTURE_RAW" "$SMOKE_PACKET_CAPTURE_ERROR"
  SMOKE_PACKET_CAPTURE_RAW=""
  SMOKE_PACKET_CAPTURE_ERROR=""
  outbound="$(jq -er '.packets.outbound' "$SMOKE_PACKET_CAPTURE_SUMMARY")"
  jq -n \
    --argjson outbound "$outbound" \
    --argjson inbound "$(jq -er '.packets.inbound' "$SMOKE_PACKET_CAPTURE_SUMMARY")" \
    '{
      state: "complete",
      packets: {outbound: $outbound, inbound: $inbound},
      payload_captured: false
    }' >"$SMOKE_PACKET_CAPTURE_STATUS"
  log "captured peer-relay packet metadata (outbound=$outbound)"
  [[ "$outbound" -gt 0 ]] || {
    log "peer-relay packet diagnostic captured no outbound request"
    return 1
  }
}

cw() {
  if ((${#SMOKE_OAUTH_ENV[@]})); then
    env -i "${SMOKE_OAUTH_ENV[@]}" "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"
    return
  fi
  "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"
}

cw_with_timeout() {
  local duration="$1"
  shift
  if ((${#SMOKE_OAUTH_ENV[@]})); then
    env -i "${SMOKE_OAUTH_ENV[@]}" timeout "$duration" \
      "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"
    return
  fi
  timeout "$duration" "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"
}

kubectl_dev() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

seconds_now() {
  date +%s
}

wait_until() {
  local message="$1"
  local deadline="$2"
  shift 2

  SMOKE_LAST_WAIT_DETAIL=""
  while (( "$(seconds_now)" < deadline )); do
    if "$@"; then
      return 0
    fi
    sleep 5
  done
  if [[ -n "$SMOKE_LAST_WAIT_DETAIL" ]]; then
    die "timed out waiting for $message; last detail: $SMOKE_LAST_WAIT_DETAIL"
  fi
  die "timed out waiting for $message"
}

smoke_only_configured() {
  ((${#SMOKE_ONLY_PHASES[@]} > 0))
}

maybe_default_kubeconfig() {
  if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
    export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
  fi
}

select_kube_context() {
  local contexts context_err current_context candidate

  context_err="$TMPDIR_SMOKE/kubectl-context.err"
  if ! contexts="$(kubectl config get-contexts -o name 2>"$context_err")"; then
    sed 's/[[:cntrl:]]//g' "$context_err" >&2 || true
    die "failed to read Kubernetes contexts"
  fi

  if [[ -n "$KUBE_CONTEXT" ]]; then
    if grep -Fxq "$KUBE_CONTEXT" <<<"$contexts"; then
      log "using Kubernetes context $KUBE_CONTEXT"
      return 0
    fi
    printf '%s\n' "$contexts" | sed 's/^/[runtime-smoke] available Kubernetes context: /' >&2
    die "KUBE_CONTEXT=$KUBE_CONTEXT is not present in the active kubeconfig"
  fi

  for candidate in codewire-dev default; do
    if grep -Fxq "$candidate" <<<"$contexts"; then
      KUBE_CONTEXT="$candidate"
      export KUBE_CONTEXT
      log "using Kubernetes context $KUBE_CONTEXT"
      return 0
    fi
  done

  current_context="$(kubectl config current-context 2>"$context_err" || true)"
  if [[ -n "$current_context" ]]; then
    KUBE_CONTEXT="$current_context"
    export KUBE_CONTEXT
    log "using Kubernetes context $KUBE_CONTEXT"
    return 0
  fi

  printf '%s\n' "$contexts" | sed 's/^/[runtime-smoke] available Kubernetes context: /' >&2
  die "failed to select Kubernetes context"
}

prepare_cli() {
  [[ -n "$CODEWIRE_SERVER_URL" ]] || die "CODEWIRE_SERVER_URL is required"
  [[ -n "$EXPECTED_CODEWIRE_DEV_SERVER_URL" || "$ALLOW_NON_DEV" == "1" ]] || \
    die "EXPECTED_CODEWIRE_DEV_SERVER_URL is required"
  [[ "$CODEWIRE_SERVER_URL" == "$EXPECTED_CODEWIRE_DEV_SERVER_URL" || "$ALLOW_NON_DEV" == "1" ]] || \
    die "refusing to run against $CODEWIRE_SERVER_URL without ALLOW_NON_DEV=1"
  require_cmd awk
  require_cmd sed
  require_cmd timeout

  mkdir -p "$SMOKE_TMP_PARENT"
  TMPDIR_SMOKE="$(mktemp -d "$SMOKE_TMP_PARENT/codewire-runtime-smoke.XXXXXX")"
  chmod 0700 "$TMPDIR_SMOKE"

  case "$SMOKE_AUTH_MODE" in
    api-key)
      if [[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]]; then
        export CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"
      elif [[ "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == "1" && -n "${CODEWIRE_API_KEY:-}" ]]; then
        :
      else
        die "CODEWIRE_DEV_SMOKE_API_KEY is required; for local runs use scripts/runtime/dev/with-dev-smoke-auth.sh; set ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=1 only for manual debugging"
      fi
      export CW_CONFIG_DIR="$TMPDIR_SMOKE/cw-config"
      mkdir -p "$CW_CONFIG_DIR"
      ;;
    admin-oidc)
      [[ -z "${CODEWIRE_DEV_SMOKE_API_KEY:-}" && -z "${CODEWIRE_API_KEY:-}" ]] || \
        die "--admin-oidc refuses inherited API keys"
      [[ "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == "0" ]] || \
        die "--admin-oidc refuses ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE"
      if [[ -z "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" ]]; then
        [[ -n "${HOME:-}" ]] || die "--admin-oidc requires HOME or CODEWIRE_ADMIN_OAUTH_CONFIG_DIR"
        CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$HOME/.config/cw"
      fi
      validate_admin_oauth_config "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR"
      export CW_CONFIG_DIR="$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR"
      ;;
    *) die "unsupported smoke auth mode: $SMOKE_AUTH_MODE" ;;
  esac

  if [[ -z "$CW_BIN" ]]; then
    require_cmd cargo
    CW_BIN="$TMPDIR_SMOKE/cw"
    log "building cw CLI with timeout $SMOKE_CW_BUILD_TIMEOUT"
    if ! (cd "$ROOT" && timeout "$SMOKE_CW_BUILD_TIMEOUT" cargo build --locked --profile ci -p codewire-cli-bin --bin cw) >"$TMPDIR_SMOKE/rust-build-cw.log" 2>&1; then
      sed 's/[[:cntrl:]]//g' "$TMPDIR_SMOKE/rust-build-cw.log" >&2 || true
      die "cw CLI build failed"
    fi
    cp "$ROOT/target/ci/cw" "$CW_BIN"
  fi
  [[ -x "$CW_BIN" ]] || die "cw binary is not executable: $CW_BIN"
  assert_smoke_principal
}

validate_admin_oauth_config() {
  local config_dir="$1"
  local path mode

  require_cmd stat
  [[ -d "$config_dir" && ! -L "$config_dir" ]] || \
    die "--admin-oidc config directory is missing or not a real directory"
  mode="$(stat -c '%a' "$config_dir")"
  [[ "$mode" == "700" ]] || die "--admin-oidc config directory must be mode 0700"

  for path in "$config_dir/config.json" "$config_dir/credentials.json"; do
    [[ -f "$path" && ! -L "$path" ]] || \
      die "--admin-oidc requires regular config.json and credentials.json files"
    mode="$(stat -c '%a' "$path")"
    [[ "$mode" == "600" ]] || \
      die "--admin-oidc config.json and credentials.json must be mode 0600"
  done
}

assert_smoke_principal() {
  if [[ "$SMOKE_AUTH_MODE" == "admin-oidc" ]]; then
    assert_admin_oauth_principal
    return
  fi
  [[ -n "$EXPECTED_CODEWIRE_SMOKE_USER_EMAIL" ]] || return 0
  require_cmd jq

  local orgs_out="$TMPDIR_SMOKE/organizations.json"
  local orgs_err="$TMPDIR_SMOKE/organizations.err"
  if ! cw org list --output json >"$orgs_out" 2>"$orgs_err"; then
    sed 's/[[:cntrl:]]//g' "$orgs_err" >&2 || true
    die "failed to verify the smoke API key organization"
  fi

  if ! jq -e --arg slug "$CODEWIRE_DEV_SMOKE_ORG_SLUG" '
      type == "array"
      and length == 1
      and .[0].slug == $slug
      and .[0].role == "owner"
      and ((.[0].id | type) == "string")
      and ((.[0].id | length) > 0)
  ' "$orgs_out" >/dev/null; then
    die "smoke API key must own exactly the dedicated dev smoke organization"
  fi

  local expected_org_id
  expected_org_id="$(jq -er '.[0].id' "$orgs_out")"
  local current_org_out="$TMPDIR_SMOKE/current-organization.out"
  local current_org_err="$TMPDIR_SMOKE/current-organization.err"
  if ! cw org current >"$current_org_out" 2>"$current_org_err"; then
    sed 's/[[:cntrl:]]//g' "$current_org_err" >&2 || true
    die "authenticated smoke principal has no usable current organization"
  fi
  if ! awk -v expected_org_id="$expected_org_id" '
      $1 == "ID:" && $2 == expected_org_id { found = 1 }
      END { exit(found ? 0 : 1) }
    ' "$current_org_out"; then
    die "current organization does not match the authenticated organization list"
  fi

  local environments_out="$TMPDIR_SMOKE/environments.json"
  local environments_err="$TMPDIR_SMOKE/environments.err"
  if ! cw --cloud ls --output json >"$environments_out" 2>"$environments_err"; then
    sed 's/[[:cntrl:]]//g' "$environments_err" >&2 || true
    die "authenticated smoke principal cannot list environments for its current organization"
  fi
  jq -e 'type == "array"' "$environments_out" >/dev/null ||
    die "environment list did not return a JSON array"

  local keys_out="$TMPDIR_SMOKE/api-keys.out"
  local keys_err="$TMPDIR_SMOKE/api-keys.err"
  if ! cw api-keys list >"$keys_out" 2>"$keys_err"; then
    sed 's/[[:cntrl:]]//g' "$keys_err" >&2 || true
    die "failed to verify the smoke API key metadata"
  fi

  local key_material="${CODEWIRE_API_KEY#cw_}"
  local expected_prefix="${key_material:0:8}"
  if ! awk \
      -v expected_prefix="$expected_prefix" \
      -v expected_name="$CODEWIRE_DEV_SMOKE_API_KEY_NAME" '
        NR > 1 && $1 == expected_prefix && $2 == expected_name {
          matches++
        }
        END {
          exit(matches == 1 ? 0 : 1)
        }
      ' "$keys_out"; then
    die "authenticated API key does not match the dedicated dev smoke fixture"
  fi
}

assert_admin_oauth_principal() {
  require_cmd jq

  local whoami_out="$TMPDIR_SMOKE/admin-whoami.json"
  local whoami_err="$TMPDIR_SMOKE/admin-whoami.err"
  if ! cw whoami --output json >"$whoami_out" 2>"$whoami_err"; then
    sed 's/[[:cntrl:]]//g' "$whoami_err" >&2 || true
    die "saved admin OIDC login is not usable for the selected server"
  fi
  jq -e '
      type == "object"
      and ((.id | type) == "string" and (.id | length) > 0)
      and ((.email | type) == "string" and (.email | length) > 0)
    ' "$whoami_out" >/dev/null || \
    die "saved admin OIDC login did not return an account identity"
  if [[ -n "$EXPECTED_CODEWIRE_ADMIN_EMAIL" ]]; then
    jq -e --arg email "$EXPECTED_CODEWIRE_ADMIN_EMAIL" '.email == $email' \
      "$whoami_out" >/dev/null || \
      die "saved admin OIDC login does not match EXPECTED_CODEWIRE_ADMIN_EMAIL"
  fi

  local current_org_out="$TMPDIR_SMOKE/admin-current-organization.out"
  local current_org_err="$TMPDIR_SMOKE/admin-current-organization.err"
  if ! cw org current >"$current_org_out" 2>"$current_org_err"; then
    sed 's/[[:cntrl:]]//g' "$current_org_err" >&2 || true
    die "saved admin OIDC login has no usable current organization"
  fi

  local environments_out="$TMPDIR_SMOKE/admin-environments.json"
  local environments_err="$TMPDIR_SMOKE/admin-environments.err"
  if ! cw --cloud ls --output json >"$environments_out" 2>"$environments_err"; then
    sed 's/[[:cntrl:]]//g' "$environments_err" >&2 || true
    die "saved admin OIDC login cannot list environments for its current organization"
  fi
  jq -e 'type == "array"' "$environments_out" >/dev/null || \
    die "admin environment list did not return a JSON array"
}

create_environment() {
  local create_out="$TMPDIR_SMOKE/create.out"
  local -a source_args=()
  if [[ -n "$APP_SECRET_DOCUMENT" ]]; then
    if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
      verify_application_all_scope_metadata
    fi
    source_args=(--cloud --file "$APP_SECRET_DOCUMENT")
    APP_SECRET_CREATE_ATTEMPTED=1
  elif [[ -n "$PROVIDER_SSH_DOCUMENT" ]]; then
    source_args=(--cloud --file "$PROVIDER_SSH_DOCUMENT")
    PROVIDER_SSH_CREATE_ATTEMPTED=1
  fi

  case "$SMOKE_ISOLATION_TIER" in
    standard|confidential) ;;
    *) die "SMOKE_ISOLATION_TIER must be standard or confidential" ;;
  esac

  log "creating environment $SMOKE_NAME on $CODEWIRE_SERVER_URL"
  if ! cw create \
      "${source_args[@]}" \
      --image "$SMOKE_IMAGE" \
      --name "$SMOKE_NAME" \
      --cpu "$SMOKE_CPU" \
      --memory "$SMOKE_MEMORY" \
      --disk "$SMOKE_DISK" \
      --isolation "$SMOKE_ISOLATION_TIER" \
      --ttl "$SMOKE_TTL" \
      --no-network \
      --no-wait \
      --yes >"$create_out" 2>&1; then
    sed 's/[[:cntrl:]]//g' "$create_out" >&2 || true
    die "cw create failed"
  fi

  ENV_ID="$(awk '/^[[:space:]]*ID:/ {print $2; exit}' "$create_out")"
  [[ -n "$ENV_ID" ]] || {
    sed 's/[[:cntrl:]]//g' "$create_out" >&2 || true
    die "failed to parse environment ID from cw create output"
  }
  log "environment id $ENV_ID"
}

application_secrets_selected() {
  local phase
  for phase in "${SMOKE_ONLY_PHASES[@]}"; do
    [[ "$phase" != application-secrets && "$phase" != application-secrets-all-scopes ]] || return 0
  done
  return 1
}

application_all_scopes_selected() {
  [[ "${#SMOKE_ONLY_PHASES[@]}" == 1 && "${SMOKE_ONLY_PHASES[0]}" == application-secrets-all-scopes ]]
}

application_all_scopes_requested() {
  local phase
  for phase in "${SMOKE_ONLY_PHASES[@]}"; do
    [[ "$phase" != application-secrets-all-scopes ]] || return 0
  done
  return 1
}

validate_application_secrets_options() {
  [[ -z "$SMOKE_EXISTING_ENV_ID" && "$SMOKE_KEEP_ENV" == 0 && "$SMOKE_SKIP_KUBE" == 0 ]] ||
    die 'application-secrets requires a fresh disposable environment and Kubernetes checks; --existing-env, --keep and --skip-kube are unsupported'
  [[ "$SMOKE_AUTH_MODE" == api-key && "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == 0 &&
     -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" && -n "$EXPECTED_CODEWIRE_SMOKE_USER_EMAIL" ]] ||
    die 'application-secrets requires the existing dedicated Dev smoke API-key wrapper; no owner OAuth or generic-key fallback'
  [[ "$ALLOW_NON_DEV" == 0 && -n "$EXPECTED_CODEWIRE_DEV_SERVER_URL" &&
     "$CODEWIRE_SERVER_URL" == "$EXPECTED_CODEWIRE_DEV_SERVER_URL" ]] ||
    die 'application-secrets requires the exact configured Dev endpoint'
  [[ -n "$SANDBOX_NAMESPACE" ]] || die 'application-secrets requires SANDBOX_NAMESPACE'
  local command
  for command in jq python3 sha256sum script; do require_cmd "$command"; done
}

validate_application_all_scopes_options() {
  application_all_scopes_selected ||
    die 'application-secrets-all-scopes must be the sole selected phase'
  [[ "$SMOKE_AUTH_MODE" == admin-oidc && -z "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" &&
     -z "${CW_CONFIG_DIR:-}" ]] ||
    die 'application-secrets-all-scopes requires --admin-oidc without any saved login directory'
  [[ -z "${CODEWIRE_API_KEY:-}" && -z "${CODEWIRE_DEV_SMOKE_API_KEY:-}" &&
     "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == 0 ]] ||
    die 'application-secrets-all-scopes refuses API keys and generic-key fallback'
  [[ "$ALLOW_NON_DEV" == 0 && "$CODEWIRE_SERVER_URL" == https://codewire-dev.sh &&
     "$EXPECTED_CODEWIRE_DEV_SERVER_URL" == https://codewire-dev.sh ]] ||
    die 'application-secrets-all-scopes requires the exact https://codewire-dev.sh endpoint'
  [[ -z "$SMOKE_EXISTING_ENV_ID" && "$SMOKE_KEEP_ENV" == 0 && "$SMOKE_SKIP_KUBE" == 1 ]] ||
    die 'application-secrets-all-scopes requires a fresh disposable environment without Kubernetes access'
  [[ -n "$EXPECTED_CODEWIRE_ADMIN_EMAIL" ]] ||
    die 'application-secrets-all-scopes requires an exact account email'
  [[ "$EXPECTED_CODEWIRE_ADMIN_USER_ID" =~ ^[0-9a-f]{32}$ &&
     "$EXPECTED_CODEWIRE_ADMIN_USER_ID" != 00000000000000000000000000000000 ]] ||
    die 'application-secrets-all-scopes requires an exact non-nil 32-hex account ID'
  [[ "$EXPECTED_CODEWIRE_ORGANIZATION_ID" =~ ^[0-9a-f]{32}$ &&
     "$EXPECTED_CODEWIRE_ORGANIZATION_ID" != 00000000000000000000000000000000 ]] ||
    die 'application-secrets-all-scopes requires an exact non-nil 32-hex organization ID'
  local command runtime_parent="${XDG_RUNTIME_DIR:-}"
  for command in awk findmnt jq python3 realpath script sed sha256sum stat timeout; do
    require_cmd "$command"
  done
  [[ "$CW_BIN" == /* && -f "$CW_BIN" && -x "$CW_BIN" && ! -L "$CW_BIN" &&
     "$(realpath -e -- "$CW_BIN")" == "$CW_BIN" ]] ||
    die 'application-secrets-all-scopes requires a canonical absolute prebuilt normal cw executable'
  [[ -n "$runtime_parent" && "$(realpath -e -- "$runtime_parent")" == "$runtime_parent" &&
     "$(stat -c '%u:%a' "$runtime_parent")" == "$(id -u):700" &&
     "$(findmnt -nro FSTYPE -T "$runtime_parent")" == tmpfs ]] ||
    die 'application-secrets-all-scopes requires a canonical owner-0700 tmpfs XDG_RUNTIME_DIR'
  validate_dev_smoke_browser_auth
}

# Optional automation uses the same fresh user OAuth grant as owner approval.
# These are paths/identity metadata only; no credential values enter shell state.
validate_dev_smoke_browser_auth() {
  if [[ -z "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" &&
        -z "$DEV_SMOKE_BROWSER_AUTH_BUN_BIN" &&
        -z "$DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN" ]]; then
    return 0
  fi
  [[ "$SMOKE_AUTH_MODE" == admin-oidc && "$ALLOW_NON_DEV" == 0 &&
     "$CODEWIRE_SERVER_URL" == https://codewire-dev.sh &&
     "$EXPECTED_CODEWIRE_DEV_SERVER_URL" == https://codewire-dev.sh &&
     -z "${CODEWIRE_API_KEY:-}" && -z "${CODEWIRE_DEV_SMOKE_API_KEY:-}" &&
     "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == 0 &&
     -z "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" && -z "${CW_CONFIG_DIR:-}" ]] ||
    die 'browser automation requires fresh Dev account OAuth without saved login or API keys'
  [[ "$EXPECTED_CODEWIRE_ADMIN_USER_ID" =~ ^[0-9a-f]{32}$ &&
     "$EXPECTED_CODEWIRE_ADMIN_USER_ID" != 00000000000000000000000000000000 &&
     "$EXPECTED_CODEWIRE_ORGANIZATION_ID" =~ ^[0-9a-f]{32}$ &&
     "$EXPECTED_CODEWIRE_ORGANIZATION_ID" != 00000000000000000000000000000000 &&
     -n "$EXPECTED_CODEWIRE_ADMIN_EMAIL" ]] ||
    die 'browser automation requires exact expected account and organization identities'
  local path runtime_parent="${XDG_RUNTIME_DIR:-}"
  for path in "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" "$DEV_SMOKE_BROWSER_AUTH_BUN_BIN" \
      "$DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN" "$CW_BIN"; do
    [[ "$path" == /* && -f "$path" && ! -L "$path" &&
       "$(realpath -e -- "$path")" == "$path" ]] ||
      die 'browser automation requires canonical regular credential and executable paths'
  done
  [[ "$(stat -c '%u:%a' -- "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE")" == "$(id -u):600" &&
     -x "$DEV_SMOKE_BROWSER_AUTH_BUN_BIN" && -x "$DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN" &&
     -x "$CW_BIN" && "${CW_BIN##*/}" != cw-local-credential-broker-smoke ]] ||
    die 'browser automation requires an owner-private credential file and executable runtimes'
  [[ "$runtime_parent" == /* && -d "$runtime_parent" && ! -L "$runtime_parent" &&
     "$(realpath -e -- "$runtime_parent")" == "$runtime_parent" &&
     "$(stat -c '%u:%a' -- "$runtime_parent")" == "$(id -u):700" &&
     "$(findmnt -nro FSTYPE -T "$runtime_parent")" == tmpfs ]] ||
    die 'browser automation requires an owner-private canonical tmpfs runtime parent'
}

prepare_dev_smoke_browser_login() {
  local config_dir="$1" work_parent work_dir helper_status=0 cleanup_status=0
  local -a ux_args=()
  # Only this protected all-scope journey admits the disposable UX sandbox.
  # Provider-SSH and other browser login consumers retain their existing scope.
  if application_all_scopes_selected; then ux_args=(--ux-walkthrough enabled); fi
  work_parent="$(dirname -- "$config_dir")"
  work_dir="$(mktemp -d "$work_parent/.cw-browser-auth.XXXXXX")" ||
    die 'cannot create isolated browser helper runtime'
  chmod 0700 "$work_dir" || die 'cannot secure isolated browser helper runtime'
  # The checked-in helper enforces empty owner-0700 tmpfs state before reading
  # the separately supplied credential file. Run Bun from the checked-in root
  # with installation disabled: auto-install would write package state into the
  # empty OAuth config directory before the helper can validate it. Its output
  # contains fixed stages only and it never inherits shell, owner-provider,
  # browser or OpenBao state.
  if ! (
    ulimit -c 0
    cd -- "$ROOT"
    exec env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C TMPDIR="$work_dir" \
      "$DEV_SMOKE_BROWSER_AUTH_BUN_BIN" --no-env-file --config=/dev/null --no-install \
      "$ROOT/apps/dashboard/scripts/prepare-dev-smoke-browser-auth.ts" \
      --cw-bin "$CW_BIN" --config-dir "$config_dir" \
      --credential-file "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" \
      --expected-user-id "$EXPECTED_CODEWIRE_ADMIN_USER_ID" \
      --expected-email "$EXPECTED_CODEWIRE_ADMIN_EMAIL" \
      --expected-org-id "$EXPECTED_CODEWIRE_ORGANIZATION_ID" \
      --chromium-executable "$DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN" "${ux_args[@]}"
  ); then
    helper_status=1
  fi
  if [[ "$work_dir" == "$work_parent"/.cw-browser-auth.?????? && -d "$work_dir" && ! -L "$work_dir" &&
        "$(stat -c '%u:%a' -- "$work_dir")" == "$(id -u):700" ]]; then
    rm -rf -- "$work_dir" || cleanup_status=1
    [[ ! -e "$work_dir" && ! -L "$work_dir" ]] || cleanup_status=1
  else
    cleanup_status=1
  fi
  [[ "$cleanup_status" == 0 ]] || die 'isolated browser helper runtime cleanup failed'
  [[ "$helper_status" == 0 ]] || die 'fresh automated Dev browser login failed'
}

assert_fresh_oauth_principal() {
  assert_admin_oauth_principal
  jq -es --arg id "$EXPECTED_CODEWIRE_ADMIN_USER_ID" --arg email "$EXPECTED_CODEWIRE_ADMIN_EMAIL" '
    length == 1 and (.[0] | .id == $id and .email == $email)
  ' "$TMPDIR_SMOKE/admin-whoami.json" >/dev/null ||
    die 'fresh OAuth login did not match the exact expected account identity'
  cw_with_timeout 30 org list --output json >"$TMPDIR_SMOKE/admin-organizations.json" ||
    die 'fresh OAuth login cannot list its organization ownership'
  jq -es --arg id "$EXPECTED_CODEWIRE_ORGANIZATION_ID" '
    length == 1 and (.[0] | type == "array" and
      ([.[] | select(.id == $id and .role == "owner")] | length) == 1 and
      ([.[] | select(.id == $id)] | length) == 1)
  ' "$TMPDIR_SMOKE/admin-organizations.json" >/dev/null ||
    die 'fresh OAuth account must exactly own the selected dedicated organization'
  [[ "$(awk '$1 == "ID:" {print $2}' "$TMPDIR_SMOKE/admin-current-organization.out")" == \
      "$EXPECTED_CODEWIRE_ORGANIZATION_ID" &&
     "$(awk '$1 == "Role:" {print $2}' "$TMPDIR_SMOKE/admin-current-organization.out")" == owner ]] ||
    die 'fresh OAuth login did not select the exact owned organization'
}

prepare_fresh_oauth_cli() {
  mkdir -p "$SMOKE_TMP_PARENT"
  TMPDIR_SMOKE="$(mktemp -d "$SMOKE_TMP_PARENT/codewire-runtime-smoke.XXXXXX")"
  chmod 0700 "$TMPDIR_SMOKE"
  mkdir -m 0700 "$TMPDIR_SMOKE/auth-home"
  SMOKE_OAUTH_RUNTIME_PARENT="$XDG_RUNTIME_DIR"
  SMOKE_OAUTH_RUNTIME_DIR="$(mktemp -d "$SMOKE_OAUTH_RUNTIME_PARENT/.cwapp-XXXXXX")"
  chmod 0700 "$SMOKE_OAUTH_RUNTIME_DIR"
  SMOKE_OAUTH_LOGIN_ATTEMPTED=1
  SMOKE_OAUTH_LOGIN_DIR="$SMOKE_OAUTH_RUNTIME_DIR/login"
  mkdir -m 0700 "$SMOKE_OAUTH_LOGIN_DIR"
  CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$SMOKE_OAUTH_LOGIN_DIR"
  SMOKE_OAUTH_ENV=(PATH=/usr/bin:/bin "HOME=$TMPDIR_SMOKE/auth-home"
    "USER=$(id -un)" "LOGNAME=$(id -un)" SHELL=/bin/bash TERM=xterm-256color LC_ALL=C
    "CW_CONFIG_DIR=$SMOKE_OAUTH_LOGIN_DIR" "XDG_RUNTIME_DIR=$SMOKE_OAUTH_RUNTIME_DIR"
    "DBUS_SESSION_BUS_ADDRESS=unix:path=$SMOKE_OAUTH_RUNTIME_DIR/no-owner-bus")
  if [[ -n "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" ]]; then
    prepare_dev_smoke_browser_login "$SMOKE_OAUTH_LOGIN_DIR"
  else
    cw_with_timeout 600 login --org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" ||
      die 'fresh owner-operated Dev login failed'
  fi
  validate_admin_oauth_config "$SMOKE_OAUTH_LOGIN_DIR"
  assert_fresh_oauth_principal
}

cleanup_fresh_oauth_login() {
  local rc=0
  cw_with_timeout 30 logout >"$TMPDIR_SMOKE/app-logout.out" 2>"$TMPDIR_SMOKE/app-logout.err" || rc=1
  if [[ "$SMOKE_OAUTH_RUNTIME_DIR" == "$SMOKE_OAUTH_RUNTIME_PARENT"/.cwapp-?????? ]]; then
    rm -rf -- "$SMOKE_OAUTH_RUNTIME_DIR"
    [[ ! -e "$SMOKE_OAUTH_RUNTIME_DIR" && ! -L "$SMOKE_OAUTH_RUNTIME_DIR" ]] || rc=1
  else
    rc=1
  fi
  [[ "$rc" == 0 ]] || log 'fresh all-scope login cleanup failed'
  return "$rc"
}

assert_application_artifacts_redacted() {
  local status value
  ((${#APP_SECRET_VALUES[@]} > 0)) || return 0
  for value in "${APP_SECRET_VALUES[@]}"; do
    [[ -n "$value" ]] || die 'application-secret artifact inspection has an empty pattern'
  done
  # Only synthetic patterns enter this anonymous pipe, never grep argv/files.
  if grep -Fq -f <(printf '%s\n' "${APP_SECRET_VALUES[@]}") -- "$@"; then
    die 'application-secret value entered smoke output or metadata; output suppressed'
  else
    status=$?
    [[ "$status" == 1 ]] || die 'application-secret artifact inspection failed'
  fi
}

assert_application_scope_metadata() {
  local file="$1"
  shift
  local expected
  if (($# == 0)); then expected='[]'
  else expected="$(printf '%s\n' "$@" | jq -Rsc 'split("\n")[:-1] | sort')"; fi
  jq -es --argjson expected "$expected" '
    length == 1 and (.[0] |
      type == "array" and
      (map(.key) | sort) == $expected and
      all(.[]; type == "object" and
        (keys | sort) == ["created_at", "key", "updated_at"] and
        (.key | type) == "string" and
        (.created_at | type) == "string" and
        (.updated_at | type) == "string"))
  ' "$file" >/dev/null
}

application_secret_hash() {
  printf '%s' "$1" | sha256sum | cut -d ' ' -f 1
}

application_all_scopes_hash_checks() {
  local -n hashes="$1"
  local index key hash checks=''
  for index in "${!APP_SECRET_ALL_KEYS[@]}"; do
    key="${APP_SECRET_ALL_KEYS[$index]}"
    hash="${hashes[$index]}"
    if [[ "$hash" == absent ]]; then
      checks+="test \"\${${key}+x}\" != x; "
    else
      checks+="test \"\${${key}+x}\" = x; test \"\$(printf %s \"\$${key}\" | sha256sum | cut -d ' ' -f 1)\" = '$hash'; "
    fi
  done
  printf '%s' "$checks"
}

create_application_secret_project() {
  local project="$1" index="$2" project_id
  jq -e --arg name "$project" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/app-projects-before.json" >/dev/null || die 'synthetic project name already exists'
  # Retain exact intent before the request so a committed create with a lost
  # response is still reconciled by cleanup.
  APP_SECRET_PROJECTS+=("$project")
  cw_with_timeout 30 secrets --cloud projects create "$project" \
    >"$TMPDIR_SMOKE/app-create-project-$index.out" 2>"$TMPDIR_SMOKE/app-create-project-$index.err" ||
    die 'dedicated smoke identity cannot create its disposable secret project'
  cw_with_timeout 30 secrets --cloud projects list --output json >"$TMPDIR_SMOKE/app-projects.json" ||
    die 'cannot resolve the created platform secret project'
  project_id="$(jq -er --arg name "$project" '
    [.[] | select(.name == $name)] | if length == 1 then .[0].id else error("ambiguous project") end
    | select(test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))
  ' "$TMPDIR_SMOKE/app-projects.json")" || die 'created application project ID is missing or ambiguous'
  APP_SECRET_IDS+=("$project_id")
}

prepare_application_all_scope_secrets() {
  local nonce prefix project index key value install startup checks
  local org_unique org_op org_pu org_cfg user_unique user_pu user_cfg config_hash
  local -a project_unique=() project_op=() project_pu=() project_cfg=()
  nonce="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die 'synthetic application identity generation failed'
  prefix="CWAPP_${nonce^^}"
  APP_SECRET_ALL_KEYS=("${prefix}_ORG" "${prefix}_PROJECT" "${prefix}_USER"
    "${prefix}_ORG_PROJECT" "${prefix}_PROJECT_USER" "${prefix}_CONFIG")

  cw_with_timeout 30 secrets --cloud --user list --output json >"$TMPDIR_SMOKE/app-user-before.json" ||
    die 'dedicated all-scope identity cannot list personal secret metadata'
  cw_with_timeout 30 secrets --cloud --organization list --output json >"$TMPDIR_SMOKE/app-org-before.json" ||
    die 'dedicated all-scope identity cannot list organization secret metadata'
  if ! jq -es 'length == 1 and (.[0] | type == "array" and length == 0)' \
      "$TMPDIR_SMOKE/app-user-before.json" >/dev/null ||
     ! jq -es 'length == 1 and (.[0] | type == "array" and length == 0)' \
      "$TMPDIR_SMOKE/app-org-before.json" >/dev/null; then
    die 'all-scope acceptance requires initially empty personal and organization scopes'
  fi
  cw_with_timeout 30 secrets --cloud projects list --output json >"$TMPDIR_SMOKE/app-projects-before.json" ||
    die 'dedicated all-scope identity cannot list platform secret projects'
  cw_with_timeout 30 --cloud ls --output json >"$TMPDIR_SMOKE/app-environments-before.json" ||
    die 'dedicated all-scope identity cannot inspect its environment names'
  jq -e --arg name "$SMOKE_NAME" 'type == "array" and all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/app-environments-before.json" >/dev/null ||
    die 'application smoke environment name already exists; choose a fresh --name'

  org_unique="cwdevall${nonce}org"; org_op="cwdevall${nonce}orgop"
  org_pu="cwdevall${nonce}orgpu"; org_cfg="cwdevall${nonce}orgcfg"
  user_unique="cwdevall${nonce}user"; user_pu="cwdevall${nonce}userpu"
  user_cfg="cwdevall${nonce}usercfg"
  APP_SECRET_VALUES+=("$org_unique" "$org_op" "$org_pu" "$org_cfg"
    "$user_unique" "$user_pu" "$user_cfg")
  local -a org_keys=("${APP_SECRET_ALL_KEYS[0]}" "${APP_SECRET_ALL_KEYS[3]}"
    "${APP_SECRET_ALL_KEYS[4]}" "${APP_SECRET_ALL_KEYS[5]}")
  local -a org_values=("$org_unique" "$org_op" "$org_pu" "$org_cfg")
  local -a user_keys=("${APP_SECRET_ALL_KEYS[2]}" "${APP_SECRET_ALL_KEYS[4]}"
    "${APP_SECRET_ALL_KEYS[5]}")
  local -a user_values=("$user_unique" "$user_pu" "$user_cfg")
  for index in "${!org_keys[@]}"; do
    key="${org_keys[$index]}"; value="${org_values[$index]}"
    APP_SECRET_ORG_ATTEMPTS+=("$key")
    printf '%s' "$value" | cw_with_timeout 30 secrets --cloud --organization set "$key" \
      >"$TMPDIR_SMOKE/app-set-org-$index.out" 2>"$TMPDIR_SMOKE/app-set-org-$index.err" ||
      die 'cannot write an owned organization secret via protected stdin'
  done
  for index in "${!user_keys[@]}"; do
    key="${user_keys[$index]}"; value="${user_values[$index]}"
    APP_SECRET_USER_ATTEMPTS+=("$key")
    printf '%s' "$value" | cw_with_timeout 30 secrets --cloud --user set "$key" \
      >"$TMPDIR_SMOKE/app-set-user-$index.out" 2>"$TMPDIR_SMOKE/app-set-user-$index.err" ||
      die 'cannot write an owned personal secret via protected stdin'
  done

  for index in 0 1; do
    project="dev-app-${nonce}-${index}"
    create_application_secret_project "$project" "$index"
    project_unique+=("cwdevall${nonce}project${index}")
    project_op+=("cwdevall${nonce}projectop${index}")
    project_pu+=("cwdevall${nonce}projectpu${index}")
    project_cfg+=("cwdevall${nonce}projectcfg${index}")
    APP_SECRET_VALUES+=("${project_unique[$index]}" "${project_op[$index]}"
      "${project_pu[$index]}" "${project_cfg[$index]}")
    local -a project_keys=("${APP_SECRET_ALL_KEYS[1]}" "${APP_SECRET_ALL_KEYS[3]}"
      "${APP_SECRET_ALL_KEYS[4]}" "${APP_SECRET_ALL_KEYS[5]}")
    local -a project_values=("${project_unique[$index]}" "${project_op[$index]}"
      "${project_pu[$index]}" "${project_cfg[$index]}")
    local key_index
    for key_index in "${!project_keys[@]}"; do
      printf '%s' "${project_values[$key_index]}" | cw_with_timeout 30 secrets --cloud \
        --project "id:${APP_SECRET_IDS[$index]}" set "${project_keys[$key_index]}" \
        >"$TMPDIR_SMOKE/app-set-$index-$key_index.out" 2>"$TMPDIR_SMOKE/app-set-$index-$key_index.err" ||
        die 'cannot write an owned project secret via protected stdin'
    done
    cw_with_timeout 30 secrets --cloud --project "id:${APP_SECRET_IDS[$index]}" list --output json \
      >"$TMPDIR_SMOKE/app-keys-$index.json" || die 'cannot inspect write-only application key metadata'
    assert_application_scope_metadata "$TMPDIR_SMOKE/app-keys-$index.json" "${project_keys[@]}" ||
      die 'application project key metadata is malformed or contains unknown fields'
  done

  config_hash="$(application_secret_hash ordinary-config)"
  APP_SECRET_ALL_HASHES_A=("$(application_secret_hash "$org_unique")"
    "$(application_secret_hash "${project_unique[0]}")" "$(application_secret_hash "$user_unique")"
    "$(application_secret_hash "${project_op[0]}")" "$(application_secret_hash "$user_pu")" "$config_hash")
  APP_SECRET_ALL_HASHES_B=("$(application_secret_hash "$org_unique")"
    "$(application_secret_hash "${project_unique[1]}")" "$(application_secret_hash "$user_unique")"
    "$(application_secret_hash "${project_op[1]}")" "$(application_secret_hash "$user_pu")" "$config_hash")
  APP_SECRET_ALL_HASHES_CLEAR=(absent absent absent absent absent "$config_hash")
  ((${#APP_SECRET_ALL_HASHES_A[@]} == ${#APP_SECRET_ALL_KEYS[@]} &&
     ${#APP_SECRET_ALL_HASHES_B[@]} == ${#APP_SECRET_ALL_KEYS[@]} &&
     ${#APP_SECRET_ALL_HASHES_CLEAR[@]} == ${#APP_SECRET_ALL_KEYS[@]})) ||
    die 'all-scope application hash matrix is incomplete'
  checks="$(application_all_scopes_hash_checks APP_SECRET_ALL_HASHES_A)"
  install="set -eu; $checks test ! -e /workspace/.cw-app-smoke; mkdir /workspace/.cw-app-smoke; printf '1\\n' > /workspace/.cw-app-smoke/install-count"
  startup="set -eu; { "
  for index in "${!APP_SECRET_ALL_KEYS[@]}"; do
    key="${APP_SECRET_ALL_KEYS[$index]}"
    startup+="if test \"\${${key}+x}\" = x; then digest=\"\$(printf %s \"\$${key}\" | sha256sum | cut -d ' ' -f 1)\"; else digest=absent; fi; printf '%s=%s\\n' '$key' \"\$digest\"; "
  done
  startup+="} > /workspace/.cw-app-smoke/startup-sha"
  APP_SECRET_DOCUMENT="$TMPDIR_SMOKE/app-codewire.json"
  jq -n --arg project "platform:id:${APP_SECRET_IDS[0]}" --arg install "$install" --arg startup "$startup" \
    --arg config_key "${APP_SECRET_ALL_KEYS[5]}" '
    {version:1, working_directory:"/workspace",
      secrets:{project:$project,organization:true,user:"platform"},
      environment:{($config_key):"ordinary-config"}, install_command:$install, startup_script:$startup}
  ' >"$APP_SECRET_DOCUMENT"
  assert_application_artifacts_redacted "$TMPDIR_SMOKE"/app-*.json "$TMPDIR_SMOKE"/app-*.out "$TMPDIR_SMOKE"/app-*.err
}

verify_application_all_scope_metadata() {
  cw_with_timeout 30 secrets --cloud --user list --output json >"$TMPDIR_SMOKE/app-user-final.json" ||
    die 'cannot re-list owned personal secret metadata before environment creation'
  cw_with_timeout 30 secrets --cloud --organization list --output json >"$TMPDIR_SMOKE/app-org-final.json" ||
    die 'cannot re-list owned organization secret metadata before environment creation'
  if ! assert_application_scope_metadata "$TMPDIR_SMOKE/app-user-final.json" "${APP_SECRET_USER_ATTEMPTS[@]}" ||
     ! assert_application_scope_metadata "$TMPDIR_SMOKE/app-org-final.json" "${APP_SECRET_ORG_ATTEMPTS[@]}"; then
    die 'shared-scope metadata contains malformed, leaky or non-attempt-owned keys; environment creation refused'
  fi
}

prepare_application_secrets() {
  local nonce project value index key install startup
  if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
    prepare_application_all_scope_secrets
    return
  fi
  nonce="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
  [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || die 'synthetic application identity generation failed'
  # Use only the already checked dedicated smoke org, never a personal scope.
  cw_with_timeout 30 secrets --cloud projects list --output json >"$TMPDIR_SMOKE/app-projects-before.json" ||
    die 'dedicated smoke identity cannot list platform secret projects'
  cw_with_timeout 30 --cloud ls --output json >"$TMPDIR_SMOKE/app-environments-before.json" ||
    die 'dedicated smoke identity cannot inspect its environment names'
  jq -e --arg name "$SMOKE_NAME" 'all(.[]; .name != $name)' \
    "$TMPDIR_SMOKE/app-environments-before.json" >/dev/null ||
    die 'application smoke environment name already exists; choose a fresh --name'
  APP_SECRET_VALUES=("cwdevapp${nonce}a" "cwdevapp${nonce}b")
  for index in 0 1; do
    project="dev-app-${nonce}-${index}"
    create_application_secret_project "$project" "$index"
    value="${APP_SECRET_VALUES[$index]}"
    APP_SECRET_HASHES+=("$(printf '%s' "$value" | sha256sum | cut -d ' ' -f 1)")
    for key in DATABASE_URL CW_DEV_PRECEDENCE; do
      printf '%s' "$value" | cw_with_timeout 30 secrets --cloud --project "id:${APP_SECRET_IDS[$index]}" set "$key" \
        >"$TMPDIR_SMOKE/app-set-$index-$key.out" 2>"$TMPDIR_SMOKE/app-set-$index-$key.err" ||
        die 'dedicated smoke identity cannot write its synthetic project secret via protected stdin'
    done
    cw_with_timeout 30 secrets --cloud --project "id:${APP_SECRET_IDS[$index]}" list --output json \
      >"$TMPDIR_SMOKE/app-keys-$index.json" || die 'cannot inspect write-only application key metadata'
    jq -e 'map(.key) | sort == ["CW_DEV_PRECEDENCE", "DATABASE_URL"]' \
      "$TMPDIR_SMOKE/app-keys-$index.json" >/dev/null || die 'application key metadata changed names'
  done
  install="set -eu; test \"\$(printf %s \"\$DATABASE_URL\" | sha256sum | cut -d ' ' -f 1)\" = '${APP_SECRET_HASHES[0]}'; test \"\$CW_DEV_PRECEDENCE\" = ordinary-config; test ! -e /workspace/.cw-app-smoke; mkdir /workspace/.cw-app-smoke; printf '1\\n' > /workspace/.cw-app-smoke/install-count; printf 'workspace-preserved\\n' > /workspace/.cw-app-smoke/preserved"
  # shellcheck disable=SC2016 # Expanded by the managed guest, never this host.
  startup='set -eu; test "$CW_DEV_PRECEDENCE" = ordinary-config; if test "${DATABASE_URL+x}" = x; then printf %s "$DATABASE_URL" | sha256sum | cut -d " " -f 1; else printf "absent\n"; fi > /workspace/.cw-app-smoke/startup-sha'
  APP_SECRET_DOCUMENT="$TMPDIR_SMOKE/app-codewire.json"
  jq -n --arg project "platform:id:${APP_SECRET_IDS[0]}" --arg install "$install" --arg startup "$startup" \
    '{version:1, working_directory:"/workspace", secrets:{project:$project},
      environment:{CW_DEV_PRECEDENCE:"ordinary-config"}, install_command:$install, startup_script:$startup}' \
    >"$APP_SECRET_DOCUMENT"
  assert_application_artifacts_redacted "$TMPDIR_SMOKE"/app-*.json "$TMPDIR_SMOKE"/app-*.out "$TMPDIR_SMOKE"/app-*.err
}

application_environment_ready() {
  local project="$1" previous_generation="$2"
  cw_with_timeout 30 --cloud info "$ENV_ID" --output json \
    >"$TMPDIR_SMOKE/app-environment.json" 2>"$TMPDIR_SMOKE/app-info.err" || return 1
  if jq -e '.setup_error | type == "string" and length > 0' \
      "$TMPDIR_SMOKE/app-environment.json" >/dev/null; then
    die 'application environment setup failed; output suppressed'
  fi
  jq -e --arg id "$ENV_ID" --arg project "$project" --argjson previous "$previous_generation" \
    --argjson all_scopes "$APP_SECRET_ALL_SCOPES" '
    .id == $id and .state == "running" and
    (.operation_generation | type == "number" and . > 0) and
    ($previous == 0 or .operation_generation == $previous) and
    .setup_complete == true and .setup_error == null and
    (.source_selection | type == "object") and (.source_selection.secrets | type == "object") and
    .source_selection.credentials == null and .source_selection.profile_revision == null and
    (.source_selection.secrets.project // "") == $project and
    (if $all_scopes == 1 then
      .source_selection.secrets == (if $project == "" then {} else
        {project:$project,user:"platform",organization:true} end)
    else
      (.source_selection.secrets.user // null) == null and
      (.source_selection.secrets.organization // false) == false
    end)
  ' "$TMPDIR_SMOKE/app-environment.json" >/dev/null
}

capture_application_pod() {
  local phase="$1" generation="$2" claim_identity claim_uid sandbox_name sandbox_identity sandbox_uid pod_name
  # Match the product authority chain. Agent Sandbox does not copy a Claim UID
  # label onto the Pod; labels alone would not prove controller ownership.
  claim_identity="$(kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxclaim "$CLAIM_NAME" -o json |
    jq -er --arg name "$CLAIM_NAME" --arg ns "$SANDBOX_NAMESPACE" --arg id "$ENV_ID" '
      select(.metadata.name == $name and .metadata.namespace == $ns and .metadata.deletionTimestamp == null and
        .metadata.labels["codewire.sh/environment-id"] == $id and .metadata.labels["codewire.sh/type"] == "sandbox") |
      [.metadata.uid, .status.sandbox.name] |
      select(all(.[]; type == "string" and test("^[a-z0-9][a-z0-9.-]*$"))) | @tsv')" ||
    die 'application smoke claim identity is unavailable'
  IFS=$'\t' read -r claim_uid sandbox_name <<<"$claim_identity"
  sandbox_identity="$(kubectl_dev -n "$SANDBOX_NAMESPACE" get sandbox "$sandbox_name" -o json |
    jq -er --arg name "$sandbox_name" --arg ns "$SANDBOX_NAMESPACE" --arg claim "$CLAIM_NAME" --arg uid "$claim_uid" '
      select(.metadata.name == $name and .metadata.namespace == $ns and .metadata.deletionTimestamp == null) |
      select([.metadata.ownerReferences[]? | select(.controller == true)] |
        length == 1 and (.[0] | .apiVersion == "extensions.agents.x-k8s.io/v1beta1" and
          .kind == "SandboxClaim" and .name == $claim and .uid == $uid)) |
      [.metadata.uid, (.metadata.annotations["agents.x-k8s.io/pod-name"] // .metadata.name)] |
      select(all(.[]; type == "string" and test("^[a-z0-9][a-z0-9.-]*$"))) | @tsv')" ||
    die 'application smoke Sandbox is not controlled by the exact Claim'
  IFS=$'\t' read -r sandbox_uid pod_name <<<"$sandbox_identity"
  local secret_keys_json='["DATABASE_URL"]' config_key=''
  if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
    secret_keys_json="$(printf '%s\n' "${APP_SECRET_ALL_KEYS[@]:0:5}" | jq -Rsc 'split("\n")[:-1]')"
    config_key="${APP_SECRET_ALL_KEYS[5]}"
  fi
  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$pod_name" -o json |
    jq -e --arg claim "$claim_uid" --arg sandbox "$sandbox_name" --arg sandbox_uid "$sandbox_uid" \
      --arg pod "$pod_name" --arg ns "$SANDBOX_NAMESPACE" --arg id "$ENV_ID" --arg generation "$generation" --arg phase "$phase" \
      --argjson secret_keys "$secret_keys_json" --arg config_key "$config_key" '
      select(.metadata.deletionTimestamp == null and .status.phase == "Running" and
        .metadata.name == $pod and .metadata.namespace == $ns and
        .metadata.labels["codewire.sh/environment-id"] == $id and
        .metadata.labels["codewire.sh/type"] == "workspace" and
        .metadata.labels["codewire.sh/environment-operation-generation"] == $generation) |
      select([.metadata.ownerReferences[]? | select(.controller == true)] |
        length == 1 and (.[0] | .apiVersion == "agents.x-k8s.io/v1beta1" and
          .kind == "Sandbox" and .name == $sandbox and .uid == $sandbox_uid)) |
      select([.spec.containers[] | select(.name == "workspace")] | length == 1) |
      [.spec.containers[] | select(.name == "workspace") | .env[]?] as $env |
      select(all($env[]; (.name as $name | $secret_keys | index($name) | not))) |
      select($config_key == "" or
        ([$env[] | select(.name == $config_key) | .value] | length <= 1 and all(.[]; . == "ordinary-config"))) |
      select(if $phase == "clear" then
        all($env[]; .name != "CODEWIRE_ENVIRONMENT_ID" and
          .name != "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION" and
          .name != "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256")
      else [$env[] | select(.name == "CODEWIRE_ENVIRONMENT_ID") | .value] == [$id] and
        [$env[] | select(.name == "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION") | .value] == [$generation] and
        ([$env[] | select(.name == "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256") | .value] |
          length == 1 and (.[0] | test("^[0-9a-f]{64}$"))) end) |
      {uid:.metadata.uid, claim_uid:$claim, generation:$generation,
       volumes:[.spec.volumes[]? | select(.persistentVolumeClaim != null) | {name,claim:.persistentVolumeClaim.claimName}]}
    ' >"$TMPDIR_SMOKE/app-pod-$phase.json" || die 'application workspace Pod identity or immutable generation is wrong'
  jq -e '.uid | type == "string" and length > 0' "$TMPDIR_SMOKE/app-pod-$phase.json" >/dev/null ||
    die 'application workspace Pod identity is missing'
}

application_guest_check() {
  local expected="$1"
  cat <<SCRIPT
set -eu
application_fail() { printf 'application check failed: %s\\n' "\$1" >&2; exit 1; }
test "\${CW_DEV_PRECEDENCE:-}" = ordinary-config || application_fail ordinary-precedence
test "\$(cat /workspace/.cw-app-smoke/install-count)" = 1 || application_fail install-count
test "\$(cat /workspace/.cw-app-smoke/preserved)" = workspace-preserved || application_fail workspace-preservation
if test '$expected' = absent; then
  test "\${DATABASE_URL+x}" != x || application_fail cleared-projection
else
  test "\${DATABASE_URL+x}" = x || application_fail missing-projection
  test "\$(printf %s "\$DATABASE_URL" | sha256sum | cut -d ' ' -f 1)" = '$expected' || application_fail current-projection
fi
attempt=0
while test "\$(cat /workspace/.cw-app-smoke/startup-sha 2>/dev/null || true)" != '$expected'; do
  attempt=\$((attempt + 1)); test "\$attempt" -lt 100 || application_fail startup-projection; sleep 0.1
done
python3 - <<'PY'
import json
from pathlib import Path
root = Path('/home/codewire/.codewire')
ordinary = json.loads((root / 'environment.json').read_text())
assert 'DATABASE_URL' not in ordinary
assert ordinary['CW_DEV_PRECEDENCE'] == 'ordinary-config'
sessions = list((root / 'daemon' / 'sessions').glob('*/session.json'))
assert sessions, 'managed session metadata is missing'
for path in sessions:
    session = json.loads(path.read_text())
    # Launch values stay with the live owner: a saved session record never
    # carries an environment, so no projected value can persist in it.
    assert 'env' not in session
PY
printf 'application-secret-check-ok\\n'
SCRIPT
}

application_all_scopes_guest_check() {
  local hashes_name="$1" marker_sha256="$2"
  local -n hashes="$hashes_name"
  local checks index key hash startup_checks='' keys_json config_key
  [[ "$marker_sha256" =~ ^[0-9a-f]{64}$ ]] || die 'application workspace marker digest is invalid'
  checks="$(application_all_scopes_hash_checks "$hashes_name")"
  for index in "${!APP_SECRET_ALL_KEYS[@]}"; do
    key="${APP_SECRET_ALL_KEYS[$index]}"; hash="${hashes[$index]}"
    startup_checks+="grep -Fx '$key=$hash' /workspace/.cw-app-smoke/startup-sha >/dev/null && "
  done
  startup_checks="${startup_checks% && }"
  keys_json="$(printf '%s\n' "${APP_SECRET_ALL_KEYS[@]}" | jq -Rsc 'split("\n")[:-1]')"
  config_key="${APP_SECRET_ALL_KEYS[5]}"
  cat <<SCRIPT
set -eu
application_fail() { printf 'application check failed: %s\\n' "\$1" >&2; exit 1; }
$checks
test "\$(cat /workspace/.cw-app-smoke/install-count)" = 1 || application_fail install-count
test -f /workspace/.cw-app-smoke/preservation-marker || application_fail workspace-marker-missing
test "\$(sha256sum /workspace/.cw-app-smoke/preservation-marker | cut -d ' ' -f 1)" = '$marker_sha256' || application_fail workspace-marker-replaced
attempt=0
until $startup_checks; do
  attempt=\$((attempt + 1)); test "\$attempt" -lt 100 || application_fail startup-projection; sleep 0.1
done
python3 - <<'PY'
import json
from pathlib import Path
root = Path('/home/codewire/.codewire')
keys = $keys_json
config_key = '$config_key'
ordinary = json.loads((root / 'environment.json').read_text())
assert ordinary[config_key] == 'ordinary-config'
assert all(key not in ordinary for key in keys if key != config_key)
sessions = list((root / 'daemon' / 'sessions').glob('*/session.json'))
assert sessions, 'managed session metadata is missing'
for path in sessions:
    session = json.loads(path.read_text())
    # Launch values stay with the live owner: a saved session record never
    # carries an environment, so no projected value can persist in it.
    assert 'env' not in session
PY
printf 'application-secret-check-ok\\n'
SCRIPT
}

create_application_workspace_marker() {
  local marker_script output="$TMPDIR_SMOKE/app-workspace-marker-sha256.out"
  # The marker bytes never leave the managed workspace. The host retains only
  # their digest so later public cw run calls can prove workspace continuity.
  # shellcheck disable=SC2016 # Expanded only by the managed guest shell.
  marker_script='set -eu; marker=/workspace/.cw-app-smoke/preservation-marker; test ! -e "$marker"; umask 077; head -c 32 /dev/urandom > "$marker"; sha256sum "$marker" | cut -d " " -f 1'
  cw_with_timeout "$SMOKE_EXEC_TIMEOUT" run --no-tty "$ENV_ID" -- /bin/sh -c "$marker_script" \
    >"$output" 2>"$TMPDIR_SMOKE/app-workspace-marker.err" ||
    die 'managed workspace marker creation failed; output suppressed'
  APP_WORKSPACE_MARKER_SHA256="$(cat "$output")"
  [[ "$APP_WORKSPACE_MARKER_SHA256" =~ ^[0-9a-f]{64}$ && "$(wc -l <"$output")" == 1 ]] ||
    die 'managed workspace marker returned an invalid digest receipt'
}

application_restart_witness_guest() {
  local hashes_name="$1" marker_sha256="$2"
  local checks witness_lifetime
  [[ "$marker_sha256" =~ ^[0-9a-f]{64}$ ]] || die 'application restart witness marker digest is invalid'
  checks="$(application_all_scopes_hash_checks "$hashes_name")"
  witness_lifetime=$((SMOKE_TIMEOUT_SECONDS + 300))
  cat <<SCRIPT
set -eu
$checks
test -f /workspace/.cw-app-smoke/preservation-marker
test "\$(sha256sum /workspace/.cw-app-smoke/preservation-marker | cut -d ' ' -f 1)" = '$marker_sha256'
printf 'application-restart-witness-ready\\n'
exec sleep '$witness_lifetime'
SCRIPT
}

application_restart_witness_ready() {
  local phase="$1" session_id="$2"
  local logs="$TMPDIR_SMOKE/app-restart-witness-$phase.log"
  local sessions="$TMPDIR_SMOKE/app-restart-witness-$phase-ready.json"
  local error="$TMPDIR_SMOKE/app-restart-witness-$phase-ready.err"

  if ! cw_with_timeout 30 logs "$ENV_ID" --session "$session_id" --raw >"$logs" 2>"$error"; then
    SMOKE_LAST_WAIT_DETAIL="public logs did not return exact managed session $session_id"
    return 1
  fi
  if ! grep -qx application-restart-witness-ready "$logs"; then
    SMOKE_LAST_WAIT_DETAIL="exact managed session $session_id has not emitted its ready receipt"
    return 1
  fi
  if ! cw_with_timeout 30 ls "$ENV_ID" --output json >"$sessions" 2>"$error"; then
    SMOKE_LAST_WAIT_DETAIL="public session list did not return for exact managed session $session_id"
    return 1
  fi
  if ! jq -e --arg id "$session_id" '
    type == "array" and
    ([.[] | select(.session_id == $id)] | length) == 1 and
    ([.[] | select(.session_id == $id)][0].state == "Running")
  ' "$sessions" >/dev/null; then
    SMOKE_LAST_WAIT_DETAIL="exact managed session $session_id is not uniquely Running after its ready receipt"
    return 1
  fi
}

start_application_restart_witness() {
  local hashes_name="$1" phase="$2" guest_script deadline session_id
  local launch="$TMPDIR_SMOKE/app-restart-witness-$phase-launch.json"
  local error="$TMPDIR_SMOKE/app-restart-witness-$phase-launch.err"
  [[ -z "$APP_RESTART_WITNESS_SESSION_ID" ]] || die 'application restart witness is already running'
  guest_script="$(application_restart_witness_guest "$hashes_name" "$APP_WORKSPACE_MARKER_SHA256")"
  cw_with_timeout 30 run --no-tty --output json "$ENV_ID" -- /bin/sh -c "$guest_script" \
    >"$launch" 2>"$error" || die 'managed application restart witness launch failed; output suppressed'
  jq -e '
    type == "object" and
    (.session_id | type == "string" and length > 0) and
    (.state == "Starting" or .state == "Running") and
    (.command | type == "array" and length == 3 and
      .[0] == "/bin/sh" and .[1] == "-c" and
      (.[2] | contains("application-restart-witness-ready"))) and
    .pty == false and .exit_code == null
  ' "$launch" >/dev/null || die 'managed application restart witness returned invalid session identity metadata'
  session_id="$(jq -er '.session_id' "$launch")" || die 'managed application restart witness session identity is missing'
  APP_RESTART_WITNESS_SESSION_ID="$session_id"
  deadline=$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))
  wait_until "exact managed session $session_id readiness" "$deadline" \
    application_restart_witness_ready "$phase" "$session_id"
}

application_restart_witness_terminal() {
  local phase="$1" session_id="$2"
  local sessions="$TMPDIR_SMOKE/app-restart-witness-$phase-terminal.json"
  local error="$TMPDIR_SMOKE/app-restart-witness-$phase-terminal.err"
  if ! cw_with_timeout 30 ls "$ENV_ID" --output json >"$sessions" 2>"$error"; then
    SMOKE_LAST_WAIT_DETAIL="public session list did not return for exact managed session $session_id"
    return 1
  fi
  if ! jq -e --arg id "$session_id" '
    type == "array" and
    ([.[] | select(.session_id == $id)] | length) == 1 and
    ([.[] | select(.session_id == $id)][0].state as $state |
      $state == "Stopped" or $state == "Exited" or
      $state == "Failed" or $state == "Interrupted")
  ' "$sessions" >/dev/null; then
    SMOKE_LAST_WAIT_DETAIL="exact managed session $session_id is missing, ambiguous or non-terminal"
    return 1
  fi
}

wait_for_application_restart_witness_termination() {
  local phase="$1" deadline session_id="$APP_RESTART_WITNESS_SESSION_ID"
  [[ -n "$session_id" ]] || die 'application restart witness session identity is missing'
  deadline=$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))
  wait_until "exact managed session $session_id to reach a terminal state after source $phase" "$deadline" \
    application_restart_witness_terminal "$phase" "$session_id"
  APP_RESTART_WITNESS_SESSION_ID=""
}

run_application_secret_pty() {
  local guest_script="$1" phase="$2" command receipt
  # cw needs terminal stdin to read its initial size. Redirect cw's stdout
  # inside that host PTY so attach is noninteractive and propagates the guest
  # exit status, rather than waiting for the interactive detach chord.
  if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
    printf -v command '%q ' env -i "${SMOKE_OAUTH_ENV[@]}" \
      "$CW_BIN" --server "$CODEWIRE_SERVER_URL" run --tty "$ENV_ID" -- \
      /bin/sh -c "set -eu; test -t 0; test -t 1; $guest_script"
  else
    printf -v command '%q ' "$CW_BIN" --server "$CODEWIRE_SERVER_URL" run --tty "$ENV_ID" -- \
      /bin/sh -c "set -eu; test -t 0; test -t 1; $guest_script"
  fi
  printf -v receipt '%q' "$TMPDIR_SMOKE/app-pty-$phase.log"
  command+=" >$receipt"
  if ! timeout --foreground --kill-after=5s "$SMOKE_EXEC_TIMEOUT" \
      env SHELL=/bin/bash script -qefc "$command" /dev/null </dev/null \
      >"$TMPDIR_SMOKE/app-pty-$phase.out" 2>"$TMPDIR_SMOKE/app-pty-$phase.err"; then
    die 'application-secret PTY launch failed; output suppressed'
  fi
  grep -Eq $'^application-secret-check-ok\r?$' "$TMPDIR_SMOKE/app-pty-$phase.log" ||
    die 'application-secret PTY did not return its exact child receipt'
}

assert_application_source_update() {
  local file="$1" project="$2" generation="$3"
  jq -es --arg id "$ENV_ID" --arg project "$project" --argjson generation "$generation" \
    --argjson all_scopes "$APP_SECRET_ALL_SCOPES" '
    length == 1 and (.[0] |
      type == "object" and .environment_id == $id and
      .operation_generation == $generation and .outcome == "restart_required" and
      (.selection | type == "object" and has("secrets") and has("credentials") and has("profile_revision")) and
      (.selection.secrets | type == "object") and
      (.selection.secrets | if has("project") then .project == $project else $project == "" end) and
      (if $all_scopes == 1 then
        .selection.secrets == (if $project == "" then {} else
          {project:$project,user:"platform",organization:true} end)
      else
        (.selection.secrets | (has("user") | not) or .user == null) and
        (.selection.secrets | (has("organization") | not) or .organization == false)
      end) and
      .selection.credentials == null and .selection.profile_revision == null)
  ' "$file" >/dev/null || die 'application source update acknowledgement did not match the exact submitted operation and selection'
}

run_application_secret_exec() {
  local guest_script="$1" phase="$2" deadline="$3" remaining timeout_seconds
  local output="$TMPDIR_SMOKE/app-exec-$phase.out" error="$TMPDIR_SMOKE/app-exec-$phase.err"
  while :; do
    remaining=$((deadline - $(seconds_now)))
    ((remaining > 0)) || die 'timed out waiting for managed application startup projection; output suppressed'
    timeout_seconds="$SMOKE_EXEC_TIMEOUT"
    ((timeout_seconds <= remaining)) || timeout_seconds="$remaining"
    if cw_with_timeout "$timeout_seconds" run --no-tty "$ENV_ID" -- /bin/sh -c "$guest_script" \
        >"$output" 2>"$error"; then
      grep -qx application-secret-check-ok "$output" || die 'managed exec omitted application receipt'
      return 0
    fi
    # Running/setup-complete precedes post-start configuration. Retry only its
    # exact fixed guest failure, never projection, preservation or transport errors.
    if ! { [[ ! -s "$error" && "$(wc -c <"$output")" == 45 ]] &&
           grep -qx 'application check failed: startup-projection' "$output"; } &&
       ! { [[ ! -s "$output" && "$(wc -c <"$error")" == 45 ]] &&
           grep -qx 'application check failed: startup-projection' "$error"; }; then
      die 'managed application-secret exec failed; output suppressed'
    fi
    (( $(seconds_now) < deadline )) || die 'timed out waiting for managed application startup projection; output suppressed'
    sleep 5
  done
}

run_application_secrets_smoke() {
  local phase expected project generation=0 previous_uid='' guest_script hashes_name='' phase_deadline
  for phase in a b clear; do
    phase_deadline=$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))
    case "$phase" in
      a)
        project="platform:id:${APP_SECRET_IDS[0]}"; expected="${APP_SECRET_HASHES[0]:-}"
        hashes_name=APP_SECRET_ALL_HASHES_A
        ;;
      b)
        project="platform:id:${APP_SECRET_IDS[1]}"; expected="${APP_SECRET_HASHES[1]:-}"
        hashes_name=APP_SECRET_ALL_HASHES_B
        local -a scope_args=()
        if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
          scope_args=(--user-secrets platform --org-secrets)
        fi
        if cw_with_timeout 30 --cloud update "$ENV_ID" --secrets "$project" "${scope_args[@]}" --output json </dev/null \
            >"$TMPDIR_SMOKE/app-unconfirmed.out" 2>"$TMPDIR_SMOKE/app-unconfirmed.err"; then
          die 'unconfirmed application source replacement unexpectedly succeeded'
        fi
        grep -Fq 'source selection requires --yes for noninteractive or JSON commands; no source change was submitted' \
          "$TMPDIR_SMOKE/app-unconfirmed.err" || die 'unconfirmed source edit failed for an unexpected reason; output suppressed'
        application_environment_ready "platform:id:${APP_SECRET_IDS[0]}" 0 || die 'unconfirmed source edit changed selection'
        [[ "$(jq -r .operation_generation "$TMPDIR_SMOKE/app-environment.json")" == "$generation" ]] ||
          die 'unconfirmed source edit changed generation'
        if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
          start_application_restart_witness APP_SECRET_ALL_HASHES_A "$phase"
        fi
        cw_with_timeout 30 --cloud update "$ENV_ID" --secrets "$project" "${scope_args[@]}" --yes --output json \
          >"$TMPDIR_SMOKE/app-update-b.json" 2>"$TMPDIR_SMOKE/app-update-b.err" || die 'application source replacement failed'
        assert_application_source_update "$TMPDIR_SMOKE/app-update-b.json" "$project" "$generation"
        ;;
      clear)
        project=''; expected=absent
        hashes_name=APP_SECRET_ALL_HASHES_CLEAR
        if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
          start_application_restart_witness APP_SECRET_ALL_HASHES_B "$phase"
        fi
        cw_with_timeout 30 --cloud update "$ENV_ID" --clear-secrets --yes --output json \
          >"$TMPDIR_SMOKE/app-update-clear.json" 2>"$TMPDIR_SMOKE/app-update-clear.err" || die 'application source clear failed'
        assert_application_source_update "$TMPDIR_SMOKE/app-update-clear.json" "$project" "$generation"
        ;;
    esac
    if [[ "$phase" != a && "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
      wait_for_application_restart_witness_termination "$phase"
    fi
    # Generation fences the owning Temporal workflow, not each source edit.
    # Restart completion additionally requires a new exact Pod UID below.
    wait_until 'current application source, workflow authority and completed setup' "$phase_deadline" \
      application_environment_ready "$project" "$generation"
    # The all-scope journey stays on the public API/data plane: setup readiness
    # plus its child-visible marker prove restart completion and workspace
    # preservation. The ordinary project-only journey retains its Kubernetes
    # identity and PVC assertions.
    if [[ "$phase" == a && "$APP_SECRET_ALL_SCOPES" != 1 ]]; then run_kube_assertions; fi
    generation="$(jq -er .operation_generation "$TMPDIR_SMOKE/app-environment.json")"
    if [[ "$APP_SECRET_ALL_SCOPES" != 1 ]]; then
      capture_application_pod "$phase" "$generation"
      if [[ -n "$previous_uid" ]]; then
        [[ "$(jq -r .uid "$TMPDIR_SMOKE/app-pod-$phase.json")" != "$previous_uid" ]] || die 'source replacement reused the old Pod'
        [[ "$(jq -c .volumes "$TMPDIR_SMOKE/app-pod-$phase.json")" == "$(jq -c .volumes "$TMPDIR_SMOKE/app-pod-a.json")" ]] ||
          die 'source replacement changed persistent workspace claims'
        [[ "$(jq -r .claim_uid "$TMPDIR_SMOKE/app-pod-$phase.json")" == "$(jq -r .claim_uid "$TMPDIR_SMOKE/app-pod-a.json")" ]] ||
          die 'source replacement changed the exact owned SandboxClaim'
      fi
      previous_uid="$(jq -r .uid "$TMPDIR_SMOKE/app-pod-$phase.json")"
    fi
    if [[ "$phase" == a && "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
      create_application_workspace_marker
    fi
    if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
      guest_script="$(application_all_scopes_guest_check "$hashes_name" "$APP_WORKSPACE_MARKER_SHA256")"
    else
      guest_script="$(application_guest_check "$expected")"
    fi
    run_application_secret_exec "$guest_script" "$phase" "$phase_deadline"
    run_application_secret_pty "$guest_script" "$phase"
    cw_with_timeout 30 ls "$ENV_ID" --output json >"$TMPDIR_SMOKE/app-sessions-$phase.json" || die 'session metadata inspection failed'
    assert_application_artifacts_redacted "$TMPDIR_SMOKE"/app-*.json "$TMPDIR_SMOKE"/app-*.out "$TMPDIR_SMOKE"/app-*.err "$TMPDIR_SMOKE"/app-pty-*.log "$TMPDIR_SMOKE/create.out"
  done
  if [[ "$APP_SECRET_ALL_SCOPES" == 1 ]]; then
    log 'application organization/project/personal precedence passed install/startup, exec/PTY, replacement/clear and preservation'
  else
    log 'application project secrets passed install/startup, exec/PTY, replacement/clear and preservation; no personal/provider claim'
  fi
}

application_environment_destroyed() {
  local state
  # info deliberately resolves only live environments, and absence is not
  # terminal cleanup proof. report reads this exact ID, deleted or not, so the
  # check never depends on the size of the organization's deleted history.
  cw_with_timeout 30 report "$ENV_ID" --output json \
    >"$TMPDIR_SMOKE/app-cleanup-environment.json" 2>/dev/null || return 1
  state="$(jq -ers --arg id "$ENV_ID" '
    if length != 1 or (.[0].environment | type) != "object" then error("expected one environment report") else .[0].environment end |
    if .id == $id and (.state | type) == "string" then .state
    else error("expected the exact owned environment") end
  ' "$TMPDIR_SMOKE/app-cleanup-environment.json" 2>/dev/null)" || return 2
  [[ "$state" == destroyed ]]
}

cleanup_application_shared_scope() {
  local scope="$1" attempts_name="$2"
  local -n attempts="$attempts_name"
  local key index status rc=0 metadata="$TMPDIR_SMOKE/app-cleanup-$scope.json"
  local classification="$TMPDIR_SMOKE/app-cleanup-$scope-commands.tsv"
  local -a scope_args=("--$scope")
  for index in "${!attempts[@]}"; do
    key="${attempts[$index]}"
    if cw_with_timeout 30 secrets --cloud "${scope_args[@]}" list --output json >"$metadata" \
        2>"$TMPDIR_SMOKE/app-cleanup-$scope-list-$index.err"; then status=0; else status=$?; fi
    printf 'list\t%s\t%s\n' "$index" "$status" >>"$classification"
    if [[ "$status" != 0 ]]; then
      rc=1
      continue
    fi
    if ! jq -es --arg key "$key" '
        length == 1 and (.[0] | type == "array" and
          all(.[]; type == "object" and (.key | type) == "string") and
          ([.[] | select(.key == $key)] | length) <= 1)
      ' "$metadata" >/dev/null 2>"$TMPDIR_SMOKE/app-cleanup-$scope-metadata-$index.err"; then
      rc=1
      continue
    fi
    if jq -es --arg key "$key" '.[0] | any(.[]; .key == $key)' "$metadata" >/dev/null \
        2>>"$TMPDIR_SMOKE/app-cleanup-$scope-metadata-$index.err"; then
      if cw_with_timeout 30 secrets --cloud "${scope_args[@]}" delete "$key" \
        >"$TMPDIR_SMOKE/app-cleanup-$scope-$index.out" \
        2>"$TMPDIR_SMOKE/app-cleanup-$scope-$index.err"; then status=0; else status=$?; rc=1; fi
      printf 'delete\t%s\t%s\n' "$index" "$status" >>"$classification"
    fi
  done
  if cw_with_timeout 30 secrets --cloud "${scope_args[@]}" list --output json >"$metadata" \
      2>"$TMPDIR_SMOKE/app-cleanup-$scope-list-final.err"; then status=0; else status=$?; fi
  printf 'list\tfinal\t%s\n' "$status" >>"$classification"
  if [[ "$status" != 0 ]]; then
    return 1
  fi
  local attempted_json
  attempted_json="$(printf '%s\n' "${attempts[@]}" | jq -Rsc 'split("\n")[:-1]')"
  jq -es --argjson attempted "$attempted_json" '
    length == 1 and (.[0] | type == "array" and
      all(.[]; type == "object" and (.key | type) == "string") and
      all(.[]; (.key as $key | $attempted | index($key) | not)) and length == 0)
  ' "$metadata" >/dev/null 2>"$TMPDIR_SMOKE/app-cleanup-$scope-metadata-final.err" || rc=1
  return "$rc"
}

cleanup_application_secrets() {
  local project project_id selector index status rc=0 deadline
  if [[ -z "$ENV_ID" && "$APP_SECRET_CREATE_ATTEMPTED" == 1 ]]; then
    if cw_with_timeout 30 --cloud ls --output json >"$TMPDIR_SMOKE/app-cleanup-environments.json" 2>/dev/null; then
      ENV_ID="$(jq -ers --arg name "$SMOKE_NAME" '
        if length != 1 or (.[0] | type) != "array" then error("expected environment array") else .[0] end |
        [.[] | select(.name == $name)] |
        if length == 1 then .[0].id else error("ambiguous owned environment") end |
        select(type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))' \
        "$TMPDIR_SMOKE/app-cleanup-environments.json")" || rc=1
    else rc=1; fi
  fi
  if [[ -n "$ENV_ID" ]]; then
    cw_with_timeout 60 --cloud rm --yes "$ENV_ID" >"$TMPDIR_SMOKE/app-cleanup-env.out" 2>"$TMPDIR_SMOKE/app-cleanup-env.err" || rc=1
    deadline=$(( $(seconds_now) + SMOKE_TIMEOUT_SECONDS ))
    while :; do
      if application_environment_destroyed; then break; else status=$?; fi
      if [[ "$status" != 1 ]]; then rc=1; break; fi
      if (( $(seconds_now) >= deadline )); then rc=1; break; fi
      sleep 5
    done
  fi
  for index in "${!APP_SECRET_PROJECTS[@]}"; do
    project="${APP_SECRET_PROJECTS[$index]}"
    project_id="${APP_SECRET_IDS[$index]:-}"
    selector="$project"
    [[ -z "$project_id" ]] || selector="id:$project_id"
    cw_with_timeout 30 secrets --cloud projects list --output json >"$TMPDIR_SMOKE/app-cleanup-projects.json" 2>/dev/null || { rc=1; continue; }
    jq -e 'type == "array"' "$TMPDIR_SMOKE/app-cleanup-projects.json" >/dev/null || { rc=1; continue; }
    if jq -e --arg name "$project" --arg id "$project_id" \
        'any(.[]; if $id == "" then .name == $name else .id == $id end)' "$TMPDIR_SMOKE/app-cleanup-projects.json" >/dev/null; then
      cw_with_timeout 30 secrets --cloud projects delete "$selector" --yes >"$TMPDIR_SMOKE/app-cleanup-project.out" 2>"$TMPDIR_SMOKE/app-cleanup-project.err" || rc=1
    fi
    cw_with_timeout 30 secrets --cloud projects list --output json >"$TMPDIR_SMOKE/app-cleanup-projects.json" 2>/dev/null &&
      jq -e --arg name "$project" --arg id "$project_id" 'type == "array" and all(.[]; .name != $name and .id != $id)' "$TMPDIR_SMOKE/app-cleanup-projects.json" >/dev/null || rc=1
  done
  if ((${#APP_SECRET_USER_ATTEMPTS[@]} > 0)); then
    cleanup_application_shared_scope user APP_SECRET_USER_ATTEMPTS || rc=1
  fi
  if ((${#APP_SECRET_ORG_ATTEMPTS[@]} > 0)); then
    cleanup_application_shared_scope organization APP_SECRET_ORG_ATTEMPTS || rc=1
  fi
  if [[ "$APP_SECRET_ALL_SCOPES" == 1 && "$rc" == 0 ]]; then
    assert_application_artifacts_redacted "$TMPDIR_SMOKE"/app-cleanup-*.json \
      "$TMPDIR_SMOKE"/app-cleanup-*.out "$TMPDIR_SMOKE"/app-cleanup-*.err || rc=1
  fi
  [[ "$rc" == 0 ]] || log 'application smoke cleanup incomplete; exact owned IDs remain in private smoke evidence'
  return "$rc"
}

record_environment_artifact() {
  [[ -n "$SMOKE_ARTIFACT_DIR" ]] || return 0
  mkdir -p "$SMOKE_ARTIFACT_DIR"
  jq -n \
    --arg environment_id "$ENV_ID" \
    --arg environment_name "$SMOKE_NAME" \
    --argjson retained "$([[ "$SMOKE_KEEP_ENV" == "1" ]] && printf true || printf false)" \
    '{
      environment_id: $environment_id,
      environment_name: $environment_name,
      retained: $retained
    }' >"$SMOKE_ARTIFACT_DIR/environment.json"
}

fail_if_workspace_crashloop() {
  local environment_state="$1"
  local pods_json="$TMPDIR_SMOKE/workspace-startup-pods.json"
  local kubectl_err="$TMPDIR_SMOKE/workspace-startup-pods.err"
  local crashloop

  [[ "$SMOKE_SKIP_KUBE" != "1" ]] || return 0
  if ! kubectl_dev -n "$SANDBOX_NAMESPACE" get pod \
      -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=workspace" \
      -o json >"$pods_json" 2>"$kubectl_err"; then
    return 0
  fi
  # The workspace container runs the daemon, which serves SSH and the
  # tailnet: its crash loop is the environment's access failing.
  crashloop="$(jq -r '
      [
        .items[]?
        | .status.containerStatuses[]?
        | select(.name == "workspace")
        | select(.state.waiting.reason == "CrashLoopBackOff")
        | ["CrashLoopBackOff", (.restartCount // 0)]
      ][0] // empty
      | if type == "array" then @tsv else empty end
    ' "$pods_json")"
  [[ -n "$crashloop" ]] || return 0

  local reason restart_count
  IFS=$'\t' read -r reason restart_count <<<"$crashloop"
  collect_failure_diagnostics "workspace-crashloop" || true
  die "workspace daemon container entered $reason while environment state=$environment_state (restart_count=$restart_count)"
}

env_is_running() {
  local info_out="$TMPDIR_SMOKE/env-info.out"
  if ! cw info "$ENV_ID" >"$info_out" 2>&1; then
    return 1
  fi
  local state error_reason
  state="$(awk '$1 == "State:" {print $2; exit}' "$info_out")"
  error_reason="$(awk '$1 == "ErrorReason:" {print substr($0, index($0, $2)); exit}' "$info_out")"
  if [[ -n "$error_reason" ]]; then
    sed 's/[[:cntrl:]]//g' "$info_out" >&2 || true
    collect_failure_diagnostics "environment-error" || true
    die "environment entered error state"
  fi
  if [[ "$state" != "running" ]]; then
    fail_if_workspace_crashloop "${state:-unknown}"
  fi
  [[ "$state" == "running" ]]
}

wait_environment() {
  log "waiting for environment to reach running"
  wait_until "environment running" "$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))" env_is_running
}

claim_exists() {
  local json="$TMPDIR_SMOKE/claim-list.json"
  local err="$TMPDIR_SMOKE/claim-list.err"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxclaim \
    -l "codewire.sh/environment-id=$ENV_ID" -o json >"$json" 2>"$err" || {
      SMOKE_LAST_WAIT_DETAIL="$(sed 's/[[:cntrl:]]//g' "$err" | tail -n 1)"
      return 1
    }
  if ! CLAIM_NAME="$(jq -r '.items[0].metadata.name // empty' "$json" 2>"$TMPDIR_SMOKE/claim-list-jq.err")"; then
    SMOKE_LAST_WAIT_DETAIL="$(sed 's/[[:cntrl:]]//g' "$TMPDIR_SMOKE/claim-list-jq.err" | tail -n 1)"
    return 1
  fi
  if [[ -z "$CLAIM_NAME" ]]; then
    SMOKE_LAST_WAIT_DETAIL="no SandboxClaim found with codewire.sh/environment-id=$ENV_ID in namespace $SANDBOX_NAMESPACE"
    return 1
  fi
  return 0
}

pod_exists_for_claim() {
  local claim_json="$TMPDIR_SMOKE/claim.json"
  local pods_json="$TMPDIR_SMOKE/pods.json"
  local err="$TMPDIR_SMOKE/pod-adoption.err"
  local claim_uid

  kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxclaim "$CLAIM_NAME" -o json >"$claim_json" 2>"$err" || {
    SMOKE_LAST_WAIT_DETAIL="$(sed 's/[[:cntrl:]]//g' "$err" | tail -n 1)"
    return 1
  }
  claim_uid="$(jq -r '.metadata.uid // empty' "$claim_json")"
  if [[ -z "$claim_uid" ]]; then
    SMOKE_LAST_WAIT_DETAIL="SandboxClaim $CLAIM_NAME has no metadata.uid yet"
    return 1
  fi
  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod \
    -l "agents.x-k8s.io/claim-uid=$claim_uid" -o json >"$pods_json" 2>"$err" || {
      SMOKE_LAST_WAIT_DETAIL="$(sed 's/[[:cntrl:]]//g' "$err" | tail -n 1)"
      return 1
    }
  if [[ "$(jq '.items | length' "$pods_json")" == "0" ]]; then
    kubectl_dev -n "$SANDBOX_NAMESPACE" get pod \
      -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=workspace" -o json >"$pods_json" 2>"$err" || {
        SMOKE_LAST_WAIT_DETAIL="$(sed 's/[[:cntrl:]]//g' "$err" | tail -n 1)"
        return 1
      }
  fi
  POD_NAME="$(jq -r '.items[0].metadata.name // empty' "$pods_json")"
  if [[ -z "$POD_NAME" ]]; then
    SMOKE_LAST_WAIT_DETAIL="no workspace pod found for SandboxClaim $CLAIM_NAME yet"
    return 1
  fi
  return 0
}

assert_runtime_node_storage() {
  local node_name="$1"
  local node_json capacity allocatable disk_pressure allocatable_bytes min_bytes

  require_uint EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB "$EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB"
  [[ "$EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB" != "0" ]] || return 0

  min_bytes="$((EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB * 1024 * 1024 * 1024))"
  node_json="$(kubectl_dev get node "$node_name" -o json)"
  capacity="$(jq -r '.status.capacity["ephemeral-storage"] // empty' <<<"$node_json")"
  allocatable="$(jq -r '.status.allocatable["ephemeral-storage"] // empty' <<<"$node_json")"
  disk_pressure="$(jq -r '[.status.conditions[]? | select(.type == "DiskPressure") | .status][0] // "Unknown"' <<<"$node_json")"
  [[ -n "$allocatable" ]] || die "runtime node $node_name missing allocatable ephemeral-storage"
  [[ "$disk_pressure" == "False" ]] || die "runtime node $node_name DiskPressure=$disk_pressure"
  allocatable_bytes="$(quantity_to_bytes "$allocatable")"
  [[ "$allocatable_bytes" -ge "$min_bytes" ]] || \
    die "runtime node $node_name allocatable ephemeral-storage=$allocatable, want at least ${EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB}Gi"
  log "runtime node storage ok: $node_name capacity=$capacity allocatable=$allocatable DiskPressure=$disk_pressure min=${EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB}Gi"
}

assert_pod_coco_kernel_params() {
  [[ -n "$EXPECTED_KATA_COCO_KBS_URL" || -n "$EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI" ]] || return 0

  local pod_json="$1"
  local label="$2"
  local annotation_key="io.katacontainers.config.hypervisor.kernel_params"
  local kernel_params

  kernel_params="$(jq -r --arg key "$annotation_key" '.metadata.annotations[$key] // empty' "$pod_json")"
  if [[ -n "$EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI" ]]; then
    [[ "$kernel_params" == *"agent.image_registry_auth=$EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI"* ]] || \
      die "$label missing CoCo image_registry_auth kernel param for $EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI"
  fi
  if [[ "$EXPECTED_RUNTIME_CLASS" == "confidential" ]]; then
    [[ "$kernel_params" == *"agent.guest_components_procs=confidential-data-hub"* ]] || \
      die "$label missing CoCo guest_components_procs=confidential-data-hub kernel param"
    [[ "$kernel_params" != *"agent.guest_components_rest_api="* ]] || \
      die "$label exposes the guest-components REST API in a confidential workload"
  else
    [[ "$kernel_params" == *"agent.guest_components_rest_api=resource"* ]] || \
      die "$label missing CoCo guest_components_rest_api=resource kernel param"
  fi
  [[ "$kernel_params" == *"agent.log_vport=1025"* ]] || \
    die "$label missing CoCo agent.log_vport=1025 kernel param"
  if [[ -n "$EXPECTED_KATA_COCO_KBS_URL" ]]; then
    [[ "$kernel_params" == *"agent.aa_kbc_params=cc_kbc::$EXPECTED_KATA_COCO_KBS_URL"* ]] || \
      die "$label missing CoCo aa_kbc_params kernel param for $EXPECTED_KATA_COCO_KBS_URL"
  fi
}

assert_docker_socket_contract() {
  local pod_json="$1"
  local volume_count medium workspace_mount_count dind_mount_count readiness_command

  volume_count="$(jq '[.spec.volumes[]? | select(.name == "docker-sock")] | length' "$pod_json")"
  workspace_mount_count="$(jq '[.spec.containers[]? | select(.name == "workspace") | .volumeMounts[]? | select(.name == "docker-sock" and .mountPath == "/var/run/docker")] | length' "$pod_json")"
  dind_mount_count="$(jq '[.spec.containers[]? | select(.name == "dind") | .volumeMounts[]? | select(.name == "docker-sock" and .mountPath == "/var/run/docker")] | length' "$pod_json")"
  readiness_command="$(jq -r '[.spec.containers[]? | select(.name == "workspace") | .readinessProbe.exec.command[2] // empty][0] // empty' "$pod_json")"

  if [[ "$EXPECTED_DOCKER_MODE" == "none" ]]; then
    [[ "$volume_count" == "0" ]] || \
      die "Docker-disabled workspace declares $volume_count docker-sock volume(s), want 0"
    [[ "$workspace_mount_count" == "0" && "$dind_mount_count" == "0" ]] || \
      die "Docker-disabled workspace still mounts docker-sock"
    [[ -z "$readiness_command" ]] || \
      die "Docker-disabled workspace still declares a Docker readiness probe"
    return
  fi

  [[ "$volume_count" == "1" ]] || \
    die "Docker-enabled workspace declares $volume_count docker-sock volume(s), want 1"
  medium="$(jq -r '[.spec.volumes[]? | select(.name == "docker-sock") | .emptyDir.medium // empty][0] // empty' "$pod_json")"
  [[ "$medium" == "Memory" ]] || \
    die "docker-sock emptyDir medium=${medium:-<default>}, want Memory for Kata cross-container Unix sockets"
  [[ "$workspace_mount_count" == "1" && "$dind_mount_count" == "1" ]] || \
    die "docker-sock mount counts workspace=$workspace_mount_count dind=$dind_mount_count, want 1/1"
  [[ "$readiness_command" == "test -f /codewire/run/daemon/ready && docker version --format '{{.Server.Version}}' >/dev/null" ]] || \
    die "workspace Docker readiness probe does not prove the cross-container daemon connection"
  jq -e '
    .spec.containers[]
    | select(.name == "workspace")
    | .readinessProbe
    | .periodSeconds == 2
      and .timeoutSeconds == 2
      and .failureThreshold == 3
      and .successThreshold == 1
  ' "$pod_json" >/dev/null || \
    die "workspace Docker readiness probe timing contract drifted"
}

assert_pod_shape() {
  local pod_json="$TMPDIR_SMOKE/pod.json"
  local runtime_class node node_label containers daemon_images

  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$POD_NAME" -o json >"$pod_json"
  runtime_class="$(jq -r '.spec.runtimeClassName // ""' "$pod_json")"
  node="$(jq -r '.spec.nodeName // ""' "$pod_json")"
  dind_image="$(jq -r '.spec.containers[] | select(.name=="dind") | .image' "$pod_json")"
  dind_status_image="$(jq -r '.status.containerStatuses[]? | select(.name=="dind") | .image // ""' "$pod_json")"
  dind_image_id="$(jq -r '.status.containerStatuses[]? | select(.name=="dind") | .imageID // ""' "$pod_json")"
  containers="$(jq -r '[.spec.containers[].name] | sort | join(",")' "$pod_json")"
  assert_pod_coco_kernel_params "$pod_json" "workspace pod"

  [[ "$runtime_class" == "$EXPECTED_RUNTIME_CLASS" ]] || \
    die "workspace pod runtimeClassName=$runtime_class, want $EXPECTED_RUNTIME_CLASS"
  case "$EXPECTED_DOCKER_MODE" in
    none)
      [[ "$containers" == "workspace" ]] || \
        die "workspace pod containers=$containers, want workspace for EXPECTED_DOCKER_MODE=none"
      ;;
    guest-dind|local-dind-direct|profile-default|"")
      [[ "$containers" == "dind,workspace" ]] || \
        die "workspace pod containers=$containers, want dind,workspace"
      ;;
    *)
      die "unsupported EXPECTED_DOCKER_MODE=$EXPECTED_DOCKER_MODE"
      ;;
  esac
  assert_docker_socket_contract "$pod_json"
  # The workspace daemon hosts SSH and the tailnet (#2460).
  assert_no_gateway_objects
  if [[ -n "$EXPECTED_DAEMON_IMAGE" ]]; then
    # The daemon reaches the Pod as a read-only image volume or through its
    # init container; either way it is this release's daemon image.
    daemon_images="$(jq -r '
      [(.spec.initContainers[]? | select(.name == "codewire-daemon-init") | .image),
       (.spec.volumes[]? | .image.reference // empty)] | unique | join(",")
    ' "$pod_json")"
    [[ "$daemon_images" == "$EXPECTED_DAEMON_IMAGE" ]] || \
      die "workspace daemon image=${daemon_images:-<none>}, want $EXPECTED_DAEMON_IMAGE"
  fi
  if [[ -n "$EXPECTED_DIND_IMAGE" && "$EXPECTED_DOCKER_MODE" != "none" ]]; then
    [[ "$dind_image" == "$EXPECTED_DIND_IMAGE" ]] || \
      die "dind image=$dind_image, want $EXPECTED_DIND_IMAGE"
    log "dind status image=${dind_status_image:-<unset>} imageID=${dind_image_id:-<unset>}"
  fi
  if [[ -n "$EXPECTED_NODE" ]]; then
    [[ "$node" == "$EXPECTED_NODE" ]] || die "node=$node, want $EXPECTED_NODE"
  fi
  node_label="$(kubectl_dev get node "$node" -o "jsonpath={.metadata.labels.${EXPECTED_NODE_KATA_LABEL//./\\.}}" 2>/dev/null || true)"
  [[ "$node_label" == "$EXPECTED_NODE_KATA_VALUE" ]] || \
    die "node $node label $EXPECTED_NODE_KATA_LABEL=$node_label, want $EXPECTED_NODE_KATA_VALUE"
  assert_runtime_node_storage "$node"

  local host_socket_count workspace_docker_host expected_binding_url
  local dind_bootstrap dind_data_image dind_data_root dind_data_size dind_mount_mode
  host_socket_count="$(jq '[.spec.volumes[]? | select(.hostPath? and ((.hostPath.path == "/var/run/docker.sock") or (.hostPath.path == "/var/run/docker") or (.hostPath.path == "/run/containerd/containerd.sock") or (.hostPath.path == "/run/containerd")))] | length' "$pod_json")"
  [[ "$host_socket_count" == "0" ]] || die "workspace pod mounts host Docker/containerd socket volume"

  workspace_docker_host="$(jq -r '.spec.containers[] | select(.name=="workspace") | .env[]? | select(.name=="DOCKER_HOST") | .value // ""' "$pod_json")"
  dind_bootstrap="$(jq -r '.spec.containers[] | select(.name=="dind") | .command[2] // ""' "$pod_json")"
  dind_data_image="$(jq -r '.spec.containers[] | select(.name=="dind") | .env[]? | select(.name=="CODEWIRE_DOCKER_DATA_IMAGE") | .value // ""' "$pod_json")"
  dind_data_root="$(jq -r '.spec.containers[] | select(.name=="dind") | .env[]? | select(.name=="CODEWIRE_DOCKER_DATA_ROOT") | .value // ""' "$pod_json")"
  dind_data_size="$(jq -r '.spec.containers[] | select(.name=="dind") | .env[]? | select(.name=="CODEWIRE_DOCKER_DATA_SIZE") | .value // ""' "$pod_json")"
  dind_mount_mode="$(jq -r '.spec.containers[] | select(.name=="dind") | .env[]? | select(.name=="CODEWIRE_DOCKER_MOUNT_MODE") | .value // ""' "$pod_json")"
  expected_binding_url="https://codewire-orchestration-workspace-binding.${CODEWIRE_SERVER_NAMESPACE}.svc.cluster.local:8087"

  if [[ "$EXPECTED_DOCKER_MODE" == "none" ]]; then
    [[ -z "$workspace_docker_host" ]] || \
      die "workspace DOCKER_HOST=$workspace_docker_host, want empty for EXPECTED_DOCKER_MODE=none"
  else
    [[ "$workspace_docker_host" == "unix:///var/run/docker/docker.sock" ]] || \
      die "workspace DOCKER_HOST=$workspace_docker_host, want unix:///var/run/docker/docker.sock"
  fi
  # An identity-free daemon binds to the dedicated listener over TLS with
  # the published internal roots and learns everything else, including its
  # tailnet endpoints, from that binding: no daemon token, environment
  # identity or tailnet configuration is rendered into the Pod.
  jq -e --arg url "$expected_binding_url" '
    (.spec.containers[] | select(.name == "workspace")) as $w
    | ([$w.env[]? | select(.name == "CODEWIRE_WORKSPACE_BINDING_URL") | .value] == [$url])
    and ([$w.env[]?.name] | (index("CODEWIRE_DAEMON_AUTH_TOKEN") | not) and (index("CODEWIRE_ENVIRONMENT_ID") | not))
    and ([$w.env[]?.name
          | select(startswith("CODEWIRE_TAILNET_") or startswith("CODEWIRE_UDP_RELAY_")
                   or startswith("CODEWIRE_STUN_") or . == "CODEWIRE_DERP_URL")] | length == 0)
    and ([$w.volumeMounts[]? | select(
          .name == "orchestration-internal-roots"
          and .mountPath == "/run/codewire-orchestration-internal-roots"
          and .readOnly == true)] | length == 1)
  ' "$pod_json" >/dev/null || \
    die "workspace Pod is not an identity-free daemon binding to $expected_binding_url with the internal roots"
  if [[ "$EXPECTED_DOCKER_MODE" != "none" ]]; then
    [[ "$dind_bootstrap" == *"--data-root \"\$data_root\""* && "$dind_bootstrap" == *"--storage-driver vfs"* ]] || \
      die "dind bootstrap does not use explicit data root with vfs storage driver"
    [[ "$dind_data_image" == "/workspace/.codewire/docker-data.ext4" ]] || \
      die "dind CODEWIRE_DOCKER_DATA_IMAGE=$dind_data_image, want /workspace/.codewire/docker-data.ext4"
    [[ "$dind_data_size" =~ ^[0-9]+G$ ]] || \
      die "dind CODEWIRE_DOCKER_DATA_SIZE=$dind_data_size, want <size>G"
    if [[ "$EXPECTED_RUNTIME_CLASS" == "confidential" ]]; then
      [[ "$dind_mount_mode" == "none" ]] || \
        die "dind CODEWIRE_DOCKER_MOUNT_MODE=$dind_mount_mode, want none for confidential"
      [[ "$dind_data_root" == "/workspace/.codewire/docker-root" ]] || \
        die "dind CODEWIRE_DOCKER_DATA_ROOT=$dind_data_root, want /workspace/.codewire/docker-root for confidential"
    else
      [[ "$dind_mount_mode" == "loop" ]] || \
        die "dind CODEWIRE_DOCKER_MOUNT_MODE=$dind_mount_mode, want loop"
      [[ "$dind_bootstrap" == *"mkfs.ext4"* && "$dind_bootstrap" == *"mount -o loop"* ]] || \
        die "dind bootstrap does not mount ext4 data root for $EXPECTED_RUNTIME_CLASS"
      [[ "$dind_data_root" == "/var/lib/docker" ]] || \
        die "dind CODEWIRE_DOCKER_DATA_ROOT=$dind_data_root, want /var/lib/docker"
    fi
  fi
  assert_tailnet_discovery_shape "$pod_json"

  kubectl_dev -n "$SANDBOX_NAMESPACE" exec "$POD_NAME" -c workspace -- id >/dev/null
  if [[ "$EXPECTED_DOCKER_MODE" != "none" ]]; then
    if [[ "$EXPECTED_RUNTIME_CLASS" == "confidential" ]]; then
      # shellcheck disable=SC2016 # The guest shell/awk expand these expressions.
      kubectl_dev -n "$SANDBOX_NAMESPACE" exec "$POD_NAME" -c dind -- sh -ec '
        test -d /workspace/.codewire/docker-root
        ! awk '\''$2 == "/workspace/.codewire/docker-root" && $3 == "ext4" { found = 1 } END { exit found ? 0 : 1 }'\'' /proc/mounts
        docker -H unix:///var/run/docker/docker.sock info >/tmp/codewire-docker-info.txt
        grep -q "Storage Driver: vfs" /tmp/codewire-docker-info.txt
        grep -q "Docker Root Dir: /workspace/.codewire/docker-root" /tmp/codewire-docker-info.txt
      ' >/dev/null
      log "dind plain workspace data root ok: /workspace/.codewire/docker-root"
    else
      local dind_mount_info dind_mount_last
      dind_mount_info=""
      dind_mount_last=""
      for _ in $(seq 1 90); do
        # shellcheck disable=SC2016 # The guest shell/awk expand these expressions.
        if dind_mount_info="$(kubectl_dev -n "$SANDBOX_NAMESPACE" exec "$POD_NAME" -c dind -- sh -ec '
          line="$(awk '\''$2 == "/var/lib/docker" && $3 == "ext4" { print $1 " " $3; found = 1; exit } END { if (!found) exit 1 }'\'' /proc/mounts)"
          set -- $line
          source="$1"
          fstype="$2"
          case "$source" in
            /dev/loop*|/dev/*) ;;
            *)
              echo "expected /var/lib/docker ext4 mount to come from a guest block source, got ${source:-<none>}" >&2
              exit 1
              ;;
          esac
          echo "source=$source fstype=$fstype"
        ' 2>&1)"; then
          break
        fi
        dind_mount_last="$dind_mount_info"
        dind_mount_info=""
        sleep 1
      done
      [[ -n "$dind_mount_info" ]] || \
        die "dind /var/lib/docker did not become a guest ext4 over-mount; last check: ${dind_mount_last:-<no /var/lib/docker ext4 mount>}"
      log "dind /var/lib/docker mount ok: $dind_mount_info"
    fi
  fi

  log "workspace pod $POD_NAME runtime=$runtime_class node=$node hosts SSH and the tailnet; no gateway objects"
}

# The workspace daemon hosts SSH and the tailnet (#2460): the environment owns
# no gateway Pod, Deployment, Service or NetworkPolicy, by label or by name.
assert_no_gateway_objects() {
  local labelled named
  labelled="$(kubectl_dev -n "$SANDBOX_NAMESPACE" get pod,deployment,service,networkpolicy \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=gateway" -o name)"
  named="$(kubectl_dev -n "$SANDBOX_NAMESPACE" get --ignore-not-found -o name \
    "deployment/cw-gateway-$ENV_ID" "service/cw-gateway-svc-$ENV_ID" \
    "networkpolicy/cw-gw-net-$ENV_ID" "networkpolicy/cw-gw-warm-$ENV_ID")"
  [[ -z "$labelled$named" ]] || \
    die "environment $ENV_ID owns gateway objects: $(printf '%s %s' "$labelled" "$named" | tr '\n' ' ')"
}

assert_tailnet_discovery_shape() {
  if expect_tailnet_direct_udp; then
    assert_tailnet_direct_udp_discovery_shape "$1"
    return
  fi
  if expect_tailnet_peer_relay; then
    assert_tailnet_peer_relay_discovery_shape "$1"
    return
  fi
  [[ -z "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" || "$EXPECTED_TAILNET_PATH_TRANSPORT" == "any" ]] || \
    die "unsupported EXPECTED_TAILNET_PATH_TRANSPORT=$EXPECTED_TAILNET_PATH_TRANSPORT"
  log "tailnet discovery shape check skipped for EXPECTED_TAILNET_PATH_TRANSPORT=${EXPECTED_TAILNET_PATH_TRANSPORT:-any}"
}

# The workspace daemon is the tailnet peer. It receives its direct-UDP and
# relay endpoints from its access grant and allocates relay slots through
# orchestration, so its Pod carries no tailnet configuration, its policy
# reaches only the relay's public data port (never the allocator) and no
# direct-UDP Service allocates a NodePort.
assert_tailnet_peer_relay_discovery_shape() {
  local pod_json="$1"
  local direct_udp_label direct_udp_service_json direct_udp_services
  local direct_udp_lb_service_json direct_udp_lb_nodeport_count daemon_policy_json

  direct_udp_label="$(jq -r '.metadata.labels["codewire.sh/direct-udp-service"]? // ""' "$pod_json")"
  [[ -z "$direct_udp_label" ]] || \
    die "pod still has legacy codewire.sh/direct-udp-service selector label $direct_udp_label"

  jq -e '
    [.spec.containers[] | select(.name == "workspace") | .env[]?.name
     | select(startswith("CODEWIRE_TAILNET_") or startswith("CODEWIRE_UDP_RELAY_"))]
    | length == 0
  ' "$pod_json" >/dev/null || \
    die "workspace Pod carries static tailnet or relay settings; the daemon must take them from its access grant"

  direct_udp_service_json="$TMPDIR_SMOKE/direct-udp-service.json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get service -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=direct-udp" -o json >"$direct_udp_service_json"
  direct_udp_services="$(jq -r '.items | length' "$direct_udp_service_json")"
  [[ "$direct_udp_services" == "0" ]] || \
    die "expected no direct UDP NodePort Services for peer relay environment $ENV_ID, found $direct_udp_services"

  direct_udp_lb_service_json="$TMPDIR_SMOKE/direct-udp-lb-services.json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get service -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/runtime-network=direct-udp" -o json >"$direct_udp_lb_service_json"
  direct_udp_lb_nodeport_count="$(jq '[.items[]? | select(.spec.type == "NodePort" or (.spec.allocateLoadBalancerNodePorts != false) or ([.spec.ports[]? | select(has("nodePort"))] | length > 0))] | length' "$direct_udp_lb_service_json")"
  [[ "$direct_udp_lb_nodeport_count" == "0" ]] || \
    die "direct UDP LoadBalancer service must not allocate NodePorts"

  daemon_policy_json="$TMPDIR_SMOKE/workspace-peer-relay-networkpolicy.json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get networkpolicy \
    -l "codewire.sh/environment-id=${ENV_ID},app.kubernetes.io/component=workspace-daemon" \
    -o json >"$daemon_policy_json"
  jq -e --arg ns "$CODEWIRE_SERVER_NAMESPACE" '
    [.items[]?.spec.egress[]?
      | select(
          (.to[]? | .namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == $ns
                    and .podSelector.matchLabels["app.kubernetes.io/component"] == "udp-relay")
          and ([.ports[]? | select(.protocol == "UDP" and ((.port | tonumber) == 41641))] | length > 0))]
    | length > 0
  ' "$daemon_policy_json" >/dev/null || \
    die "workspace NetworkPolicy does not allow the shared UDP relay data port 41641 in namespace $CODEWIRE_SERVER_NAMESPACE"
  jq -e '
    [.items[]?.spec.egress[]? | .ports[]? | select(.protocol == "TCP" and ((.port | tonumber) == 8095))]
    | length == 0
  ' "$daemon_policy_json" >/dev/null || \
    die "workspace NetworkPolicy reaches the UDP relay allocator; orchestration allocates relay slots"

  log "tailnet peer relay mode: the daemon reaches only the relay data port, and no NodePort direct UDP service exists"
}

assert_tailnet_direct_udp_discovery_shape() {
  local pod_json="$1"
  local direct_udp_service_json direct_udp_services

  assert_tailnet_peer_relay_discovery_shape "$pod_json"

  direct_udp_service_json="$TMPDIR_SMOKE/direct-udp-lb-service.json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get service -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=direct-udp-lb" -o json >"$direct_udp_service_json"
  direct_udp_services="$(jq -r '.items | length' "$direct_udp_service_json")"
  [[ "$direct_udp_services" == "1" ]] || \
    die "expected exactly one direct UDP LoadBalancer service for $ENV_ID, found $direct_udp_services"

  # The LoadBalancer selects the workspace Pod's tailnet port; the doctor's
  # evidence proves the daemon advertises exactly this endpoint.
  jq -e --arg ip "$EXPECTED_TAILNET_DIRECT_UDP_LB_IP" --arg zone "$EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE" --arg id "$ENV_ID" '
    .items[0].spec.type == "LoadBalancer"
    and .items[0].spec.allocateLoadBalancerNodePorts == false
    and .items[0].spec.loadBalancerClass == "io.cilium/l2-announcer"
    and .items[0].metadata.annotations["lbipam.cilium.io/ips"] == $ip
    and .items[0].metadata.labels["codewire.sh/transport-zone"] == $zone
    and .items[0].metadata.annotations["lbipam.cilium.io/sharing-key"] == "codewire-direct-udp"
    and .items[0].metadata.annotations["lbipam.cilium.io/sharing-cross-namespace"] == "*"
    and .items[0].spec.selector["codewire.sh/type"] == "workspace"
    and .items[0].spec.selector["codewire.sh/environment-id"] == $id
    and ([.items[0].spec.ports[]? | select(.protocol == "UDP" and ((.targetPort | tonumber) == 31000) and (has("nodePort") | not))] | length == 1)
  ' "$direct_udp_service_json" >/dev/null || \
    die "direct UDP LoadBalancer service does not select the workspace tailnet port on Cilium LB-IPAM $EXPECTED_TAILNET_DIRECT_UDP_LB_IP"

  log "tailnet direct UDP mode: Cilium LoadBalancer $EXPECTED_TAILNET_DIRECT_UDP_LB_IP selects the workspace tailnet port without NodePorts"
}

assert_sandbox_template_derp_egress() {
  local claim_json="$TMPDIR_SMOKE/claim-template.json"
  local claim_shadow_json="$TMPDIR_SMOKE/claim-shadow.json"
  local template_json="$TMPDIR_SMOKE/sandboxtemplate.json"
  local daemon_policy_json="$TMPDIR_SMOKE/workspace-daemon-networkpolicy.json"
  local daemon_service_json="$TMPDIR_SMOKE/workspace-daemon-service.json"
  local template_name claim_shadow_name

  kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxclaim "$CLAIM_NAME" -o json >"$claim_json"
  template_name="$(jq -r '.spec.sandboxTemplateRef.name // empty' "$claim_json")"
  if [[ -z "$template_name" ]]; then
    claim_shadow_name="$(jq -r '.spec.warmPoolRef.name // empty' "$claim_json")"
    [[ -n "$claim_shadow_name" ]] || \
      die "SandboxClaim $CLAIM_NAME has neither sandboxTemplateRef.name nor warmPoolRef.name"
    kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxwarmpool "$claim_shadow_name" -o json >"$claim_shadow_json"
    template_name="$(jq -r '.spec.sandboxTemplateRef.name // empty' "$claim_shadow_json")"
    [[ -n "$template_name" ]] || \
      die "claim shadow SandboxWarmPool $claim_shadow_name has no sandboxTemplateRef.name"
  fi
  kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxtemplate "$template_name" -o json >"$template_json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get networkpolicy \
    -l "codewire.sh/environment-id=${ENV_ID},app.kubernetes.io/component=workspace-daemon" \
    -o json >"$daemon_policy_json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get service \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=workspace-daemon" \
    -o json >"$daemon_service_json"

  # The daemon reaches DERP through its public edge (world TCP 443) and only
  # STUN on the DERP Pods, never their TLS port.
  jq -e --arg ns "$CODEWIRE_SERVER_NAMESPACE" '
    [
      .items[]?.spec.egress[]?
      | select(
          (
            .to[]?
            | .namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == $ns
              and .podSelector.matchLabels["app.kubernetes.io/component"] == "derp"
          )
          and ([.ports[]? | select(.protocol == "UDP" and ((.port | tonumber) == 3478))] | length > 0)
          and ([.ports[]? | select(.protocol == "TCP")] | length == 0)
        )
    ]
    | length > 0
  ' "$daemon_policy_json" >/dev/null || \
    die "workspace NetworkPolicy does not allow exactly DERP STUN (UDP 3478) to codewire-derp in namespace $CODEWIRE_SERVER_NAMESPACE"

  # Tailnet UDP reaches the daemon from the world only: every peer is an
  # ipBlock excluding the private, carrier-grade NAT and loopback ranges.
  jq -e '
    [
      .items[]?.spec.ingress[]?
      | select([.ports[]? | select(.protocol == "UDP" and ((.port | tonumber) == 31000))] | length > 0)
      | select((.from | length) > 0 and all(.from[];
          (keys == ["ipBlock"])
          and (if .ipBlock.cidr == "0.0.0.0/0" then
                 ((.ipBlock.except // []) as $except
                  | ["10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                  | all(. as $range | $except | index($range) != null))
               else .ipBlock.cidr == "::/0" and ((.ipBlock.except // []) | index("fc00::/7") != null)
               end)))
    ]
    | length > 0
  ' "$daemon_policy_json" >/dev/null || \
    die "workspace NetworkPolicy does not admit tailnet UDP 31000 from world addresses only"

  jq -e '
    [.items[]?.spec.ingress[]? | .from[]?.podSelector.matchLabels["codewire.sh/type"] | select(. == "gateway")]
    | length == 0
  ' "$daemon_policy_json" >/dev/null || \
    die "workspace NetworkPolicy still admits gateway-labelled pods"

  jq -e --arg server_namespace "$CODEWIRE_SERVER_NAMESPACE" '
    [
      .items[]?.spec.ingress[]?
      | select(
          ([.from[]?
            | select(
                .namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == $server_namespace
                and .podSelector.matchLabels["app.kubernetes.io/name"] == "codewire"
                and .podSelector.matchLabels["app.kubernetes.io/component"] == "orchestration"
              )
            ] | length > 0)
          and ([.ports[]? | select(.protocol == "TCP" and ((.port | tonumber) == 7777))] | length > 0)
          and ([.ports[]? | select(.protocol == "TCP" and ((.port | tonumber) == 2222))] | length > 0)
        )
    ]
    | length > 0
  ' "$daemon_policy_json" >/dev/null || \
    die "workspace daemon NetworkPolicy must allow Codewire orchestration in $CODEWIRE_SERVER_NAMESPACE to TCP 7777 and SSH 2222"

  jq -e '
    (.items | length == 1)
    and (.items[0].spec.type == "ClusterIP")
    and ([.items[0].spec.ports[]? | select(.protocol == "TCP" and ((.port | tonumber) == 7777) and (has("nodePort") | not))] | length > 0)
  ' "$daemon_service_json" >/dev/null || \
    die "workspace daemon service must be a ClusterIP Service on TCP 7777 without NodePort"

  assert_sandbox_template_kata_init_data "$template_json" "$template_name"
}

assert_sandbox_template_kata_init_data() {
  [[ "$EXPECTED_KATA_AGENT_POLICY_ANNOTATION" == "1" || "$EXPECTED_KATA_COCO_INIT_DATA_ANNOTATION" == "1" ]] || return 0

  local template_json="$1"
  local template_name="$2"
  local annotation_key="io.katacontainers.config.hypervisor.cc_init_data"
  local kernel_annotation_key="io.katacontainers.config.hypervisor.kernel_params"
  local encoded decoded kernel_params

  require_cmd base64
  require_cmd gzip

  encoded="$(jq -r --arg key "$annotation_key" '.spec.podTemplate.metadata.annotations[$key] // empty' "$template_json")"
  [[ -n "$encoded" ]] || die "SandboxTemplate $template_name missing Kata init-data annotation $annotation_key"

  decoded="$TMPDIR_SMOKE/kata-coco-init-data.toml"
  if ! printf '%s' "$encoded" | base64 -d | gzip -dc >"$decoded" 2>"$TMPDIR_SMOKE/kata-coco-init-data.decode.err"; then
    sed 's/[[:cntrl:]]//g' "$TMPDIR_SMOKE/kata-coco-init-data.decode.err" >&2 || true
    die "SandboxTemplate $template_name has invalid Kata init-data annotation"
  fi

  grep -qx 'version = "0.1.0"' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing version"
  grep -qx 'algorithm = "sha256"' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing algorithm"
  grep -q '^package agent_policy$' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing agent_policy package"
  grep -q '^default ExecProcessRequest := true$' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing ExecProcessRequest allow default"
  grep -q '^default ReadStreamRequest := true$' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing ReadStreamRequest allow default"
  grep -q '^default WriteStreamRequest := true$' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing WriteStreamRequest allow default"
  grep -q '^default CopyFileRequest := true$' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing CopyFileRequest allow default"
  grep -q '^default GetDiagnosticDataRequest := false$' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing GetDiagnosticDataRequest deny default"
  grep -q '^default SetPolicyRequest := false$' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing SetPolicyRequest deny default"
  grep -q '^default StartTracingRequest := false$' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing StartTracingRequest deny default"
  grep -q '^default StopTracingRequest := false$' "$decoded" || \
    die "SandboxTemplate $template_name Kata init-data missing StopTracingRequest deny default"

  if [[ -n "$EXPECTED_KATA_COCO_KBS_URL" ]]; then
    grep -Fxq "\"aa.toml\" = '''" "$decoded" || \
      die "SandboxTemplate $template_name Kata init-data missing aa.toml"
    grep -q '^\[token_configs.kbs\]$' "$decoded" || \
      die "SandboxTemplate $template_name aa.toml missing token_configs.kbs"
    grep -Fxq "\"cdh.toml\" = '''" "$decoded" || \
      die "SandboxTemplate $template_name Kata init-data missing cdh.toml"
    grep -Fxq "url = \"$EXPECTED_KATA_COCO_KBS_URL\"" "$decoded" || \
      die "SandboxTemplate $template_name Kata init-data missing KBS URL $EXPECTED_KATA_COCO_KBS_URL"
    if [[ "$EXPECTED_RUNTIME_CLASS" == "confidential" ]]; then
      grep -Fxq 'protected_resource_uri_prefixes = ["kbs:///default/codewire-workspace-luks/"]' "$decoded" || \
        die "SandboxTemplate $template_name cdh.toml missing protected volume-key namespace"
    fi
  fi
  if grep -q '^\[\[credentials\]\]$' "$decoded"; then
    die "SandboxTemplate $template_name should not prefetch CoCo test resources at guest boot"
  fi
  if [[ -n "$EXPECTED_KATA_COCO_KBS_URL" || -n "$EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI" ]]; then
    kernel_params="$(jq -r --arg key "$kernel_annotation_key" '.spec.podTemplate.metadata.annotations[$key] // empty' "$template_json")"
    if [[ -n "$EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI" ]]; then
      [[ "$kernel_params" == *"agent.image_registry_auth=$EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI"* ]] || \
        die "SandboxTemplate $template_name missing CoCo image_registry_auth kernel param for $EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI"
    fi
    if [[ "$EXPECTED_RUNTIME_CLASS" == "confidential" ]]; then
      [[ "$kernel_params" == *"agent.guest_components_procs=confidential-data-hub"* ]] || \
        die "SandboxTemplate $template_name missing CoCo guest_components_procs=confidential-data-hub kernel param"
      [[ "$kernel_params" != *"agent.guest_components_rest_api="* ]] || \
        die "SandboxTemplate $template_name exposes guest-components REST in a confidential workload"
    else
      [[ "$kernel_params" == *"agent.guest_components_rest_api=resource"* ]] || \
        die "SandboxTemplate $template_name missing CoCo guest_components_rest_api=resource kernel param"
    fi
    [[ "$kernel_params" == *"agent.log_vport=1025"* ]] || \
      die "SandboxTemplate $template_name missing CoCo agent.log_vport=1025 kernel param"
    if [[ -n "$EXPECTED_KATA_COCO_KBS_URL" ]]; then
      [[ "$kernel_params" == *"agent.aa_kbc_params=cc_kbc::$EXPECTED_KATA_COCO_KBS_URL"* ]] || \
        die "SandboxTemplate $template_name missing CoCo aa_kbc_params kernel param for $EXPECTED_KATA_COCO_KBS_URL"
    fi
  fi

  log "SandboxTemplate $template_name carries Kata init-data policy annotation"
}

assert_public_stun_edge() {
  local services_json stun_json host_network stun_port_env stun_port_count stale_nodeport_count

  services_json="$TMPDIR_SMOKE/server-services.json"
  stun_json="$TMPDIR_SMOKE/codewire-stun-deploy.json"

  kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get service -o json >"$services_json"
  stale_nodeport_count="$(jq '
    [
      .items[]?
      | select(
          .metadata.name == "codewire-derp-stun"
          or (
            .spec.type == "NodePort"
            and ([.spec.ports[]? | select((.nodePort // 0) == 30478 or (.port // 0) == 30478 or (.targetPort // 0) == 30478)] | length > 0)
          )
        )
    ]
    | length
  ' "$services_json")"
  [[ "$stale_nodeport_count" == "0" ]] || \
    die "server namespace $CODEWIRE_SERVER_NAMESPACE still exposes obsolete STUN NodePort 30478/codewire-derp-stun"

  kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment codewire-stun -o json >"$stun_json"
  host_network="$(jq -r '.spec.template.spec.hostNetwork // false' "$stun_json")"
  stun_port_env="$(jq -r '.spec.template.spec.containers[] | select(.name=="stun") | .env[]? | select(.name=="STUN_PORT") | .value // ""' "$stun_json")"
  stun_port_count="$(jq '
    [
      .spec.template.spec.containers[]?
      | select(.name == "stun")
      | .ports[]?
      | select(.protocol == "UDP" and (.containerPort == 3478))
    ]
    | length
  ' "$stun_json")"

  [[ "$host_network" == "true" ]] || die "codewire-stun must run hostNetwork for public UDP 3478"
  [[ "$stun_port_env" == "3478" ]] || die "codewire-stun STUN_PORT=$stun_port_env, want 3478"
  [[ "$stun_port_count" != "0" ]] || die "codewire-stun does not declare UDP containerPort 3478"

  log "public STUN edge uses host-network UDP 3478 and no NodePort 30478"
}

assert_cilium_stun_host_egress_policy() {
  local policy_json="$TMPDIR_SMOKE/cilium-stun-host-egress-policy.json"

  if ! kubectl_dev get crd ciliumclusterwidenetworkpolicies.cilium.io >/dev/null 2>&1; then
    log "CiliumClusterwideNetworkPolicy CRD not installed; skipping Cilium STUN host egress assertion"
    return
  fi

  kubectl_dev get ciliumclusterwidenetworkpolicy codewire-sandbox-allow-stun-host-egress -o json >"$policy_json"

  jq -e '
    .spec.endpointSelector.matchLabels["k8s:io.cilium.k8s.namespace.labels.codewire.sh/resource-type"] == "sandbox"
    and .spec.endpointSelector.matchLabels["k8s:io.cilium.k8s.namespace.labels.codewire.sh/runtime-scope"] == "shared"
    and (
      [
        .spec.egress[]?
        | select(
            ((.toEntities // []) | index("host"))
            and ((.toEntities // []) | index("remote-node"))
            and (
              [
                .toPorts[]?.ports[]?
                | select(.protocol == "UDP" and ((.port | tonumber) == 3478))
              ] | length > 0
            )
          )
      ] | length > 0
    )
  ' "$policy_json" >/dev/null || \
    die "CiliumClusterwideNetworkPolicy codewire-sandbox-allow-stun-host-egress must allow sandbox namespaces to host/remote-node UDP 3478"

  log "Cilium policy allows sandbox STUN egress to host/remote-node UDP 3478"
}

run_kube_assertions() {
  [[ "$SMOKE_SKIP_KUBE" != "1" ]] || {
    log "skipping Kubernetes assertions"
    return
  }
  [[ -n "$CODEWIRE_SERVER_NAMESPACE" ]] || \
    die "CODEWIRE_SERVER_NAMESPACE is required for Kubernetes assertions"
  maybe_default_kubeconfig
  require_cmd kubectl
  require_cmd jq
  select_kube_context

  assert_public_stun_edge
  assert_cilium_stun_host_egress_policy
  log "waiting for SandboxClaim in $SANDBOX_NAMESPACE"
  wait_until "SandboxClaim" "$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))" claim_exists
  assert_sandbox_template_derp_egress
  log "waiting for pod adopted by $CLAIM_NAME"
  wait_until "sandbox pod" "$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))" pod_exists_for_claim
  log "waiting for pod readiness"
  kubectl_dev -n "$SANDBOX_NAMESPACE" wait "pod/$POD_NAME" \
    --for=condition=Ready --timeout="${SMOKE_TIMEOUT_SECONDS}s"
  assert_pod_shape
}

discover_runtime_objects() {
  maybe_default_kubeconfig
  require_cmd kubectl
  require_cmd jq
  select_kube_context

  if [[ -z "$CLAIM_NAME" ]]; then
    log "discovering SandboxClaim in $SANDBOX_NAMESPACE"
    wait_until "SandboxClaim" "$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))" claim_exists
  fi
  if [[ -z "$POD_NAME" ]]; then
    log "discovering workspace pod adopted by $CLAIM_NAME"
    wait_until "sandbox pod" "$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))" pod_exists_for_claim
  fi
}

run_cw_session_script() {
  local script="$1"
  cw_with_timeout "$SMOKE_EXEC_TIMEOUT" \
    run --no-tty "$ENV_ID" -- sh -lc "$script"
}

classify_coco_rest_isolation_result() {
  local command_exit="$1"
  local stdout_file="$2"
  local stderr_file="$3"
  local marker marker_count

  COCO_REST_ISOLATION_STATUS="command_failed"
  COCO_REST_ISOLATION_CURL_EXIT=""
  COCO_REST_ISOLATION_EVIDENCE_SOURCE="none"

  marker_count="$(grep -Ec \
    '^coco_rest_isolation_v1 status=(passed|listener_present|inconclusive_transport) curl_exit=[0-9]+$' \
    "$stdout_file" || true)"
  if [[ "$marker_count" == "1" ]]; then
    marker="$(grep -E \
      '^coco_rest_isolation_v1 status=(passed|listener_present|inconclusive_transport) curl_exit=[0-9]+$' \
      "$stdout_file")"
    if [[ "$marker" =~ ^coco_rest_isolation_v1\ status=(passed|listener_present|inconclusive_transport)\ curl_exit=([0-9]+)$ ]]; then
      COCO_REST_ISOLATION_STATUS="${BASH_REMATCH[1]}"
      COCO_REST_ISOLATION_CURL_EXIT="${BASH_REMATCH[2]}"
      COCO_REST_ISOLATION_EVIDENCE_SOURCE="guest_marker"
      case "$COCO_REST_ISOLATION_STATUS:$COCO_REST_ISOLATION_CURL_EXIT:$command_exit" in
        passed:7:0) return 0 ;;
        listener_present:0:*)
          [[ "$command_exit" != "0" ]] && return 0
          ;;
        inconclusive_transport:*:*)
          [[ "$COCO_REST_ISOLATION_CURL_EXIT" != "0" \
            && "$COCO_REST_ISOLATION_CURL_EXIT" != "7" \
            && "$command_exit" != "0" ]] && return 0
          ;;
      esac
      COCO_REST_ISOLATION_STATUS="command_failed"
      return 0
    fi
  elif [[ "$marker_count" != "0" ]]; then
    return 0
  fi

  if [[ "$command_exit" != "0" ]] \
      && grep -Fq 'session exited with code 24' "$stderr_file"; then
    COCO_REST_ISOLATION_STATUS="listener_present"
    COCO_REST_ISOLATION_CURL_EXIT="0"
    COCO_REST_ISOLATION_EVIDENCE_SOURCE="cli_terminal_status"
  elif [[ "$command_exit" != "0" ]] \
      && grep -Fq 'session exited with code 25' "$stderr_file"; then
    COCO_REST_ISOLATION_STATUS="inconclusive_transport"
    COCO_REST_ISOLATION_EVIDENCE_SOURCE="cli_terminal_status"
  elif [[ "$command_exit" == "0" ]]; then
    if [[ -s "$stdout_file" ]]; then
      COCO_REST_ISOLATION_STATUS="output_malformed"
    else
      COCO_REST_ISOLATION_STATUS="output_missing"
    fi
  fi
}

record_coco_rest_isolation_receipt() {
  local command_exit="$1"
  local receipt="$TMPDIR_SMOKE/coco-rest-isolation.json"

  jq -n \
    --arg status "$COCO_REST_ISOLATION_STATUS" \
    --argjson command_exit "$command_exit" \
    --arg curl_exit "$COCO_REST_ISOLATION_CURL_EXIT" \
    --arg evidence_source "$COCO_REST_ISOLATION_EVIDENCE_SOURCE" \
    '{
      schema: "codewire.coco-rest-isolation/v1",
      status: $status,
      commandExit: $command_exit,
      curlExit: (if $curl_exit == "" then null else ($curl_exit | tonumber) end),
      evidenceSource: $evidence_source,
      rawOutputCapturedPrivately: true
    }' >"$receipt"
  chmod 0600 "$receipt"
  COCO_REST_ISOLATION_RECEIPT="$receipt"

  if [[ -n "$SMOKE_ARTIFACT_DIR" ]]; then
    mkdir -p "$SMOKE_ARTIFACT_DIR"
    cp "$receipt" "$SMOKE_ARTIFACT_DIR/coco-rest-isolation.json"
    chmod 0600 "$SMOKE_ARTIFACT_DIR/coco-rest-isolation.json"
    COCO_REST_ISOLATION_RECEIPT="$SMOKE_ARTIFACT_DIR/coco-rest-isolation.json"
  fi
}

wait_for_cw_run() {
  local deadline out last
  out="$TMPDIR_SMOKE/cw-run-ready.out"
  deadline=$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))

  log "waiting for cw run readiness"
  while (( "$(seconds_now)" < deadline )); do
    if cw_with_timeout 30 run --no-tty "$ENV_ID" -- true >"$out" 2>&1; then
      return
    fi
    last="$(sed 's/[[:cntrl:]]//g' "$out" | tail -n 1)"
    sleep 5
  done

  sed 's/[[:cntrl:]]//g' "$out" >&2 || true
  if [[ -n "${last:-}" ]]; then
    die "timed out waiting for cw run readiness; last detail: $last"
  fi
  die "timed out waiting for cw run readiness"
}

run_environment_session_smoke() {
  local success_out success_err failure_out failure_err sessions_json
  local success_session

  success_out="$TMPDIR_SMOKE/cw-run-session-success.out"
  success_err="$TMPDIR_SMOKE/cw-run-session-success.err"
  failure_out="$TMPDIR_SMOKE/cw-run-session-failure.out"
  failure_err="$TMPDIR_SMOKE/cw-run-session-failure.err"
  sessions_json="$TMPDIR_SMOKE/cw-run-sessions.json"

  log "checking generated platform session run/list/logs and failure propagation"
  cw_with_timeout "$SMOKE_EXEC_TIMEOUT" \
    run --no-tty "$ENV_ID" -- printf platform-session-smoke \
    >"$success_out" 2>"$success_err"
  grep -qF 'platform-session-smoke' "$success_out" ||
    die "platform session output was not returned"
  if grep -qF 'Launched session' "$success_out"; then
    die "platform session lifecycle diagnostics polluted command stdout"
  fi

  if cw_with_timeout "$SMOKE_EXEC_TIMEOUT" \
      run --no-tty "$ENV_ID" -- sh -lc \
        'printf platform-session-failure; exit 42' \
      >"$failure_out" 2>"$failure_err"; then
    die "failed platform session unexpectedly returned success"
  fi
  grep -qF 'platform-session-failure' "$failure_out" ||
    die "failed platform session output was not returned"
  grep -qF 'session exited with code 42' "$failure_err" ||
    die "failed platform session exit status was not propagated"

  cw ls "$ENV_ID" --output json >"$sessions_json"
  jq -e '
    any(.[];
      .command == ["printf", "platform-session-smoke"] and
      .state == "Exited" and
      .exit_code == 0
    ) and
    any(.[];
      .command == ["sh", "-lc", "printf platform-session-failure; exit 42"] and
      .state == "Exited" and
      .exit_code == 42
    )
  ' "$sessions_json" >/dev/null ||
    die "platform durable session records drifted"

  success_session="$(
    jq -er '
      first(
        .[]
        | select(
            .command == ["printf", "platform-session-smoke"] and
            .exit_code == 0
          )
      )
      | .session_id
    ' "$sessions_json"
  )"
  cw logs "$ENV_ID" --session "$success_session" --raw |
    grep -qF 'platform-session-smoke' ||
    die "saved platform session output was not readable"
}

assert_coco_guest_test_resource() {
  [[ -n "$EXPECTED_KATA_COCO_TEST_RESOURCE_URI" ]] || return 0

  if [[ "$EXPECTED_RUNTIME_CLASS" == "confidential" ]]; then
    local script stdout_file stderr_file command_exit
    script="$(cat <<SCRIPT
set -eu
uri=$(shell_quote "$EXPECTED_KATA_COCO_TEST_RESOURCE_URI")
case "\$uri" in
  kbs:///*) resource_path="\${uri#kbs:///}" ;;
  *) echo "unsupported CoCo test resource URI: \$uri" >&2; exit 1 ;;
esac
command -v curl >/dev/null 2>&1 || {
  echo "curl is required for the confidential REST-isolation assertion" >&2
  exit 1
}
set +e
# The durable session stream combines guest stdout and stderr. Suppress curl's
# redundant diagnostic so it cannot interleave with the structural result; the
# exact curl exit code below remains the decision-bearing evidence.
curl --max-time 3 -sS -o /dev/null \
  "http://127.0.0.1:8006/cdh/resource/\$resource_path" 2>/dev/null
status=\$?
set -e
case "\$status" in
  7)
    printf 'coco_rest_isolation_v1 status=passed curl_exit=7\\n'
    ;;
  0)
    printf 'coco_rest_isolation_v1 status=listener_present curl_exit=0\\n'
    exit 24
    ;;
  *)
    printf 'coco_rest_isolation_v1 status=inconclusive_transport curl_exit=%s\\n' "\$status"
    exit 25
    ;;
esac
SCRIPT
)"

    stdout_file="$TMPDIR_SMOKE/coco-rest-isolation.stdout"
    stderr_file="$TMPDIR_SMOKE/coco-rest-isolation.stderr"
    : >"$stdout_file"
    : >"$stderr_file"
    chmod 0600 "$stdout_file" "$stderr_file"

    log "asserting the confidential workload cannot reach a guest CDH REST listener"
    if run_cw_session_script "$script" >"$stdout_file" 2>"$stderr_file"; then
      command_exit=0
    else
      command_exit=$?
    fi
    classify_coco_rest_isolation_result \
      "$command_exit" "$stdout_file" "$stderr_file"
    record_coco_rest_isolation_receipt "$command_exit"

    case "$COCO_REST_ISOLATION_STATUS" in
      passed)
        log "confidential guest CDH REST listener is absent (curl_exit=7)"
        return 0
        ;;
      listener_present)
        die "confidential guest CDH REST listener is reachable (curl_exit=0; receipt=$COCO_REST_ISOLATION_RECEIPT)"
        ;;
      inconclusive_transport)
        die "confidential guest CDH REST isolation probe was inconclusive (curl_exit=${COCO_REST_ISOLATION_CURL_EXIT:-unknown}; receipt=$COCO_REST_ISOLATION_RECEIPT)"
        ;;
      output_missing)
        die "cw run returned success without the guest REST-isolation marker (attachment output gap; receipt=$COCO_REST_ISOLATION_RECEIPT)"
        ;;
      output_malformed)
        die "cw run returned non-empty output without one valid guest REST-isolation marker (malformed or interleaved output; receipt=$COCO_REST_ISOLATION_RECEIPT)"
        ;;
      *)
        die "confidential guest CDH REST isolation probe failed before classification (command_exit=$command_exit; receipt=$COCO_REST_ISOLATION_RECEIPT)"
        ;;
    esac
  fi

  local expected_content="$EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT"
  if [[ -z "$expected_content" ]]; then
    expected_content="codewire confidential trustee test resource"
  fi

  local script
  script="$(cat <<SCRIPT
set -eu
uri=$(shell_quote "$EXPECTED_KATA_COCO_TEST_RESOURCE_URI")
expected=$(shell_quote "$expected_content")
case "\$uri" in
  kbs:///*) resource_path="\${uri#kbs:///}" ;;
  *) echo "unsupported CoCo test resource URI: \$uri" >&2; exit 1 ;;
esac
if command -v curl >/dev/null 2>&1; then
  actual="\$(curl -fsS "http://127.0.0.1:8006/cdh/resource/\$resource_path")"
else
  actual="\$(RESOURCE_PATH="\$resource_path" /bin/bash <<'BASH'
set -eu
exec 3<>/dev/tcp/127.0.0.1/8006
printf 'GET /cdh/resource/%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' "\$RESOURCE_PATH" >&3
response="\$(cat <&3)"
printf '%s' "\${response#*\$'\\r\\n\\r\\n'}"
BASH
)"
fi
if [ "\$actual" != "\$expected" ]; then
  echo "unexpected CoCo test resource content for \$uri" >&2
  exit 1
fi
printf 'coco-test-resource-ok\\n'
SCRIPT
)"

  log "asserting CoCo test resource $EXPECTED_KATA_COCO_TEST_RESOURCE_URI through guest CDH REST"
  run_cw_session_script "$script" | grep -qx 'coco-test-resource-ok' || \
    die "CoCo test resource assertion failed"
}

run_docker_smoke() {
  [[ "$SMOKE_SKIP_DOCKER" != "1" ]] || {
    log "skipping Docker guest smoke"
    return
  }
  require_bool01 SMOKE_DOCKER_STRESS "$SMOKE_DOCKER_STRESS"
  require_uint SMOKE_DOCKER_STRESS_ITERATIONS "$SMOKE_DOCKER_STRESS_ITERATIONS"
  require_uint SMOKE_DOCKER_POSTGRES_ROWS "$SMOKE_DOCKER_POSTGRES_ROWS"
  require_uint SMOKE_DOCKER_LARGE_IMAGE_MAX_SECONDS "$SMOKE_DOCKER_LARGE_IMAGE_MAX_SECONDS"
  require_bool01 SMOKE_DOCKER_OOM_STRESS "$SMOKE_DOCKER_OOM_STRESS"

  local docker_smoke_id common
  docker_smoke_id="${ENV_ID//-/}"
  docker_smoke_id="${docker_smoke_id:0:12}"
  common="$(cat <<SCRIPT
set -eu
SMOKE_DOCKER_STRESS=$SMOKE_DOCKER_STRESS
SMOKE_DOCKER_STRESS_ITERATIONS=$SMOKE_DOCKER_STRESS_ITERATIONS
SMOKE_DOCKER_POSTGRES_ROWS=$SMOKE_DOCKER_POSTGRES_ROWS
SMOKE_DOCKER_LARGE_IMAGE=$(shell_quote "$SMOKE_DOCKER_LARGE_IMAGE")
SMOKE_DOCKER_LARGE_IMAGE_MAX_SECONDS=$SMOKE_DOCKER_LARGE_IMAGE_MAX_SECONDS
SMOKE_DOCKER_EGRESS_SMALL_URL=$(shell_quote "$SMOKE_DOCKER_EGRESS_SMALL_URL")
SMOKE_DOCKER_EGRESS_LARGE_URL=$(shell_quote "$SMOKE_DOCKER_EGRESS_LARGE_URL")
SMOKE_DOCKER_OOM_STRESS=$SMOKE_DOCKER_OOM_STRESS
smoke_id=$(shell_quote "$docker_smoke_id")
work="/tmp/codewire-runtime-smoke-\$smoke_id"
pg="codewire-runtime-postgres-\$smoke_id"
vol="\${pg}-data"
compose_project="codewireruntimesmoke\${smoke_id}"
log_ctr="codewire-runtime-log-\$smoke_id"
mc_net="codewire-runtime-mc-\$smoke_id"
mc_server="codewire-runtime-mc-server-\$smoke_id"
restart_ctr="codewire-runtime-restart-\$smoke_id"
sigterm_ctr="codewire-runtime-sigterm-\$smoke_id"
oom_ctr="codewire-runtime-oom-\$smoke_id"
docker_smoke_cleanup() {
  docker rm -f "\$pg" "\$log_ctr" "\$mc_server" "\$restart_ctr" "\$sigterm_ctr" "\$oom_ctr" >/dev/null 2>&1 || true
  docker network rm "\$mc_net" >/dev/null 2>&1 || true
  docker volume rm "\$vol" >/dev/null 2>&1 || true
  docker compose -p "\$compose_project" -f "\$work/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "\$work"
}
docker_pull_retry() {
  image="\$1"
  attempts="\${2:-4}"
  delay=3
  attempt=1
  while [ "\$attempt" -le "\$attempts" ]; do
    if docker pull "\$image"; then
      return 0
    fi
    rc="\$?"
    if [ "\$attempt" -eq "\$attempts" ]; then
      return "\$rc"
    fi
    echo "docker pull \$image failed on attempt \$attempt/\$attempts; retrying" >&2
    sleep "\$delay"
    delay="\$((delay * 2))"
    attempt="\$((attempt + 1))"
  done
}
mkdir -p "\$work"
SCRIPT
)"

  run_docker_smoke_phase() {
    local name="$1"
    local body="$2"
    log "running Docker guest smoke phase: $name"
    run_cw_session_script "$common
$body"
  }

  run_docker_smoke_phase "preflight/build" "$(cat <<'SCRIPT'
docker_smoke_cleanup
mkdir -p "$work"
test "$DOCKER_HOST" = "unix:///var/run/docker/docker.sock"
docker version >/dev/null
storage_driver="$(docker info --format "{{.Driver}}")"
if [ "$storage_driver" != "vfs" ]; then
  echo "expected guest dockerd storage driver vfs, got ${storage_driver}" >&2
  exit 1
fi
docker info --format "{{.ServerVersion}}" >/dev/null

echo "docker build smoke"
docker_pull_retry busybox:1.36
cat > "$work/Dockerfile" <<'EOF'
FROM busybox:1.36
CMD ["sh", "-c", "echo docker-build-ok"]
EOF
docker build -q -t codewire-runtime-build-smoke:latest "$work" >/dev/null
docker run --rm codewire-runtime-build-smoke:latest | grep -qx docker-build-ok
SCRIPT
)"

  run_docker_smoke_phase "lifecycle/compose/network" "$(cat <<'SCRIPT'
echo "docker lifecycle/logs/exec smoke"
docker_pull_retry busybox:1.36
docker run -d --name "$log_ctr" busybox:1.36 sh -c "echo lifecycle-log-ok; sleep 300" >/dev/null
docker exec "$log_ctr" sh -c "echo lifecycle-exec-ok" | grep -qx lifecycle-exec-ok
docker logs "$log_ctr" | grep -qx lifecycle-log-ok
docker rm -f "$log_ctr" >/dev/null

echo "docker compose smoke"
cat > "$work/compose.yaml" <<'EOF'
services:
  app:
    image: busybox:1.36
    command: sh -c "echo compose-run-ok"
EOF
docker compose version >/dev/null
docker compose -p "$compose_project" -f "$work/compose.yaml" up --abort-on-container-exit --exit-code-from app >/dev/null
docker compose -p "$compose_project" -f "$work/compose.yaml" down -v --remove-orphans >/dev/null

echo "nginx rootfs smoke"
docker_pull_retry nginx:alpine
docker run --rm nginx:alpine sh -lc "test -f /docker-entrypoint.sh && test -x /usr/sbin/nginx && nginx -v >/dev/null 2>&1"

echo "multi-container docker network smoke"
docker network create "$mc_net" >/dev/null
docker run -d --name "$mc_server" --network "$mc_net" busybox:1.36 \
  sh -c "mkdir -p /www; echo multi-container-ok > /www/index.html; httpd -f -p 8080 -h /www" >/dev/null
mc_ready=0
for _ in $(seq 1 30); do
  if out="$(docker run --rm --network "$mc_net" busybox:1.36 wget -qO- "http://${mc_server}:8080" 2>/dev/null)" && [ "$out" = "multi-container-ok" ]; then
    mc_ready=1
    break
  fi
  sleep 1
done
test "$mc_ready" = "1"
docker rm -f "$mc_server" >/dev/null
docker network rm "$mc_net" >/dev/null
SCRIPT
)"

  run_docker_smoke_phase "egress" "$(cat <<'SCRIPT'
echo "guest docker egress and DNS smoke"
docker_pull_retry curlimages/curl:8.11.1
for url in "$SMOKE_DOCKER_EGRESS_SMALL_URL" "https://www.google.com/"; do
  egress_ready=0
  for _ in $(seq 1 3); do
    if docker run --rm curlimages/curl:8.11.1 -fsS --max-time 20 "$url" >/dev/null; then
      egress_ready=1
      break
    fi
    sleep 2
  done
  test "$egress_ready" = "1"
done
SCRIPT
)"

  run_docker_smoke_phase "restart/sigterm" "$(cat <<'SCRIPT'
echo "container restart-on-failure smoke"
docker run -d --name "$restart_ctr" --restart=on-failure:1 busybox:1.36 sh -c "echo restart-attempt; exit 42" >/dev/null
restart_seen=0
for _ in $(seq 1 30); do
  restart_count="$(docker inspect -f "{{.RestartCount}}" "$restart_ctr")"
  running="$(docker inspect -f "{{.State.Running}}" "$restart_ctr")"
  if [ "$restart_count" -ge 1 ] && [ "$running" = "false" ]; then
    restart_seen=1
    break
  fi
  sleep 1
done
test "$restart_seen" = "1"
test "$(docker inspect -f "{{.State.ExitCode}}" "$restart_ctr")" = "42"
docker logs "$restart_ctr" | grep -q "restart-attempt"
docker rm -f "$restart_ctr" >/dev/null

echo "graceful SIGTERM smoke"
docker run -d --name "$sigterm_ctr" busybox:1.36 sh -c "trap 'echo SIGTERM_CAUGHT; exit 0' TERM; echo SIGTERM_READY; while true; do sleep 1; done" >/dev/null
sigterm_ready=0
for _ in $(seq 1 10); do
  if docker logs "$sigterm_ctr" 2>/dev/null | grep -q "SIGTERM_READY"; then
    sigterm_ready=1
    break
  fi
  sleep 1
done
test "$sigterm_ready" = "1"
docker stop --time 5 "$sigterm_ctr" >/dev/null
docker logs "$sigterm_ctr" | grep -q "SIGTERM_CAUGHT"
test "$(docker inspect -f "{{.State.ExitCode}}" "$sigterm_ctr")" = "0"
docker rm -f "$sigterm_ctr" >/dev/null
SCRIPT
)"

  run_docker_smoke_phase "postgres" "$(cat <<'SCRIPT'
echo "postgres container smoke"
docker_pull_retry postgres:17-alpine
docker volume create "$vol" >/dev/null
docker run -d --name "$pg" \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=smoke \
  -v "$vol:/var/lib/postgresql/data" \
  postgres:17-alpine >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$pg" pg_isready -h 127.0.0.1 -U postgres -d smoke >/dev/null 2>&1; then
    break
  fi
  if [ $(( _ % 5 )) -eq 0 ]; then
    echo "waiting for postgres startup ($_/60)"
  fi
  sleep 1
done
docker exec "$pg" pg_isready -h 127.0.0.1 -U postgres -d smoke >/dev/null
docker exec "$pg" psql -h 127.0.0.1 -U postgres -d smoke -v ON_ERROR_STOP=1 \
  -c "CREATE TABLE IF NOT EXISTS runtime_smoke (value text primary key);" \
  -c "INSERT INTO runtime_smoke(value) VALUES ('runtime-write-ok') ON CONFLICT DO NOTHING;" >/dev/null
if [ "$SMOKE_DOCKER_POSTGRES_ROWS" -gt 0 ]; then
  docker exec "$pg" psql -h 127.0.0.1 -U postgres -d smoke -v ON_ERROR_STOP=1 \
    -c "CREATE TABLE IF NOT EXISTS runtime_rows (id integer PRIMARY KEY, payload text);" \
    -c "TRUNCATE runtime_rows;" \
    -c "INSERT INTO runtime_rows SELECT g, md5(g::text) FROM generate_series(1,${SMOKE_DOCKER_POSTGRES_ROWS}) g;" >/dev/null
  test "$(docker exec "$pg" psql -h 127.0.0.1 -U postgres -d smoke -tAc "SELECT count(*) FROM runtime_rows")" = "$SMOKE_DOCKER_POSTGRES_ROWS"
fi
docker restart "$pg" >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$pg" pg_isready -h 127.0.0.1 -U postgres -d smoke >/dev/null 2>&1; then
    break
  fi
  if [ $(( _ % 5 )) -eq 0 ]; then
    echo "waiting for postgres restart ($_/60)"
  fi
  sleep 1
done
test "$(docker exec "$pg" psql -h 127.0.0.1 -U postgres -d smoke -tAc "SELECT value FROM runtime_smoke LIMIT 1")" = "runtime-write-ok"
docker exec "$pg" test -f /var/lib/postgresql/data/PG_VERSION
SCRIPT
)"

  if [[ "$SMOKE_DOCKER_STRESS" == "1" ]]; then
    run_docker_smoke_phase "stress-loop" "$(cat <<'SCRIPT'
if [ "$SMOKE_DOCKER_STRESS" = "1" ]; then
  echo "container stress loop"
  docker_pull_retry busybox:1.36
  docker_pull_retry alpine:3.22
  for i in $(seq 1 "$SMOKE_DOCKER_STRESS_ITERATIONS"); do
    docker run --rm busybox:1.36 sh -lc "d=\$(mktemp -d); dd if=/dev/zero of=\$d/blob bs=1M count=16 >/dev/null 2>&1; sha256sum \$d/blob >/dev/null; echo stress-${i}-busybox-ok" | grep -qx "stress-${i}-busybox-ok"
    docker run --rm alpine:3.22 sh -lc "for n in \$(seq 1 50); do true; done; echo stress-${i}-alpine-ok" | grep -qx "stress-${i}-alpine-ok"
  done

  echo "large egress smoke"
  docker_pull_retry curlimages/curl:8.11.1
  docker run --rm curlimages/curl:8.11.1 -fsS --max-time 45 "$SMOKE_DOCKER_EGRESS_LARGE_URL" >/dev/null

  echo "large image cold-start smoke"
  docker_pull_retry "$SMOKE_DOCKER_LARGE_IMAGE"
  start_ts="$(date +%s)"
  docker run --rm "$SMOKE_DOCKER_LARGE_IMAGE" python - <<'PY' | grep -qx large-image-ok
print("large-image-ok")
PY
  elapsed="$(( $(date +%s) - start_ts ))"
  echo "large image ${SMOKE_DOCKER_LARGE_IMAGE} completed in ${elapsed}s"
  test "$elapsed" -le "$SMOKE_DOCKER_LARGE_IMAGE_MAX_SECONDS"

  echo "large image warm-start smoke"
  start_ts="$(date +%s)"
  docker run --rm "$SMOKE_DOCKER_LARGE_IMAGE" python - <<'PY' | grep -qx large-image-warm-ok
print("large-image-warm-ok")
PY
  elapsed="$(( $(date +%s) - start_ts ))"
  echo "large image warm run completed in ${elapsed}s"
  test "$elapsed" -le "$SMOKE_DOCKER_LARGE_IMAGE_MAX_SECONDS"

  if [ "$SMOKE_DOCKER_OOM_STRESS" = "1" ]; then
    echo "docker memory limit OOM smoke"
    if docker run --name "$oom_ctr" --memory=64m --memory-swap=64m "$SMOKE_DOCKER_LARGE_IMAGE" python - <<'PY' >/dev/null 2>&1
buf = bytearray(256 * 1024 * 1024)
print(len(buf))
PY
    then
      echo "expected memory-limited container to fail under OOM pressure" >&2
      exit 1
    fi
    oom_killed="$(docker inspect -f "{{.State.OOMKilled}}" "$oom_ctr")"
    oom_exit="$(docker inspect -f "{{.State.ExitCode}}" "$oom_ctr")"
    if [ "$oom_killed" != "true" ] && [ "$oom_exit" = "0" ]; then
      echo "unexpected OOM smoke outcome: OOMKilled=${oom_killed} exit=${oom_exit}" >&2
      exit 1
    fi
    docker rm -f "$oom_ctr" >/dev/null
  fi
fi
SCRIPT
)"
  fi

  run_docker_smoke_phase "cleanup" "$(cat <<'SCRIPT'
docker_smoke_cleanup
echo "docker-guest-smoke-ok"
SCRIPT
)"
}

validate_confidential_preview_response() {
  local status="$1"
  local headers="$2"
  local body="$3"
  local token="$4"
  local service location

  [[ "$status" == "302" ]] || return 1
  [[ -f "$headers" && -f "$body" ]] || return 1
  service="$(awk '
    tolower($0) ~ /^x-codewire-service:[[:space:]]*/ {
      value = $0
      sub(/^[^:]*:[[:space:]]*/, "", value)
      sub(/\r$/, "", value)
    }
    END { print value }
  ' "$headers")"
  [[ "$service" == "codewire-orchestration" ]] || return 1
  location="$(awk '
    tolower($0) ~ /^location:[[:space:]]*/ {
      value = $0
      sub(/^[^:]*:[[:space:]]*/, "", value)
      sub(/\r$/, "", value)
    }
    END { print value }
  ' "$headers")"
  [[ "$location" == */sign-in\?redirect_uri=* ]] || return 1
  ! grep -Fq "$token" "$body"
}

run_app_preview_smoke() {
  require_cmd curl
  require_cmd jq
  require_uint SMOKE_APP_PREVIEW_PORT "$SMOKE_APP_PREVIEW_PORT"
  [[ "$SMOKE_APP_PREVIEW_PORT" -ge 1 && "$SMOKE_APP_PREVIEW_PORT" -le 65535 ]] || \
    die "SMOKE_APP_PREVIEW_PORT must be between 1 and 65535"
  [[ "$SMOKE_APP_PREVIEW_LABEL" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || \
    die "SMOKE_APP_PREVIEW_LABEL must be a DNS-safe label"

  local token start_script stop_script port_json port_err rm_json rm_err
  local preview_url preview_host_port preview_host preview_body preview_err
  local preview_headers preview_status preview_ok preview_failure
  local cleanup_body cleanup_status port_cleanup_ok cleanup_failure

  token="codewire-preview-${ENV_ID//-/}-$(date -u +%s)"
  start_script="$(cat <<SCRIPT
set -eu
port=$SMOKE_APP_PREVIEW_PORT
token=$(shell_quote "$token")
work=/workspace/codewire-preview-smoke
pidfile="\$work/server.pid"
mkdir -p "\$work"
if [ -f "\$pidfile" ]; then
  old_pid="\$(cat "\$pidfile" 2>/dev/null || true)"
  if [ -n "\$old_pid" ]; then
    kill "\$old_pid" >/dev/null 2>&1 || true
  fi
  rm -f "\$pidfile"
fi

if command -v python3 >/dev/null 2>&1; then
  cat > "\$work/server.py" <<'PY'
import http.server
import os
import socketserver

TOKEN = os.environ["CODEWIRE_APP_PREVIEW_TOKEN"]
PORT = int(os.environ["CODEWIRE_APP_PREVIEW_PORT"])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (TOKEN + "\\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

with Server(("0.0.0.0", PORT), Handler) as httpd:
    httpd.serve_forever()
PY
  CODEWIRE_APP_PREVIEW_TOKEN="\$token" CODEWIRE_APP_PREVIEW_PORT="\$port" \
    nohup python3 "\$work/server.py" >"\$work/server.log" 2>&1 &
elif command -v node >/dev/null 2>&1; then
  cat > "\$work/server.js" <<'JS'
const http = require("http");
const token = process.env.CODEWIRE_APP_PREVIEW_TOKEN;
const port = Number(process.env.CODEWIRE_APP_PREVIEW_PORT);
http
  .createServer((_req, res) => {
    const body = token + "\n";
    res.writeHead(200, {
      "content-type": "text/plain; charset=utf-8",
      "content-length": Buffer.byteLength(body),
    });
    res.end(body);
  })
  .listen(port, "0.0.0.0");
JS
  CODEWIRE_APP_PREVIEW_TOKEN="\$token" CODEWIRE_APP_PREVIEW_PORT="\$port" \
    nohup node "\$work/server.js" >"\$work/server.log" 2>&1 &
elif command -v busybox >/dev/null 2>&1; then
  printf '%s\\n' "\$token" > "\$work/index.html"
  nohup busybox httpd -f -p "0.0.0.0:\$port" -h "\$work" >"\$work/server.log" 2>&1 &
else
  echo "no python3, node, or busybox available for app preview smoke" >&2
  exit 1
fi
echo "\$!" > "\$pidfile"

ready=0
for _ in \$(seq 1 60); do
  out=""
  if command -v curl >/dev/null 2>&1; then
    out="\$(curl -fsS --max-time 2 "http://127.0.0.1:\$port/" 2>/dev/null || true)"
  elif command -v wget >/dev/null 2>&1; then
    out="\$(wget -qO- -T 2 "http://127.0.0.1:\$port/" 2>/dev/null || true)"
  elif command -v python3 >/dev/null 2>&1; then
    out="\$(CODEWIRE_APP_PREVIEW_PORT="\$port" python3 - <<'PY' 2>/dev/null || true
import os
import urllib.request
with urllib.request.urlopen(f"http://127.0.0.1:{os.environ['CODEWIRE_APP_PREVIEW_PORT']}/", timeout=2) as resp:
    print(resp.read().decode("utf-8"), end="")
PY
)"
  elif command -v node >/dev/null 2>&1; then
    out="\$(CODEWIRE_APP_PREVIEW_PORT="\$port" node - <<'JS' 2>/dev/null || true
const http = require("http");
const port = process.env.CODEWIRE_APP_PREVIEW_PORT;
http
  .get("http://127.0.0.1:" + port + "/", (res) => {
    let body = "";
    res.on("data", (chunk) => (body += chunk));
    res.on("end", () => process.stdout.write(body));
  })
  .on("error", () => process.exit(1));
JS
)"
  fi
  if [ "\$out" = "\$token" ]; then
    ready=1
    break
  fi
  pid="\$(cat "\$pidfile" 2>/dev/null || true)"
  if [ -n "\$pid" ] && ! kill -0 "\$pid" >/dev/null 2>&1; then
    cat "\$work/server.log" >&2 || true
    exit 1
  fi
  sleep 1
done
test "\$ready" = "1"
printf 'app-preview-service-ok\\n'
SCRIPT
)"

  log "starting app preview smoke service on port $SMOKE_APP_PREVIEW_PORT"
  run_cw_session_script "$start_script" | grep -qx 'app-preview-service-ok' || \
    die "app preview service did not become ready inside the environment"

  port_json="$TMPDIR_SMOKE/app-preview-port.json"
  port_err="$TMPDIR_SMOKE/app-preview-port.err"
  log "registering preview port $SMOKE_APP_PREVIEW_PORT label=$SMOKE_APP_PREVIEW_LABEL"
  if ! cw ports "$ENV_ID" --publish "$SMOKE_APP_PREVIEW_PORT" \
      --label "$SMOKE_APP_PREVIEW_LABEL" \
      --access public \
      --output json >"$port_json" 2>"$port_err"; then
    sed 's/[[:cntrl:]]//g' "$port_err" >&2 || true
    die "cw ports --publish failed"
  fi

  preview_url="$(jq -r '.preview_url // empty' "$port_json")"
  [[ -n "$preview_url" ]] || die "cw ports --publish returned empty preview_url"
  [[ "$preview_url" == http://* || "$preview_url" == https://* ]] || \
    die "cw ports --publish returned invalid preview_url=$preview_url"
  preview_host_port="${preview_url#http://}"
  preview_host_port="${preview_host_port#https://}"
  if [[ "$preview_host_port" == */* ]]; then
    preview_host_port="${preview_host_port%%/*}"
  fi
  preview_host="${preview_host_port%%:*}"
  [[ -n "$preview_host" ]] || die "failed to parse preview host from $preview_url"

  preview_body="$TMPDIR_SMOKE/app-preview-response.txt"
  preview_err="$TMPDIR_SMOKE/app-preview-response.err"
  preview_headers="$TMPDIR_SMOKE/app-preview-response.headers"
  preview_ok=0
  preview_failure=""
  log "fetching preview URL $preview_url"
  if [[ "$SMOKE_ISOLATION_TIER" == "confidential" ]]; then
    preview_status="$(curl --ipv4 -sS --connect-timeout 5 --max-time 15 \
      --dump-header "$preview_headers" \
      --output "$preview_body" \
      --write-out '%{http_code}' \
      "$preview_url" 2>"$preview_err" || true)"
    if validate_confidential_preview_response \
        "$preview_status" "$preview_headers" "$preview_body" "$token"; then
      preview_ok=1
    else
      preview_failure="confidential preview did not enforce the sign-in boundary without exposing app content"
    fi
  else
    for _ in $(seq 1 60); do
      if curl --ipv4 -fsS --connect-timeout 5 --max-time 15 \
          "$preview_url" >"$preview_body" 2>"$preview_err"; then
        if grep -Fxq "$token" "$preview_body"; then
          preview_ok=1
          break
        fi
      fi
      sleep 2
    done
    if [[ "$preview_ok" != "1" ]]; then
      preview_failure="public preview URL did not return the app preview token"
    fi
  fi

  rm_json="$TMPDIR_SMOKE/app-preview-port-delete.json"
  rm_err="$TMPDIR_SMOKE/app-preview-port-delete.err"
  port_cleanup_ok=1
  cleanup_failure=""
  log "removing preview port label=$SMOKE_APP_PREVIEW_LABEL"
  if ! cw ports "$ENV_ID" --unpublish "$SMOKE_APP_PREVIEW_PORT" \
      --label "$SMOKE_APP_PREVIEW_LABEL" \
      --output json >"$rm_json" 2>"$rm_err"; then
    port_cleanup_ok=0
    cleanup_failure="cw ports --unpublish failed"
  fi

  cleanup_body="$TMPDIR_SMOKE/app-preview-after-delete.txt"
  cleanup_status=0
  if [[ "$port_cleanup_ok" == "1" ]] && \
      curl --ipv4 -fsS --connect-timeout 5 --max-time 15 \
      "$preview_url" >"$cleanup_body" 2>/dev/null; then
    cleanup_status=1
  fi
  if [[ "$cleanup_status" == "1" ]] && grep -Fq "$token" "$cleanup_body"; then
    cleanup_failure="preview URL still served the deleted app preview port"
  fi

  # shellcheck disable=SC2016 # Expanded only by the managed guest shell.
  stop_script='set -eu
work=/workspace/codewire-preview-smoke
pidfile="$work/server.pid"
if [ -f "$pidfile" ]; then
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [ -n "$pid" ]; then
    kill "$pid" >/dev/null 2>&1 || true
  fi
  rm -f "$pidfile"
fi
printf "app-preview-service-cleaned\n"'
  run_cw_session_script "$stop_script" >/dev/null 2>&1 || true
  [[ -z "$cleanup_failure" ]] || die "$cleanup_failure"
  [[ -z "$preview_failure" ]] || die "$preview_failure"
  if [[ "$SMOKE_ISOLATION_TIER" == "confidential" ]]; then
    log "confidential app preview sign-in boundary passed"
  else
    log "public app preview smoke passed"
  fi
}

# Read the guest's usable CPUs and total RAM through the ordinary session path.
# Sets GUEST_NPROC and GUEST_MEMTOTAL_KIB.
read_guest_compute() {
  local label="$1"
  local out="$TMPDIR_SMOKE/resize-guest-$label.out"
  local script line

  # shellcheck disable=SC2016 # Expanded by the guest shell, not here.
  script='printf "guest_compute_v1 nproc=%s memtotal_kib=%s\n" "$(nproc)" "$(sed -n "s/^MemTotal:[[:space:]]*\([0-9]*\) kB$/\1/p" /proc/meminfo)"'
  run_cw_session_script "$script" >"$out" || die "guest compute probe failed ($label)"
  line="$(grep -E '^guest_compute_v1 nproc=[0-9]+ memtotal_kib=[0-9]+$' "$out" | tail -n 1 || true)"
  [[ -n "$line" ]] || die "guest compute probe returned no parseable line ($label)"
  GUEST_NPROC="${line#*nproc=}"
  GUEST_NPROC="${GUEST_NPROC%% *}"
  GUEST_MEMTOTAL_KIB="${line##*memtotal_kib=}"
}

# A completed resize must be visible in the guest, not only in cgroup limits.
# CPU: the guest must have at least as many CPUs as the workspace CPU limit.
# Memory: MemTotal must grow by at least 90% of the increase; the rest allows
# for the kernel's per-page bookkeeping. (#2266)
assert_resize_guest_truth() {
  local before_mem_kib="$1" after_nproc="$2" after_mem_kib="$3"
  local previous_memory_mib="$4" desired_cpu_millicores="$5" desired_memory_mib="$6"
  local growth_kib required_kib

  if (( after_nproc * 1000 < desired_cpu_millicores )); then
    die "guest has $after_nproc CPUs after a resize to ${desired_cpu_millicores}m; the CPU limit is not backed by guest vCPUs (#2266)"
  fi
  if (( desired_memory_mib > previous_memory_mib )); then
    growth_kib=$(( after_mem_kib - before_mem_kib ))
    required_kib=$(( (desired_memory_mib - previous_memory_mib) * 1024 * 9 / 10 ))
    if (( growth_kib < required_kib )); then
      die "guest MemTotal grew by ${growth_kib} KiB after a $(( desired_memory_mib - previous_memory_mib )) MiB memory increase (needs at least ${required_kib} KiB); the memory limit is not backed by guest RAM (#2266)"
    fi
  fi
}

run_resize_guest_smoke() {
  local info_json="$TMPDIR_SMOKE/resize-guest-environment.json"
  local resize_json="$TMPDIR_SMOKE/resize-guest-result.json"
  local resize_err="$TMPDIR_SMOKE/resize-guest-result.err"
  local previous_cpu previous_memory desired_cpu desired_memory
  local before_nproc before_mem_kib applied_mode pod_replaced

  require_uint SMOKE_RESIZE_GUEST_CPU_DELTA "$SMOKE_RESIZE_GUEST_CPU_DELTA"
  require_uint SMOKE_RESIZE_GUEST_MEMORY_DELTA "$SMOKE_RESIZE_GUEST_MEMORY_DELTA"
  (( SMOKE_RESIZE_GUEST_CPU_DELTA + SMOKE_RESIZE_GUEST_MEMORY_DELTA > 0 )) ||
    die "resize-guest needs a CPU or memory increase"
  [[ -z "$SMOKE_EXISTING_ENV_ID" ]] ||
    die "resize-guest changes resources and may replace the workspace Pod; run it on a fresh disposable environment"

  cw info "$ENV_ID" --output json >"$info_json" ||
    die "failed to read environment resources before resize"
  previous_cpu="$(jq -er '.cpu_millicores' "$info_json")"
  previous_memory="$(jq -er '.memory_mb' "$info_json")"
  require_uint previous_cpu "$previous_cpu"
  require_uint previous_memory "$previous_memory"
  desired_cpu=$(( previous_cpu + SMOKE_RESIZE_GUEST_CPU_DELTA ))
  desired_memory=$(( previous_memory + SMOKE_RESIZE_GUEST_MEMORY_DELTA ))

  read_guest_compute before
  before_nproc="$GUEST_NPROC"
  before_mem_kib="$GUEST_MEMTOTAL_KIB"
  log "guest before resize: nproc=$before_nproc MemTotal=${before_mem_kib}kB (workspace ${previous_cpu}m/${previous_memory}Mi)"

  log "resizing to ${desired_cpu}m/${desired_memory}Mi with restart consent"
  if ! cw_with_timeout "$SMOKE_TIMEOUT_SECONDS" resize "$ENV_ID" \
      --cpu "${desired_cpu}m" \
      --memory "${desired_memory}MB" \
      --allow-restart \
      --force \
      --yes \
      --output json >"$resize_json" 2>"$resize_err"; then
    sed 's/[[:cntrl:]]//g' "$resize_err" >&2 || true
    die "cw resize failed"
  fi
  jq -e --argjson cpu "$desired_cpu" --argjson memory "$desired_memory" '
    .operation.state == "completed"
    and .operation.last_applied_resources.cpu_millicores == $cpu
    and .operation.last_applied_resources.memory_mb == $memory
  ' "$resize_json" >/dev/null || die "resize did not complete at the requested resources"
  applied_mode="$(jq -r '.operation.applied_mode' "$resize_json")"
  pod_replaced="$(jq -r '.operation.pod_replaced' "$resize_json")"

  wait_environment
  wait_for_cw_run
  read_guest_compute after
  log "guest after resize: nproc=$GUEST_NPROC MemTotal=${GUEST_MEMTOTAL_KIB}kB (mode=$applied_mode pod_replaced=$pod_replaced)"
  assert_resize_guest_truth "$before_mem_kib" "$GUEST_NPROC" "$GUEST_MEMTOTAL_KIB" \
    "$previous_memory" "$desired_cpu" "$desired_memory"
  log "resize reached the guest: nproc $before_nproc -> $GUEST_NPROC, MemTotal ${before_mem_kib}kB -> ${GUEST_MEMTOTAL_KIB}kB"
}

assert_tailnet_path_probe() {
  local stderr="$1"
  local expected_transport="${2:-$EXPECTED_TAILNET_PATH_TRANSPORT}"
  local line transport

  line="$(grep 'path probe transport=' "$stderr" | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    if [[ -z "$expected_transport" && "$REQUIRE_TAILNET_PATH_PROBE" != "1" ]]; then
      log "tailnet path probe not found in $stderr; no expected transport configured"
      return
    fi
    if [[ -n "$expected_transport" ]]; then
      die "tailnet path probe not found in $stderr; expected transport=$expected_transport"
    fi
    die "tailnet path probe not found in $stderr; path probe is required"
  fi

  transport="$(sed -n 's/.*path probe transport=\([^[:space:]]*\).*/\1/p' <<<"$line")"
  [[ -n "$transport" ]] || die "failed to parse tailnet path probe transport from $stderr"
  if [[ -n "$expected_transport" ]] && ! tailnet_transport_matches "$transport" "$expected_transport"; then
    grep 'cw tailnet:' "$stderr" | tail -n 80 | sed 's/[[:cntrl:]]//g' >&2 || true
    die "tailnet path transport=$transport, want $expected_transport; evidence in $stderr"
  fi

  if [[ -n "$expected_transport" ]]; then
    log "captured tailnet path probe transport=$transport for expected=$expected_transport in $stderr"
  else
    log "captured tailnet path probe transport=$transport in $stderr; no exact transport required"
  fi
}

tailnet_transport_matches() {
  local actual="$1"
  local expected="$2"

  if [[ -z "$expected" || "$expected" == "any" ]]; then
    return 0
  fi
  if [[ "$actual" == "$expected" ]]; then
    return 0
  fi
  if [[ ( "$actual" == "peer_relay" || "$actual" == "udp_relay" ) &&
        ( "$expected" == "peer_relay" || "$expected" == "udp_relay" ) ]]; then
    return 0
  fi
  if [[ ( "$actual" == "derp" || "$actual" == "derp_relay" ) &&
        ( "$expected" == "derp" || "$expected" == "derp_relay" ) ]]; then
    return 0
  fi
  return 1
}

run_tailnet_doctor() {
  local expect="${EXPECTED_TAILNET_PATH_TRANSPORT:-any}"
  local evidence_name="tailnet-doctor"
  local stdout stderr
  local -a args
  local -a env_args=()
  local doctor_rc=0 packet_rc=0

  require_bool01 SMOKE_DERP_FALLBACK "$SMOKE_DERP_FALLBACK"
  if expect_tailnet_peer_relay; then
    evidence_name="tailnet-doctor-peer-relay"
  fi
  stdout="$TMPDIR_SMOKE/${evidence_name}.json"
  stderr="$TMPDIR_SMOKE/${evidence_name}.err"

  args=(
    doctor tailnet "$ENV_ID"
    --output json
    --direct-wait "$SMOKE_TAILNET_DIRECT_WAIT"
    --peer-timeout "$SMOKE_TAILNET_PEER_TIMEOUT"
    --expect "$expect"
  )
  if [[ "$SMOKE_DERP_FALLBACK" != "1" ]]; then
    args+=(--skip-forced-derp)
  fi
  if expect_tailnet_peer_relay; then
    env_args+=(CW_TAILNET_SUPPRESS_PEER_DIRECT_UDP=1)
  fi

  log "running tailnet doctor probe (expect=$expect direct_wait=$SMOKE_TAILNET_DIRECT_WAIT peer_timeout=$SMOKE_TAILNET_PEER_TIMEOUT)"
  start_peer_relay_packet_diagnostics
  set +e
  timeout "$SMOKE_TAILNET_DOCTOR_TIMEOUT" env "${env_args[@]}" "$CW_BIN" \
    --server "$CODEWIRE_SERVER_URL" "${args[@]}" >"$stdout" 2>"$stderr"
  doctor_rc="$?"
  set -e
  stop_peer_relay_packet_diagnostics || packet_rc="$?"
  if [[ "$SMOKE_PACKET_CAPTURE_UNAVAILABLE" == "1" ]]; then
    packet_rc=1
  fi
  if [[ "$doctor_rc" == "124" ]]; then
    record_tailnet_doctor_timeout "$evidence_name" "$expect" "$stdout"
    capture_tailnet_doctor_failure_diagnostics
    die "tailnet doctor exceeded its outer timeout; structural receipt recorded"
  fi
  if [[ "$doctor_rc" != "0" ]]; then
    sed 's/[[:cntrl:]]//g' "$stderr" >&2 || true
    if ! capture_tailnet_client_failure_diagnostics "$stdout"; then
      capture_tailnet_doctor_failure_diagnostics
      die "tailnet doctor client diagnostics unavailable: invalid report"
    fi
    if [[ -n "$SMOKE_ARTIFACT_DIR" \
      && -s "$SMOKE_ARTIFACT_DIR/client-tailnet-peer-relay.json" ]]; then
      sed 's/[[:cntrl:]]//g' \
        "$SMOKE_ARTIFACT_DIR/client-tailnet-peer-relay.json" >&2 || true
    fi
    capture_tailnet_doctor_failure_diagnostics
    die "tailnet doctor probe failed; evidence in $stdout and $stderr"
  fi
  [[ "$packet_rc" == "0" ]] || \
    die "local peer-relay packet evidence is incomplete; correlate the external exact-tuple observers"
  log "tailnet doctor probe passed; evidence in $stdout"
  assert_tailnet_doctor_endpoint_evidence "$stdout"
  if [[ "$SMOKE_SKIP_KUBE" != "1" ]]; then
    discover_runtime_objects
    assert_daemon_tailnet_log_evidence
  else
    log "application-only smoke accepted client-observed tailnet evidence"
  fi
}

record_tailnet_doctor_timeout() {
  local evidence_name="$1"
  local expect="$2"
  local doctor_json="$3"
  local receipt="$TMPDIR_SMOKE/${evidence_name}-timeout.json"
  local forced_derp=false

  [[ "$SMOKE_DERP_FALLBACK" != "1" ]] || forced_derp=true
  jq -n \
    --arg expect "$expect" \
    --arg direct_wait "$SMOKE_TAILNET_DIRECT_WAIT" \
    --arg peer_timeout "$SMOKE_TAILNET_PEER_TIMEOUT" \
    --arg outer_timeout "$SMOKE_TAILNET_DOCTOR_TIMEOUT" \
    --argjson forced_derp "$forced_derp" \
    --argjson report_present "$([[ -s "$doctor_json" ]] && printf true || printf false)" \
    '{
      schema: "codewire.tailnet-doctor-timeout/v1",
      status: "outer_timeout",
      exitCode: 124,
      expectedTransport: $expect,
      directWait: $direct_wait,
      peerTimeout: $peer_timeout,
      outerTimeout: $outer_timeout,
      forcedDerp: $forced_derp,
      reportPresent: $report_present
    }' >"$receipt"
  if [[ -n "$SMOKE_ARTIFACT_DIR" ]]; then
    mkdir -p "$SMOKE_ARTIFACT_DIR"
    cp "$receipt" "$SMOKE_ARTIFACT_DIR/$(basename "$receipt")"
  fi
  jq -c . "$receipt" >&2
  log "tailnet doctor outer-timeout receipt captured in $receipt"
}

capture_tailnet_client_failure_diagnostics() {
  local doctor_json="$1"
  local output

  [[ -n "$SMOKE_ARTIFACT_DIR" ]] || return 0
  if [[ ! -s "$doctor_json" ]]; then
    log "tailnet doctor client diagnostics unavailable: missing report"
    return 1
  fi
  output="$SMOKE_ARTIFACT_DIR/client-tailnet-peer-relay.json"
  mkdir -p "$SMOKE_ARTIFACT_DIR"
  if ! jq -e '
      .direct
      | select(type == "object")
      | select(.stages | type == "array")
      | {
        schema: "codewire-tailnet-peer-relay-diagnostic-v1",
        stages: [
          .stages[]?
          | {
              name,
              status,
              duration_ms: (.duration_ms // null)
            }
        ],
        direct_path: (
          .direct_path
          | if type == "object" then
              {
                ready,
                transport,
                derp_region_id: (.derp_region_id // null)
              }
            else null
            end
        ),
        final_path: (
          .final_path
          | if type == "object" then
              {
                ready,
                transport,
                derp_region_id: (.derp_region_id // null)
              }
            else null
            end
        ),
        peer_relay: (
          .peer_relay
          | if type == "object" then
              {
                state,
                derp_disco_received,
                notifications_opened,
                notifications_unknown_peer,
                notifications_received,
                notification_actions,
                notification_no_actions,
                relay_disco_sent,
                relay_disco_send_failures,
                relay_disco_received,
                relay_drops,
                relay_unmatched,
                relay_wg_sent,
                relay_wg_received
              }
            else null
            end
        )
      }
    ' "$doctor_json" >"$output"; then
    rm -f "$output"
    log "tailnet doctor client diagnostics unavailable: invalid report"
    return 1
  fi
  log "tailnet doctor client diagnostics captured in $output"
}

capture_tailnet_doctor_failure_diagnostics() {
  local marker="workspace daemon UDP peer relay allocation diagnostic"
  local output="$TMPDIR_SMOKE/daemon-tailnet-allocator-doctor-failure.log"
  local raw_output="$TMPDIR_SMOKE/daemon-tailnet-allocator-doctor-failure.jsonl"
  local kubectl_error="$TMPDIR_SMOKE/daemon-tailnet-allocator-doctor-failure.err"
  local -a pipeline_status

  [[ "$SMOKE_SKIP_KUBE" != "1" ]] || {
    log "Kubernetes allocator diagnostics disabled for application-only smoke"
    return 0
  }

  if [[ -z "$POD_NAME" ]]; then
    { [[ -n "$CLAIM_NAME" ]] || claim_exists; } && pod_exists_for_claim || true
  fi
  if [[ -z "$POD_NAME" ]]; then
    log "tailnet doctor failure allocator diagnostics unavailable: workspace pod not found"
    return 0
  fi

  set +e
  kubectl_dev -n "$SANDBOX_NAMESPACE" logs "$POD_NAME" -c workspace --tail=400 2>"$kubectl_error" \
    | jq -Rc --arg marker "$marker" '
        fromjson?
        | select(.fields.message == $marker)
        | select(.fields.outcome | IN(
            "started",
            "queued",
            "retry_scheduled",
            "answer_retry_deferred"
          ))
        | select(.fields.path == "peer_relay")
        | select([
            .fields.peer_count,
            .fields.queued_count,
            .fields.in_flight_count,
            .fields.attempt_count,
            .fields.failure_count
          ] | all(type == "number" and . >= 0 and floor == .))
      ' >"$raw_output"
  pipeline_status=("${PIPESTATUS[@]}")
  set -e

  if (( pipeline_status[0] != 0 )); then
    log "tailnet doctor failure allocator diagnostics unavailable: workspace daemon log read failed"
    return 0
  fi
  if (( pipeline_status[1] != 0 )) || [[ ! -s "$raw_output" ]]; then
    log "tailnet doctor failure allocator diagnostics found no value-blind events"
    return 0
  fi

  jq -r '
      .fields
      | "outcome=\(.outcome) path=\(.path) peer_count=\(.peer_count) queued_count=\(.queued_count) in_flight_count=\(.in_flight_count) attempt_count=\(.attempt_count) failure_count=\(.failure_count)"
    ' "$raw_output" >"$output"
  if [[ -n "$SMOKE_ARTIFACT_DIR" ]]; then
    mkdir -p "$SMOKE_ARTIFACT_DIR"
    cp "$raw_output" "$output" "$SMOKE_ARTIFACT_DIR/"
  fi
  sed 's/[[:cntrl:]]//g' "$output" >&2 || true
  log "tailnet doctor failure allocator diagnostics captured in $raw_output and $output"
}

assert_tailnet_doctor_endpoint_evidence() {
  local doctor_json="$1"

  if expect_tailnet_direct_udp; then
    assert_tailnet_doctor_direct_udp_evidence "$doctor_json"
    return
  fi
  if expect_tailnet_peer_relay; then
    assert_tailnet_doctor_peer_relay_evidence "$doctor_json"
    return
  fi
  [[ -z "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" || "$EXPECTED_TAILNET_PATH_TRANSPORT" == "any" ]] || \
    die "unsupported EXPECTED_TAILNET_PATH_TRANSPORT=$EXPECTED_TAILNET_PATH_TRANSPORT"
}

assert_tailnet_doctor_direct_udp_evidence() {
  local doctor_json="$1"

  jq -e \
    --arg ip "$EXPECTED_TAILNET_DIRECT_UDP_LB_IP" \
    --arg stun_host "$EXPECTED_STUN_HOST" \
    --argjson stun_port "$EXPECTED_STUN_PORT" \
    '
      (
        (.direct.direct_path.transport == "direct_udp" and .direct.direct_path.ready == true and ((.direct.direct_path.endpoint // "") | contains($ip)))
        or
        (.direct.final_path.transport == "direct_udp" and .direct.final_path.ready == true and ((.direct.final_path.endpoint // "") | contains($ip)))
      )
      and (
        if $stun_host == "" then
          (
            ([.direct.derp_map.regions[]?.nodes[]? | select(.stun_only == true)] | length) >= 1
            or ((.direct.derp_map.stun_nodes // 0) >= 1)
          )
        else
          (
            ([.direct.derp_map.regions[]?.nodes[]? | select(.stun_only == true and .host_name == $stun_host and .stun_port == $stun_port)] | length) >= 1
            or ((.direct.derp_map.stun_nodes // 0) >= 1)
          )
        end
      )
    ' "$doctor_json" >/dev/null || \
    die "tailnet doctor did not prove direct_udp via Cilium LoadBalancer IP $EXPECTED_TAILNET_DIRECT_UDP_LB_IP with STUN $EXPECTED_STUN_HOST:$EXPECTED_STUN_PORT"

  [[ "$SMOKE_DERP_FALLBACK" != "1" ]] || assert_tailnet_doctor_forced_derp_evidence "$doctor_json"

  log "tailnet doctor proved direct_udp via Cilium LoadBalancer IP $EXPECTED_TAILNET_DIRECT_UDP_LB_IP and STUN map $EXPECTED_STUN_HOST:$EXPECTED_STUN_PORT"
}

assert_tailnet_doctor_forced_derp_evidence() {
  local doctor_json="$1"

  [[ -s "$doctor_json" ]] || die "tailnet doctor evidence missing for forced DERP fallback: $doctor_json"
  jq -e '
    (
      (.forced_derp.final_path.transport == "derp" or .forced_derp.final_path.transport == "derp_relay")
      and .forced_derp.final_path.ready == true
    )
    or (
      (.forced_derp.direct_path.transport == "derp" or .forced_derp.direct_path.transport == "derp_relay")
      and .forced_derp.direct_path.ready == true
    )
  ' "$doctor_json" >/dev/null || \
    die "tailnet doctor did not prove ready forced DERP fallback"
}

assert_tailnet_doctor_peer_relay_evidence() {
  local doctor_json="$1"

  jq -e \
    --arg endpoint "$EXPECTED_TAILNET_PEER_RELAY_ENDPOINT" \
    --arg stun_host "$EXPECTED_STUN_HOST" \
    --argjson stun_port "$EXPECTED_STUN_PORT" \
    '
      (
        ((.direct.direct_path.transport == "udp_relay" or .direct.direct_path.transport == "peer_relay") and ((.direct.direct_path.peer_relay // .direct.direct_path.endpoint // "") | contains($endpoint)))
        or
        ((.direct.final_path.transport == "udp_relay" or .direct.final_path.transport == "peer_relay") and ((.direct.final_path.peer_relay // .direct.final_path.endpoint // "") | contains($endpoint)))
      )
      and (
        if $stun_host == "" then
          (
            ([.direct.derp_map.regions[]?.nodes[]? | select(.stun_only == true)] | length) >= 1
            or ((.direct.derp_map.stun_nodes // 0) >= 1)
          )
        else
          (
            ([.direct.derp_map.regions[]?.nodes[]? | select(.stun_only == true and .host_name == $stun_host and .stun_port == $stun_port)] | length) >= 1
            or ((.direct.derp_map.stun_nodes // 0) >= 1)
          )
        end
      )
    ' "$doctor_json" >/dev/null || \
    die "tailnet doctor did not prove peer_relay via shared endpoint $EXPECTED_TAILNET_PEER_RELAY_ENDPOINT with STUN $EXPECTED_STUN_HOST:$EXPECTED_STUN_PORT"

  [[ "$SMOKE_DERP_FALLBACK" != "1" ]] || assert_tailnet_doctor_forced_derp_evidence "$doctor_json"

  log "tailnet doctor proved peer_relay via shared relay endpoint $EXPECTED_TAILNET_PEER_RELAY_ENDPOINT and STUN map $EXPECTED_STUN_HOST:$EXPECTED_STUN_PORT"
}

select_kube_context_best_effort() {
  local contexts current_context candidate

  [[ -n "$KUBE_CONTEXT" ]] && return 0
  contexts="$(kubectl config get-contexts -o name 2>/dev/null || true)"
  for candidate in codewire-dev default; do
    if grep -Fxq "$candidate" <<<"$contexts"; then
      KUBE_CONTEXT="$candidate"
      export KUBE_CONTEXT
      return 0
    fi
  done
  current_context="$(kubectl config current-context 2>/dev/null || true)"
  if [[ -n "$current_context" ]]; then
    KUBE_CONTEXT="$current_context"
    export KUBE_CONTEXT
  fi
}

stage_kubernetes_failure_diagnostics() {
  local source_dir="$1"
  local label="$2"
  local bundle_dir manifest_file shadow_source="" candidate manifest_entries
  local file file_name byte_count

  [[ -n "$SMOKE_ARTIFACT_DIR" ]] || return 0
  bundle_dir="$SMOKE_ARTIFACT_DIR/kubernetes-failure"
  manifest_file="$SMOKE_ARTIFACT_DIR/kubernetes-failure-manifest.json"
  mkdir -p "$bundle_dir"

  if [[ -s "$source_dir/sandboxclaims.json" ]] \
      && jq -e 'type == "object" and (.items | type == "array")' \
        "$source_dir/sandboxclaims.json" >/dev/null 2>&1; then
    jq '
      def safe_token:
        if type == "string"
            and length > 0
            and length <= 316
            and test("^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
        then . else null end;
      {
        schema: "codewire-kubernetes-claim-diagnostic-v1",
        read_state: "available",
        count: (.items | length),
        claims: [
          .items[]?
          | {
              name: (.metadata.name | safe_token),
              generation: (
                .metadata.generation
                | if type == "number" and . >= 0 then . else null end
              ),
              deleting: (.metadata.deletionTimestamp != null),
              claim_shadow: (.spec.warmPoolRef.name | safe_token),
              template: (.spec.sandboxTemplateRef.name | safe_token),
              sandbox_assigned: (
                (.status.sandbox.name | safe_token) != null
              ),
              conditions: [
                .status.conditions[]?
                | {
                    type: (.type | safe_token),
                    status: (
                      .status
                      | if . == "True" or . == "False" or . == "Unknown"
                        then . else null end
                    ),
                    reason: (.reason | safe_token),
                    observed_generation: (
                      .observedGeneration
                      | if type == "number" and . >= 0 then . else null end
                    )
                  }
                  | with_entries(select(.value != null))
              ]
            }
            | with_entries(select(.value != null))
        ]
      }
    ' "$source_dir/sandboxclaims.json" >"$bundle_dir/claim.json"
  else
    jq -n '{
      schema: "codewire-kubernetes-claim-diagnostic-v1",
      read_state: "unavailable",
      count: 0,
      claims: []
    }' >"$bundle_dir/claim.json"
  fi

  for candidate in "$source_dir"/sandboxwarmpool-*.json; do
    [[ -f "$candidate" ]] || continue
    shadow_source="$candidate"
    break
  done
  if [[ -n "$shadow_source" && -s "$shadow_source" ]] \
      && jq -e 'type == "object"' "$shadow_source" >/dev/null 2>&1; then
    jq '
      def safe_token:
        if type == "string"
            and length > 0
            and length <= 316
            and test("^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
        then . else null end;
      def count_value:
        if type == "number" and . >= 0 and floor == . then . else null end;
      {
        schema: "codewire-kubernetes-claim-shadow-diagnostic-v1",
        read_state: "available",
        name: (.metadata.name | safe_token),
        generation: (.metadata.generation | count_value),
        template: (.spec.sandboxTemplateRef.name | safe_token),
        desired_replicas: (.spec.replicas | count_value),
        current_replicas: (.status.replicas | count_value),
        ready_replicas: (.status.readyReplicas | count_value)
      }
      | with_entries(select(.value != null))
    ' "$shadow_source" >"$bundle_dir/claim-shadow.json"
  else
    jq -n '{
      schema: "codewire-kubernetes-claim-shadow-diagnostic-v1",
      read_state: "unavailable"
    }' >"$bundle_dir/claim-shadow.json"
  fi

  if [[ -s "$source_dir/pods.json" ]] \
      && jq -e 'type == "object" and (.items | type == "array")' \
        "$source_dir/pods.json" >/dev/null 2>&1; then
    jq '
      def safe_token:
        if type == "string"
            and length > 0
            and length <= 316
            and test("^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
        then . else null end;
      def count_value:
        if type == "number" and . >= 0 and floor == . then . else null end;
      def container_state:
        if .waiting != null then
          {
            state: "waiting",
            reason: (.waiting.reason | safe_token)
          }
        elif .terminated != null then
          {
            state: "terminated",
            reason: (.terminated.reason | safe_token),
            exit_code: (
              .terminated.exitCode
              | if type == "number" and floor == . then . else null end
            ),
            signal: (.terminated.signal | count_value)
          }
        elif .running != null then
          {state: "running"}
        else
          {state: "unknown"}
        end
        | with_entries(select(.value != null));
      {
        schema: "codewire-kubernetes-pod-diagnostic-v1",
        read_state: "available",
        count: (.items | length),
        pods: [
          .items[]?
          | {
              name: (.metadata.name | safe_token),
              phase: (.status.phase | safe_token),
              node_assigned: ((.spec.nodeName | safe_token) != null),
              runtime_class_configured: (
                (.spec.runtimeClassName | safe_token) != null
              ),
              conditions: [
                .status.conditions[]?
                | {
                    type: (.type | safe_token),
                    status: (
                      .status
                      | if . == "True" or . == "False" or . == "Unknown"
                        then . else null end
                    ),
                    reason: (.reason | safe_token)
                  }
                  | with_entries(select(.value != null))
              ],
              containers: [
                .status.containerStatuses[]?
                | {
                    name: (.name | safe_token),
                    ready: (.ready == true),
                    restart_count: (.restartCount | count_value),
                    image_resolved: (
                      .imageID | type == "string" and length > 0
                    ),
                    state: (.state | container_state)
                  }
                  | with_entries(select(.value != null))
              ]
            }
            | with_entries(select(.value != null))
        ]
      }
    ' "$source_dir/pods.json" >"$bundle_dir/pods.json"
  else
    jq -n '{
      schema: "codewire-kubernetes-pod-diagnostic-v1",
      read_state: "unavailable",
      count: 0,
      pods: []
    }' >"$bundle_dir/pods.json"
  fi

  if [[ -s "$source_dir/events.json" ]] \
      && jq -e 'type == "object" and (.items | type == "array")' \
        "$source_dir/events.json" >/dev/null 2>&1; then
    jq \
      --slurpfile claims "$bundle_dir/claim.json" \
      --slurpfile pods "$bundle_dir/pods.json" '
        def safe_token:
          if type == "string"
              and length > 0
              and length <= 316
              and test("^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
          then . else null end;
        def safe_timestamp:
          if type == "string"
              and length <= 64
              and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]+Z?$")
          then . else null end;
        def count_value:
          if type == "number" and . >= 0 and floor == . then . else null end;
        def message_class:
          ascii_downcase
          | if test("schedul|insufficient|affinity|taint") then "scheduling"
            elif test("image.*pull|pull.*image|registry") then "image_pull"
            elif test("sandbox|runtimeclass|runtime") then "runtime"
            elif test("volume|mount|persistentvolume|pvc") then "storage"
            else "other"
            end;
        (
          (($claims[0].claims // []) | map(.name))
          + (($pods[0].pods // []) | map(.name))
          | map(select(type == "string"))
        ) as $object_names
        | {
            schema: "codewire-kubernetes-event-diagnostic-v1",
            read_state: "available",
            events: [
              .items[]?
              | select(
                  .involvedObject.name as $name
                  | $object_names
                  | index($name)
                )
              | {
                  object_kind: (.involvedObject.kind | safe_token),
                  object_name: (.involvedObject.name | safe_token),
                  type: (.type | safe_token),
                  reason: (.reason | safe_token),
                  reporting_controller: (
                    (.reportingController // .source.component) | safe_token
                  ),
                  count: (.count | count_value),
                  first_timestamp: (
                    (.firstTimestamp // .eventTime) | safe_timestamp
                  ),
                  last_timestamp: (
                    (.lastTimestamp // .eventTime) | safe_timestamp
                  ),
                  message_class: (
                    ((.reason // "") + " " + (.message // ""))
                    | message_class
                  )
                }
                | with_entries(select(.value != null))
            ]
          }
      ' "$source_dir/events.json" >"$bundle_dir/events.json"
  else
    jq -n '{
      schema: "codewire-kubernetes-event-diagnostic-v1",
      read_state: "unavailable",
      events: []
    }' >"$bundle_dir/events.json"
  fi

  manifest_entries="$({
    for file in "$bundle_dir"/*.json; do
      file_name="$(basename "$file")"
      byte_count="$(wc -c <"$file" | tr -d '[:space:]')"
      jq -n \
        --arg path "kubernetes-failure/$file_name" \
        --argjson bytes "$byte_count" \
        '{path: $path, bytes: $bytes}'
    done
  } | jq -s 'sort_by(.path)')"
  jq -n \
    --arg failure_label "$label" \
    --argjson files "$manifest_entries" \
    '{
      schema: "codewire-kubernetes-failure-manifest-v1",
      failure_label: $failure_label,
      data_contract: "allowlisted-structured-fields-only",
      files: $files
    }' >"$manifest_file"
  log "staged value-blind Kubernetes failure diagnostics in $bundle_dir"
}

collect_failure_diagnostics() {
  local label="$1"
  local dir pods_json pod container containers claim_json claim_shadow_name template_name

  [[ "$SMOKE_COLLECT_FAILURE_DIAGNOSTICS" == "1" ]] || return 0
  [[ "$SMOKE_SKIP_KUBE" != "1" ]] || return 0
  [[ "$SMOKE_FAILURE_DIAGNOSTICS_CAPTURED" != "1" ]] || return 0
  [[ -n "$ENV_ID" && -n "$TMPDIR_SMOKE" && -d "$TMPDIR_SMOKE" ]] || return 0
  command -v kubectl >/dev/null 2>&1 || return 0
  command -v jq >/dev/null 2>&1 || return 0

  maybe_default_kubeconfig
  select_kube_context_best_effort
  kubectl_dev version --client >/dev/null 2>&1 || return 0

  SMOKE_FAILURE_DIAGNOSTICS_CAPTURED=1
  dir="$TMPDIR_SMOKE/kube-diagnostics-$label"
  mkdir -p "$dir"
  log "capturing Kubernetes failure diagnostics in $dir"

  kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxclaim \
    -l "codewire.sh/environment-id=$ENV_ID" -o json \
    >"$dir/sandboxclaims.json" 2>"$dir/sandboxclaims.err" || true
  CLAIM_NAME="${CLAIM_NAME:-$(jq -r '.items[0].metadata.name // empty' "$dir/sandboxclaims.json" 2>/dev/null || true)}"
  if [[ -n "$CLAIM_NAME" ]]; then
    claim_json="$dir/sandboxclaim-$CLAIM_NAME.json"
    kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxclaim "$CLAIM_NAME" -o json \
      >"$claim_json" 2>"$dir/sandboxclaim-$CLAIM_NAME.err" || true
    claim_shadow_name="$(jq -r '.spec.warmPoolRef.name // empty' "$claim_json" 2>/dev/null || true)"
    template_name="$(jq -r '.spec.sandboxTemplateRef.name // empty' "$claim_json" 2>/dev/null || true)"
    if [[ -n "$claim_shadow_name" ]]; then
      kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxwarmpool "$claim_shadow_name" -o json \
        >"$dir/sandboxwarmpool-$claim_shadow_name.json" 2>"$dir/sandboxwarmpool-$claim_shadow_name.err" || true
      template_name="$(jq -r '.spec.sandboxTemplateRef.name // empty' "$dir/sandboxwarmpool-$claim_shadow_name.json" 2>/dev/null || true)"
    fi
    if [[ -n "$template_name" ]]; then
      kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxtemplate "$template_name" -o json \
        >"$dir/sandboxtemplate-$template_name.json" 2>"$dir/sandboxtemplate-$template_name.err" || true
    fi
  fi

  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod \
    -l "codewire.sh/environment-id=$ENV_ID" -o wide \
    >"$dir/pods-wide.txt" 2>"$dir/pods-wide.err" || true
  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod \
    -l "codewire.sh/environment-id=$ENV_ID" -o json \
    >"$dir/pods.json" 2>"$dir/pods.err" || true
  kubectl_dev -n "$SANDBOX_NAMESPACE" describe pod \
    -l "codewire.sh/environment-id=$ENV_ID" \
    >"$dir/pods-describe.txt" 2>"$dir/pods-describe.err" || true
  kubectl_dev -n "$SANDBOX_NAMESPACE" get events --sort-by=.lastTimestamp \
    >"$dir/events.txt" 2>"$dir/events.err" || true
  kubectl_dev -n "$SANDBOX_NAMESPACE" get events --sort-by=.lastTimestamp -o json \
    >"$dir/events.json" 2>"$dir/events-json.err" || true

  pods_json="$dir/pods.json"
  if [[ -s "$pods_json" ]]; then
    while IFS= read -r pod; do
      [[ -n "$pod" ]] || continue
      containers="$(jq -r --arg pod "$pod" '.items[] | select(.metadata.name == $pod) | .spec.containers[].name' "$pods_json" 2>/dev/null || true)"
      while IFS= read -r container; do
        [[ -n "$container" ]] || continue
        kubectl_dev -n "$SANDBOX_NAMESPACE" logs "$pod" -c "$container" --tail=200 \
          >"$dir/log-$pod-$container.txt" 2>"$dir/log-$pod-$container.err" || true
        kubectl_dev -n "$SANDBOX_NAMESPACE" logs "$pod" -c "$container" --previous --tail=200 \
          >"$dir/log-$pod-$container-previous.txt" 2>"$dir/log-$pod-$container-previous.err" || true
      done <<<"$containers"
    done < <(jq -r '.items[].metadata.name // empty' "$pods_json" 2>/dev/null || true)
  fi

  stage_kubernetes_failure_diagnostics "$dir" "$label"
}

capture_container_log() {
  local pod="$1"
  local container="$2"
  local output="$3"
  local err="${output}.err"

  [[ -n "$pod" ]] || return 1
  kubectl_dev -n "$SANDBOX_NAMESPACE" logs "$pod" -c "$container" >"$output" 2>"$err"
}

capture_ssh_failure_evidence() {
  local label="$1"
  local logs

  [[ "$SMOKE_SKIP_KUBE" != "1" ]] || {
    log "Kubernetes SSH-failure diagnostics disabled for application-only smoke"
    return 0
  }

  logs="$TMPDIR_SMOKE/workspace-${label}-after-fail.log"
  if capture_container_log "$POD_NAME" workspace "$logs"; then
    log "captured workspace SSH-failure logs in $logs"
  else
    log "failed to capture workspace SSH-failure logs; stderr in ${logs}.err"
  fi

  logs="$TMPDIR_SMOKE/dind-${label}-after-fail.log"
  if capture_container_log "$POD_NAME" dind "$logs"; then
    log "captured dind SSH-failure logs in $logs"
  else
    log "failed to capture dind SSH-failure logs; stderr in ${logs}.err"
  fi

  kubectl_dev -n "$SANDBOX_NAMESPACE" get events --sort-by=.lastTimestamp \
    >"$TMPDIR_SMOKE/events-${label}-after-fail.txt" 2>"$TMPDIR_SMOKE/events-${label}-after-fail.err" || true
}

assert_daemon_tailnet_log_evidence() {
  local logs="$TMPDIR_SMOKE/daemon-tailnet.log"

  capture_container_log "$POD_NAME" workspace "$logs"

  grep -q 'rust tailnet direct UDP socket bound' "$logs" || \
    die "workspace daemon logs do not show direct UDP socket bind; evidence in $logs"
  grep -q 'rust tailnet startup STUN discovery complete' "$logs" || \
    die "workspace daemon logs do not show startup STUN discovery; evidence in $logs"
  grep -q 'workspace tailnet direct UDP enabled' "$logs" || \
    die "workspace daemon logs do not show direct UDP transport enabled; evidence in $logs"
  grep -q 'workspace tailnet peer up' "$logs" || \
    die "workspace daemon logs do not show its tailnet peer up; evidence in $logs"

  log "workspace daemon logs prove STUN discovery, direct UDP and its tailnet peer; evidence in $logs"
}

run_ssh_transport_smoke() {
  local transport="$1"
  local label="${2:-$transport}"
  local expected_transport="${3:-$EXPECTED_TAILNET_PATH_TRANSPORT}"
  local force_derp="${4:-0}"
  local known_hosts="$TMPDIR_SMOKE/known_hosts.$label"
  local stdout="$TMPDIR_SMOKE/ssh-$label.out"
  local stderr="$TMPDIR_SMOKE/ssh-$label.err"
  local expected_output="${label}-ssh-ok"
  local debug_tailnet=0
  local -a env_args

  if [[ "$transport" == "tailnet" && "$SMOKE_TAILNET_DEBUG" == "1" ]]; then
    debug_tailnet=1
  fi

  env_args=(
    CW_SSH_TRANSPORT="$transport"
    CW_TAILNET_DIRECT_WAIT="$SMOKE_TAILNET_DIRECT_WAIT"
    CW_TAILNET_PEER_TIMEOUT="$SMOKE_TAILNET_PEER_TIMEOUT"
    CW_TAILNET_DIAL_TIMEOUT="$SMOKE_TAILNET_DIAL_TIMEOUT"
  )
  if [[ "$transport" == "tailnet" && "$force_derp" != "1" && -n "$expected_transport" && "$expected_transport" != "any" ]]; then
    env_args+=(CW_TAILNET_EXPECTED_TRANSPORT="$expected_transport")
  fi
  if [[ "$transport" == "tailnet" && "$force_derp" != "1" && ( "$expected_transport" == "peer_relay" || "$expected_transport" == "udp_relay" ) ]]; then
    env_args+=(CW_TAILNET_SUPPRESS_PEER_DIRECT_UDP=1)
  fi
  if [[ "$debug_tailnet" == "1" ]]; then
    env_args+=(CW_DEBUG_TAILNET=1)
  fi
  if [[ "$force_derp" == "1" ]]; then
    env_args+=(CW_DERP_ONLY=1 TS_DEBUG_NEVER_DIRECT_UDP=1)
  fi

  if [[ "$force_derp" == "1" ]]; then
    log "running SSH smoke over $transport with forced DERP relay"
  elif [[ "$label" != "$transport" ]]; then
    log "running SSH smoke over $transport ($label)"
  else
    log "running SSH smoke over $transport"
  fi

  if ! env "${env_args[@]}" timeout "$SMOKE_SSH_TIMEOUT" ssh -F /dev/null \
      -o BatchMode=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile="$known_hosts" \
      -o "LogLevel=$SMOKE_SSH_LOG_LEVEL" \
      -o ConnectTimeout="$SMOKE_SSH_CONNECT_TIMEOUT" \
      -o "ProxyCommand=$CW_BIN --server $CODEWIRE_SERVER_URL shell --stdio %h" \
      "codewire@cw-$ENV_ID" \
      "printf '${expected_output}\n'" >"$stdout" 2>"$stderr"; then
    sed 's/[[:cntrl:]]//g' "$stderr" >&2 || true
    capture_ssh_failure_evidence "$label"
    die "$label SSH smoke failed"
  fi

  grep -qx "$expected_output" "$stdout" || die "$label SSH smoke returned unexpected output"
  if [[ "$transport" == "tailnet" && "$debug_tailnet" == "1" ]]; then
    if [[ "$force_derp" == "1" ]] && ! grep -q 'path probe transport=' "$stderr"; then
      assert_tailnet_doctor_forced_derp_evidence "$TMPDIR_SMOKE/tailnet-doctor.json"
      log "forced DERP SSH completed; tailnet doctor evidence covers forced DERP path"
    else
      assert_tailnet_path_probe "$stderr" "$expected_transport"
    fi
  fi
}

# OpenSSH over the WebSocket transport with the managed block's trust:
# StrictHostKeyChecking yes and no first use. With no pinned file, the only
# trust source is `cw ssh known-hosts`, the key the environment's bound Pod
# recorded with the platform.
# The block `cw setup ssh` writes, exactly as a user gets it. Its commands
# carry no server: they find it through CODEWIRE_SERVER_URL, which every
# user-path ssh below exports.
user_ssh_config() {
  local config="$TMPDIR_SMOKE/ssh_config"
  if [[ ! -s "$config" ]]; then
    "$CW_BIN" --server "$CODEWIRE_SERVER_URL" setup ssh --ssh-config-file "$config" >/dev/null ||
      die "cw setup ssh could not write the managed SSH block"
  fi
  printf '%s\n' "$config"
}

# OpenSSH as a user runs it, through the managed block: its ProxyCommand and
# its only host-key trust, `cw ssh known-hosts`.
user_ssh() {
  local config
  config="$(user_ssh_config)" || return
  env CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" CW_SSH_TRANSPORT=websocket \
    timeout "$SMOKE_SSH_TIMEOUT" ssh -F "$config" \
    -o BatchMode=yes \
    -o "LogLevel=$SMOKE_SSH_LOG_LEVEL" \
    -o ConnectTimeout="$SMOKE_SSH_CONNECT_TIMEOUT" \
    "cw-$ENV_ID" "$@"
}

user_scp() {
  local config
  config="$(user_ssh_config)" || return
  env CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" CW_SSH_TRANSPORT=websocket \
    timeout "$SMOKE_SSH_TIMEOUT" scp -F "$config" \
    -o BatchMode=yes \
    -o "LogLevel=$SMOKE_SSH_LOG_LEVEL" \
    -o ConnectTimeout="$SMOKE_SSH_CONNECT_TIMEOUT" \
    "$@"
}

run_host_key_probe_once() {
  local label="$1"
  local pinned="${2:-}"
  local stdout="$TMPDIR_SMOKE/ssh-host-key-${label}.out"
  local stderr="$TMPDIR_SMOKE/ssh-host-key-${label}.err"
  local expected_output="host-key-${label}-ok"
  local cw_command

  if [[ -z "$pinned" ]]; then
    user_ssh "printf '${expected_output}\n'" >"$stdout" 2>"$stderr" </dev/null || return 1
    grep -qx "$expected_output" "$stdout"
    return
  fi
  # A pinned known_hosts file in place of the block's KnownHostsCommand.
  cw_command="$(printf '%q --server %q' "$CW_BIN" "$CODEWIRE_SERVER_URL")"
  if ! env CW_SSH_TRANSPORT=websocket timeout "$SMOKE_SSH_TIMEOUT" ssh -F /dev/null \
      -o BatchMode=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=yes \
      -o GlobalKnownHostsFile=/dev/null \
      -o UpdateHostKeys=no \
      -o "UserKnownHostsFile=$pinned" \
      -o "LogLevel=$SMOKE_SSH_LOG_LEVEL" \
      -o ConnectTimeout="$SMOKE_SSH_CONNECT_TIMEOUT" \
      -o "ProxyCommand=$cw_command shell --stdio %h" \
      "codewire@cw-$ENV_ID" \
      "printf '${expected_output}\n'" >"$stdout" 2>"$stderr" </dev/null; then
    return 1
  fi

  grep -qx "$expected_output" "$stdout"
}

# What a user does over the managed block once it trusts the recorded key: a
# command line the workspace shell parses, with its exit status, and an
# SFTP-mode scp round trip in the home directory.
run_user_ssh_journey() {
  local output status up down
  require_cmd scp
  status=0
  output="$(user_ssh 'printf a && printf b | tr b B; exit 7' 2>"$TMPDIR_SMOKE/ssh-journey.err" </dev/null)" ||
    status=$?
  [[ "$output" == "aB" && "$status" -eq 7 ]] || {
    sed 's/[[:cntrl:]]//g' "$TMPDIR_SMOKE/ssh-journey.err" >&2 || true
    die "ssh did not run a shell command line: output '$output', exit $status (want 'aB', 7)"
  }
  up="$TMPDIR_SMOKE/scp-up.txt"
  down="$TMPDIR_SMOKE/scp-down.txt"
  printf 'smoke-scp-%s\n' "$ENV_ID" >"$up"
  user_scp "$up" "cw-$ENV_ID:smoke-scp.txt" </dev/null || die "scp (SFTP mode) upload to the home directory failed"
  user_scp "cw-$ENV_ID:smoke-scp.txt" "$down" </dev/null || die "scp (SFTP mode) download from the home directory failed"
  cmp -s "$up" "$down" || die "scp (SFTP mode) round trip changed the file"
  log "user SSH: shell command lines keep their exit status; SFTP-mode scp round-trips"
}

# The recorded key must be served: retry only until the daemon answers.
wait_for_host_key_probe() {
  local label="$1"
  local pinned="${2:-}"
  local deadline stderr

  deadline=$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))
  stderr="$TMPDIR_SMOKE/ssh-host-key-${label}.err"
  while (( "$(seconds_now)" < deadline )); do
    if run_host_key_probe_once "$label" "$pinned"; then
      return
    fi
    if grep -Eq 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed' "$stderr"; then
      break
    fi
    sleep 5
  done

  sed 's/[[:cntrl:]]//g' "$stderr" >&2 || true
  capture_ssh_failure_evidence "host-key-${label}"
  die "host-key $label SSH probe failed"
}

# A key other than the recorded one must be refused as a changed host key,
# never trusted or merely unreachable.
expect_host_key_refused() {
  local label="$1"
  local pinned="$2"
  local stderr="$TMPDIR_SMOKE/ssh-host-key-${label}.err"

  if run_host_key_probe_once "$label" "$pinned"; then
    die "host-key $label SSH probe trusted a key the platform did not record"
  fi
  grep -Eq 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed' "$stderr" || {
    sed 's/[[:cntrl:]]//g' "$stderr" >&2 || true
    die "host-key $label SSH probe failed without a host-key refusal"
  }
}

# One known_hosts line: the key the environment's bound Pod recorded with the
# platform (a public key; nothing secret).
recorded_host_key_line() {
  timeout 60 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" ssh known-hosts "cw-$ENV_ID" 2>/dev/null
}

env_is_stopped() {
  local info_out="$TMPDIR_SMOKE/env-info-stop.out"
  cw info "$ENV_ID" >"$info_out" 2>&1 || return 1
  [[ "$(awk '$1 == "State:" {print $2; exit}' "$info_out")" == "stopped" ]]
}

# The daemon serves SSH with a host key it generated for its Pod; only its
# public key is recorded with the platform (#2460), and only the bound Pod's
# key is served. Prove the served key is the recorded one, a changed key is
# refused, and a stop and start, which replaces the Pod, rotates the key.
run_host_key_smoke() {
  local before after pinned previous_pin forged

  require_cmd ssh-keygen
  before="$(recorded_host_key_line)" || die "cw ssh known-hosts returned no recorded host key for cw-$ENV_ID"
  [[ "$before" =~ ^cw-$ENV_ID\ ssh-ed25519\ [A-Za-z0-9+/]+=*$ ]] || \
    die "recorded host key for cw-$ENV_ID is not one OpenSSH Ed25519 known_hosts line"

  log "verifying the daemon presents the host key the platform recorded"
  wait_for_host_key_probe recorded
  run_user_ssh_journey
  pinned="$TMPDIR_SMOKE/known_hosts.recorded"
  printf '%s\n' "$before" >"$pinned"
  wait_for_host_key_probe pinned "$pinned"

  forged="$TMPDIR_SMOKE/forged-host-key"
  ssh-keygen -q -t ed25519 -N '' -C '' -f "$forged" >/dev/null
  printf 'cw-%s %s\n' "$ENV_ID" "$(awk '{print $1, $2}' "$forged.pub")" >"$TMPDIR_SMOKE/known_hosts.forged"
  expect_host_key_refused forged "$TMPDIR_SMOKE/known_hosts.forged"
  log "a host key other than the recorded one is refused"

  if [[ -n "$SMOKE_EXISTING_ENV_ID" ]]; then
    log "host-key rotation needs a stop and start; skipped for the reused environment $ENV_ID"
    return
  fi
  log "stopping and starting $ENV_ID to prove the host key rotates with the Pod"
  cw stop "$ENV_ID" >/dev/null
  wait_until "environment stopped" "$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))" env_is_stopped
  cw start "$ENV_ID" >/dev/null
  wait_environment
  POD_NAME=""
  if [[ "$SMOKE_SKIP_KUBE" != "1" ]]; then
    discover_runtime_objects
  fi
  after="$(recorded_host_key_line)" || die "cw ssh known-hosts returned no host key after the restart"
  [[ "$after" != "$before" ]] || die "the recorded host key did not rotate across stop and start"
  wait_for_host_key_probe rotated
  previous_pin="$TMPDIR_SMOKE/known_hosts.previous-generation"
  cp "$pinned" "$previous_pin"
  expect_host_key_refused previous-generation "$previous_pin"
  log "the host key rotated with the Pod; the previous Pod's key is refused"
}

run_ssh_smoke() {
  local initial_expected_transport

  [[ "$SMOKE_SKIP_SSH" != "1" ]] || {
    log "skipping SSH transport smoke"
    return
  }
  require_bool01 SMOKE_DERP_FALLBACK "$SMOKE_DERP_FALLBACK"
  require_bool01 SMOKE_PEER_RELAY_MATRIX "$SMOKE_PEER_RELAY_MATRIX"
  require_uint SMOKE_SSH_CONNECT_TIMEOUT "$SMOKE_SSH_CONNECT_TIMEOUT"
  run_tailnet_doctor
  require_cmd ssh
  run_ssh_transport_smoke tailnet
  if [[ "$SMOKE_DERP_FALLBACK" == "1" ]]; then
    run_ssh_transport_smoke tailnet tailnet-derp derp_relay 1
  fi
  run_ssh_transport_smoke websocket
  if [[ "$SMOKE_PEER_RELAY_MATRIX" == "1" ]]; then
    initial_expected_transport="$EXPECTED_TAILNET_PATH_TRANSPORT"
    EXPECTED_TAILNET_PATH_TRANSPORT=peer_relay
    log "running same-environment shared UDP peer-relay proof"
    run_tailnet_doctor
    run_ssh_transport_smoke tailnet tailnet-peer-relay peer_relay
    EXPECTED_TAILNET_PATH_TRANSPORT="$initial_expected_transport"
  fi
  run_host_key_smoke
}

run_selected_phase() {
  local phase="$1"

  case "$phase" in
    kube)
      run_kube_assertions
      ;;
    exec)
      wait_for_cw_run
      run_environment_session_smoke
      ;;
    application-secrets)
      run_application_secrets_smoke
      ;;
    application-secrets-all-scopes)
      run_application_secrets_smoke
      ;;
    provider-ssh)
      run_provider_ssh_smoke
      ;;
    coco)
      assert_coco_guest_test_resource
      ;;
    docker)
      wait_for_cw_run
      run_docker_smoke
      ;;
    doctor)
      run_tailnet_doctor
      ;;
    ssh)
      discover_runtime_objects
      run_ssh_smoke
      ;;
    tailnet-ssh)
      discover_runtime_objects
      require_cmd ssh
      run_ssh_transport_smoke tailnet
      ;;
    derp-ssh)
      discover_runtime_objects
      require_cmd ssh
      run_ssh_transport_smoke tailnet tailnet-derp derp_relay 1
      ;;
    websocket-ssh)
      discover_runtime_objects
      require_cmd ssh
      run_ssh_transport_smoke websocket
      ;;
    host-key)
      discover_runtime_objects
      assert_pod_shape
      require_cmd ssh
      run_host_key_smoke
      ;;
    app-preview)
      wait_for_cw_run
      run_app_preview_smoke
      ;;
    resize-guest)
      wait_for_cw_run
      run_resize_guest_smoke
      ;;
    *)
      die "unknown smoke phase: $phase"
      ;;
  esac
}

run_selected_phases() {
  local phase

  for phase in "${SMOKE_ONLY_PHASES[@]}"; do
    log "running selected smoke phase: $phase"
    run_selected_phase "$phase"
  done
}

resize_guest_requested() {
  local phase

  if smoke_only_configured; then
    for phase in "${SMOKE_ONLY_PHASES[@]}"; do
      [[ "$phase" != resize-guest ]] || return 0
    done
    return 1
  fi
  [[ "$SMOKE_RESIZE_GUEST" == "1" ]]
}

main() {
  require_bool01 SMOKE_RESIZE_GUEST "$SMOKE_RESIZE_GUEST"
  if resize_guest_requested && [[ -n "$SMOKE_EXISTING_ENV_ID" ]]; then
    die "resize-guest changes resources and may replace the workspace Pod; run it on a fresh disposable environment"
  fi
  validate_dev_smoke_browser_auth
  if [[ -n "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" ]]; then
    [[ ${#SMOKE_ONLY_PHASES[@]} == 1 ]] ||
      die 'browser automation supports only the all-scope or provider-SSH acceptance journey'
    if ! application_all_scopes_selected && ! provider_ssh_selected; then
      die 'browser automation supports only the all-scope or provider-SSH acceptance journey'
    fi
  fi
  if application_all_scopes_requested; then
    APP_SECRET_ALL_SCOPES=1
    SMOKE_SKIP_KUBE=1
    validate_application_all_scopes_options
  elif application_secrets_selected; then
    validate_application_secrets_options
  fi
  if provider_ssh_selected; then validate_provider_ssh_options; fi
  if [[ "$APP_SECRET_ALL_SCOPES" == 1 || -n "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" ]]; then
    prepare_fresh_oauth_cli
  else
    prepare_cli
  fi
  if application_secrets_selected; then prepare_application_secrets; fi
  if provider_ssh_selected; then prepare_provider_ssh; fi
  if [[ -n "$SMOKE_EXISTING_ENV_ID" ]]; then
    ENV_ID="$SMOKE_EXISTING_ENV_ID"
    SMOKE_KEEP_ENV=1
    log "using existing environment $ENV_ID"
  else
    create_environment
  fi
  record_environment_artifact
  if [[ -z "$SMOKE_EXISTING_ENV_ID" ]]; then
    wait_environment
  fi

  if smoke_only_configured; then
    run_selected_phases
  else
    run_kube_assertions
    wait_for_cw_run
    assert_coco_guest_test_resource
    run_docker_smoke
    if [[ "$SMOKE_APP_PREVIEW" == "1" ]]; then
      run_app_preview_smoke
    fi
    run_ssh_smoke
    if [[ "$SMOKE_RESIZE_GUEST" == "1" ]]; then
      run_resize_guest_smoke
    fi
  fi
  log "runtime smoke passed for $ENV_ID"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then trap cleanup EXIT; trap 'handle_signal INT' INT; trap 'handle_signal TERM' TERM; main "$@"; fi
