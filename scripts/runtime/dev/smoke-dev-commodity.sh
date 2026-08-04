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
SMOKE_TAILNET_DOCTOR_TIMEOUT="${SMOKE_TAILNET_DOCTOR_TIMEOUT:-$SMOKE_SSH_TIMEOUT}"
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
EXPECTED_GATEWAY_IMAGE="${EXPECTED_GATEWAY_IMAGE:-}"
EXPECTED_DIND_IMAGE="${EXPECTED_DIND_IMAGE:-}"
EXPECTED_NODE="${EXPECTED_NODE:-}"
EXPECTED_NODE_KATA_LABEL="${EXPECTED_NODE_KATA_LABEL:-katacontainers.io/kata-runtime}"
EXPECTED_NODE_KATA_VALUE="${EXPECTED_NODE_KATA_VALUE:-true}"
EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB="${EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB:-500}"
EXPECTED_GATEWAY_STUN_HOST="${EXPECTED_GATEWAY_STUN_HOST:-}"
EXPECTED_GATEWAY_STUN_PORT="${EXPECTED_GATEWAY_STUN_PORT:-3478}"
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
readonly CODEWIRE_DEV_SMOKE_ORG_SLUG="codewire-dev-smoke"
readonly CODEWIRE_DEV_SMOKE_API_KEY_NAME="runtime-dev-commodity-smoke"
ALLOW_NON_DEV="${ALLOW_NON_DEV:-0}"
ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE="${ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE:-0}"
CW_BIN="${CW_BIN:-}"

ENV_ID=""
TMPDIR_SMOKE=""
CLAIM_NAME=""
POD_NAME=""
GATEWAY_POD_NAME=""
GATEWAY_OLD_POD_NAME=""
SMOKE_LAST_WAIT_DETAIL=""
SMOKE_FAILURE_DIAGNOSTICS_CAPTURED=0
SMOKE_PACKET_CAPTURE_PID=""
SMOKE_PACKET_CAPTURE_RAW=""
SMOKE_PACKET_CAPTURE_ERROR=""
SMOKE_PACKET_CAPTURE_SUMMARY=""
SMOKE_PACKET_CAPTURE_STATUS=""
SMOKE_PACKET_CAPTURE_UNAVAILABLE=0
declare -a SMOKE_ONLY_PHASES=()

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
  --only PHASE             Run only one smoke phase; repeatable. Phases:
                           kube, exec, coco, docker, doctor, ssh,
                           tailnet-ssh, derp-ssh, websocket-ssh,
                           host-key, app-preview
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
                           Defaults to SMOKE_SSH_TIMEOUT; outer timeout for
                           cw doctor tailnet.
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
                           cw env port, fetches its preview URL, removes the
                           port, and verifies the preview no longer serves it
  SMOKE_APP_PREVIEW_PORT   Defaults to 8080
  SMOKE_APP_PREVIEW_LABEL  Defaults to app
  SMOKE_COLLECT_FAILURE_DIAGNOSTICS
                           Defaults to 1. On failure, captures Kubernetes
                           claim/template/pod/event/log evidence into the
                           smoke evidence directory before deleting the env.
  SMOKE_PACKET_DIAGNOSTICS
                           Defaults to 0. Set to 1 only for the admitted
                           host-network diagnostic. Captures route metadata and
                           UDP headers for the configured peer relay without payload.
  EXPECTED_GATEWAY_IMAGE   Optional exact image assertion for codewire-gateway
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
  EXPECTED_GATEWAY_STUN_HOST
                           Expected CODEWIRE_STUN_HOST on the gateway
  EXPECTED_GATEWAY_STUN_PORT
                           Expected CODEWIRE_STUN_PORT on the gateway
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
                           Required configured bind address expected on gateway
                           pods in peer_relay mode.
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
                           Optional; when set, workspace and gateway pods plus
                           the SandboxTemplate must carry CoCo kernel params
                           for guest registry auth via this KBS resource URI.
  EXPECTED_KATA_COCO_TEST_RESOURCE_URI
                           Optional; when set, the smoke fetches this
                           non-sensitive Trustee/KBS resource through the
                           guest CDH REST API after boot.
  EXPECTED_KATA_COCO_TEST_RESOURCE_PATH
                           Deprecated compatibility input; ignored by the
                           current CDH REST smoke path.
  EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT
                           Optional expected resource content. Defaults to
                           the dev KBS public marker when the URI is set.
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
    --only)
      [[ $# -ge 2 ]] || die "--only requires a phase"
      case "$2" in
        kube|exec|coco|docker|doctor|ssh|tailnet-ssh|derp-ssh|websocket-ssh|host-key|app-preview)
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
  if [[ -n "$ENV_ID" && "$SMOKE_KEEP_ENV" != "1" && -x "${CW_BIN:-}" ]]; then
    log "deleting smoke environment $ENV_ID"
    "$CW_BIN" --server "$CODEWIRE_SERVER_URL" env rm --yes "$ENV_ID" >/dev/null 2>&1 || true
  elif [[ -n "$ENV_ID" && "$SMOKE_KEEP_ENV" == "1" ]]; then
    log "kept smoke environment $ENV_ID"
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

trap cleanup EXIT
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

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
  "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"
}

cw_with_timeout() {
  local duration="$1"
  shift
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
  if [[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]]; then
    export CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"
  elif [[ "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == "1" && -n "${CODEWIRE_API_KEY:-}" ]]; then
    :
  else
    die "CODEWIRE_DEV_SMOKE_API_KEY is required; for local runs use scripts/runtime/dev/with-dev-smoke-auth.sh; set ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=1 only for manual debugging"
  fi

  require_cmd awk
  require_cmd sed
  require_cmd timeout

  mkdir -p "$SMOKE_TMP_PARENT"
  TMPDIR_SMOKE="$(mktemp -d "$SMOKE_TMP_PARENT/codewire-runtime-smoke.XXXXXX")"
  export CW_CONFIG_DIR="$TMPDIR_SMOKE/cw-config"
  mkdir -p "$CW_CONFIG_DIR"

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

assert_smoke_principal() {
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
  if ! cw env list --output json >"$environments_out" 2>"$environments_err"; then
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

create_environment() {
  local create_out="$TMPDIR_SMOKE/create.out"

  log "creating environment $SMOKE_NAME on $CODEWIRE_SERVER_URL"
  if ! cw env create \
      --image "$SMOKE_IMAGE" \
      --name "$SMOKE_NAME" \
      --cpu "$SMOKE_CPU" \
      --memory "$SMOKE_MEMORY" \
      --disk "$SMOKE_DISK" \
      --ttl "$SMOKE_TTL" \
      --no-org-secrets \
      --no-user-secrets \
      --no-network \
      --no-wait \
      --yes >"$create_out" 2>&1; then
    sed 's/[[:cntrl:]]//g' "$create_out" >&2 || true
    die "cw env create failed"
  fi

  ENV_ID="$(awk '/^[[:space:]]*ID:/ {print $2; exit}' "$create_out")"
  [[ -n "$ENV_ID" ]] || {
    sed 's/[[:cntrl:]]//g' "$create_out" >&2 || true
    die "failed to parse environment ID from cw env create output"
  }
  log "environment id $ENV_ID"
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

env_is_running() {
  local info_out="$TMPDIR_SMOKE/env-info.out"
  if ! cw env info "$ENV_ID" >"$info_out" 2>&1; then
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

gateway_pod_exists() {
  local pods_json="$TMPDIR_SMOKE/gateway-pods.json"
  local err="$TMPDIR_SMOKE/gateway-pods.err"

  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=gateway" \
    -o json >"$pods_json" 2>"$err" || {
      SMOKE_LAST_WAIT_DETAIL="$(sed 's/[[:cntrl:]]//g' "$err" | tail -n 1)"
      return 1
    }
  GATEWAY_POD_NAME="$(jq -r '.items[0].metadata.name // empty' "$pods_json")"
  if [[ -z "$GATEWAY_POD_NAME" ]]; then
    SMOKE_LAST_WAIT_DETAIL="no gateway pod found with codewire.sh/environment-id=$ENV_ID in namespace $SANDBOX_NAMESPACE"
    return 1
  fi
  return 0
}

gateway_restarted_pod_exists() {
  gateway_pod_exists || return 1
  if [[ -n "$GATEWAY_OLD_POD_NAME" && "$GATEWAY_POD_NAME" == "$GATEWAY_OLD_POD_NAME" ]]; then
    SMOKE_LAST_WAIT_DETAIL="gateway pod is still $GATEWAY_POD_NAME; waiting for restart"
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
  [[ "$kernel_params" == *"agent.guest_components_rest_api=resource"* ]] || \
    die "$label missing CoCo guest_components_rest_api=resource kernel param"
  if [[ -n "$EXPECTED_KATA_COCO_KBS_URL" ]]; then
    [[ "$kernel_params" == *"agent.aa_kbc_params=cc_kbc::$EXPECTED_KATA_COCO_KBS_URL"* ]] || \
      die "$label missing CoCo aa_kbc_params kernel param for $EXPECTED_KATA_COCO_KBS_URL"
  fi
}

assert_pod_shape() {
  local pod_json="$TMPDIR_SMOKE/pod.json"
  local gateway_pod_json="$TMPDIR_SMOKE/gateway-pod.json"
  local gateway_deploy_json="$TMPDIR_SMOKE/gateway-deployment.json"
  local runtime_class gateway_runtime_class node gateway_node node_label gateway_node_label
  local gateway_image gateway_status_image gateway_image_id containers gateway_containers
  local gateway_secret_names gateway_secret_count gateway_secret_resource gateway_secret_data_size
  local gateway_host_key_env

  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$POD_NAME" -o json >"$pod_json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$GATEWAY_POD_NAME" -o json >"$gateway_pod_json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get deploy \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=gateway" \
    -o json >"$gateway_deploy_json"
  gateway_secret_names="$(kubectl_dev -n "$SANDBOX_NAMESPACE" get secret \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=gateway-host-key" \
    -o name)"
  gateway_secret_count="$(printf '%s\n' "$gateway_secret_names" | sed '/^$/d' | wc -l | tr -d ' ')"
  gateway_secret_resource="$(printf '%s\n' "$gateway_secret_names" | sed -n '1p')"
  gateway_secret_data_size=0
  if [[ -n "$gateway_secret_resource" ]]; then
    gateway_secret_data_size="$(kubectl_dev -n "$SANDBOX_NAMESPACE" get "$gateway_secret_resource" \
      -o jsonpath='{.data.host_ed25519}' | wc -c | tr -d ' ')"
  fi
  runtime_class="$(jq -r '.spec.runtimeClassName // ""' "$pod_json")"
  gateway_runtime_class="$(jq -r '.spec.runtimeClassName // ""' "$gateway_pod_json")"
  node="$(jq -r '.spec.nodeName // ""' "$pod_json")"
  gateway_node="$(jq -r '.spec.nodeName // ""' "$gateway_pod_json")"
  gateway_image="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .image' "$gateway_pod_json")"
  gateway_status_image="$(jq -r '.status.containerStatuses[]? | select(.name=="codewire-gateway") | .image // ""' "$gateway_pod_json")"
  gateway_image_id="$(jq -r '.status.containerStatuses[]? | select(.name=="codewire-gateway") | .imageID // ""' "$gateway_pod_json")"
  dind_image="$(jq -r '.spec.containers[] | select(.name=="dind") | .image' "$pod_json")"
  dind_status_image="$(jq -r '.status.containerStatuses[]? | select(.name=="dind") | .image // ""' "$pod_json")"
  dind_image_id="$(jq -r '.status.containerStatuses[]? | select(.name=="dind") | .imageID // ""' "$pod_json")"
  containers="$(jq -r '[.spec.containers[].name] | sort | join(",")' "$pod_json")"
  gateway_containers="$(jq -r '[.spec.containers[].name] | sort | join(",")' "$gateway_pod_json")"
  gateway_host_key_env="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_SSH_HOST_KEY_PATH") | .value // ""' "$gateway_pod_json")"
  assert_pod_coco_kernel_params "$pod_json" "workspace pod"
  assert_pod_coco_kernel_params "$gateway_pod_json" "gateway pod"

  [[ "$runtime_class" == "$EXPECTED_RUNTIME_CLASS" ]] || \
    die "workspace pod runtimeClassName=$runtime_class, want $EXPECTED_RUNTIME_CLASS"
  [[ "$gateway_runtime_class" == "$EXPECTED_RUNTIME_CLASS" ]] || \
    die "gateway pod runtimeClassName=$gateway_runtime_class, want $EXPECTED_RUNTIME_CLASS"
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
  [[ "$gateway_containers" == "codewire-gateway" ]] || \
    die "gateway pod containers=$gateway_containers, want codewire-gateway"
  jq -e '.items[]?.spec.template.spec.containers[]? | select(.name=="codewire-gateway")' "$gateway_deploy_json" >/dev/null || \
    die "gateway Deployment is missing codewire-gateway container"
  [[ "$gateway_secret_count" == "1" ]] || \
    die "gateway host key Secret count=$gateway_secret_count, want 1"
  [[ "$gateway_secret_data_size" -gt 0 ]] || \
    die "gateway host key Secret is missing host_ed25519 data"
  [[ "$gateway_host_key_env" == "/codewire/gateway/ssh/host_ed25519" ]] || \
    die "gateway CODEWIRE_SSH_HOST_KEY_PATH=$gateway_host_key_env, want /codewire/gateway/ssh/host_ed25519"
  jq -e '
    .items[0].spec.template.spec
    | (
        [
          .initContainers[]?
          | select(
              .name == "codewire-gateway-host-key-init"
              and ([.volumeMounts[]? | select(.name == "gateway-host-key" and .readOnly == true)] | length == 1)
              and ([.volumeMounts[]? | select(.name == "workspace")] | length == 0)
            )
        ] | length == 1
      )
      and (
        [
          .volumes[]?
          | select(.name == "gateway-host-key" and .secret.secretName != null)
        ] | length == 1
      )
      and (
        [
          .containers[]?
          | select(.name == "codewire-gateway")
          | .volumeMounts[]?
          | select(.name == "workspace")
        ] | length == 0
      )
  ' "$gateway_deploy_json" >/dev/null || \
    die "gateway Deployment must seed host key from a read-only Secret without mounting workspace state"
  if [[ -n "$EXPECTED_GATEWAY_IMAGE" ]]; then
    [[ "$gateway_image" == "$EXPECTED_GATEWAY_IMAGE" ]] || \
      die "gateway image=$gateway_image, want $EXPECTED_GATEWAY_IMAGE"
    log "gateway status image=${gateway_status_image:-<unset>} imageID=${gateway_image_id:-<unset>}"
  fi
  if [[ -n "$EXPECTED_DIND_IMAGE" && "$EXPECTED_DOCKER_MODE" != "none" ]]; then
    [[ "$dind_image" == "$EXPECTED_DIND_IMAGE" ]] || \
      die "dind image=$dind_image, want $EXPECTED_DIND_IMAGE"
    log "dind status image=${dind_status_image:-<unset>} imageID=${dind_image_id:-<unset>}"
  fi
  if [[ -n "$EXPECTED_NODE" ]]; then
    [[ "$node" == "$EXPECTED_NODE" ]] || die "node=$node, want $EXPECTED_NODE"
    [[ "$gateway_node" == "$EXPECTED_NODE" ]] || die "gateway node=$gateway_node, want $EXPECTED_NODE"
  fi
  node_label="$(kubectl_dev get node "$node" -o "jsonpath={.metadata.labels.${EXPECTED_NODE_KATA_LABEL//./\\.}}" 2>/dev/null || true)"
  [[ "$node_label" == "$EXPECTED_NODE_KATA_VALUE" ]] || \
    die "node $node label $EXPECTED_NODE_KATA_LABEL=$node_label, want $EXPECTED_NODE_KATA_VALUE"
  gateway_node_label="$(kubectl_dev get node "$gateway_node" -o "jsonpath={.metadata.labels.${EXPECTED_NODE_KATA_LABEL//./\\.}}" 2>/dev/null || true)"
  [[ "$gateway_node_label" == "$EXPECTED_NODE_KATA_VALUE" ]] || \
    die "gateway node $gateway_node label $EXPECTED_NODE_KATA_LABEL=$gateway_node_label, want $EXPECTED_NODE_KATA_VALUE"
  assert_runtime_node_storage "$node"
  if [[ "$gateway_node" != "$node" ]]; then
    assert_runtime_node_storage "$gateway_node"
  fi

  local host_socket_count workspace_docker_host gateway_docker_env_count gateway_resources gateway_shim_addr gateway_auth_count
  local dind_bootstrap dind_data_image dind_data_root dind_data_size dind_mount_mode
  local gateway_binding_url gateway_derp_url gateway_stun_host gateway_stun_port
  local expected_binding_url expected_derp_url
  host_socket_count="$(jq -s '[.[].spec.volumes[]? | select(.hostPath? and ((.hostPath.path == "/var/run/docker.sock") or (.hostPath.path == "/var/run/docker") or (.hostPath.path == "/run/containerd/containerd.sock") or (.hostPath.path == "/run/containerd")))] | length' "$pod_json" "$gateway_pod_json")"
  [[ "$host_socket_count" == "0" ]] || die "workspace or gateway pod mounts host Docker/containerd socket volume"

  workspace_docker_host="$(jq -r '.spec.containers[] | select(.name=="workspace") | .env[]? | select(.name=="DOCKER_HOST") | .value // ""' "$pod_json")"
  gateway_docker_env_count="$(jq '[.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_DOCKER_PROXY_SOCK" or .name=="CODEWIRE_DOCKER_UPSTREAM_SOCK")] | length' "$gateway_pod_json")"
  gateway_shim_addr="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_WORKSPACE_SHIM_ADDR") | .value // ""' "$gateway_pod_json")"
  gateway_auth_count="$(jq '[.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_DAEMON_AUTH_TOKEN" and (.value // "" | length > 0))] | length' "$gateway_pod_json")"
  gateway_binding_url="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_BINDING_URL") | .value // ""' "$gateway_pod_json")"
  gateway_derp_url="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_DERP_URL") | .value // ""' "$gateway_pod_json")"
  gateway_stun_host="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_STUN_HOST") | .value // ""' "$gateway_pod_json")"
  gateway_stun_port="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_STUN_PORT") | .value // ""' "$gateway_pod_json")"
  gateway_resources="$(jq -c '.spec.containers[] | select(.name=="codewire-gateway") | .resources // {}' "$gateway_pod_json")"
  dind_bootstrap="$(jq -r '.spec.containers[] | select(.name=="dind") | .command[2] // ""' "$pod_json")"
  dind_data_image="$(jq -r '.spec.containers[] | select(.name=="dind") | .env[]? | select(.name=="CODEWIRE_DOCKER_DATA_IMAGE") | .value // ""' "$pod_json")"
  dind_data_root="$(jq -r '.spec.containers[] | select(.name=="dind") | .env[]? | select(.name=="CODEWIRE_DOCKER_DATA_ROOT") | .value // ""' "$pod_json")"
  dind_data_size="$(jq -r '.spec.containers[] | select(.name=="dind") | .env[]? | select(.name=="CODEWIRE_DOCKER_DATA_SIZE") | .value // ""' "$pod_json")"
  dind_mount_mode="$(jq -r '.spec.containers[] | select(.name=="dind") | .env[]? | select(.name=="CODEWIRE_DOCKER_MOUNT_MODE") | .value // ""' "$pod_json")"
  expected_binding_url="http://codewire-orchestration.${CODEWIRE_SERVER_NAMESPACE}.svc.cluster.local:8085"
  expected_derp_url="https://codewire-derp.${CODEWIRE_SERVER_NAMESPACE}.svc.cluster.local:8443"

  if [[ "$EXPECTED_DOCKER_MODE" == "none" ]]; then
    [[ -z "$workspace_docker_host" ]] || \
      die "workspace DOCKER_HOST=$workspace_docker_host, want empty for EXPECTED_DOCKER_MODE=none"
  else
    [[ "$workspace_docker_host" == "unix:///var/run/docker/docker.sock" ]] || \
      die "workspace DOCKER_HOST=$workspace_docker_host, want unix:///var/run/docker/docker.sock"
  fi
  [[ "$gateway_docker_env_count" == "0" ]] || \
    die "gateway must not mount or proxy the workspace Docker socket after the workspace/gateway split"
  [[ "$gateway_shim_addr" == cw-daemon-*:7777 ]] || \
    die "gateway CODEWIRE_WORKSPACE_SHIM_ADDR=$gateway_shim_addr, want cw-daemon-<env>:7777"
  [[ "$gateway_auth_count" == "1" ]] || \
    die "gateway missing non-empty CODEWIRE_DAEMON_AUTH_TOKEN"
  [[ "$gateway_binding_url" == "$expected_binding_url" ]] || \
    die "gateway CODEWIRE_BINDING_URL=$gateway_binding_url, want $expected_binding_url"
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
  [[ "$gateway_derp_url" == "$expected_derp_url" ]] || \
    die "gateway CODEWIRE_DERP_URL=$gateway_derp_url, want $expected_derp_url"
  [[ "$gateway_stun_host" == "$EXPECTED_GATEWAY_STUN_HOST" ]] || \
    die "gateway CODEWIRE_STUN_HOST=$gateway_stun_host, want $EXPECTED_GATEWAY_STUN_HOST"
  [[ "$gateway_stun_port" == "$EXPECTED_GATEWAY_STUN_PORT" ]] || \
    die "gateway CODEWIRE_STUN_PORT=$gateway_stun_port, want $EXPECTED_GATEWAY_STUN_PORT"
  assert_tailnet_discovery_shape "$pod_json" "$gateway_pod_json"
  jq -e '
    .spec.containers[]
    | select(.name=="codewire-gateway")
    | .resources.requests.cpu == "100m"
      and .resources.requests.memory == "128Mi"
      and .resources.limits.cpu == "500m"
      and .resources.limits.memory == "256Mi"
  ' "$gateway_pod_json" >/dev/null || \
    die "gateway resources=$gateway_resources, want explicit commodity gateway resources"

  kubectl_dev -n "$SANDBOX_NAMESPACE" logs "$GATEWAY_POD_NAME" -c codewire-gateway --tail=20 >/dev/null
  kubectl_dev -n "$SANDBOX_NAMESPACE" exec "$POD_NAME" -c workspace -- id >/dev/null
  if [[ "$EXPECTED_DOCKER_MODE" != "none" ]]; then
    if [[ "$EXPECTED_RUNTIME_CLASS" == "confidential" ]]; then
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

  log "workspace pod $POD_NAME runtime=$runtime_class node=$node; gateway pod $GATEWAY_POD_NAME runtime=$gateway_runtime_class node=$gateway_node image=$gateway_image"
}

assert_tailnet_discovery_shape() {
  if expect_tailnet_direct_udp; then
    assert_tailnet_direct_udp_discovery_shape "$1" "$2"
    return
  fi
  if expect_tailnet_peer_relay; then
    assert_tailnet_peer_relay_discovery_shape "$1" "$2"
    return
  fi
  [[ -z "${EXPECTED_TAILNET_PATH_TRANSPORT:-}" || "$EXPECTED_TAILNET_PATH_TRANSPORT" == "any" ]] || \
    die "unsupported EXPECTED_TAILNET_PATH_TRANSPORT=$EXPECTED_TAILNET_PATH_TRANSPORT"
  log "tailnet discovery shape check skipped for EXPECTED_TAILNET_PATH_TRANSPORT=${EXPECTED_TAILNET_PATH_TRANSPORT:-any}"
}

assert_tailnet_peer_relay_discovery_shape() {
  local pod_json="$1"
  local gateway_pod_json="$2"
  local direct_udp_label direct_udp_env_count direct_udp_bind_addr relay_allocator_url relay_bind_addrs
  local direct_udp_service_json direct_udp_services direct_udp_lb_service_json direct_udp_lb_nodeport_count
  local gateway_policy_json gateway_service_json gateway_nodeport_count

  direct_udp_label="$(jq -rs '[.[].metadata.labels["codewire.sh/direct-udp-service"]? // empty] | map(select(. != "")) | join(",")' "$pod_json" "$gateway_pod_json")"
  [[ -z "$direct_udp_label" ]] || \
    die "pod still has legacy codewire.sh/direct-udp-service selector label $direct_udp_label"

  direct_udp_env_count="$(jq '[.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_TAILNET_UDP_PORT" or .name=="CODEWIRE_TAILNET_ADVERTISE_ENDPOINTS")] | length' "$gateway_pod_json")"
  [[ "$direct_udp_env_count" == "0" ]] || \
    die "gateway has legacy static tailnet UDP env vars; peer relay mode must allocate relay endpoints"

  direct_udp_bind_addr="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_TAILNET_UDP_LISTEN_ADDR") | .value // ""' "$gateway_pod_json")"
  [[ -z "$direct_udp_bind_addr" || "$direct_udp_bind_addr" == "0.0.0.0:31000" ]] || \
    die "gateway CODEWIRE_TAILNET_UDP_LISTEN_ADDR=$direct_udp_bind_addr, want unset or 0.0.0.0:31000"

  relay_allocator_url="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_UDP_RELAY_ALLOCATOR_URL") | .value // ""' "$gateway_pod_json")"
  [[ -z "$relay_allocator_url" ]] || \
    die "gateway CODEWIRE_UDP_RELAY_ALLOCATOR_URL=$relay_allocator_url, want transport-zone binding instead of flat relay config"

  relay_bind_addrs="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_UDP_RELAY_BIND_ADDRS") | .value // ""' "$gateway_pod_json")"
  [[ -z "$relay_bind_addrs" ]] || \
    die "gateway CODEWIRE_UDP_RELAY_BIND_ADDRS=$relay_bind_addrs, want transport-zone binding instead of flat relay config"

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

  gateway_service_json="$TMPDIR_SMOKE/gateway-service.json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get service \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=gateway" \
    -o json >"$gateway_service_json"
  gateway_nodeport_count="$(jq '[.items[]? | select(.spec.type == "NodePort" or ([.spec.ports[]? | select(has("nodePort"))] | length > 0))] | length' "$gateway_service_json")"
  [[ "$gateway_nodeport_count" == "0" ]] || \
    die "gateway service must remain ClusterIP without NodePorts"

  gateway_policy_json="$TMPDIR_SMOKE/gateway-peer-relay-networkpolicy.json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get networkpolicy \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=gateway" \
    -o json >"$gateway_policy_json"
  jq -e --arg ns "$CODEWIRE_SERVER_NAMESPACE" '
    [
      .items[]?.spec.egress[]?
      | select(
          (
            .to[]?
            | .namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == $ns
              and .podSelector.matchLabels["app.kubernetes.io/component"] == "udp-relay"
          )
          and ([.ports[]? | select(.protocol == "TCP" and ((.port | tonumber) == 8095))] | length > 0)
          and ([.ports[]? | select(.protocol == "UDP" and ((.port | tonumber) == 41641))] | length > 0)
        )
    ]
    | length > 0
  ' "$gateway_policy_json" >/dev/null || \
    die "gateway NetworkPolicy does not allow shared UDP relay allocator egress to namespace $CODEWIRE_SERVER_NAMESPACE on TCP 8095 and UDP 41641"

  log "tailnet peer relay mode uses shared relay allocator, ClusterIP gateway service, and no NodePort direct UDP services"
}

assert_tailnet_direct_udp_discovery_shape() {
  local pod_json="$1"
  local gateway_pod_json="$2"
  local direct_udp_env endpoint_env direct_udp_service_json direct_udp_services

  assert_tailnet_peer_relay_discovery_shape "$pod_json" "$gateway_pod_json"

  endpoint_env="$(jq -r '.spec.containers[] | select(.name=="codewire-gateway") | .env[]? | select(.name=="CODEWIRE_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS") | .value // ""' "$gateway_pod_json")"
  [[ "$endpoint_env" == "$EXPECTED_TAILNET_DIRECT_UDP_LB_IP:"* ]] || \
    die "gateway CODEWIRE_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS=$endpoint_env, want $EXPECTED_TAILNET_DIRECT_UDP_LB_IP:<port>"

  direct_udp_service_json="$TMPDIR_SMOKE/direct-udp-lb-service.json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get service -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=direct-udp-lb" -o json >"$direct_udp_service_json"
  direct_udp_services="$(jq -r '.items | length' "$direct_udp_service_json")"
  [[ "$direct_udp_services" == "1" ]] || \
    die "expected exactly one direct UDP LoadBalancer service for $ENV_ID, found $direct_udp_services"

  direct_udp_env="$endpoint_env" jq -e --arg ip "$EXPECTED_TAILNET_DIRECT_UDP_LB_IP" --arg zone "$EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE" '
    .items[0].spec.type == "LoadBalancer"
    and .items[0].spec.allocateLoadBalancerNodePorts == false
    and .items[0].spec.loadBalancerClass == "io.cilium/l2-announcer"
    and .items[0].metadata.annotations["lbipam.cilium.io/ips"] == $ip
    and .items[0].metadata.labels["codewire.sh/transport-zone"] == $zone
    and .items[0].metadata.annotations["lbipam.cilium.io/sharing-key"] == "codewire-direct-udp"
    and .items[0].metadata.annotations["lbipam.cilium.io/sharing-cross-namespace"] == "*"
    and ([.items[0].spec.ports[]? | select(.protocol == "UDP" and ((.targetPort | tonumber) == 31000) and (has("nodePort") | not))] | length == 1)
    and (
      (.items[0].metadata.annotations["lbipam.cilium.io/ips"] + ":" + ((.items[0].spec.ports[] | select(.protocol == "UDP") | .port) | tostring))
      == env.direct_udp_env
    )
  ' "$direct_udp_service_json" >/dev/null || \
    die "direct UDP LoadBalancer service does not match advertised Cilium LB-IPAM endpoint $endpoint_env"

  log "tailnet direct UDP mode advertises Cilium LoadBalancer endpoint $endpoint_env without NodePorts"
}

assert_sandbox_template_derp_egress() {
  local claim_json="$TMPDIR_SMOKE/claim-template.json"
  local warm_pool_json="$TMPDIR_SMOKE/claim-warmpool.json"
  local template_json="$TMPDIR_SMOKE/sandboxtemplate.json"
  local gateway_policy_json="$TMPDIR_SMOKE/gateway-networkpolicy.json"
  local daemon_policy_json="$TMPDIR_SMOKE/workspace-daemon-networkpolicy.json"
  local daemon_service_json="$TMPDIR_SMOKE/workspace-daemon-service.json"
  local template_name warm_pool_name

  kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxclaim "$CLAIM_NAME" -o json >"$claim_json"
  template_name="$(jq -r '.spec.sandboxTemplateRef.name // empty' "$claim_json")"
  if [[ -z "$template_name" ]]; then
    warm_pool_name="$(jq -r '.spec.warmPoolRef.name // empty' "$claim_json")"
    [[ -n "$warm_pool_name" ]] || \
      die "SandboxClaim $CLAIM_NAME has neither sandboxTemplateRef.name nor warmPoolRef.name"
    kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxwarmpool "$warm_pool_name" -o json >"$warm_pool_json"
    template_name="$(jq -r '.spec.sandboxTemplateRef.name // empty' "$warm_pool_json")"
    [[ -n "$template_name" ]] || \
      die "SandboxWarmPool $warm_pool_name has no sandboxTemplateRef.name"
  fi
  kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxtemplate "$template_name" -o json >"$template_json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get networkpolicy \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=gateway" \
    -o json >"$gateway_policy_json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get networkpolicy \
    -l "codewire.sh/environment-id=${ENV_ID},app.kubernetes.io/component=workspace-daemon" \
    -o json >"$daemon_policy_json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get service \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=workspace-daemon" \
    -o json >"$daemon_service_json"

  jq -e --arg ns "$CODEWIRE_SERVER_NAMESPACE" '
    [
      .items[]?.spec.egress[]?
      | select(
          (
            .to[]?
            | .namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == $ns
              and .podSelector.matchLabels["app.kubernetes.io/component"] == "derp"
          )
          and ([.ports[]? | select(.protocol == "TCP" and ((.port | tonumber) == 8443))] | length > 0)
          and ([.ports[]? | select(.protocol == "UDP" and ((.port | tonumber) == 3478))] | length > 0)
        )
    ]
    | length > 0
  ' "$gateway_policy_json" >/dev/null || \
    die "gateway NetworkPolicy does not allow codewire-derp egress in namespace $CODEWIRE_SERVER_NAMESPACE on TCP 8443 and UDP 3478"

  jq -e '
    [
      .items[]?.spec.ingress[]?
      | select([.ports[]? | select(.protocol == "UDP" and ((.port | tonumber) == 31000))] | length > 0)
    ]
    | length > 0
  ' "$gateway_policy_json" >/dev/null || \
    die "gateway NetworkPolicy does not allow tailnet UDP ingress on UDP 31000"

  jq -e '
    [
      .items[]?.spec.ingress[]?
      | select(
          ([.from[]?.podSelector.matchLabels["codewire.sh/type"] | select(. == "gateway")] | length > 0)
          and ([.ports[]? | select(.protocol == "TCP" and ((.port | tonumber) == 7777))] | length > 0)
        )
    ]
    | length > 0
  ' "$daemon_policy_json" >/dev/null || \
    die "workspace daemon NetworkPolicy must allow gateway-labelled pods to TCP 7777"

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
        )
    ]
    | length > 0
  ' "$daemon_policy_json" >/dev/null || \
    die "workspace daemon NetworkPolicy must allow Codewire orchestration in $CODEWIRE_SERVER_NAMESPACE to TCP 7777"

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
    [[ "$kernel_params" == *"agent.guest_components_rest_api=resource"* ]] || \
      die "SandboxTemplate $template_name missing CoCo guest_components_rest_api=resource kernel param"
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
  log "waiting for gateway pod"
  wait_until "gateway pod" "$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))" gateway_pod_exists
  log "waiting for gateway pod readiness"
  kubectl_dev -n "$SANDBOX_NAMESPACE" wait "pod/$GATEWAY_POD_NAME" \
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
  if [[ -z "$GATEWAY_POD_NAME" ]]; then
    log "discovering gateway pod for $ENV_ID"
    wait_until "gateway pod" "$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))" gateway_pod_exists
  fi
}

run_cw_session_script() {
  local script="$1"
  cw_with_timeout "$SMOKE_EXEC_TIMEOUT" \
    run --no-tty "$ENV_ID" -- sh -lc "$script"
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

  cw list "$ENV_ID" --output json >"$sessions_json"
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
  cw logs "$ENV_ID" "$success_session" --raw |
    grep -qF 'platform-session-smoke' ||
    die "saved platform session output was not readable"
}

assert_coco_guest_test_resource() {
  [[ -n "$EXPECTED_KATA_COCO_TEST_RESOURCE_URI" ]] || return 0

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

run_app_preview_smoke() {
  require_cmd curl
  require_cmd jq
  require_uint SMOKE_APP_PREVIEW_PORT "$SMOKE_APP_PREVIEW_PORT"
  [[ "$SMOKE_APP_PREVIEW_PORT" -ge 1 && "$SMOKE_APP_PREVIEW_PORT" -le 65535 ]] || \
    die "SMOKE_APP_PREVIEW_PORT must be between 1 and 65535"
  [[ "$SMOKE_APP_PREVIEW_LABEL" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || \
    die "SMOKE_APP_PREVIEW_LABEL must be a DNS-safe label"

  local token start_script stop_script port_json port_err rm_json rm_err
  local preview_url preview_host_port preview_host preview_path preview_body preview_err
  local preview_ok cleanup_body cleanup_status

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
  if ! cw env port add "$SMOKE_APP_PREVIEW_PORT" \
      --env "$ENV_ID" \
      --label "$SMOKE_APP_PREVIEW_LABEL" \
      --access public \
      --output json >"$port_json" 2>"$port_err"; then
    sed 's/[[:cntrl:]]//g' "$port_err" >&2 || true
    die "cw env port add failed"
  fi

  preview_url="$(jq -r '.preview_url // empty' "$port_json")"
  [[ -n "$preview_url" ]] || die "cw env port add returned empty preview_url"
  [[ "$preview_url" == http://* || "$preview_url" == https://* ]] || \
    die "cw env port add returned invalid preview_url=$preview_url"
  preview_host_port="${preview_url#http://}"
  preview_host_port="${preview_host_port#https://}"
  preview_path="/"
  if [[ "$preview_host_port" == */* ]]; then
    preview_path="/${preview_host_port#*/}"
    preview_host_port="${preview_host_port%%/*}"
  fi
  preview_host="${preview_host_port%%:*}"
  [[ -n "$preview_host" ]] || die "failed to parse preview host from $preview_url"

  preview_body="$TMPDIR_SMOKE/app-preview-response.txt"
  preview_err="$TMPDIR_SMOKE/app-preview-response.err"
  preview_ok=0
  log "fetching preview URL $preview_url"
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
    sed 's/[[:cntrl:]]//g' "$preview_err" >&2 || true
    [[ -s "$preview_body" ]] && sed 's/[[:cntrl:]]//g' "$preview_body" >&2 || true
    die "preview URL did not return the app preview token"
  fi

  rm_json="$TMPDIR_SMOKE/app-preview-port-delete.json"
  rm_err="$TMPDIR_SMOKE/app-preview-port-delete.err"
  log "removing preview port label=$SMOKE_APP_PREVIEW_LABEL"
  if ! cw env port rm "$SMOKE_APP_PREVIEW_LABEL" \
      --env "$ENV_ID" \
      --output json >"$rm_json" 2>"$rm_err"; then
    sed 's/[[:cntrl:]]//g' "$rm_err" >&2 || true
    die "cw env port rm failed"
  fi

  cleanup_body="$TMPDIR_SMOKE/app-preview-after-delete.txt"
  cleanup_status=0
  if curl --ipv4 -fsS --connect-timeout 5 --max-time 15 \
      "$preview_url" >"$cleanup_body" 2>/dev/null; then
    cleanup_status=1
  fi
  if [[ "$cleanup_status" == "1" ]] && grep -Fq "$token" "$cleanup_body"; then
    die "preview URL still served the deleted app preview port"
  fi

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
  log "app preview smoke passed for $preview_url"
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
  discover_runtime_objects
  assert_gateway_tailnet_log_evidence
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
  local marker="rust gateway UDP peer relay allocation diagnostic"
  local output="$TMPDIR_SMOKE/gateway-tailnet-allocator-doctor-failure.log"
  local raw_output="$TMPDIR_SMOKE/gateway-tailnet-allocator-doctor-failure.jsonl"
  local kubectl_error="$TMPDIR_SMOKE/gateway-tailnet-allocator-doctor-failure.err"
  local -a pipeline_status

  if [[ -z "$GATEWAY_POD_NAME" ]] && ! gateway_pod_exists; then
    log "tailnet doctor failure allocator diagnostics unavailable: gateway pod not found"
    return 0
  fi

  set +e
  kubectl_dev -n "$SANDBOX_NAMESPACE" logs "$GATEWAY_POD_NAME" -c codewire-gateway --tail=400 2>"$kubectl_error" \
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
    log "tailnet doctor failure allocator diagnostics unavailable: gateway log read failed"
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
    --arg stun_host "$EXPECTED_GATEWAY_STUN_HOST" \
    --argjson stun_port "$EXPECTED_GATEWAY_STUN_PORT" \
    '
      (
        (.direct.direct_path.transport == "direct_udp" and .direct.direct_path.ready == true and ((.direct.direct_path.endpoint // "") | contains($ip)))
        or
        (.direct.final_path.transport == "direct_udp" and .direct.final_path.ready == true and ((.direct.final_path.endpoint // "") | contains($ip)))
      )
      and (
        (
          [
            .direct.derp_map.regions[]?.nodes[]?
            | select(.stun_only == true and .host_name == $stun_host and .stun_port == $stun_port)
          ] | length
        ) >= 1
        or ((.direct.derp_map.stun_nodes // 0) >= 1)
      )
    ' "$doctor_json" >/dev/null || \
    die "tailnet doctor did not prove direct_udp via Cilium LoadBalancer IP $EXPECTED_TAILNET_DIRECT_UDP_LB_IP with STUN $EXPECTED_GATEWAY_STUN_HOST:$EXPECTED_GATEWAY_STUN_PORT"

  [[ "$SMOKE_DERP_FALLBACK" != "1" ]] || assert_tailnet_doctor_forced_derp_evidence "$doctor_json"

  log "tailnet doctor proved direct_udp via Cilium LoadBalancer IP $EXPECTED_TAILNET_DIRECT_UDP_LB_IP and STUN map $EXPECTED_GATEWAY_STUN_HOST:$EXPECTED_GATEWAY_STUN_PORT"
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
    --arg stun_host "$EXPECTED_GATEWAY_STUN_HOST" \
    --argjson stun_port "$EXPECTED_GATEWAY_STUN_PORT" \
    '
      (
        ((.direct.direct_path.transport == "udp_relay" or .direct.direct_path.transport == "peer_relay") and ((.direct.direct_path.peer_relay // .direct.direct_path.endpoint // "") | contains($endpoint)))
        or
        ((.direct.final_path.transport == "udp_relay" or .direct.final_path.transport == "peer_relay") and ((.direct.final_path.peer_relay // .direct.final_path.endpoint // "") | contains($endpoint)))
      )
      and (
        (
          [
            .direct.derp_map.regions[]?.nodes[]?
            | select(.stun_only == true and .host_name == $stun_host and .stun_port == $stun_port)
          ] | length
        ) >= 1
        or ((.direct.derp_map.stun_nodes // 0) >= 1)
      )
    ' "$doctor_json" >/dev/null || \
    die "tailnet doctor did not prove peer_relay via shared endpoint $EXPECTED_TAILNET_PEER_RELAY_ENDPOINT with STUN $EXPECTED_GATEWAY_STUN_HOST:$EXPECTED_GATEWAY_STUN_PORT"

  [[ "$SMOKE_DERP_FALLBACK" != "1" ]] || assert_tailnet_doctor_forced_derp_evidence "$doctor_json"

  log "tailnet doctor proved peer_relay via shared relay endpoint $EXPECTED_TAILNET_PEER_RELAY_ENDPOINT and STUN map $EXPECTED_GATEWAY_STUN_HOST:$EXPECTED_GATEWAY_STUN_PORT"
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
  local bundle_dir manifest_file pool_source="" candidate manifest_entries
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
              warm_pool: (.spec.warmPoolRef.name | safe_token),
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
    pool_source="$candidate"
    break
  done
  if [[ -n "$pool_source" && -s "$pool_source" ]] \
      && jq -e 'type == "object"' "$pool_source" >/dev/null 2>&1; then
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
        schema: "codewire-kubernetes-warm-pool-diagnostic-v1",
        read_state: "available",
        name: (.metadata.name | safe_token),
        generation: (.metadata.generation | count_value),
        template: (.spec.sandboxTemplateRef.name | safe_token),
        desired_replicas: (.spec.replicas | count_value),
        current_replicas: (.status.replicas | count_value),
        ready_replicas: (.status.readyReplicas | count_value)
      }
      | with_entries(select(.value != null))
    ' "$pool_source" >"$bundle_dir/warm-pool.json"
  else
    jq -n '{
      schema: "codewire-kubernetes-warm-pool-diagnostic-v1",
      read_state: "unavailable"
    }' >"$bundle_dir/warm-pool.json"
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
  local dir pods_json pod container containers claim_json warm_pool_name template_name

  [[ "$SMOKE_COLLECT_FAILURE_DIAGNOSTICS" == "1" ]] || return 0
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
    warm_pool_name="$(jq -r '.spec.warmPoolRef.name // empty' "$claim_json" 2>/dev/null || true)"
    template_name="$(jq -r '.spec.sandboxTemplateRef.name // empty' "$claim_json" 2>/dev/null || true)"
    if [[ -n "$warm_pool_name" ]]; then
      kubectl_dev -n "$SANDBOX_NAMESPACE" get sandboxwarmpool "$warm_pool_name" -o json \
        >"$dir/sandboxwarmpool-$warm_pool_name.json" 2>"$dir/sandboxwarmpool-$warm_pool_name.err" || true
      template_name="$(jq -r '.spec.sandboxTemplateRef.name // empty' "$dir/sandboxwarmpool-$warm_pool_name.json" 2>/dev/null || true)"
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

  logs="$TMPDIR_SMOKE/gateway-tailnet-${label}-after-fail.log"
  if capture_container_log "$GATEWAY_POD_NAME" codewire-gateway "$logs"; then
    log "captured gateway SSH-failure logs in $logs"
  else
    log "failed to capture gateway SSH-failure logs; stderr in ${logs}.err"
  fi

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

assert_gateway_tailnet_log_evidence() {
  local logs="$TMPDIR_SMOKE/gateway-tailnet.log"

  capture_container_log "$GATEWAY_POD_NAME" codewire-gateway "$logs"

  grep -q 'rust gateway resolved STUN servers for direct UDP' "$logs" || \
    die "gateway logs do not show Rust STUN server resolution; evidence in $logs"
  grep -q 'rust tailnet direct UDP socket bound' "$logs" || \
    die "gateway logs do not show direct UDP socket bind; evidence in $logs"
  grep -q 'rust tailnet startup STUN discovery complete' "$logs" || \
    die "gateway logs do not show startup STUN discovery; evidence in $logs"
  grep -q 'rust gateway tailnet direct UDP transport enabled' "$logs" || \
    die "gateway logs do not show direct UDP transport enabled; evidence in $logs"

  log "gateway logs prove Rust STUN discovery and direct UDP transport startup; evidence in $logs"
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

run_gateway_host_key_probe_once() {
  local strict="$1"
  local label="$2"
  local known_hosts="$3"
  local stdout="$TMPDIR_SMOKE/ssh-host-key-${label}.out"
  local stderr="$TMPDIR_SMOKE/ssh-host-key-${label}.err"
  local expected_output="host-key-${label}-ok"

  if ! env CW_SSH_TRANSPORT=websocket timeout "$SMOKE_SSH_TIMEOUT" ssh -F /dev/null \
      -o BatchMode=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o "StrictHostKeyChecking=$strict" \
      -o UserKnownHostsFile="$known_hosts" \
      -o "LogLevel=$SMOKE_SSH_LOG_LEVEL" \
      -o ConnectTimeout="$SMOKE_SSH_CONNECT_TIMEOUT" \
      -o "ProxyCommand=$CW_BIN --server $CODEWIRE_SERVER_URL shell --stdio %h" \
      "codewire@cw-$ENV_ID" \
      "printf '${expected_output}\n'" >"$stdout" 2>"$stderr"; then
    return 1
  fi

  grep -qx "$expected_output" "$stdout"
}

run_gateway_host_key_probe() {
  local strict="$1"
  local label="$2"
  local known_hosts="$3"
  local stderr="$TMPDIR_SMOKE/ssh-host-key-${label}.err"

  if ! run_gateway_host_key_probe_once "$strict" "$label" "$known_hosts"; then
    sed 's/[[:cntrl:]]//g' "$stderr" >&2 || true
    capture_ssh_failure_evidence "host-key-${label}"
    die "gateway host-key $label SSH probe failed"
  fi
}

wait_for_gateway_host_key_probe() {
  local strict="$1"
  local label="$2"
  local known_hosts="$3"
  local deadline stderr

  deadline=$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))
  stderr="$TMPDIR_SMOKE/ssh-host-key-${label}.err"
  while (( "$(seconds_now)" < deadline )); do
    if run_gateway_host_key_probe_once "$strict" "$label" "$known_hosts"; then
      return
    fi
    if grep -Eq 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed' "$stderr"; then
      break
    fi
    sleep 5
  done

  sed 's/[[:cntrl:]]//g' "$stderr" >&2 || true
  capture_ssh_failure_evidence "host-key-${label}"
  die "gateway host-key $label SSH probe failed"
}

run_gateway_host_key_restart_smoke() {
  local deploy_json="$TMPDIR_SMOKE/gateway-host-key-restart-deploy.json"
  local deploy_name known_hosts

  discover_runtime_objects
  kubectl_dev -n "$SANDBOX_NAMESPACE" get deploy \
    -l "codewire.sh/environment-id=${ENV_ID},codewire.sh/type=gateway" \
    -o json >"$deploy_json"
  deploy_name="$(jq -r '.items[0].metadata.name // empty' "$deploy_json")"
  [[ -n "$deploy_name" ]] || die "gateway Deployment not found for host-key restart smoke"
  kubectl_dev -n "$SANDBOX_NAMESPACE" wait "pod/$GATEWAY_POD_NAME" \
    --for=condition=Ready --timeout="${SMOKE_TIMEOUT_SECONDS}s"

  known_hosts="$TMPDIR_SMOKE/known_hosts.host-key-restart"
  log "recording gateway SSH host key before gateway pod restart"
  run_gateway_host_key_probe accept-new before "$known_hosts"

  GATEWAY_OLD_POD_NAME="$GATEWAY_POD_NAME"
  log "restarting gateway Deployment $deploy_name to prove SSH host key stability"
  kubectl_dev -n "$SANDBOX_NAMESPACE" rollout restart "deployment/$deploy_name" >/dev/null
  kubectl_dev -n "$SANDBOX_NAMESPACE" rollout status "deployment/$deploy_name" \
    --timeout="${SMOKE_TIMEOUT_SECONDS}s"

  GATEWAY_POD_NAME=""
  wait_until "restarted gateway pod" "$(( "$(seconds_now)" + SMOKE_TIMEOUT_SECONDS ))" gateway_restarted_pod_exists
  kubectl_dev -n "$SANDBOX_NAMESPACE" wait "pod/$GATEWAY_POD_NAME" \
    --for=condition=Ready --timeout="${SMOKE_TIMEOUT_SECONDS}s"

  log "verifying gateway SSH host key is stable after pod restart"
  wait_for_gateway_host_key_probe yes after "$known_hosts"
  log "gateway SSH host key remained stable across pod restart"
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
  run_gateway_host_key_restart_smoke
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
      run_gateway_host_key_restart_smoke
      ;;
    app-preview)
      wait_for_cw_run
      run_app_preview_smoke
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

main() {
  prepare_cli
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
  fi
  log "runtime smoke passed for $ENV_ID"
}

main "$@"
