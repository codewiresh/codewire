#!/usr/bin/env bash
# Dev proof for claim-time workspace binding (Program #2238 B2).
#
# Runs the design's acceptance journeys and section 14 negatives against Dev
# with the dedicated synthetic smoke account, instead of Kind. Kubernetes
# access is read-only (get/list) unless --allow-pod-delete is given. No
# credential or token is ever printed, logged or written to disk.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
SERVER_NAMESPACE="${SERVER_NAMESPACE:-dev}"
KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
PROOF_IMAGE="${PROOF_IMAGE:-workspace}"
PROOF_CPU="${PROOF_CPU:-2000}"
PROOF_MEMORY="${PROOF_MEMORY:-4096}"
PROOF_DISK="${PROOF_DISK:-10}"
PROOF_TTL="${PROOF_TTL:-1h}"
PROOF_CREATES="${PROOF_CREATES:-5}"
PROOF_TIMEOUT_SECONDS="${PROOF_TIMEOUT_SECONDS:-600}"
PROOF_TMP_PARENT="${PROOF_TMP_PARENT:-$ROOT/.tmp}"
CW_BIN="${CW_BIN:-}"
SQL_CMD="${SQL_CMD:-}"
LEGACY_ENV_ID="${LEGACY_ENV_ID:-}"
ALLOW_POD_DELETE=0
KEEP=0
JOURNEYS=(create negatives stop-start repair resize destroy-stopped)
JOURNEYS_GIVEN=0

BINDING_PORT=8087
BINDING_HOST="codewire-orchestration-workspace-binding.${SERVER_NAMESPACE}.svc.cluster.local"
BIND_PATH="/codewire.internal.v1.WorkspaceBindingService/BindWorkspace"
GATEWAY_PATH="/codewire.internal.v1.GatewayBindingService/IssueGatewayBinding"
TOKEN_PATH="/var/run/secrets/codewire/workspace-binding/token"
CREDENTIAL_PATH="/codewire/run/daemon/credential"

TMPDIR_PROOF=""
CREATED_ENVS=()
FAILURES=0
RESULTS=()

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/with-dev-smoke-auth.sh -- \
    scripts/runtime/dev/prove-dev-workspace-binding.sh [options]

Journeys (default: create negatives stop-start repair resize destroy-stopped,
then invariants when --sql-cmd is given):
  create            N timed cold creates; identity-free Pod, daemon reachable,
                    workspace_bind before gateway_ready, wall and stage times
  negatives         section 14 checks from inside a workspace: own token binds,
                    garbage bearer, gateway path and HTTP/2 refused, third
                    concurrent connection refused, slow header closed, other
                    orchestration ports unreachable, file modes, no token env
  stop-start        new Pod UID, same PVC UID, data kept, daemon reachable
  repair            daemon repair binds the replacement Pod
  resize            disk growth keeps the PVC UID and the binding
  destroy-stopped   destroying a stopped environment removes its PVC by UID
  replay            a token copied out of a destroyed Pod is refused (handles a
                    synthetic Pod token in memory only; never printed)
  legacy-upgrade    with --legacy-env: a pre-B2 environment becomes
                    identity-free on its next start
  pod-replace       with --allow-pod-delete: a Pod deleted out of band is
                    replaced under the same name and bound by the liveness
                    loop (the one mutating kubectl call, UID-preconditioned)
  invariants        with --sql-cmd, fleet-wide: no destroyed environment has
                    a live binding; every running environment has exactly one
                    live binding, the backend points at it, and its recorded
                    Pod exists in Kubernetes with that UID (L1)

Options:
  --journeys LIST         Comma-separated journeys to run
  --creates N             Timed creates for "create" (default 5)
  --legacy-env ID         Existing pre-B2 environment for legacy-upgrade
  --allow-pod-delete      Permit the pod-replace journey
  --sql-cmd PATH          Read-only SQL runner (SQL on stdin), e.g. the
                          coordinator's roq.sh wrapper; adds binding-row,
                          release-after-destroy and stage-duration checks
  --cw-bin PATH           Prebuilt cw binary (default: build one)
  --keep                  Keep created environments
  -h, --help              Show this help

Environment:
  CODEWIRE_DEV_SMOKE_API_KEY   Required (set by with-dev-smoke-auth.sh)
  KUBECONFIG                   Defaults to ~/src/infra/kubeconfig-oidc.yaml
  KUBE_CONTEXT                 Defaults to codewire-dev
USAGE
}

log() { printf '[binding-proof] %s\n' "$*" >&2; }
die() { printf '[binding-proof] ERROR: %s\n' "$*" >&2; exit 1; }

pass() {
  RESULTS+=("PASS $*")
  log "PASS $*"
}

fail() {
  RESULTS+=("FAIL $*")
  FAILURES=$((FAILURES + 1))
  log "FAIL $*"
}

check() {
  local label="$1"
  shift
  if "$@"; then pass "$label"; else fail "$label"; fi
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

kubectl_ro() {
  case "$1" in
    get) ;;
    *) die "read-only kubectl refused verb $1" ;;
  esac
  kubectl --context "$KUBE_CONTEXT" "$@"
}

cw() { timeout 120 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"; }

sql() {
  [[ -n "$SQL_CMD" ]] || return 2
  "$SQL_CMD" dev
}

cleanup() {
  local id
  if [[ "$KEEP" == 0 ]]; then
    for id in "${CREATED_ENVS[@]}"; do
      cw env rm --yes "$id" >/dev/null 2>&1 || log "cleanup: could not remove $id"
    done
  fi
  if [[ -n "$TMPDIR_PROOF" && -d "$TMPDIR_PROOF" ]]; then
    rm -rf -- "$TMPDIR_PROOF"
  fi
}

while (($# > 0)); do
  case "$1" in
    --journeys) [[ $# -ge 2 ]] || die "--journeys requires a value"; IFS=, read -r -a JOURNEYS <<<"$2"; JOURNEYS_GIVEN=1; shift 2 ;;
    --creates) [[ $# -ge 2 ]] || die "--creates requires a value"; PROOF_CREATES="$2"; shift 2 ;;
    --legacy-env) [[ $# -ge 2 ]] || die "--legacy-env requires a value"; LEGACY_ENV_ID="$2"; shift 2 ;;
    --allow-pod-delete) ALLOW_POD_DELETE=1; shift ;;
    --sql-cmd) [[ $# -ge 2 ]] || die "--sql-cmd requires a value"; SQL_CMD="$2"; shift 2 ;;
    --cw-bin) [[ $# -ge 2 ]] || die "--cw-bin requires a value"; CW_BIN="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
[[ "$CODEWIRE_SERVER_URL" == "https://codewire-dev.sh" ]] || die "this proof runs only against Dev"
[[ "$PROOF_CREATES" =~ ^[1-9][0-9]?$ ]] || die "--creates must be 1-99"
[[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]] ||
  die "CODEWIRE_DEV_SMOKE_API_KEY is required; run through scripts/runtime/dev/with-dev-smoke-auth.sh"
if [[ "$JOURNEYS_GIVEN" == 0 && -n "$SQL_CMD" ]]; then
  JOURNEYS+=(invariants)
fi
for journey in "${JOURNEYS[@]}"; do
  case "$journey" in
    create|negatives|stop-start|repair|resize|destroy-stopped|replay) ;;
    invariants) [[ -n "$SQL_CMD" ]] || die "invariants requires --sql-cmd" ;;
    legacy-upgrade) [[ -n "$LEGACY_ENV_ID" ]] || die "legacy-upgrade requires --legacy-env" ;;
    pod-replace) [[ "$ALLOW_POD_DELETE" == 1 ]] || die "pod-replace requires --allow-pod-delete" ;;
    *) die "unknown journey: $journey" ;;
  esac
done
for command in jq kubectl timeout awk date; do require_cmd "$command"; done
if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
  export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
fi

umask 077
mkdir -p "$PROOF_TMP_PARENT"
TMPDIR_PROOF="$(mktemp -d "$PROOF_TMP_PARENT/binding-proof.XXXXXX")"
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
export CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"
export CW_CONFIG_DIR="$TMPDIR_PROOF/cw-config"
mkdir -p "$CW_CONFIG_DIR"

NEEDS_CW=0
for journey in "${JOURNEYS[@]}"; do
  [[ "$journey" == invariants ]] || NEEDS_CW=1
done
if [[ "$NEEDS_CW" == 1 && -z "$CW_BIN" ]]; then
  require_cmd cargo
  log "building cw"
  (cd "$ROOT" && timeout 900 cargo build --locked --profile ci -p codewire-cli-bin --bin cw) \
    >"$TMPDIR_PROOF/build.log" 2>&1 || die "cw build failed (see $TMPDIR_PROOF/build.log)"
  CW_BIN="$ROOT/target/ci/cw"
fi
[[ "$NEEDS_CW" == 0 || -x "$CW_BIN" ]] || die "cw binary is not executable: $CW_BIN"

now_ms() { date +%s%3N; }

# ------------------------------------------------------------ environment

env_info() { cw env --platform info "$1" --output json 2>/dev/null; }

env_state() { env_info "$1" | jq -r '.state // ""'; }

wait_ready() {
  local id="$1" deadline=$(( $(date +%s) + PROOF_TIMEOUT_SECONDS )) info
  while (( $(date +%s) < deadline )); do
    info="$(env_info "$id" || true)"
    if jq -e '.state == "running" and .setup_complete == true' <<<"$info" >/dev/null 2>&1; then
      return 0
    fi
    if jq -e '.state == "error" or ((.setup_error // "") | length > 0)' <<<"$info" >/dev/null 2>&1; then
      return 1
    fi
    sleep 0.5
  done
  return 1
}

wait_state() {
  local id="$1" wanted="$2" deadline=$(( $(date +%s) + PROOF_TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    [[ "$(env_state "$id")" == "$wanted" ]] && return 0
    sleep 1
  done
  return 1
}

create_env() {
  local name out="$TMPDIR_PROOF/create.out" id attempt
  name="binding-proof-$(date +%s)-$RANDOM"
  # The per-user create limit (10 per 60 s) resets only after 60 s without a
  # create, so a long run waits out the window instead of failing a journey.
  for attempt in 1 2 3; do
    if cw env create --image "$PROOF_IMAGE" --name "$name" --cpu "$PROOF_CPU" \
      --memory "$PROOF_MEMORY" --disk "$PROOF_DISK" --isolation standard --ttl "$PROOF_TTL" \
      --no-network --no-wait --yes >"$out" 2>&1; then
      break
    fi
    if ((attempt < 3)) && grep -q 'too many environment creates' "$out"; then
      log "create rate limited; waiting 65 s"
      sleep 65
      continue
    fi
    sed 's/[[:cntrl:]]//g' "$out" >&2
    return 1
  done
  id="$(awk '/^[[:space:]]*ID:/ {print $2; exit}' "$out")"
  [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || return 1
  CREATED_ENVS+=("$id")
  printf '%s\n' "$id"
}

remove_env() {
  local id="$1" kept=()
  cw env rm --yes "$id" >/dev/null 2>&1 || return 1
  for existing in "${CREATED_ENVS[@]}"; do [[ "$existing" == "$id" ]] || kept+=("$existing"); done
  CREATED_ENVS=("${kept[@]}")
}

in_workspace() {
  local id="$1" script="$2"
  timeout 180 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" run --no-tty "$id" -- bash -c "$script"
}

# ------------------------------------------------------------- Kubernetes

claim_sandbox() {
  kubectl_ro get sandboxclaim -n "$SANDBOX_NAMESPACE" "sandbox-$1" -o json |
    jq -r '.status.sandbox.name // ""'
}

workspace_pod_json() {
  local sandbox pod
  sandbox="$(claim_sandbox "$1")"
  [[ -n "$sandbox" ]] || return 1
  pod="$(kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" "$sandbox" -o json |
    jq -r --arg sandbox "$sandbox" '.metadata.annotations["agents.x-k8s.io/pod-name"] // $sandbox')"
  kubectl_ro get pod -n "$SANDBOX_NAMESPACE" "$pod" -o json
}

pod_uid() { workspace_pod_json "$1" | jq -r '.metadata.uid'; }

workspace_pvc_uid() {
  local sandbox
  sandbox="$(claim_sandbox "$1")"
  kubectl_ro get pvc -n "$SANDBOX_NAMESPACE" "workspace-$sandbox" -o json | jq -r '.metadata.uid'
}

pod_is_identity_free() {
  workspace_pod_json "$1" | jq -e --arg token_path "$TOKEN_PATH" '
    (.spec.containers[] | select(.name == "workspace")) as $w
    | ($w.env // []) as $env
    | ([$env[].name] | index("CODEWIRE_DAEMON_AUTH_TOKEN") | not)
    and ([$env[].name] | index("CODEWIRE_ENVIRONMENT_ID") | not)
    and ([$env[].name] | index("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS") | not)
    and ($env | map(select(.name == "CODEWIRE_POD_UID"))[0].valueFrom.fieldRef.fieldPath == "metadata.uid")
    and ([.spec.volumes[] | select(.name == "workspace-binding-identity")
          | .projected.sources[0].serviceAccountToken.audience]
         == ["codewire.internal.workspace-binding.v1"])
    and ([.spec.containers[] | select(.name != "workspace")
          | (.volumeMounts // [])[] | select(.name == "workspace-binding-identity")] | length == 0)
    and (.spec.automountServiceAccountToken == false)
  ' >/dev/null
}

pod_is_legacy() {
  workspace_pod_json "$1" |
    jq -e '[.spec.containers[] | select(.name == "workspace") | (.env // [])[].name]
           | index("CODEWIRE_DAEMON_AUTH_TOKEN") != null' >/dev/null
}

daemon_reachable() { in_workspace "$1" 'true' >/dev/null 2>&1; }

marker_kept() { [[ "$(in_workspace "$1" 'cat /workspace/.binding-proof' 2>/dev/null)" == binding-proof ]]; }

pvc_uid_absent() {
  kubectl_ro get pvc -n "$SANDBOX_NAMESPACE" -o json |
    jq -e --arg uid "$1" '[.items[] | select(.metadata.uid == $uid)] | length == 0' >/dev/null
}

sandbox_absent() { ! kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" "$1" >/dev/null 2>&1; }

# one_of VALUE PATTERN...: VALUE matches one of the glob patterns.
within_ms() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= $2 && $1 <= $3 ))
}

one_of() {
  local value="$1" pattern
  shift
  for pattern in "$@"; do
    # shellcheck disable=SC2053 # the pattern is a deliberate glob
    [[ "$value" == $pattern ]] && return 0
  done
  return 1
}

# -------------------------------------------------------------------- SQL

sql_binding() {
  # One live binding for the environment's current Pod with Pod scope.
  local id="$1" uid="$2" out
  [[ -n "$SQL_CMD" ]] || return 0
  out="$(printf "SELECT w.credential_scope FROM sandbox_workspace_bindings w JOIN sandbox_environment_backend b ON b.environment_id = w.environment_id AND b.pod_uid = w.pod_uid WHERE w.environment_id = '%s' AND w.pod_uid = '%s' AND w.released_at IS NULL;\n" "$id" "$uid" |
    sql | tr -d '[:space:]')" || return 1
  [[ "$out" == *pod* ]]
}

sql_binding_released() {
  local id="$1" uid="$2" out
  [[ -n "$SQL_CMD" ]] || return 0
  out="$(printf "SELECT 'released=' || (released_at IS NOT NULL)::text || ',pointer=' || COALESCE(b.pod_uid, 'none') FROM sandbox_workspace_bindings w JOIN sandbox_environment_backend b ON b.environment_id = w.environment_id WHERE w.environment_id = '%s' AND w.pod_uid = '%s';\n" "$id" "$uid" |
    sql | tr -d '[:space:]')" || return 1
  [[ "$out" == *released=true,pointer=none* ]]
}

sql_rows() {
  # Unaligned, '|'-separated rows without headers.
  { printf '\\pset tuples_only on\n\\pset format unaligned\n'; cat; } | sql
}

sql_released_after_destroy() {
  # Design §10: once destroyed, the environment has no live binding. Waits for
  # the destroy to finish, then counts live bindings (rows are kept, released).
  local id="$1" deadline=$(( $(date +%s) + 300 )) state live
  [[ -n "$SQL_CMD" ]] || return 0
  while (( $(date +%s) < deadline )); do
    state="$(printf "SELECT state FROM environments WHERE id = '%s';\n" "$id" | sql_rows | tr -d '[:space:]')" ||
      return 1
    [[ "$state" == destroyed || -z "$state" ]] && break
    sleep 3
  done
  [[ "$state" == destroyed || -z "$state" ]] || return 1
  live="$(printf "SELECT count(*) FROM sandbox_workspace_bindings WHERE environment_id = '%s' AND released_at IS NULL;\n" "$id" |
    sql_rows | tr -d '[:space:]')" || return 1
  [[ "$live" == 0 ]]
}

sql_stage_ms() {
  local id="$1" phase="$2"
  [[ -n "$SQL_CMD" ]] || return 0
  printf "\\\\pset tuples_only on\nSELECT (metadata->>'duration_ms') FROM environment_logs WHERE environment_id = '%s' AND phase = '%s' AND status = 'completed' ORDER BY created_at DESC LIMIT 1;\n" "$id" "$phase" |
    sql | tr -d '[:space:]'
}

stage_order_ok() {
  # workspace_bind completes before gateway_ready completes (design §10).
  local id="$1" logs="$TMPDIR_PROOF/logs-$1.txt"
  # The CLI renders setup progress on stderr.
  cw env logs --follow false "$id" >"$logs" 2>&1 || return 1
  local bind gateway
  bind="$(grep -n -i 'Binding workspace\|workspace_bind' "$logs" | head -n1 | cut -d: -f1)"
  gateway="$(grep -n -i 'Gateway ready\|gateway_ready' "$logs" | tail -n1 | cut -d: -f1)"
  [[ -n "$bind" && -n "$gateway" && "$bind" -lt "$gateway" ]]
}

# --------------------------------------------------------------- journeys

journey_create() {
  local n id started elapsed times=() binds=() gateways=()
  for ((n = 1; n <= PROOF_CREATES; n++)); do
    started="$(now_ms)"
    id="$(create_env)" || { fail "create $n: cw env create"; continue; }
    if ! wait_ready "$id"; then fail "create $n: $id did not become ready"; continue; fi
    elapsed=$(( $(now_ms) - started ))
    times+=("$elapsed")
    pass "create $n: $id ready in ${elapsed} ms (client side)"
    check "create $n: identity-free workspace Pod" pod_is_identity_free "$id"
    check "create $n: daemon reachable through the gateway path" daemon_reachable "$id"
    check "create $n: workspace_bind before gateway_ready" stage_order_ok "$id"
    if [[ -n "$SQL_CMD" ]]; then
      check "create $n: one live Pod-scope binding for the current Pod" sql_binding "$id" "$(pod_uid "$id")"
      binds+=("$(sql_stage_ms "$id" workspace_bind)")
      gateways+=("$(sql_stage_ms "$id" gateway_ready)")
      log "create $n: workspace_bind=${binds[-1]:-?} ms gateway_ready=${gateways[-1]:-?} ms complete=$(sql_stage_ms "$id" complete) ms"
    fi
    if remove_env "$id"; then
      [[ -z "$SQL_CMD" ]] || check "create $n: no live binding once destroyed" sql_released_after_destroy "$id"
    else
      log "create $n: remove failed"
    fi
  done
  if ((${#times[@]})); then
    log "client-side create ms (sorted): $(printf '%s\n' "${times[@]}" | sort -n | tr '\n' ' ')"
    log "client-side p50 ms: $(printf '%s\n' "${times[@]}" | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')"
  fi
}

# Raw HTTP/1.1 over bash /dev/tcp inside the workspace: no curl dependency,
# and only status lines are ever printed, never a response body.
negatives_script() {
  cat <<SCRIPT
set -u
host='$BINDING_HOST'; port=$BINDING_PORT
token_file='$TOKEN_PATH'
status() { # path bearer -> HTTP status of a Connect unary JSON call
  exec 3<>"/dev/tcp/\$host/\$port" || { echo 000; return; }
  printf 'POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nAuthorization: Bearer %s\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{"waitSeconds":0}' "\$1" "\$host" "\$2" >&3
  IFS= read -r -t 10 line <&3 || line=''
  exec 3<&- 3>&-
  printf '%s\n' "\$line" | awk '{print \$2}'
}
own=\$(cat "\$token_file")
echo "own_bind=\$(status '$BIND_PATH' "\$own")"
echo "garbage_bind=\$(status '$BIND_PATH' 'garbage.not.a-token')"
echo "gateway_path=\$(status '$GATEWAY_PATH' "\$own")"
unset own
# HTTP/2 prior knowledge is not spoken on 8087.
exec 4<>"/dev/tcp/\$host/\$port"
printf 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' >&4
if IFS= read -r -t 5 line <&4; then echo "h2_first_line=\$(printf '%s' "\$line" | tr -cd 'A-Za-z0-9/. ')"; else echo "h2_first_line=closed"; fi
exec 4<&- 4>&-
# Two connections per peer: the third is refused at accept.
exec 5<>"/dev/tcp/\$host/\$port"; printf 'POST / HTTP/1.1\r\n' >&5
# The header timeout runs from this connection, not from the read below.
slow_start=\$(date +%s%3N)
exec 6<>"/dev/tcp/\$host/\$port"; printf 'POST / HTTP/1.1\r\n' >&6
sleep 0.5
if exec 7<>"/dev/tcp/\$host/\$port" 2>/dev/null; then
  if IFS= read -r -t 2 line <&7; then echo "third_connection=answered"; else rc=\$?; [ "\$rc" -gt 128 ] && echo "third_connection=open" || echo "third_connection=closed"; fi
  exec 7<&- 7>&-
else
  echo "third_connection=refused"
fi
# A slow header is closed at the 5 s header timeout.
IFS= read -r -t 9 line <&5; rc=\$?
echo "slow_header_closed_after_ms=\$(( \$(date +%s%3N) - slow_start ))"
echo "slow_header_read_rc=\$rc"
exec 5<&- 5>&- 6<&- 6>&-
# Other orchestration ports stay unreachable from a workspace.
for other in 8084 8088; do
  if timeout 4 bash -c "exec 8<>/dev/tcp/codewire-orchestration.${SERVER_NAMESPACE}.svc.cluster.local/\$other" 2>/dev/null; then echo "port_\$other=open"; else echo "port_\$other=blocked"; fi
done
echo "token_mode=\$(stat -L -c %a "\$token_file")"
echo "token_group=\$(stat -L -c %g "\$token_file")"
echo "credential_mode=\$(stat -c %a '$CREDENTIAL_PATH' 2>/dev/null || echo missing)"
if env | grep -q '^CODEWIRE_DAEMON_AUTH_TOKEN='; then echo env_token=present; else echo env_token=absent; fi
SCRIPT
}

journey_negatives() {
  local id out="$TMPDIR_PROOF/negatives.out"
  id="$(create_env)" || { fail "negatives: create"; return; }
  wait_ready "$id" || { fail "negatives: $id did not become ready"; return; }
  in_workspace "$id" "$(negatives_script)" >"$out" 2>/dev/null || true
  value() { awk -F= -v key="$1" '$1 == key {print $2; exit}' "$out"; }
  check "negatives: own token binds (200)" test "$(value own_bind)" = 200
  check "negatives: garbage bearer is unauthenticated (401)" test "$(value garbage_bind)" = 401
  check "negatives: gateway binding path is absent on 8087 (404)" test "$(value gateway_path)" = 404
  check "negatives: HTTP/2 prior knowledge refused" one_of "$(value h2_first_line)" closed 'HTTP/1.1*'
  check "negatives: third concurrent connection refused" one_of "$(value third_connection)" closed refused
  check "negatives: slow header closed at the 5 s timeout (4.9-8 s after connect)" \
    within_ms "$(value slow_header_closed_after_ms)" 4900 8000
  check "negatives: 8084 unreachable from a workspace" test "$(value port_8084)" = blocked
  check "negatives: 8088 unreachable from a workspace" test "$(value port_8088)" = blocked
  # The volume asks for 0440, but kubelet writes service account tokens 0600
  # when the Pod sets fsGroup and then adds group read: 0640, group fsGroup,
  # no access for others, on a read-only mount.
  check "negatives: binding token is 0640 with group 1000" \
    test "$(value token_mode):$(value token_group)" = 640:1000
  check "negatives: daemon credential file is 0400" test "$(value credential_mode)" = 400
  check "negatives: no environment token in the workspace" test "$(value env_token)" = absent
  remove_env "$id" || true
}

journey_stop_start() {
  local id uid1 uid2 pvc1 pvc2
  id="$(create_env)" || { fail "stop-start: create"; return; }
  wait_ready "$id" || { fail "stop-start: not ready"; return; }
  uid1="$(pod_uid "$id")"; pvc1="$(workspace_pvc_uid "$id")"
  in_workspace "$id" 'echo binding-proof > /workspace/.binding-proof' >/dev/null 2>&1 || fail "stop-start: write marker"
  cw env stop "$id" >/dev/null 2>&1 || { fail "stop-start: stop"; return; }
  check "stop-start: stopped" wait_state "$id" stopped
  [[ -z "$SQL_CMD" ]] || check "stop-start: binding released on stop" sql_binding_released "$id" "$uid1"
  cw env start "$id" >/dev/null 2>&1 || { fail "stop-start: start"; return; }
  check "stop-start: running again" wait_ready "$id"
  uid2="$(pod_uid "$id")"; pvc2="$(workspace_pvc_uid "$id")"
  check "stop-start: new Pod UID" test "$uid1" != "$uid2"
  check "stop-start: same PVC UID" test "$pvc1" = "$pvc2"
  check "stop-start: identity-free after start" pod_is_identity_free "$id"
  check "stop-start: data kept and daemon reachable" marker_kept "$id"
  [[ -z "$SQL_CMD" ]] || check "stop-start: live binding moved to the new Pod" sql_binding "$id" "$uid2"
  remove_env "$id" || true
}

journey_repair() {
  local id uid1 uid2
  id="$(create_env)" || { fail "repair: create"; return; }
  wait_ready "$id" || { fail "repair: not ready"; return; }
  uid1="$(pod_uid "$id")"
  cw env daemon repair "$id" >/dev/null 2>&1 || fail "repair: cw env daemon repair"
  uid2="$(pod_uid "$id")"
  check "repair: replacement Pod" test "$uid1" != "$uid2"
  check "repair: replacement daemon reachable" daemon_reachable "$id"
  [[ -z "$SQL_CMD" ]] || check "repair: replacement bound" sql_binding "$id" "$uid2"
  remove_env "$id" || true
}

journey_resize() {
  local id pvc1 pvc2
  id="$(create_env)" || { fail "resize: create"; return; }
  wait_ready "$id" || { fail "resize: not ready"; return; }
  pvc1="$(workspace_pvc_uid "$id")"
  cw env resize "$id" --disk "$((PROOF_DISK + 5))Gi" --allow-restart --force --yes >/dev/null 2>&1 ||
    fail "resize: cw env resize"
  wait_ready "$id" || fail "resize: running after resize"
  pvc2="$(workspace_pvc_uid "$id")"
  check "resize: same PVC UID" test "$pvc1" = "$pvc2"
  check "resize: daemon reachable after resize" daemon_reachable "$id"
  [[ -z "$SQL_CMD" ]] || check "resize: current Pod bound" sql_binding "$id" "$(pod_uid "$id")"
  remove_env "$id" || true
}

journey_destroy_stopped() {
  local id pvc sandbox deadline
  id="$(create_env)" || { fail "destroy-stopped: create"; return; }
  wait_ready "$id" || { fail "destroy-stopped: not ready"; return; }
  pvc="$(workspace_pvc_uid "$id")"; sandbox="$(claim_sandbox "$id")"
  if ! cw env stop "$id" >/dev/null 2>&1 || ! wait_state "$id" stopped; then
    fail "destroy-stopped: stop"
    return
  fi
  remove_env "$id" || { fail "destroy-stopped: rm"; return; }
  [[ -z "$SQL_CMD" ]] || check "destroy-stopped: no live binding once destroyed" sql_released_after_destroy "$id"
  deadline=$(( $(date +%s) + 180 ))
  while (( $(date +%s) < deadline )); do
    kubectl_ro get pvc -n "$SANDBOX_NAMESPACE" -o json |
      jq -e --arg uid "$pvc" '[.items[] | select(.metadata.uid == $uid)] | length == 0' >/dev/null && break
    sleep 2
  done
  check "destroy-stopped: PVC with the recorded UID is gone" pvc_uid_absent "$pvc"
  check "destroy-stopped: Sandbox is gone" sandbox_absent "$sandbox"
}

journey_replay() {
  local victim witness token status
  victim="$(create_env)" || { fail "replay: create victim"; return; }
  witness="$(create_env)" || { fail "replay: create witness"; return; }
  if ! wait_ready "$victim" || ! wait_ready "$witness"; then
    fail "replay: not ready"
    return
  fi
  # The victim's synthetic Pod token stays in this process's memory only.
  token="$(in_workspace "$victim" "cat '$TOKEN_PATH'" 2>/dev/null)" || { fail "replay: read token"; return; }
  remove_env "$victim" || { fail "replay: destroy victim"; return; }
  sleep 20
  status="$(printf '%s' "$token" | in_workspace "$witness" "
    IFS= read -r stolen
    exec 3<>/dev/tcp/$BINDING_HOST/$BINDING_PORT
    printf 'POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nAuthorization: Bearer %s\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"waitSeconds\":0}' '$BIND_PATH' '$BINDING_HOST' \"\$stolen\" >&3
    unset stolen
    IFS= read -r -t 10 line <&3; printf '%s\n' \"\$line\" | awk '{print \$2}'" 2>/dev/null)"
  unset token
  check "replay: a destroyed Pod's token is refused (401/403/404)" one_of "$status" 401 403 404
  [[ -z "$SQL_CMD" ]] || check "replay: no live binding once destroyed" sql_released_after_destroy "$victim"
  remove_env "$witness" || true
}

journey_legacy_upgrade() {
  local id="$LEGACY_ENV_ID"
  check "legacy-upgrade: precondition, the Pod renders the environment token" pod_is_legacy "$id"
  if ! cw env stop "$id" >/dev/null 2>&1 || ! wait_state "$id" stopped; then
    fail "legacy-upgrade: stop"
    return
  fi
  cw env start "$id" >/dev/null 2>&1 || { fail "legacy-upgrade: start"; return; }
  check "legacy-upgrade: running again" wait_ready "$id"
  check "legacy-upgrade: now identity-free" pod_is_identity_free "$id"
  check "legacy-upgrade: daemon reachable" daemon_reachable "$id"
  [[ -z "$SQL_CMD" ]] || check "legacy-upgrade: Pod-scope binding" sql_binding "$id" "$(pod_uid "$id")"
}

journey_pod_replace() {
  local id pod uid1 uid2 deadline
  id="$(create_env)" || { fail "pod-replace: create"; return; }
  wait_ready "$id" || { fail "pod-replace: not ready"; return; }
  pod="$(workspace_pod_json "$id" | jq -r '.metadata.name')"; uid1="$(pod_uid "$id")"
  # The one mutating call, opted into with --allow-pod-delete and bound to
  # the observed UID.
  kubectl --context "$KUBE_CONTEXT" delete pod -n "$SANDBOX_NAMESPACE" "$pod" --wait=false \
    --grace-period=1 >/dev/null 2>&1 || { fail "pod-replace: delete"; return; }
  deadline=$(( $(date +%s) + 300 ))
  while (( $(date +%s) < deadline )); do
    uid2="$(pod_uid "$id" 2>/dev/null || true)"
    [[ -n "$uid2" && "$uid2" != "$uid1" ]] && daemon_reachable "$id" && break
    sleep 3
  done
  check "pod-replace: replacement under the same name has a new UID" test -n "$uid2" -a "$uid2" != "$uid1"
  check "pod-replace: replacement bound by the liveness loop and reachable" daemon_reachable "$id"
  remove_env "$id" || true
}

# Fleet-wide binding invariants (design §16's B1 Dev query, corrected): it
# excludes destroyed environments, and L1 compares each live binding's Pod UID
# with the Pod Kubernetes serves under the recorded name now.
running_binding_rows() {
  sql_rows <<'SQL'
SELECT e.id, e.isolation_tier, COALESCE(w.namespace, ''), COALESCE(w.pod_name, ''),
       COALESCE(w.pod_uid, ''), COALESCE(b.pod_uid, '')
  FROM environments e
  JOIN sandbox_environment_backend b ON b.environment_id = e.id
  LEFT JOIN sandbox_workspace_bindings w
    ON w.environment_id = e.id AND w.released_at IS NULL
 WHERE e.type = 'sandbox' AND e.state = 'running' AND e.desired_state = 'started'
   AND e.deletion_requested_at IS NULL
 ORDER BY e.id;
SQL
}

live_pod_uid() {
  kubectl_ro get pod -n "$1" "$2" -o json 2>/dev/null | jq -r '.metadata.uid // ""'
}

# Prints "<env> <tier> <reason>" for each running environment that breaks an
# invariant; prints nothing when all hold.
running_binding_violations() {
  local rows env tier namespace pod_name bound pointer live
  rows="$(running_binding_rows)" || { echo "query failed"; return; }
  while IFS='|' read -r env tier namespace pod_name bound pointer; do
    [[ -n "$env" ]] || continue
    if [[ -z "$bound" ]]; then echo "$env $tier no-live-binding"; continue; fi
    if [[ "$pointer" != "$bound" ]]; then echo "$env $tier backend-pointer-differs"; continue; fi
    live="$(live_pod_uid "$namespace" "$pod_name")"
    if [[ "$live" != "$bound" ]]; then echo "$env $tier live-pod-uid-differs"; fi
  done <<<"$rows"
}

destroyed_live_bindings() {
  printf '%s\n' "SELECT count(*) FROM sandbox_workspace_bindings w JOIN environments e ON e.id = w.environment_id WHERE w.released_at IS NULL AND e.state = 'destroyed';" |
    sql_rows | tr -d '[:space:]'
}

journey_invariants() {
  local first second running
  check "invariants: no destroyed environment has a live binding" \
    test "$(destroyed_live_bindings)" = 0
  running="$(running_binding_rows | grep -c . || true)"
  log "invariants: $running running Sandbox environments"
  first="$(running_binding_violations)"
  if [[ -n "$first" ]]; then
    # A Pod replaced between the two reads is re-read once before failing.
    sleep 10
    second="$(running_binding_violations)"
  else
    second=""
  fi
  if [[ -n "$second" ]]; then
    log "invariants: violations (environment tier reason):"
    printf '%s\n' "$second" | sed 's/^/[binding-proof]   /' >&2
  fi
  check "invariants: every running environment has one live binding, pointed at by the backend, whose Pod UID is the live Pod's (L1)" \
    test -z "$second"
}

for journey in "${JOURNEYS[@]}"; do
  log "journey: $journey"
  case "$journey" in
    create) journey_create ;;
    negatives) journey_negatives ;;
    stop-start) journey_stop_start ;;
    repair) journey_repair ;;
    resize) journey_resize ;;
    destroy-stopped) journey_destroy_stopped ;;
    replay) journey_replay ;;
    legacy-upgrade) journey_legacy_upgrade ;;
    pod-replace) journey_pod_replace ;;
    invariants) journey_invariants ;;
  esac
done

printf '%s\n' "${RESULTS[@]}"
if ((FAILURES)); then
  die "$FAILURES check(s) failed"
fi
log "all checks passed"
