#!/usr/bin/env bash
# Dev proof for shared warm pools (Program #2238 C5).
#
# Times pool hits, a forced pool-empty miss and an off-shape create against
# Dev with the dedicated synthetic smoke account, then checks the unbound
# members' invariants. Kubernetes access is read-only (get only) and the SQL
# runner only ever reads. No credential or token is ever printed, logged or
# written to disk.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
# Orchestration's namespace: the one peer a pool template admits (#3626).
SERVER_NAMESPACE="${SERVER_NAMESPACE:-dev}"
KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
PROOF_IMAGE="${PROOF_IMAGE:-workspace}"
# One of the Dev pool shapes (1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=2).
PROOF_CPU="${PROOF_CPU:-1000}"
PROOF_MEMORY="${PROOF_MEMORY:-4096}"
PROOF_DISK="${PROOF_DISK:-10}"
# A shape no pool holds: it must go cold through its own shadow pool.
OFF_SHAPE_CPU="${OFF_SHAPE_CPU:-1500}"
PROOF_TTL="${PROOF_TTL:-1h}"
PROOF_HITS="${PROOF_HITS:-20}"
PROOF_MIN_HITS="${PROOF_MIN_HITS:-}"
PROOF_TIMEOUT_SECONDS="${PROOF_TIMEOUT_SECONDS:-600}"
# The path the timed first SSH must take (cw's CW_TAILNET_EXPECTED_TRANSPORT).
FIRST_SSH_TRANSPORT="${FIRST_SSH_TRANSPORT:-direct_udp}"
FIRST_SSH_TIMEOUT_SECONDS="${FIRST_SSH_TIMEOUT_SECONDS:-120}"
POOL_WAIT_SECONDS="${POOL_WAIT_SECONDS:-300}"
PROOF_TMP_PARENT="${PROOF_TMP_PARENT:-$ROOT/.tmp}"
CW_BIN="${CW_BIN:-}"
SQL_CMD="${SQL_CMD:-}"
ENFORCE_TARGETS=0
KEEP=0
JOURNEYS=(preflight hits miss off-shape invariants)
JOURNEYS_GIVEN=0

# Done-when targets on Dev: pool hit to an enabled terminal (no repository).
TARGET_HIT_P50_MS=5000
TARGET_HIT_P95_MS=10000
# Owner target (2026-10-07): a warm create is usable over SSH, carried by
# direct UDP, in under 5 s.
TARGET_FIRST_SSH_P50_MS=5000
TARGET_FIRST_SSH_P95_MS=10000

POOL_PREFIX="cw-pool-"
SHADOW_PREFIX="shadow-pool-"
MEMBER_LABEL="agents.x-k8s.io/warm-pool-sandbox"
LAUNCH_TYPE_LABEL="agents.x-k8s.io/launch-type"
REVISION_ANNOTATION="codewire.sh/pool-revision"
REVISION_ENV="CODEWIRE_WORKSPACE_POOL_REVISION"
# Program #2238 C6 (#2434): the agent-sandbox fork's birth label, and the
# bridge policy orchestration applies after a warm bind. The gateway half is
# gone with the gateway (#2460): it must never exist.
SANDBOX_UID_LABEL="agents.x-k8s.io/sandbox-uid"
DAEMON_BRIDGE_PREFIX="cw-daemon-warm-"
GATEWAY_BRIDGE_PREFIX="cw-gw-warm-"

TMPDIR_PROOF=""
CREATED_ENVS=()
WARM_IDS=()
COLD_IDS=()
HIT_TIMES=()
FIRST_SSH_WARM=()
FIRST_SSH_PID=""
FIRST_SSH_RESULT=""
FAILURES=0
RESULTS=()
POOL_NAME=""
POOL_REVISION=""
POOL_MEMBERS=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/with-dev-smoke-auth.sh -- \
    scripts/runtime/dev/prove-dev-warm-pools.sh [options]

Journeys (default: preflight hits miss off-shape invariants, then stats when
--sql-cmd is given):
  preflight   the pool for the proof shape exists with its revision, a
              capable controller observed its generation, and its template
              exists; reports replicas and ready members
  hits        N sequential creates of the pool shape, each after the pool
              holds a ready member; each must adopt a warm member
              (warmPoolRef cw-pool-*, launch-type warm), run identity-free,
              carry the pool revision and reach its daemon, own no gateway
              object, serve SSH presenting the host key the platform
              recorded (OpenSSH through cw, the managed block's settings),
              and is timed from the create to its first OpenSSH command
              over --first-ssh-transport (no WebSocket fallback),
              and its warm-member bridge must select exactly the bound Pod
              (skipped, with a message, while the fork's sandbox-uid label
              is absent); with --sql-cmd, a completed access_ready stage and
              a host key recorded by the live bound Pod; timed client
              side
  miss        with the pool full, members + 1 creates at once: at least one
              finds the pool empty, gets a fresh Sandbox and still starts
  off-shape   a shape no pool holds goes cold through its own shadow pool;
              its first SSH is timed like a hit's
  invariants  unbound members: no environment label or token, no API token,
              only workspace audiences, a current pool revision, ingress
              from orchestration alone on TCP 7777 and 2222,
              younger than 24 h, not on a cordoned node; with --sql-cmd, no
              open billing session without a live binding and no destroyed
              environment with a live binding
  stats       with --sql-cmd: warm and cold `complete` p50/p95 and stage
              p50s over this run's environments, against the Done-when
              targets (hit <= 5 s p50, <= 10 s p95); hits also report warm
              create-to-first-SSH p50/p95 against <= 5 s p50, <= 10 s p95

Acceptance needs at least 20 warm hits (the default).

Options:
  --journeys LIST         Comma-separated journeys to run
  --hits N                Sequential pool-shape creates for "hits" (default 20)
  --min-hits N            Warm hits required (default: --hits)
  --sql-cmd PATH          Read-only SQL runner (SQL on stdin), e.g. the
                          coordinator's roq.sh wrapper; adds binding,
                          billing-at-bind and stage-duration checks
  --enforce-targets       Fail when the warm p50/p95 targets are missed
  --first-ssh-transport T Path the timed first SSH must take: direct_udp
                          (default), udp_relay or derp
  --cw-bin PATH           Prebuilt cw binary (default: build one)
  --keep                  Keep created environments
  -h, --help              Show this help

Environment:
  CODEWIRE_DEV_SMOKE_API_KEY   Required (set by with-dev-smoke-auth.sh)
  KUBECONFIG                   Defaults to ~/src/infra/kubeconfig-oidc.yaml
  KUBE_CONTEXT                 Defaults to codewire-dev
  PROOF_CPU/PROOF_MEMORY/PROOF_DISK  Pool shape (default 1000/4096/10)
  OFF_SHAPE_CPU                CPU of the off-shape create (default 1500)
  SERVER_NAMESPACE             Orchestration's namespace, the pool ingress peer (default dev)
USAGE
}

log() { printf '[warm-pool-proof] %s\n' "$*" >&2; }
die() { printf '[warm-pool-proof] ERROR: %s\n' "$*" >&2; exit 1; }

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

skip() {
  RESULTS+=("SKIP $*")
  log "SKIP $*"
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

# jq -e over stdin without printing the result.
json_true() { jq -e "$@" >/dev/null; }

kubectl_ro() {
  case "$1" in
    get) ;;
    *) die "read-only kubectl refused verb $1" ;;
  esac
  kubectl --context "$KUBE_CONTEXT" "$@"
}

# Every environment this proof makes is a Dev cloud one. --cloud keeps cw from
# also asking a local VM supervisor on the proof machine, whose refusal would
# otherwise fail an id lookup (run, rm) for a cloud environment.
cw() { timeout 120 "$CW_BIN" --cloud --server "$CODEWIRE_SERVER_URL" "$@"; }

sql() {
  [[ -n "$SQL_CMD" ]] || return 2
  "$SQL_CMD" dev
}

sql_rows() {
  # Unaligned, '|'-separated rows without headers.
  { printf '\\pset tuples_only on\n\\pset format unaligned\n'; cat; } | sql
}

cleanup() {
  local id
  if [[ "$KEEP" == 0 ]]; then
    for id in "${CREATED_ENVS[@]}"; do
      cw rm --yes "$id" >/dev/null 2>&1 || log "cleanup: could not remove $id"
    done
  fi
  if [[ -n "$TMPDIR_PROOF" && -d "$TMPDIR_PROOF" ]]; then
    rm -rf -- "$TMPDIR_PROOF"
  fi
}

while (($# > 0)); do
  case "$1" in
    --journeys) [[ $# -ge 2 ]] || die "--journeys requires a value"; IFS=, read -r -a JOURNEYS <<<"$2"; JOURNEYS_GIVEN=1; shift 2 ;;
    --hits) [[ $# -ge 2 ]] || die "--hits requires a value"; PROOF_HITS="$2"; shift 2 ;;
    --min-hits) [[ $# -ge 2 ]] || die "--min-hits requires a value"; PROOF_MIN_HITS="$2"; shift 2 ;;
    --sql-cmd) [[ $# -ge 2 ]] || die "--sql-cmd requires a value"; SQL_CMD="$2"; shift 2 ;;
    --enforce-targets) ENFORCE_TARGETS=1; shift ;;
    --first-ssh-transport) [[ $# -ge 2 ]] || die "--first-ssh-transport requires a value"; FIRST_SSH_TRANSPORT="$2"; shift 2 ;;
    --cw-bin) [[ $# -ge 2 ]] || die "--cw-bin requires a value"; CW_BIN="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
[[ "$CODEWIRE_SERVER_URL" == "https://codewire-dev.sh" ]] || die "this proof runs only against Dev"
[[ "$PROOF_HITS" =~ ^[1-9][0-9]?$ ]] || die "--hits must be 1-99"
PROOF_MIN_HITS="${PROOF_MIN_HITS:-$PROOF_HITS}"
if ! [[ "$PROOF_MIN_HITS" =~ ^[0-9]+$ ]] || (( PROOF_MIN_HITS > PROOF_HITS )); then
  die "--min-hits must be 0-${PROOF_HITS}"
fi
for dimension in PROOF_CPU PROOF_MEMORY PROOF_DISK OFF_SHAPE_CPU; do
  [[ "${!dimension}" =~ ^[1-9][0-9]*$ ]] || die "$dimension must be a positive integer"
done
[[ "$OFF_SHAPE_CPU" != "$PROOF_CPU" ]] || die "OFF_SHAPE_CPU must differ from PROOF_CPU"
case "$FIRST_SSH_TRANSPORT" in
  direct_udp|udp_relay|derp) ;;
  *) die "--first-ssh-transport must be direct_udp, udp_relay or derp" ;;
esac
[[ "$FIRST_SSH_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] || die "FIRST_SSH_TIMEOUT_SECONDS must be a positive integer"
[[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]] ||
  die "CODEWIRE_DEV_SMOKE_API_KEY is required; run through scripts/runtime/dev/with-dev-smoke-auth.sh"
if [[ "$JOURNEYS_GIVEN" == 0 && -n "$SQL_CMD" ]]; then
  JOURNEYS+=(stats)
fi
for journey in "${JOURNEYS[@]}"; do
  case "$journey" in
    preflight|hits|miss|off-shape|invariants) ;;
    stats) [[ -n "$SQL_CMD" ]] || die "stats requires --sql-cmd" ;;
    *) die "unknown journey: $journey" ;;
  esac
done
for command in jq kubectl timeout awk date sort; do require_cmd "$command"; done
if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
  export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
fi

umask 077
mkdir -p "$PROOF_TMP_PARENT"
TMPDIR_PROOF="$(mktemp -d "$PROOF_TMP_PARENT/warm-pool-proof.XXXXXX")"
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
export CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"
export CW_CONFIG_DIR="$TMPDIR_PROOF/cw-config"
mkdir -p "$CW_CONFIG_DIR"

NEEDS_CW=0
for journey in "${JOURNEYS[@]}"; do
  case "$journey" in hits|miss|off-shape) NEEDS_CW=1 ;; esac
done
for journey in "${JOURNEYS[@]}"; do
  case "$journey" in hits|off-shape) require_cmd ssh ;; esac
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

percentile() { # P: sorted numbers on stdin -> nearest-rank percentile
  sort -n | awk -v p="$1" '{a[NR]=$1} END {if (NR == 0) {print ""; exit} i = int((p * NR + 99) / 100); if (i < 1) i = 1; print a[i]}'
}

# ------------------------------------------------------------ environment

env_info() { cw info "$1" --output json 2>/dev/null; }

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

create_env() { # CPU -> environment id
  local cpu="$1" name out="$TMPDIR_PROOF/create-$RANDOM.out" id attempt
  name="warm-pool-proof-$(date +%s)-$RANDOM"
  # The per-user create limit (10 per 60 s) resets only after 60 s without a
  # create; twenty hits exhaust it, so later journeys wait out the window.
  for attempt in 1 2 3; do
    # Timings start at the accepted request, not before a rate-limit wait.
    now_ms >"$TMPDIR_PROOF/create-started"
    # --no-file: a codewire.yaml where the proof runs must not change its shape.
    if cw create --no-file --image "$PROOF_IMAGE" --name "$name" --cpu "${cpu}m" \
      --memory "$PROOF_MEMORY" --disk "$PROOF_DISK" --isolation standard --ttl "$PROOF_TTL" \
      --no-network --no-wait --yes --output json >"$out" 2>"$out.err"; then
      break
    fi
    if ((attempt < 3)) && grep -q 'too many environment creates' "$out.err"; then
      log "create rate limited; waiting 65 s"
      sleep 65
      continue
    fi
    sed 's/[[:cntrl:]]//g' "$out" "$out.err" >&2
    return 1
  done
  id="$(jq -r '.id // empty' "$out" 2>/dev/null || true)"
  [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || return 1
  CREATED_ENVS+=("$id")
  printf '%s\n' "$id"
}

remove_env() {
  local id="$1" kept=() existing
  cw rm --yes "$id" >/dev/null 2>&1 || return 1
  for existing in "${CREATED_ENVS[@]}"; do [[ "$existing" == "$id" ]] || kept+=("$existing"); done
  CREATED_ENVS=("${kept[@]}")
}

in_workspace() {
  local id="$1" script="$2"
  timeout 180 "$CW_BIN" --cloud --server "$CODEWIRE_SERVER_URL" run --no-tty --in "$id" -- bash -c "$script"
}

daemon_reachable() { in_workspace "$1" 'true' >/dev/null 2>&1; }

# OpenSSH as a user runs it, through the block `cw setup ssh` writes: its
# only trusted host key is the one `cw ssh known-hosts` reads from the
# platform for the bound Pod, so success proves the bound daemon's SSH
# server presents exactly the recorded key. The block's commands carry no
# server; they find it through CODEWIRE_SERVER_URL.
ssh_presents_recorded_key() {
  local id="$1" config
  config="$(managed_ssh_config)" || return 1
  env CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" timeout 120 ssh -F "$config" -T \
    -o BatchMode=yes -o ConnectTimeout=60 \
    "cw-cloud-$id" true </dev/null >/dev/null 2>"$TMPDIR_PROOF/ssh-$id.err" ||
    { log "ssh: cw-cloud-$id: $(sed 's/[[:cntrl:]]//g' "$TMPDIR_PROOF/ssh-$id.err" | tail -n 2 | tr '\n' ' ')"; return 1; }
}

# The block `cw setup ssh` writes, once per run.
managed_ssh_config() {
  local config="$TMPDIR_PROOF/ssh_config"
  if [[ ! -s "$config" ]]; then
    "$CW_BIN" --server "$CODEWIRE_SERVER_URL" setup ssh --ssh-config-file "$config" >/dev/null ||
      { log "cw setup ssh could not write the managed SSH block"; return 1; }
  fi
  printf '%s\n' "$config"
}

# Create to the first OpenSSH command through the managed block, carried by
# FIRST_SSH_TRANSPORT. cw then refuses any other path, WebSocket included, so
# an attempt over the wrong path fails and the loop tries again until the
# deadline.
first_ssh_ms() { # ID STARTED_MS CONFIG -> elapsed ms
  local id="$1" started="$2" config="$3" deadline
  deadline=$(( $(date +%s) + FIRST_SSH_TIMEOUT_SECONDS ))
  while (( $(date +%s) < deadline )); do
    if env CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" CW_TAILNET_EXPECTED_TRANSPORT="$FIRST_SSH_TRANSPORT" \
      timeout 30 ssh -F "$config" -T -o BatchMode=yes -o ConnectTimeout=20 "cw-cloud-$id" true \
      </dev/null >/dev/null 2>&1; then
      printf '%s\n' "$(( $(now_ms) - started ))"
      return 0
    fi
    sleep 0.25
  done
  return 1
}

# Time the first SSH in the background while the create proceeds.
start_first_ssh() { # ID STARTED_MS
  local config
  config="$(managed_ssh_config)" || return 1
  first_ssh_ms "$1" "$2" "$config" >"$TMPDIR_PROOF/first-ssh-$1" &
  FIRST_SSH_PID=$!
}

# Wait for the timer, then set FIRST_SSH_RESULT to the timed first SSH in ms,
# empty when none succeeded in time. Call it directly, never inside $(...): a
# command substitution runs in a subshell, which cannot wait for the timer this
# shell started, so it read the result before the SSH finished and reported a
# slow first SSH as none at all.
finish_first_ssh() { # ID
  FIRST_SSH_RESULT=""
  [[ -n "$FIRST_SSH_PID" ]] || return 0
  wait "$FIRST_SSH_PID" 2>/dev/null || true
  FIRST_SSH_PID=""
  FIRST_SSH_RESULT="$(cat "$TMPDIR_PROOF/first-ssh-$1" 2>/dev/null || true)"
}

abandon_first_ssh() {
  [[ -n "$FIRST_SSH_PID" ]] || return 0
  kill "$FIRST_SSH_PID" 2>/dev/null || true
  wait "$FIRST_SSH_PID" 2>/dev/null || true
  FIRST_SSH_PID=""
}

# Log one timed first SSH; with a non-empty LIST name, append it there.
record_first_ssh() { # LABEL ID [LIST]
  local label="$1" id="$2" list="${3:-}" first
  finish_first_ssh "$id"
  first="$FIRST_SSH_RESULT"
  if [[ -z "$first" ]]; then
    fail "$label: no SSH over $FIRST_SSH_TRANSPORT within ${FIRST_SSH_TIMEOUT_SECONDS} s of the create"
    return
  fi
  log "$label: first SSH over $FIRST_SSH_TRANSPORT ${first} ms after the create (client side)"
  if [[ -n "$list" ]]; then
    local -n samples="$list"
    samples+=("$first")
  fi
}

# ------------------------------------------------------------- Kubernetes

pool_json() { kubectl_ro get sandboxwarmpool -n "$SANDBOX_NAMESPACE" "$POOL_NAME" -o json; }

claim_json() { kubectl_ro get sandboxclaim -n "$SANDBOX_NAMESPACE" "sandbox-$1" -o json; }

claim_sandbox() { claim_json "$1" | jq -r '.status.sandbox.name // ""'; }

claim_pool_ref() { claim_json "$1" | jq -r '.spec.warmPoolRef.name // ""'; }

sandbox_launch_type() {
  local sandbox
  sandbox="$(claim_sandbox "$1")"
  [[ -n "$sandbox" ]] || return 1
  kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" "$sandbox" -o json |
    jq -r --arg label "$LAUNCH_TYPE_LABEL" '.metadata.labels[$label] // "none"'
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

pod_is_identity_free() {
  workspace_pod_json "$1" | jq -e '
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

# The adopted Pod booted from the pool's current revision (review M1).
pod_carries_pool_revision() {
  workspace_pod_json "$1" | jq -e --arg env "$REVISION_ENV" --arg revision "$POOL_REVISION" '
    [.spec.containers[] | select(.name == "workspace") | (.env // [])[]
     | select(.name == $env) | .value] == [$revision]
  ' >/dev/null
}

# Classify one create: "warm" when its Claim names the shared pool and the
# controller adopted a member; otherwise "<pool-ref>:<launch-type>".
classify() {
  local id="$1" ref launch
  ref="$(claim_pool_ref "$id" 2>/dev/null || true)"
  launch="$(sandbox_launch_type "$id" 2>/dev/null || echo unknown)"
  if [[ "$ref" == "$POOL_PREFIX"* && "$launch" == warm ]]; then
    printf 'warm\n'
  else
    printf '%s:%s\n' "${ref:-no-pool-ref}" "$launch"
  fi
}

# Ready, unclaimed members of the proof pool: Sandboxes the pool owns that
# still carry the member label and report Ready.
pool_ready_members() {
  kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" -l "$MEMBER_LABEL" -o json |
    jq --arg pool "$POOL_NAME" '[.items[]
      | select(.metadata.deletionTimestamp == null)
      | select(any(.metadata.ownerReferences[]?; .kind == "SandboxWarmPool" and .name == $pool))
      | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length'
}

wait_pool_members() { # MIN -> waits until the pool holds MIN ready members
  local wanted="$1" deadline=$(( $(date +%s) + POOL_WAIT_SECONDS )) ready
  while (( $(date +%s) < deadline )); do
    ready="$(pool_ready_members 2>/dev/null || echo 0)"
    (( ready >= wanted )) && return 0
    sleep 2
  done
  return 1
}

discover_pool() {
  # A pool's name includes its template revision (#3572), so a rotation leaves
  # an older pool of the shape at zero replicas while pool-born claims name it.
  # The proof follows the newest pool that holds members.
  local prefix="${POOL_PREFIX}${PROOF_CPU}m-${PROOF_MEMORY}mi-${PROOF_DISK}gi-" names
  names="$(kubectl_ro get sandboxwarmpool -n "$SANDBOX_NAMESPACE" -o json |
    jq -r --arg prefix "$prefix" '[.items[] | select((.metadata.name | startswith($prefix))
      and ((.spec.replicas // 0) > 0))] | sort_by(.metadata.creationTimestamp) | last | .metadata.name // empty')"
  [[ -n "$names" ]] ||
    die "no warm pool ${prefix}* with members in ${SANDBOX_NAMESPACE}; is SANDBOX_WARM_POOL_SHAPES configured for this shape?"
  POOL_NAME="$names"
  POOL_REVISION="$(pool_json | jq -r --arg key "$REVISION_ANNOTATION" '.metadata.annotations[$key] // ""')"
  POOL_MEMBERS="$(pool_json | jq -r '.spec.replicas // 0')"
}

# C6 (#2434): after a warm hit, the bridge names exactly the bound Pod's
# Sandbox UID, no gateway half exists, and the member selector matches exactly
# one Pod in the namespace: the bound one.
bridge_selects_bound_pod() {
  local id="$1" pod="$2" sandbox sandbox_uid pod_uid selected
  sandbox="$(claim_sandbox "$id")" || return 1
  [[ -n "$sandbox" ]] || return 1
  sandbox_uid="$(kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" "$sandbox" -o json | jq -r '.metadata.uid // ""')" ||
    return 1
  pod_uid="$(jq -r '.metadata.uid // ""' <<<"$pod")"
  [[ -n "$sandbox_uid" && -n "$pod_uid" ]] || return 1
  jq -e --arg key "$SANDBOX_UID_LABEL" --arg uid "$sandbox_uid" '.metadata.labels[$key] == $uid' <<<"$pod" >/dev/null ||
    { log "bridge: $id Pod's $SANDBOX_UID_LABEL is not its Sandbox's UID"; return 1; }
  kubectl_ro get networkpolicy -n "$SANDBOX_NAMESPACE" "${DAEMON_BRIDGE_PREFIX}${id}" -o json |
    jq -e --arg key "$SANDBOX_UID_LABEL" --arg uid "$sandbox_uid" '
      .spec.podSelector == {matchLabels: {($key): $uid, "codewire.sh/type": "workspace"}}' >/dev/null ||
    { log "bridge: ${DAEMON_BRIDGE_PREFIX}${id} is missing or does not select exactly the bound Sandbox"; return 1; }
  [[ -z "$(kubectl_ro get networkpolicy -n "$SANDBOX_NAMESPACE" --ignore-not-found -o name \
    "${GATEWAY_BRIDGE_PREFIX}${id}")" ]] ||
    { log "bridge: ${GATEWAY_BRIDGE_PREFIX}${id} exists, but the gateway is gone"; return 1; }
  selected="$(kubectl_ro get pod -n "$SANDBOX_NAMESPACE" -l "${SANDBOX_UID_LABEL}=${sandbox_uid},codewire.sh/type=workspace" -o json |
    jq -c '[.items[].metadata.uid]')" || return 1
  [[ "$selected" == "[\"$pod_uid\"]" ]] || { log "bridge: $id member selector matches $selected, not exactly the bound Pod"; return 1; }
  [[ -z "$SQL_CMD" ]] || sql_binding_sandbox "$id" "$sandbox_uid"
}

check_bridge() { # N ID
  local n="$1" id="$2" pod
  pod="$(workspace_pod_json "$id" 2>/dev/null)" || { fail "hit $n: read the bound Pod for the warm-member bridge"; return; }
  if ! jq -e --arg key "$SANDBOX_UID_LABEL" '(.metadata.labels[$key] // "") != ""' <<<"$pod" >/dev/null; then
    skip "hit $n: warm-member bridge not checked: the bound Pod has no $SANDBOX_UID_LABEL label, so the agent-sandbox fork label is not deployed on this cluster and the bridge selects nothing yet"
    return
  fi
  check "hit $n: the warm-member bridge selects exactly the bound Pod" bridge_selects_bound_pod "$id" "$pod"
}

# The daemon hosts SSH and the tailnet: the environment owns no gateway
# Deployment, Service or NetworkPolicy.
no_gateway_objects() {
  local id="$1" found
  found="$(kubectl_ro get -n "$SANDBOX_NAMESPACE" --ignore-not-found -o name \
    "deployment/cw-gateway-$id" "service/cw-gateway-svc-$id" \
    "networkpolicy/cw-gw-net-$id" "networkpolicy/${GATEWAY_BRIDGE_PREFIX}${id}")" || return 1
  [[ -z "$found" ]] || { log "gateway: $id owns $(tr '\n' ' ' <<<"$found")"; return 1; }
}

bridge_absent() {
  local id="$1" present
  present="$(kubectl_ro get networkpolicy -n "$SANDBOX_NAMESPACE" --ignore-not-found -o name \
    "${DAEMON_BRIDGE_PREFIX}${id}" "${GATEWAY_BRIDGE_PREFIX}${id}")" || return 1
  [[ -z "$present" ]] || { log "bridge: $id still has $present"; return 1; }
}

# -------------------------------------------------------------------- SQL

sql_binding_sandbox() {
  # The live binding recorded the Sandbox the bridge selects.
  local id="$1" sandbox_uid="$2" out
  out="$(printf "SELECT w.sandbox_uid FROM sandbox_workspace_bindings w JOIN sandbox_environment_backend b ON b.environment_id = w.environment_id AND b.pod_uid = w.pod_uid WHERE w.environment_id = '%s' AND w.released_at IS NULL;\n" "$id" |
    sql_rows | tr -d '[:space:]')" || return 1
  [[ "$out" == "$sandbox_uid" ]] || { log "bridge: $id live binding records $out, not $sandbox_uid"; return 1; }
}

sql_binding() {
  # One live binding for the environment's current Pod with Pod scope.
  local id="$1" uid="$2" out
  [[ -n "$SQL_CMD" ]] || return 0
  out="$(printf "SELECT w.credential_scope FROM sandbox_workspace_bindings w JOIN sandbox_environment_backend b ON b.environment_id = w.environment_id AND b.pod_uid = w.pod_uid WHERE w.environment_id = '%s' AND w.pod_uid = '%s' AND w.released_at IS NULL;\n" "$id" "$uid" |
    sql | tr -d '[:space:]')" || return 1
  [[ "$out" == *pod* ]]
}

# Billing opens at bind (C3): every sandbox session of the environment starts
# at or after a binding of that same Sandbox. Prints "<bad>/<sessions>". The
# billing loop ticks every 60 s, so an environment measured and removed
# quickly may have no session yet; zero sessions is reported, not failed.
# The current incarnation completed access_ready, and the environment's live
# bound Pod has recorded a host key: the key clients are served.
sql_access_ready() {
  local id="$1" uid="$2" out
  [[ -n "$SQL_CMD" ]] || return 0
  out="$(printf "SELECT (SELECT count(*) FROM environment_logs WHERE environment_id = '%s' AND phase = 'access_ready' AND status = 'completed') || '|' || coalesce((SELECT k.pod_uid FROM sandbox_environment_backend b JOIN sandbox_workspace_bindings w ON w.environment_id = b.environment_id AND w.pod_uid = b.pod_uid AND w.released_at IS NULL JOIN sandbox_ssh_host_keys k ON k.environment_id = b.environment_id AND k.pod_uid = b.pod_uid WHERE b.environment_id = '%s'), '');\n" "$id" "$id" |
    sql_rows | tr -d '[:space:]')" || return 1
  [[ "${out%%|*}" =~ ^[1-9][0-9]*$ && "${out#*|}" == "$uid" ]] ||
    { log "access: $id access_ready rows|host-key Pod = $out, want >=1|$uid"; return 1; }
}

sql_billing_before_bind() {
  local id_list="$1"
  printf "SELECT count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM sandbox_workspace_bindings w WHERE w.environment_id = s.environment_id AND w.sandbox_uid = s.runtime_uid AND w.bound_at <= s.started_at)) || '/' || count(*) FROM sandbox_running_sessions s WHERE s.runtime_type = 'sandbox' AND s.environment_id IN (%s);\n" "$id_list" |
    sql_rows | tr -d '[:space:]'
}

sql_billing_at_bind() {
  local id="$1" out
  [[ -n "$SQL_CMD" ]] || return 0
  out="$(sql_billing_before_bind "'$id'")" || return 1
  log "billing: $id sessions starting before their bind/total = $out"
  [[ "$out" == 0/* ]]
}

sql_released_after_destroy() {
  # Once destroyed, the environment has no live binding.
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

sql_id_list() { # IDS... -> 'a','b'
  local id out=""
  for id in "$@"; do
    [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || continue
    out+="${out:+,}'$id'"
  done
  printf '%s' "$out"
}

# --------------------------------------------------------------- journeys

journey_preflight() {
  local pool template ready
  discover_pool
  pool="$(pool_json)"
  log "pool: $POOL_NAME replicas=$POOL_MEMBERS readyReplicas=$(jq -r '.status.readyReplicas // 0' <<<"$pool") revision=${POOL_REVISION:0:12}"
  check "preflight: pool carries a pool revision" test -n "$POOL_REVISION"
  check "preflight: a capable controller observed the pool's generation" \
    json_true '(.status.observedGeneration // 0) >= 1 and .status.observedGeneration == .metadata.generation' <<<"$pool"
  check "preflight: pool names its own template" \
    json_true --arg name "$POOL_NAME" '.spec.sandboxTemplateRef.name == $name' <<<"$pool"
  template="$(kubectl_ro get sandboxtemplate -n "$SANDBOX_NAMESPACE" "$POOL_NAME" -o json 2>/dev/null || true)"
  check "preflight: pool template exists at the pool's revision" \
    json_true --arg key "$REVISION_ANNOTATION" --arg revision "$POOL_REVISION" \
      '.metadata.annotations[$key] == $revision' <<<"${template:-null}"
  check "preflight: pool holds members" test "$POOL_MEMBERS" -ge 1
  ready="$(pool_ready_members || echo 0)"
  log "preflight: $ready ready unclaimed member(s)"
  (( POOL_MEMBERS >= 1 )) || die "pool $POOL_NAME holds no members; nothing to prove"
}

ensure_pool() { [[ -n "$POOL_NAME" ]] || discover_pool; }

journey_hits() {
  local n id started elapsed path uid warm=0
  ensure_pool
  for ((n = 1; n <= PROOF_HITS; n++)); do
    if ! wait_pool_members 1; then fail "hit $n: pool $POOL_NAME has no ready member after ${POOL_WAIT_SECONDS}s"; continue; fi
    id="$(create_env "$PROOF_CPU")" || { fail "hit $n: cw create"; continue; }
    started="$(<"$TMPDIR_PROOF/create-started")"
    start_first_ssh "$id" "$started" || fail "hit $n: could not start the first-SSH timer"
    if ! wait_ready "$id"; then
      abandon_first_ssh
      fail "hit $n: $id did not become ready"
      remove_env "$id" || true
      continue
    fi
    elapsed=$(( $(now_ms) - started ))
    path="$(classify "$id")"
    if [[ "$path" == warm ]]; then
      record_first_ssh "hit $n" "$id" FIRST_SSH_WARM
    else
      record_first_ssh "hit $n" "$id"
    fi
    if [[ "$path" == warm ]]; then
      warm=$((warm + 1))
      WARM_IDS+=("$id")
      HIT_TIMES+=("$elapsed")
      pass "hit $n: $id adopted a warm member, ready in ${elapsed} ms (client side)"
      check "hit $n: Pod carries the pool's current revision" pod_carries_pool_revision "$id"
      check_bridge "$n" "$id"
    else
      COLD_IDS+=("$id")
      fail "hit $n: $id was not warm ($path), ready in ${elapsed} ms"
    fi
    check "hit $n: identity-free workspace Pod" pod_is_identity_free "$id"
    check "hit $n: daemon reachable through the platform API" daemon_reachable "$id"
    check "hit $n: no gateway objects" no_gateway_objects "$id"
    check "hit $n: SSH presents the host key the platform recorded" ssh_presents_recorded_key "$id"
    if [[ -n "$SQL_CMD" ]]; then
      uid="$(pod_uid "$id")"
      check "hit $n: one live Pod-scope binding for the adopted Pod" sql_binding "$id" "$uid"
      check "hit $n: access_ready completed with a host key recorded by the adopted Pod" sql_access_ready "$id" "$uid"
      check "hit $n: billing starts at or after the bind" sql_billing_at_bind "$id"
    fi
    if remove_env "$id"; then
      if [[ -n "$SQL_CMD" ]]; then
        check "hit $n: no live binding once destroyed" sql_released_after_destroy "$id"
        check "hit $n: no warm-member bridge once destroyed" bridge_absent "$id"
      fi
    else
      log "hit $n: remove failed"
    fi
  done
  log "hits: $warm warm of $PROOF_HITS"
  if ((${#HIT_TIMES[@]})); then
    log "client-side warm create ms (sorted): $(printf '%s\n' "${HIT_TIMES[@]}" | sort -n | tr '\n' ' ')"
    log "client-side warm p50 ms: $(printf '%s\n' "${HIT_TIMES[@]}" | percentile 50) p95 ms: $(printf '%s\n' "${HIT_TIMES[@]}" | percentile 95)"
  fi
  if ((${#FIRST_SSH_WARM[@]})); then
    local first_p50 first_p95
    first_p50="$(printf '%s\n' "${FIRST_SSH_WARM[@]}" | percentile 50)"
    first_p95="$(printf '%s\n' "${FIRST_SSH_WARM[@]}" | percentile 95)"
    log "warm create to first SSH over $FIRST_SSH_TRANSPORT ms (sorted): $(printf '%s\n' "${FIRST_SSH_WARM[@]}" | sort -n | tr '\n' ' ')"
    target_check "hits: warm create to first SSH over $FIRST_SSH_TRANSPORT p50 ${first_p50} ms <= ${TARGET_FIRST_SSH_P50_MS} ms" \
      test "$first_p50" -le "$TARGET_FIRST_SSH_P50_MS"
    target_check "hits: warm create to first SSH over $FIRST_SSH_TRANSPORT p95 ${first_p95} ms <= ${TARGET_FIRST_SSH_P95_MS} ms" \
      test "$first_p95" -le "$TARGET_FIRST_SSH_P95_MS"
  fi
  check "hits: at least $PROOF_MIN_HITS warm hits" test "$warm" -ge "$PROOF_MIN_HITS"
}

journey_miss() {
  local burst n id ids=() starts=() started elapsed path cold=0 ready_ok
  ensure_pool
  burst=$((POOL_MEMBERS + 1))
  if ! wait_pool_members "$POOL_MEMBERS"; then
    fail "miss: pool $POOL_NAME did not fill to $POOL_MEMBERS ready members"
    return
  fi
  for ((n = 1; n <= burst; n++)); do
    id="$(create_env "$PROOF_CPU")" || { fail "miss: create $n"; continue; }
    started="$(<"$TMPDIR_PROOF/create-started")"
    ids+=("$id")
    starts+=("$started")
  done
  for n in "${!ids[@]}"; do
    id="${ids[$n]}"
    ready_ok=0
    wait_ready "$id" && ready_ok=1
    elapsed=$(( $(now_ms) - ${starts[$n]} ))
    path="$(classify "$id")"
    if [[ "$path" == warm ]]; then
      WARM_IDS+=("$id")
      log "miss: $id warm, ready in ${elapsed} ms"
    else
      COLD_IDS+=("$id")
      log "miss: $id not warm ($path), ready in ${elapsed} ms"
      if [[ "$path" == "$POOL_PREFIX"* ]]; then
        cold=$((cold + 1))
        check "miss: $id found the pool empty yet started" test "$ready_ok" = 1
        check "miss: $id identity-free" pod_is_identity_free "$id"
      fi
    fi
    [[ "$ready_ok" == 1 ]] || fail "miss: $id did not become ready"
  done
  check "miss: at least one of $burst concurrent creates found the pool empty" test "$cold" -ge 1
  for id in "${ids[@]}"; do remove_env "$id" || log "miss: remove $id failed"; done
}

journey_off_shape() {
  local id started elapsed ref launch
  id="$(create_env "$OFF_SHAPE_CPU")" || { fail "off-shape: create"; return; }
  started="$(<"$TMPDIR_PROOF/create-started")"
  start_first_ssh "$id" "$started" || fail "off-shape: could not start the first-SSH timer"
  if ! wait_ready "$id"; then
    abandon_first_ssh
    fail "off-shape: $id did not become ready"
    remove_env "$id" || true
    return
  fi
  elapsed=$(( $(now_ms) - started ))
  record_first_ssh "off-shape" "$id"
  COLD_IDS+=("$id")
  ref="$(claim_pool_ref "$id")"
  launch="$(sandbox_launch_type "$id" || echo unknown)"
  log "off-shape: $id (${OFF_SHAPE_CPU}m) ready in ${elapsed} ms via ${ref:-none} launch-type ${launch}"
  check "off-shape: claim names its own shadow pool" test "${ref#"$SHADOW_PREFIX"}" != "$ref"
  check "off-shape: no warm adoption" test "$launch" != warm
  check "off-shape: identity-free workspace Pod" pod_is_identity_free "$id"
  remove_env "$id" || true
}

# Every unbound member Pod, of every shared pool.
member_pods_json() {
  kubectl_ro get pod -n "$SANDBOX_NAMESPACE" -l "$MEMBER_LABEL" -o json
}

pool_revisions_json() {
  kubectl_ro get sandboxwarmpool -n "$SANDBOX_NAMESPACE" -o json |
    jq --arg prefix "$POOL_PREFIX" --arg key "$REVISION_ANNOTATION" \
      '[.items[] | select(.metadata.name | startswith($prefix)) | .metadata.annotations[$key] // empty]'
}

members_identity_free() {
  jq -e '
    ["codewire.sh/environment-id", "codewire.sh/org-id",
     "codewire.sh/environment-operation-generation", "codewire.sh/isolation-tier"] as $identity
    | all(.items[];
        ((.metadata.labels // {}) | keys) as $labels
        | ($identity | all(. as $key | $labels | index($key) | not))
        and ([.spec.containers[] | (.env // [])[].name]
             | (index("CODEWIRE_DAEMON_AUTH_TOKEN") | not) and (index("CODEWIRE_ENVIRONMENT_ID") | not))
        and (.spec.automountServiceAccountToken == false))
  ' <"$1" >/dev/null
}

members_audiences_bounded() {
  jq -e '
    ["codewire.internal.workspace-binding.v1", "codewire.internal.credential-workspace.v1"] as $allowed
    | all(.items[];
        [(.spec.volumes // [])[] | .projected.sources[]? | .serviceAccountToken? // empty | .audience]
        | all(. as $audience | $allowed | index($audience) != null))
  ' <"$1" >/dev/null
}

members_at_pool_revision() {
  local revisions
  revisions="$(pool_revisions_json)" || return 1
  jq -e --argjson revisions "$revisions" --arg env "$REVISION_ENV" '
    all(.items[];
      [.spec.containers[] | select(.name == "workspace") | (.env // [])[]
       | select(.name == $env) | .value] as $values
      | ($values | length) == 1 and ($revisions | index($values[0]) != null))
  ' <"$1" >/dev/null
}

members_young() {
  jq -e 'all(.items[]; (now - (.metadata.creationTimestamp | fromdateiso8601)) < 86400)' <"$1" >/dev/null
}

members_on_schedulable_nodes() {
  local node unschedulable
  while IFS= read -r node; do
    [[ -n "$node" ]] || continue
    unschedulable="$(kubectl_ro get node "$node" -o json | jq -r '.spec.unschedulable // false')" ||
      { log "could not read node $node"; return 1; }
    [[ "$unschedulable" == false ]] || { log "member on cordoned node $node"; return 1; }
  done < <(jq -r '.items[].spec.nodeName // empty' <"$1" | sort -u)
}

# codewire#3626: a pool template's NetworkPolicy admits exactly
# orchestration's identity (its namespace AND its Pod labels, in one peer) on
# TCP 7777 and 2222, nothing more, from a member's birth.
pool_policies_admit_only_orchestration() {
  local name
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    kubectl_ro get networkpolicy -n "$SANDBOX_NAMESPACE" "${name}-network-policy" -o json |
      jq -e --arg ns "$SERVER_NAMESPACE" '(.spec.policyTypes | index("Ingress")) != null and .spec.ingress == [{
        "from": [{
          "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": $ns } },
          "podSelector": { "matchLabels": {
            "app.kubernetes.io/component": "orchestration", "app.kubernetes.io/name": "codewire" } }
        }],
        "ports": [{ "port": 7777, "protocol": "TCP" }, { "port": 2222, "protocol": "TCP" }]
      }]' >/dev/null ||
      { log "pool $name: template NetworkPolicy is missing or admits more than orchestration on TCP 7777 and 2222"; return 1; }
  done < <(kubectl_ro get sandboxwarmpool -n "$SANDBOX_NAMESPACE" -o json |
    jq -r --arg prefix "$POOL_PREFIX" '.items[] | select(.metadata.name | startswith($prefix)) | .metadata.name')
}

open_sessions_without_binding() {
  sql_rows <<'SQL' | tr -d '[:space:]'
SELECT count(*)
  FROM sandbox_running_sessions s
 WHERE s.runtime_type = 'sandbox' AND s.ended_at IS NULL
   AND NOT EXISTS (
     SELECT 1 FROM sandbox_workspace_bindings w
      WHERE w.environment_id = s.environment_id AND w.released_at IS NULL);
SQL
}

destroyed_live_bindings() {
  printf '%s\n' "SELECT count(*) FROM sandbox_workspace_bindings w JOIN environments e ON e.id = w.environment_id WHERE w.released_at IS NULL AND e.state = 'destroyed';" |
    sql_rows | tr -d '[:space:]'
}

journey_invariants() {
  local members="$TMPDIR_PROOF/members.json" count
  member_pods_json >"$members" || { fail "invariants: list member Pods"; return; }
  count="$(jq '.items | length' "$members")"
  log "invariants: $count unbound member Pod(s)"
  check "invariants: members carry no environment, organization, generation or tier label, no environment token, no API token" \
    members_identity_free "$members"
  check "invariants: members mount only workspace-audience projected tokens" members_audiences_bounded "$members"
  check "invariants: every member carries one current pool revision" members_at_pool_revision "$members"
  check "invariants: no member is older than 24 h" members_young "$members"
  check "invariants: no member runs on a cordoned node" members_on_schedulable_nodes "$members"
  check "invariants: every shared pool's template NetworkPolicy admits exactly orchestration's identity on TCP 7777 and 2222 in one AND-ed peer" \
    pool_policies_admit_only_orchestration
  if [[ -n "$SQL_CMD" ]]; then
    check "invariants: no open billing session without a live binding" \
      test "$(open_sessions_without_binding)" = 0
    check "invariants: no destroyed environment has a live binding" \
      test "$(destroyed_live_bindings)" = 0
  fi
}

stats_for() { # PATH IDS -> table rows
  local path="$1" id_list="$2"
  sql_rows <<SQL
WITH ids(id) AS (SELECT unnest(ARRAY[${id_list}]::text[])),
complete AS (
  SELECT EXTRACT(EPOCH FROM (l.created_at - e.created_at)) * 1000 AS ms
    FROM ids
    JOIN environments e ON e.id = ids.id
    JOIN LATERAL (
      SELECT created_at FROM environment_logs
       WHERE environment_id = e.id AND phase = 'complete' AND status = 'completed'
       ORDER BY created_at LIMIT 1) l ON true
)
SELECT '${path}', 'complete', count(*),
       round(percentile_cont(0.5) WITHIN GROUP (ORDER BY ms))::bigint,
       round(percentile_cont(0.95) WITHIN GROUP (ORDER BY ms))::bigint
  FROM complete
UNION ALL
SELECT '${path}', l.phase, count(*),
       round(percentile_cont(0.5) WITHIN GROUP (ORDER BY (l.metadata->>'duration_ms')::double precision))::bigint,
       round(percentile_cont(0.95) WITHIN GROUP (ORDER BY (l.metadata->>'duration_ms')::double precision))::bigint
  FROM ids
  JOIN environment_logs l ON l.environment_id = ids.id
 WHERE l.phase IN ('create_claim', 'wait_for_ready', 'workspace_bind', 'access_ready')
   AND l.status = 'completed' AND l.metadata ? 'duration_ms'
 GROUP BY l.phase;
SQL
}

journey_stats() {
  local warm_ids cold_ids all_ids rows="$TMPDIR_PROOF/stats.txt" p50 p95 billing
  warm_ids="$(sql_id_list "${WARM_IDS[@]}")"
  cold_ids="$(sql_id_list "${COLD_IDS[@]}")"
  : >"$rows"
  [[ -z "$warm_ids" ]] || stats_for warm "$warm_ids" >>"$rows" || fail "stats: warm query"
  [[ -z "$cold_ids" ]] || stats_for cold "$cold_ids" >>"$rows" || fail "stats: cold query"
  log "stats (path | stage | samples | p50 ms | p95 ms), server side from environments.created_at:"
  awk -F'|' 'NF >= 5 {printf "[warm-pool-proof]   %-5s %-15s %4s %8s %8s\n", $1, $2, $3, $4, $5}' "$rows" >&2
  p50="$(awk -F'|' '$1 == "warm" && $2 == "complete" {print $4}' "$rows")"
  p95="$(awk -F'|' '$1 == "warm" && $2 == "complete" {print $5}' "$rows")"
  if [[ -z "$p50" ]]; then
    fail "stats: no warm complete samples"
  else
    target_check "stats: warm complete p50 ${p50} ms <= ${TARGET_HIT_P50_MS} ms" test "$p50" -le "$TARGET_HIT_P50_MS"
    target_check "stats: warm complete p95 ${p95} ms <= ${TARGET_HIT_P95_MS} ms" test "$p95" -le "$TARGET_HIT_P95_MS"
  fi
  all_ids="$(sql_id_list "${WARM_IDS[@]}" "${COLD_IDS[@]}")"
  if [[ -n "$all_ids" ]]; then
    billing="$(sql_billing_before_bind "$all_ids")" || billing=error
    log "stats: billing sessions starting before their bind/total over this run: $billing"
    check "stats: no billing session of this run started before its bind" test "${billing%%/*}" = 0
  fi
}

# Targets are information unless --enforce-targets.
target_check() {
  local label="$1"
  shift
  if "$@"; then
    pass "$label"
  elif [[ "$ENFORCE_TARGETS" == 1 ]]; then
    fail "$label"
  else
    RESULTS+=("MISS $label")
    log "MISS (target, not enforced) $label"
  fi
}

for journey in "${JOURNEYS[@]}"; do
  log "journey: $journey"
  case "$journey" in
    preflight) journey_preflight ;;
    hits) journey_hits ;;
    miss) journey_miss ;;
    off-shape) journey_off_shape ;;
    invariants) journey_invariants ;;
    stats) journey_stats ;;
  esac
done

printf '%s\n' "${RESULTS[@]}"
if ((FAILURES)); then
  die "$FAILURES check(s) failed"
fi
log "all checks passed"
