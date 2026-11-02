#!/usr/bin/env bash
# Shared warm pools (Program #2238 C5) on an explicitly named retained Kind
# cluster: pool hits timed against cold creates, a forced pool-empty miss, an
# off-shape create going cold, stale-revision refusal during a rotation,
# stop/start keeping the pool-born PVC, destroy, the cordoned-node reap, and
# the unbound-member negatives (no daemon listener, no binding for any
# environment, no credential, no billing).
#
# It needs the C0 agent-sandbox controller (SandboxWarmPool
# status.observedGeneration), a configured SANDBOX_WARM_POOL_SHAPES entry with
# members, and the canonical workspace image on every node
# (make kind-runtime-images). It changes the cluster only reversibly: it
# rolls orchestration three times for the rotation (another diagnostic
# runtime, its pool reconciler briefly paused) and restores the settings it
# found, cordons and uncordons the member nodes, and destroys the
# environments it created.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != "1" ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

WARM_POOL_ORG=org_contract_1
WARM_POOL_COOKIE='codewire.session_token=contract-admin-session-token'
WARM_POOL_TIMEOUT_SECONDS="${WARM_POOL_TIMEOUT_SECONDS:-300}"
WARM_POOL_HITS="${WARM_POOL_HITS:-3}"
WARM_POOL_MEMBER_LABEL=agents.x-k8s.io/warm-pool-sandbox
# Environments still to destroy, and every environment this run created.
WARM_POOL_ENVS=()
WARM_POOL_CREATED=()
WARM_POOL_CORDONED=()
# The orchestration settings the rotation journey changes, as found, so the
# EXIT trap can put them back ("<runtime profile>|<loops>"; "-" when unset).
WARM_POOL_RESTORE_CONFIG=""
WARM_POOL_RESULTS=()
# The e2e overlay configures no pool: its other suites create with the
# side-loaded verified workspace image, never the canonical one a member runs.
# Unless the cluster already configures a shape with members, the suite sets
# this one on orchestration and removes it again on exit.
WARM_POOL_SUITE_SHAPES="500m/1024Mi/5Gi=1"
WARM_POOL_RESTORE_SHAPES=0
WP_CPU="" WP_MEMORY="" WP_DISK="" WP_MEMBERS="" WP_POOL="" WP_IMAGE=""
WP_CODE="" WP_BODY="" WP_ID="" WP_HIT="" WP_COLD=""

run_retained_warm_pools_suite() {
  require_kind_errexit
  require_tool curl
  require_tool docker
  require_tool jq
  require_tool kind
  require_tool kubectl
  require_tool python3

  [[ "$WARM_POOL_HITS" =~ ^[1-9][0-9]?$ ]] || {
    echo "::error::WARM_POOL_HITS must be 1-99"
    return 2
  }
  trap warm_pools_suite_cleanup EXIT
  validate_retained_cluster_identity
  warm_pool_configure_suite_shape
  warm_pool_preflight
  # A cold create first, kept until the pool fills: on a cluster with no
  # SandboxWarmPool, its shadow pool is where the controller can show its
  # claim safety unless the reconciler bootstraps an empty pool itself.
  warm_pool_off_shape_cold
  warm_pool_wait_ready_members "$WP_MEMBERS"
  warm_pool_destroy "$WP_COLD"
  warm_pool_hits
  warm_pool_forced_miss
  warm_pool_wait_ready_members "$WP_MEMBERS"
  warm_pool_unbound_negatives
  warm_pool_stop_start_destroy
  warm_pool_stale_revision
  warm_pool_cordon_reap
  warm_pool_no_member_billed
  warm_pool_report
  log "retained warm-pools suite green"
}

# shellcheck disable=SC2329 # Invoked by the EXIT trap.
warm_pools_suite_cleanup() {
  local status=$? node id removed
  set +e
  for node in "${WARM_POOL_CORDONED[@]}"; do
    kubectl uncordon "$node" >/dev/null
  done
  if [ -n "$WARM_POOL_RESTORE_CONFIG" ]; then
    warm_pool_set_orchestration "${WARM_POOL_RESTORE_CONFIG%%|*}" "${WARM_POOL_RESTORE_CONFIG#*|}" >/dev/null
  fi
  for id in "${WARM_POOL_ENVS[@]}"; do
    warm_pool_rpc DeleteEnvironment \
      "{\"orgId\":\"${WARM_POOL_ORG}\",\"environmentId\":\"${id}\"}" >/dev/null
  done
  if [ "$WARM_POOL_RESTORE_SHAPES" = 1 ]; then
    # Cleanup runs without errexit; a pool left behind still fails the run.
    warm_pool_remove_suite_pool
    removed=$?
    [ "$removed" = 0 ] || status=1
  fi
  (exit "$status")
  retained_suite_cleanup
}

now_ms() { date +%s%3N; }

warm_pool_sql() {
  kubectl -n "$NS" exec deploy/postgres -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 -qAtc "$1"
}

# One Connect unary call through the ingress as the contract admin. Sets
# WP_CODE and WP_BODY; retries only while the ingress location settles (503).
warm_pool_rpc() {
  local method="$1" body="$2" headers attempt
  headers="$(mktemp "$RUN_DIR/warm-pool-rpc.XXXXXX")"
  for attempt in $(seq 1 15); do
    WP_BODY="$(curl -sS -D "$headers" -X POST \
      -H "cookie: ${WARM_POOL_COOKIE}" -H 'content-type: application/json' \
      -d "$body" "${KIND_INGRESS_URL}/codewire.v1.EnvironmentService/${method}")" || WP_BODY=""
    WP_CODE="$(awk 'NR==1{print $2}' "$headers")"
    [ "$WP_CODE" = 503 ] || break
    [ "$attempt" -lt 15 ] && sleep 2
  done
  rm -f "$headers"
}

warm_pool_canonical_image() {
  sed -n 's/^pub const PUBLIC_IMAGE: &str = "\(.*\)";$/\1/p' \
    "$ROOT/crates/codewire-workspace-image/src/pin.rs"
}

# The first configured shape with members, the canonical image on every
# node, and the controller's pool CRD with status.observedGeneration.
warm_pool_preflight() {
  local shapes entry node images
  shapes="$(warm_pool_effective_shapes)"
  entry="$(tr ',' '\n' <<<"$shapes" | grep -E '^[1-9][0-9]*m/[1-9][0-9]*Mi/[1-9][0-9]*Gi=([1-9]|1[0-6])$' | head -n1 || true)"
  if [ -z "$entry" ]; then
    echo "::error::SANDBOX_WARM_POOL_SHAPES configures no pool with members: '${shapes}'"
    return 1
  fi
  WP_CPU="${entry%%m/*}"
  WP_MEMORY="${entry#*m/}"
  WP_MEMORY="${WP_MEMORY%%Mi/*}"
  WP_DISK="${entry#*Mi/}"
  WP_DISK="${WP_DISK%%Gi=*}"
  WP_MEMBERS="${entry##*=}"
  WP_IMAGE="$(warm_pool_canonical_image)"
  if ! [[ "$WP_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "::error::canonical workspace image is not digest-pinned: ${WP_IMAGE:-missing}"
    return 1
  fi
  for node in $(kind get nodes --name "$KIND_CLUSTER_NAME"); do
    images="$(docker exec "$node" ctr -n k8s.io images ls -q)"
    if ! grep -Fxq "$WP_IMAGE" <<<"$images"; then
      echo "::error::${node} lacks the canonical workspace image ${WP_IMAGE}; run make kind-runtime-images"
      return 1
    fi
  done
  if [ "$(kubectl get crd sandboxwarmpools.extensions.agents.x-k8s.io -o json |
      jq -r '[.spec.versions[] | select(.storage) | .schema.openAPIV3Schema.properties.status.properties.observedGeneration.type] | first // ""')" != integer ]; then
    echo "::error::the SandboxWarmPool CRD records no status.observedGeneration; deploy the C0 agent-sandbox controller"
    return 1
  fi
  log "warm pool shape ${WP_CPU}m/${WP_MEMORY}Mi/${WP_DISK}Gi with ${WP_MEMBERS} member(s), image ${WP_IMAGE##*@}"
}

warm_pool_name() {
  kubectl -n "$SANDBOX_NS" get sandboxwarmpools -o json |
    jq -r --arg prefix "cw-pool-${WP_CPU}m-${WP_MEMORY}mi-${WP_DISK}gi-" \
      '[.items[] | select(.metadata.name | startswith($prefix)) | .metadata.name] | if length == 1 then .[0] else "" end'
}

# "<revision> <ready member UIDs, space separated>" for the shape's pool, when
# the controller observed its current generation and its template is at the
# pool's revision; empty otherwise. While any unclaimed member still carries
# another revision (a rotation), no member is listed: creates route cold
# until the reconciler replaces it.
warm_pool_state() {
  local pool template revision members
  pool="$(kubectl -n "$SANDBOX_NS" get sandboxwarmpool "$WP_POOL" -o json 2>/dev/null)" || return 0
  jq -e '.status.observedGeneration == .metadata.generation' <<<"$pool" >/dev/null || return 0
  revision="$(jq -r '.metadata.annotations["codewire.sh/pool-revision"] // ""' <<<"$pool")"
  template="$(kubectl -n "$SANDBOX_NS" get sandboxtemplate "$WP_POOL" \
    -o jsonpath='{.metadata.annotations.codewire\.sh/pool-revision}' 2>/dev/null)" || return 0
  [ -n "$revision" ] && [ "$template" = "$revision" ] || return 0
  members="$(kubectl -n "$SANDBOX_NS" get sandboxes -l "$WARM_POOL_MEMBER_LABEL" -o json |
    jq -r --arg pool "$WP_POOL" --arg revision "$revision" '[.items[]
      | select(.metadata.deletionTimestamp == null)
      | select(any(.metadata.ownerReferences[]?; .kind == "SandboxWarmPool" and .name == $pool))]
      | if any(.[]; [.spec.podTemplate.spec.containers[]? | select(.name == "workspace")
            | .env[]? | select(.name == "CODEWIRE_WORKSPACE_POOL_REVISION") | .value] != [$revision])
        then ""
        else [.[] | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
          | .metadata.uid] | sort | join(" ")
        end')"
  printf '%s %s\n' "$revision" "$members"
}

warm_pool_ready_count() {
  local state
  state="$(warm_pool_state)"
  # shellcheck disable=SC2086 # One word per member UID.
  set -- $state
  printf '%s\n' "$(( $# > 0 ? $# - 1 : 0 ))"
}

warm_pool_wait_ready_members() {
  local want="$1" deadline count=0
  deadline=$(( $(date +%s) + WARM_POOL_TIMEOUT_SECONDS ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    [ -n "$WP_POOL" ] || WP_POOL="$(warm_pool_name)"
    # Orchestration routes to the pool only while its template is this
    # replica's rendering.
    if [ -n "$WP_POOL" ] && [ "$(warm_pool_metric codewire_warm_pool_template_current \
        "shape=\"${WP_CPU}m-${WP_MEMORY}mi-${WP_DISK}gi\"")" = 1 ]; then
      count="$(warm_pool_ready_count)"
      [ "$count" -ge "$want" ] && {
        log "warm pool ${WP_POOL} holds ${count} ready member(s)"
        return 0
      }
    fi
    sleep 2
  done
  echo "::error::warm pool ${WP_POOL:-for ${WP_CPU}m/${WP_MEMORY}Mi/${WP_DISK}Gi} did not reach ${want} ready member(s) (has ${count})"
  kubectl -n "$SANDBOX_NS" get sandboxwarmpools,sandboxes -o wide >&2 || true
  kubectl -n "$NS" logs deploy/codewire-orchestration --tail=60 | grep -i 'warm pool' >&2 || true
  return 1
}

# Create one environment of the given shape with the canonical image; its ID
# is WP_ID. Run as a plain statement: it records the environment for
# cleanup. The contract fixture's create rate limit is cleared first.
warm_pool_create() {
  local label="$1" cpu="$2" memory="$3" disk="$4" id
  warm_pool_sql "DELETE FROM rate_limit WHERE key LIKE 'env_create:%'" >/dev/null
  warm_pool_rpc CreateEnvironment "$(jq -cn --arg org "$WARM_POOL_ORG" \
    --arg name "kind-warm-${label}-${RANDOM}" --arg image "$WP_IMAGE" \
    --argjson cpu "$cpu" --arg memory "$memory" --arg disk "$disk" \
    '{orgId: $org, name: $name, omitApplicationPreviews: true,
      projectSpec: {schemaVersion: 1, image: $image, workingDirectory: "/workspace",
        resources: {cpuMillicores: $cpu, memoryMib: $memory, diskGib: $disk}}}')"
  id="$(jq -r '.environment.id // empty' <<<"$WP_BODY" 2>/dev/null || true)"
  if [ "$WP_CODE" != 200 ] || [ -z "$id" ]; then
    echo "::error::CreateEnvironment ${label} failed: code=${WP_CODE} body=${WP_BODY}"
    return 1
  fi
  WP_ID="$id"
  WARM_POOL_ENVS+=("$id")
  WARM_POOL_CREATED+=("$id")
}

warm_pool_wait_state() {
  local id="$1" want="$2" deadline state
  deadline=$(( $(date +%s) + WARM_POOL_TIMEOUT_SECONDS ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    state="$(warm_pool_sql "SELECT e.state || ':' || COALESCE(b.setup_complete::text, 'none')
      FROM environments e LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id
      WHERE e.id = '${id}'")" || state=""
    # shellcheck disable=SC2254 # want is a glob over "<state>:<setup_complete>".
    case "$state" in
      $want) return 0 ;;
      error:*)
        echo "::error::environment ${id} failed: $(warm_pool_sql "SELECT COALESCE(error_reason, '') FROM environments WHERE id = '${id}'")"
        return 1
        ;;
    esac
    sleep 0.25
  done
  echo "::error::environment ${id} did not reach ${want} (last ${state:-missing})"
  return 1
}

# Server-side milliseconds from the environment row to its completed setup.
warm_pool_complete_ms() {
  warm_pool_sql "SELECT round(extract(epoch FROM (l.created_at - e.created_at)) * 1000)::bigint
    FROM environments e JOIN environment_logs l ON l.environment_id = e.id
    WHERE e.id = '$1' AND l.phase = 'complete' AND l.status = 'completed'
    ORDER BY l.created_at LIMIT 1"
}

warm_pool_claim() {
  kubectl -n "$SANDBOX_NS" get sandboxclaim "sandbox-$1" -o json
}

warm_pool_sandbox_name() {
  warm_pool_claim "$1" | jq -r '.status.sandbox.name // empty'
}

# warm: a cw-pool- claim adopted a ready member; pool-miss: a cw-pool- claim
# found no ready member and the controller created the Sandbox; cold: a
# per-environment shadow pool.
warm_pool_path() {
  local claim pool sandbox launch
  claim="$(warm_pool_claim "$1")"
  pool="$(jq -r '.spec.warmPoolRef.name // ""' <<<"$claim")"
  sandbox="$(jq -r '.status.sandbox.name // ""' <<<"$claim")"
  launch="$(kubectl -n "$SANDBOX_NS" get sandbox "$sandbox" \
    -o jsonpath='{.metadata.labels.agents\.x-k8s\.io/launch-type}')"
  case "$pool:$launch" in
    cw-pool-*:warm) echo warm ;;
    cw-pool-*:*) echo pool-miss ;;
    *) echo cold ;;
  esac
}

warm_pool_pod() {
  local sandbox pod
  sandbox="$(warm_pool_sandbox_name "$1")"
  pod="$(kubectl -n "$SANDBOX_NS" get sandbox "$sandbox" -o json |
    jq -r --arg name "$sandbox" '.metadata.annotations["agents.x-k8s.io/pod-name"] // $name')"
  kubectl -n "$SANDBOX_NS" get pod "$pod" -o json
}

warm_pool_pvc_uid() {
  local sandbox
  sandbox="$(warm_pool_sandbox_name "$1")"
  kubectl -n "$SANDBOX_NS" get pvc "workspace-${sandbox}" -o jsonpath='{.metadata.uid}'
}

# Create, wait for setup to complete, and record one timed start (WP_ID).
warm_pool_timed_create() {
  local label="$1" cpu="$2" memory="$3" disk="$4" started elapsed
  started="$(now_ms)"
  warm_pool_create "$label" "$cpu" "$memory" "$disk"
  warm_pool_wait_state "$WP_ID" running:true
  elapsed=$(( $(now_ms) - started ))
  WARM_POOL_RESULTS+=("${label}|$(warm_pool_path "$WP_ID")|${elapsed}|$(warm_pool_complete_ms "$WP_ID")")
}

warm_pool_destroy() {
  local id="$1" kept=() existing
  warm_pool_rpc DeleteEnvironment "{\"orgId\":\"${WARM_POOL_ORG}\",\"environmentId\":\"${id}\"}"
  if [ "$WP_CODE" != 200 ]; then
    echo "::error::DeleteEnvironment ${id} failed: code=${WP_CODE} body=${WP_BODY}"
    return 1
  fi
  warm_pool_wait_state "$id" "destroyed:*"
  for existing in "${WARM_POOL_ENVS[@]}"; do
    [ "$existing" = "$id" ] || kept+=("$existing")
  done
  WARM_POOL_ENVS=("${kept[@]}")
}

warm_pool_off_shape_cold() {
  local id path
  log "off-shape create (${WP_CPU}m/${WP_MEMORY}Mi/$((WP_DISK + 1))Gi) starts cold"
  warm_pool_timed_create off-shape "$WP_CPU" "$WP_MEMORY" "$((WP_DISK + 1))"
  id="$WP_ID"
  path="$(warm_pool_path "$id")"
  if [ "$path" != cold ] ||
      ! [[ "$(warm_pool_claim "$id" | jq -r '.spec.warmPoolRef.name')" == shadow-pool-* ]]; then
    echo "::error::an off-shape create took path ${path}, want cold through its own shadow pool"
    return 1
  fi
  WP_COLD="$id"
}

# The adopted Pod is identity-free, carries the pool's revision in its
# immutable spec, now wears its environment's labels, and is bound.
warm_pool_assert_bound_hit() {
  local id="$1" revision="$2" pod pod_uid binding
  pod="$(warm_pool_pod "$id")"
  pod_uid="$(jq -r '.metadata.uid' <<<"$pod")"
  if ! jq -e --arg id "$id" --arg revision "$revision" '
      (.spec.containers[] | select(.name == "workspace")) as $w
      | ([$w.env[]?.name] | index("CODEWIRE_DAEMON_AUTH_TOKEN") | not)
      and ([$w.env[]?.name] | index("CODEWIRE_ENVIRONMENT_ID") | not)
      and ([$w.env[]? | select(.name == "CODEWIRE_WORKSPACE_POOL_REVISION") | .value] == [$revision])
      and (.metadata.labels["codewire.sh/environment-id"] == $id)
      and (.metadata.labels["agents.x-k8s.io/warm-pool-sandbox"] == null)
      and (.spec.automountServiceAccountToken == false)
    ' <<<"$pod" >/dev/null; then
    echo "::error::warm hit ${id} Pod is not the identity-free, adopted, labelled member of revision ${revision}"
    return 1
  fi
  binding="$(warm_pool_sql "SELECT credential_scope || ':' || (released_at IS NULL)::text
    FROM sandbox_workspace_bindings WHERE environment_id = '${id}' AND pod_uid = '${pod_uid}'")"
  if [ "$binding" != pod:true ]; then
    echo "::error::warm hit ${id} has no live Pod-scope binding for its Pod (${binding:-none})"
    return 1
  fi
}

warm_pool_hits() {
  local n id state revision members sandbox_uid
  for n in $(seq 1 "$WARM_POOL_HITS"); do
    warm_pool_wait_ready_members "$WP_MEMBERS"
    state="$(warm_pool_state)"
    revision="${state%% *}"
    members=" ${state#* } "
    warm_pool_timed_create "hit-${n}" "$WP_CPU" "$WP_MEMORY" "$WP_DISK"
    id="$WP_ID"
    if [ "$(warm_pool_path "$id")" != warm ]; then
      echo "::error::pool hit ${n} (${id}) did not adopt a warm member: $(warm_pool_path "$id")"
      return 1
    fi
    sandbox_uid="$(kubectl -n "$SANDBOX_NS" get sandbox "$(warm_pool_sandbox_name "$id")" -o jsonpath='{.metadata.uid}')"
    if [[ "$members" != *" ${sandbox_uid} "* ]]; then
      echo "::error::pool hit ${n} adopted ${sandbox_uid}, not one of the ready members:${members}"
      return 1
    fi
    warm_pool_assert_bound_hit "$id" "$revision"
    log "pool hit ${n}: ${id} adopted member ${sandbox_uid}"
    # Keep the first hit for the stop/start and destroy journeys.
    if [ "$n" -eq 1 ]; then
      WP_HIT="$id"
    else
      warm_pool_destroy "$id"
    fi
  done
}

# A forced pool-empty miss: members + 1 creates of the pool's shape issued at
# once, so at least one finds no ready member (refill takes longer than a
# claim) and the controller creates its Sandbox from the pool template, or
# orchestration routes it cold. Every one of them still starts.
warm_pool_forced_miss() {
  local ids=() id n path misses=0 started elapsed
  warm_pool_wait_ready_members "$WP_MEMBERS"
  started="$(now_ms)"
  for n in $(seq 1 $((WP_MEMBERS + 1))); do
    warm_pool_create "burst-${n}" "$WP_CPU" "$WP_MEMORY" "$WP_DISK"
    ids+=("$WP_ID")
  done
  n=0
  for id in "${ids[@]}"; do
    n=$((n + 1))
    warm_pool_wait_state "$id" running:true
    elapsed=$(( $(now_ms) - started ))
    path="$(warm_pool_path "$id")"
    [ "$path" = warm ] || misses=$((misses + 1))
    WARM_POOL_RESULTS+=("burst-${n}|${path}|${elapsed}|$(warm_pool_complete_ms "$id")")
  done
  if [ "$misses" -lt 1 ]; then
    echo "::error::${#ids[@]} concurrent creates against ${WP_MEMBERS} member(s) all adopted a warm member"
    return 1
  fi
  log "forced miss: ${misses} of ${#ids[@]} concurrent creates found the pool empty and still started"
  for id in "${ids[@]}"; do
    warm_pool_destroy "$id"
  done
}

# An unclaimed member, while another environment is bound: its daemon has no
# listener, its own binding token binds nothing, and it holds no credential.
warm_pool_unbound_negatives() {
  local member pod probe probe_script uid
  member="$(kubectl -n "$SANDBOX_NS" get sandboxes -l "$WARM_POOL_MEMBER_LABEL" -o json |
    jq -r --arg pool "$WP_POOL" '[.items[]
      | select(any(.metadata.ownerReferences[]?; .kind == "SandboxWarmPool" and .name == $pool))
      | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))
      | .metadata.name] | first // empty')"
  [ -n "$member" ] || {
    echo "::error::no ready unclaimed member for the negatives"
    return 1
  }
  pod="$(kubectl -n "$SANDBOX_NS" get sandbox "$member" -o json |
    jq -r --arg name "$member" '.metadata.annotations["agents.x-k8s.io/pod-name"] // $name')"
  pod="$(kubectl -n "$SANDBOX_NS" get pod "$pod" -o json)"
  uid="$(kubectl -n "$SANDBOX_NS" get sandbox "$member" -o jsonpath='{.metadata.uid}')"
  if ! jq -e '
      (.spec.containers[] | select(.name == "workspace")) as $w
      | ([$w.env[]?.name] | index("CODEWIRE_DAEMON_AUTH_TOKEN") | not)
      and ([$w.env[]?.name] | index("CODEWIRE_ENVIRONMENT_ID") | not)
      and ([.metadata.labels // {} | keys[]]
           | map(select(. == "codewire.sh/environment-id" or . == "codewire.sh/org-id"
               or . == "codewire.sh/environment-operation-generation" or . == "codewire.sh/isolation-tier"))
           | length == 0)
      and ([.spec.volumes[]? | select(.secret != null)] | length == 0)
      and (.spec.automountServiceAccountToken == false)
    ' <<<"$pod" >/dev/null; then
    echo "::error::unclaimed member ${member} carries identity, a Secret or an API token"
    jq '{labels: .metadata.labels, env: [.spec.containers[] | {name, env: [.env[]?.name]}], volumes: [.spec.volumes[]?.name]}' <<<"$pod" >&2
    return 1
  fi
  # Nothing may listen before binding: not the credential bridge (TCP 7777,
  # 0x1E61), SSH (TCP 2222, 0x08AE) or the tailnet (UDP 31000, 0x7918). The
  # own-bind call speaks TLS to the binding listener, verified with the Pod's
  # mounted internal roots; only its status is printed, never the token.
  probe_script="$(cat <<'PROBE'
set -u
listen=absent
for table in /proc/net/tcp /proc/net/tcp6; do
  [ -r "$table" ] || continue
  if awk 'NR > 1 && $4 == "0A" && ($2 ~ /:1E61$/ || $2 ~ /:08AE$/) {found = 1} END {exit !found}' "$table"; then
    listen=present
  fi
done
for table in /proc/net/udp /proc/net/udp6; do
  [ -r "$table" ] || continue
  if awk 'NR > 1 && $2 ~ /:7918$/ {found = 1} END {exit !found}' "$table"; then
    listen=present
  fi
done
echo "daemon_listener=${listen}"
own_bind="$(python3 - <<'PY'
import http.client
import os
import ssl
import urllib.parse

url = urllib.parse.urlsplit(os.environ["CODEWIRE_WORKSPACE_BINDING_URL"])
context = ssl.create_default_context(cafile="/run/codewire-orchestration-internal-roots/ca.crt")
with open("/var/run/secrets/codewire/workspace-binding/token", encoding="ascii") as handle:
    token = handle.read().strip()
connection = http.client.HTTPSConnection(url.hostname, url.port or 443, context=context, timeout=10)
try:
    connection.request(
        "POST",
        "/codewire.internal.v1.WorkspaceBindingService/BindWorkspace",
        body=b'{"waitSeconds":0}',
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    )
    print(connection.getresponse().status)
except (OSError, http.client.HTTPException) as error:
    print("error-" + type(error).__name__)
finally:
    connection.close()
PY
)"
echo "own_bind=${own_bind}"
if [ -e /codewire/run/daemon/credential ]; then echo credential=present; else echo credential=absent; fi
PROBE
)"
  probe="$(kubectl -n "$SANDBOX_NS" exec "$(jq -r '.metadata.name' <<<"$pod")" -c workspace -- \
    bash -c "$probe_script")"
  log "unclaimed member ${member}: $(tr '\n' ' ' <<<"$probe")"
  # 404: no binding is recorded for this Pod. 429: the member's own daemon
  # already holds this Pod's long-poll slot. Either way nothing binds.
  if ! grep -Fxq daemon_listener=absent <<<"$probe" ||
      ! grep -Eq '^own_bind=(404|429)$' <<<"$probe" ||
      ! grep -Fxq credential=absent <<<"$probe"; then
    echo "::error::unclaimed member ${member} listens, binds or holds a credential"
    return 1
  fi
  if [ "$(warm_pool_sql "SELECT count(*) FROM sandbox_workspace_bindings WHERE sandbox_uid = '${uid}'")" != 0 ]; then
    echo "::error::unclaimed member ${member} has a binding row"
    return 1
  fi
  # The controller's template-owned policy admits exactly orchestration's
  # identity, in one AND-ed peer, on TCP 7777 and 2222 (codewire#3626).
  if ! kubectl -n "$SANDBOX_NS" get networkpolicy "${WP_POOL}-network-policy" -o json |
      jq -e --arg ns "$NS" '(.spec.policyTypes | index("Ingress")) != null and .spec.ingress == [{
        "from": [{
          "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": $ns } },
          "podSelector": { "matchLabels": {
            "app.kubernetes.io/component": "orchestration", "app.kubernetes.io/name": "codewire" } }
        }],
        "ports": [{ "port": 7777, "protocol": "TCP" }, { "port": 2222, "protocol": "TCP" }]
      }]' >/dev/null; then
    echo "::error::the pool's template NetworkPolicy is missing or admits more than orchestration on TCP 7777 and 2222"
    return 1
  fi
  warm_pool_template_ingress_admission
}

# codewire#3626: the template admission policy admits exactly two ingress
# shapes under a managed policy, the one rule and (for the rollout, until
# #3640) none, and refuses every widening and an Unmanaged policy.
# Each fixture (scripts/checks/repo_policy/pool_ingress.py) is the live
# template under a fresh cw-pool- name, sent as a server-side dry run with
# orchestration's identity, so the API server's own CEL decides and nothing
# is written.
warm_pool_template_ingress_admission() {
  local template fixtures name object output refused=0 admitted=0
  template="$(kubectl -n "$SANDBOX_NS" get sandboxtemplate "$WP_POOL" -o json |
    jq --arg name "${WP_POOL%-*}-00000000" 'del(.status) |
      .metadata = (.metadata | {name: $name, namespace, labels, annotations})')"
  fixtures="$(python3 -I "$ROOT/scripts/checks/repo_policy/pool_ingress.py" <<<"$template")"
  while IFS= read -r line; do
    name="$(jq -r '.name' <<<"$line")"
    object="$(jq -c '.object' <<<"$line")"
    if output="$(kubectl create --dry-run=server -o name -f - \
        --as "system:serviceaccount:${NS}:codewire-orchestration" <<<"$object" 2>&1)"; then
      if [[ "$name" != accepted* ]]; then
        echo "::error::the template admission policy admitted ${name}"
        return 1
      fi
      admitted=$((admitted + 1))
    elif [[ "$name" == accepted* ]]; then
      echo "::error::the template admission policy refused the pool template (${name}): ${output}"
      return 1
    elif ! grep -Fq "admit no ingress, or only orchestration's identity" <<<"$output"; then
      echo "::error::${name} was refused for another reason: ${output}"
      return 1
    else
      refused=$((refused + 1))
    fi
  done <<<"$fixtures"
  [ "$admitted" -eq 3 ] || { echo "::error::${admitted} of 3 pool ingress shapes were admitted"; return 1; }
  [ "$refused" -eq 16 ] || { echo "::error::${refused} of 16 pool ingress fixtures were refused"; return 1; }
  log "template admission admitted all ${admitted} pool ingress shapes and refused all ${refused} fixtures"
}

warm_pool_stop_start_destroy() {
  local id="$WP_HIT" pvc_before pvc_after pod_before pod_after pvc_name sandbox marker
  sandbox="$(warm_pool_sandbox_name "$id")"
  pvc_name="workspace-${sandbox}"
  pvc_before="$(warm_pool_pvc_uid "$id")"
  pod_before="$(warm_pool_pod "$id" | jq -r '.metadata.uid')"
  kubectl -n "$SANDBOX_NS" exec "$(warm_pool_pod "$id" | jq -r '.metadata.name')" -c workspace -- \
    sh -ceu 'printf warm-pool-proof > /workspace/.warm-pool-proof'
  log "stop/start of pool-born ${id} (Sandbox ${sandbox}, PVC ${pvc_before})"
  warm_pool_rpc StopEnvironment "{\"orgId\":\"${WARM_POOL_ORG}\",\"environmentId\":\"${id}\"}"
  [ "$WP_CODE" = 200 ] || { echo "::error::StopEnvironment failed: ${WP_CODE} ${WP_BODY}"; return 1; }
  warm_pool_wait_state "$id" "stopped:*"
  warm_pool_rpc StartEnvironment "{\"orgId\":\"${WARM_POOL_ORG}\",\"environmentId\":\"${id}\"}"
  [ "$WP_CODE" = 200 ] || { echo "::error::StartEnvironment failed: ${WP_CODE} ${WP_BODY}"; return 1; }
  warm_pool_wait_state "$id" running:true
  pvc_after="$(warm_pool_pvc_uid "$id")"
  pod_after="$(warm_pool_pod "$id" | jq -r '.metadata.uid')"
  marker="$(kubectl -n "$SANDBOX_NS" exec "$(warm_pool_pod "$id" | jq -r '.metadata.name')" -c workspace -- \
    cat /workspace/.warm-pool-proof)"
  if [ "$pvc_after" != "$pvc_before" ] || [ "$pod_after" = "$pod_before" ] || [ "$marker" != warm-pool-proof ]; then
    echo "::error::stop/start lost the pool-born PVC or data: pvc ${pvc_before} -> ${pvc_after}, pod ${pod_before} -> ${pod_after}, marker ${marker:-missing}"
    return 1
  fi
  if [ "$(kubectl -n "$SANDBOX_NS" get sandbox "$sandbox" -o json |
      jq -r --arg label "$WARM_POOL_MEMBER_LABEL" '(.metadata.labels[$label] // "") + "|" + ([.metadata.ownerReferences[]? | select(.kind == "SandboxWarmPool")] | length | tostring)')" != '|0' ]; then
    echo "::error::the restarted pool-born Sandbox ${sandbox} returned to its pool"
    return 1
  fi
  if [ "$(warm_pool_sql "SELECT count(*) FROM sandbox_workspace_bindings
      WHERE environment_id = '${id}' AND pod_uid = '${pod_after}' AND released_at IS NULL")" != 1 ] ||
      [ "$(warm_pool_sql "SELECT (released_at IS NOT NULL)::text FROM sandbox_workspace_bindings
      WHERE pod_uid = '${pod_before}'")" != true ]; then
    echo "::error::stop/start did not release the first Pod's binding and bind the second"
    return 1
  fi
  log "stop/start kept PVC ${pvc_after} and its data on a new Pod"
  warm_pool_destroy "$id"
  local deadline=$(( $(date +%s) + 180 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    kubectl -n "$SANDBOX_NS" get pvc -o json |
      jq -e --arg uid "$pvc_before" '[.items[] | select(.metadata.uid == $uid)] | length == 0' >/dev/null && break
    sleep 2
  done
  if kubectl -n "$SANDBOX_NS" get pvc -o json |
      jq -e --arg uid "$pvc_before" '[.items[] | select(.metadata.uid == $uid)] | length > 0' >/dev/null ||
      kubectl -n "$SANDBOX_NS" get sandbox "$sandbox" >/dev/null 2>&1 ||
      [ "$(warm_pool_sql "SELECT count(*) FROM sandbox_workspace_bindings
        WHERE environment_id = '${id}' AND released_at IS NULL")" != 0 ]; then
    echo "::error::destroy left the pool-born PVC ${pvc_name}, Sandbox ${sandbox} or a live binding"
    return 1
  fi
  log "destroy removed pool-born Sandbox ${sandbox}, PVC ${pvc_before} and released its binding"
}

# The sum of one orchestration counter's series carrying every given
# label="value" pair, from its metrics endpoint; 0 before it exists.
warm_pool_metric() {
  local name="$1" value
  shift
  value="$(curl -sS "${KIND_ORCHESTRATION_HTTP_URL}/metrics" |
    awk -v name="$name" -v want="$*" '
      BEGIN { n = split(want, pairs, " ") }
      index($1, name "{") == 1 {
        found = 1
        for (i = 1; i <= n; i++) if (index($1, pairs[i]) == 0) found = 0
        if (found) sum += $2
      }
      END { print sum + 0 }')" || value=0
  printf '%s\n' "${value:-0}"
}

# Set orchestration's SANDBOX_RUNTIME_PROFILE and WORKER_LOOPS ("-" unsets
# it) on its Deployment, wait for the rollout, and wait until the ingress
# routes to the new replica.
warm_pool_set_orchestration() {
  local profile="$1" loops="$2"
  local args=("SANDBOX_RUNTIME_PROFILE=${profile}")
  if [ "$loops" = - ]; then
    args+=("WORKER_LOOPS-")
  else
    args+=("WORKER_LOOPS=${loops}")
  fi
  kubectl -n "$NS" set env deploy/codewire-orchestration -c orchestration "${args[@]}" >/dev/null
  warm_pool_await_orchestration
}

# The pool shapes orchestration runs with: its container's own setting
# first, then the cluster ConfigMap it loads.
warm_pool_effective_shapes() {
  local shapes
  shapes="$(warm_pool_orchestration_env SANDBOX_WARM_POOL_SHAPES)"
  if [ "$shapes" = - ]; then
    shapes="$(kubectl -n "$NS" get configmap codewire-config \
      -o jsonpath='{.data.SANDBOX_WARM_POOL_SHAPES}')"
  fi
  printf '%s\n' "$shapes"
}

# The suite's own shape's pool objects, as "<kind>/<name>": a reconciler-owned
# pool or template whose name is that shape's.
warm_pool_suite_objects() {
  local prefix="$1"
  kubectl -n "$SANDBOX_NS" get sandboxwarmpools,sandboxtemplates \
    -l app.kubernetes.io/managed-by=codewire,codewire.sh/type=workspace-pool -o json |
    jq -r --arg prefix "$prefix" \
      '.items[] | select(.metadata.name | startswith($prefix)) | "\(.kind | ascii_downcase)/\(.metadata.name)"'
}

# Live members of the suite's shape's pools, of any revision.
warm_pool_suite_members() {
  local prefix="$1"
  kubectl -n "$SANDBOX_NS" get sandboxes -l "$WARM_POOL_MEMBER_LABEL" -o json |
    jq --arg prefix "$prefix" '[.items[] | select(.metadata.deletionTimestamp == null)
      | select(any(.metadata.ownerReferences[]?;
          .kind == "SandboxWarmPool" and (.name | startswith($prefix))))] | length'
}

# Remove the pool the suite configured (#3841). An unset shape keeps the
# reconciler inert, with no Kubernetes access, so unsetting alone leaves the
# pool behind. The suite zeroes its shape instead, which drains every revision
# of its pool, waits until no member is left, deletes that shape's pool and
# template objects, and only then unsets the setting it added.
warm_pool_remove_suite_pool() {
  local shape prefix deadline object awaited
  shape="${WARM_POOL_SUITE_SHAPES%=*}"
  prefix="cw-pool-$(tr '[:upper:]/' '[:lower:]-' <<<"$shape")-"
  log "draining the suite pool ${shape} before removing its shape"
  kubectl -n "$NS" set env deploy/codewire-orchestration -c orchestration \
    "SANDBOX_WARM_POOL_SHAPES=${shape}=0" >/dev/null || return 1
  # Called plainly, as every Kind step is: its status is checked after.
  warm_pool_await_orchestration >/dev/null
  awaited=$?
  [ "$awaited" = 0 ] || return 1
  deadline=$(( $(date +%s) + WARM_POOL_TIMEOUT_SECONDS ))
  while [ "$(warm_pool_suite_members "$prefix")" != 0 ]; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "::error::the suite pool's members did not drain within ${WARM_POOL_TIMEOUT_SECONDS} s"
      return 1
    fi
    sleep 2
  done
  while IFS= read -r object; do
    [ -n "$object" ] || continue
    kubectl -n "$SANDBOX_NS" delete "$object" --wait=true --timeout=120s >/dev/null || return 1
  done < <(warm_pool_suite_objects "$prefix")
  kubectl -n "$NS" set env deploy/codewire-orchestration -c orchestration \
    SANDBOX_WARM_POOL_SHAPES- >/dev/null || return 1
  warm_pool_await_orchestration >/dev/null
  awaited=$?
  [ "$awaited" = 0 ] || return 1
  if [ -n "$(warm_pool_suite_objects "$prefix")" ]; then
    echo "::error::the suite pool's objects remain after its shape was removed"
    return 1
  fi
}

# Configure the suite's own shape unless the cluster already runs a pool.
warm_pool_configure_suite_shape() {
  if tr ',' '\n' <<<"$(warm_pool_effective_shapes)" |
      grep -Eq '^[1-9][0-9]*m/[1-9][0-9]*Mi/[1-9][0-9]*Gi=([1-9]|1[0-6])$'; then
    return 0
  fi
  log "configuring the suite pool ${WARM_POOL_SUITE_SHAPES} on orchestration"
  WARM_POOL_RESTORE_SHAPES=1
  kubectl -n "$NS" set env deploy/codewire-orchestration -c orchestration \
    "SANDBOX_WARM_POOL_SHAPES=${WARM_POOL_SUITE_SHAPES}" >/dev/null
  warm_pool_await_orchestration
}

# Wait for orchestration's rollout, for its old replica to exit, and until the
# ingress routes to the new replica.
warm_pool_await_orchestration() {
  local deadline
  kubectl -n "$NS" rollout status deploy/codewire-orchestration --timeout=300s >/dev/null
  # A terminating replica still runs create activities with its old
  # settings until it exits; wait for it to be gone.
  deadline=$(( $(date +%s) + 120 ))
  while [ "$(date +%s)" -lt "$deadline" ] &&
      [ "$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=codewire,app.kubernetes.io/component=orchestration \
        -o json | jq '[.items[] | select(.metadata.deletionTimestamp != null)] | length')" != 0 ]; do
    sleep 1
  done
  deadline=$(( $(date +%s) + 120 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    warm_pool_rpc ListEnvironments "{\"orgId\":\"${WARM_POOL_ORG}\"}"
    [ "$WP_CODE" = 200 ] && return 0
    sleep 1
  done
  echo "::error::orchestration did not serve through the ingress after its restart (${WP_CODE})"
  return 1
}

warm_pool_orchestration_env() {
  kubectl -n "$NS" get deploy/codewire-orchestration -o json |
    jq -r --arg name "$1" '[.spec.template.spec.containers[] | select(.name == "orchestration")
      | .env[]? | select(.name == $name) | .value] | first // "-"'
}

# Stale-revision refusal. Orchestration renders a new pool revision while its
# reconciler is paused: the Kind diagnostic runtime switches between runc and
# the node default, which changes only the members' runtimeClassName. A ready
# member of the old revision stays in the pool, and a create of the pool's
# shape must start cold (route cold_revision) and leave it unclaimed.
# Resumed, the reconciler replaces the old members, and the next hit carries
# the new revision. The original settings are restored.
warm_pool_stale_revision() {
  local original loops rotated_profile paused state old_revision old_members id path
  local sandbox_uid deadline new_state new_revision cold_before uid gone=no
  original="$(warm_pool_orchestration_env SANDBOX_RUNTIME_PROFILE)"
  loops="$(warm_pool_orchestration_env WORKER_LOOPS)"
  case "$original" in
    runc) rotated_profile=none ;;
    none) rotated_profile=runc ;;
    *)
      echo "::error::orchestration runs runtime profile ${original}; the rotation journey needs a Kind diagnostic runtime"
      return 1
      ;;
  esac
  paused="env-reconciler,sandbox-liveness,billing-session,image-cache"
  warm_pool_wait_ready_members "$WP_MEMBERS"
  state="$(warm_pool_state)"
  old_revision="${state%% *}"
  old_members=" ${state#* } "
  log "rendering runtime profile ${rotated_profile} over revision ${old_revision:0:12} with the pool reconciler paused"
  WARM_POOL_RESTORE_CONFIG="${original}|${loops}"
  warm_pool_set_orchestration "$rotated_profile" "$paused"
  cold_before="$(warm_pool_metric codewire_warm_pool_routes_total 'route="cold_revision"')"
  warm_pool_timed_create stale-refused "$WP_CPU" "$WP_MEMORY" "$WP_DISK"
  id="$WP_ID"
  path="$(warm_pool_path "$id")"
  sandbox_uid="$(kubectl -n "$SANDBOX_NS" get sandbox "$(warm_pool_sandbox_name "$id")" -o jsonpath='{.metadata.uid}')"
  if [ "$path" != cold ] || [[ "$old_members" == *" ${sandbox_uid} "* ]] ||
      [ "$(warm_pool_metric codewire_warm_pool_routes_total 'route="cold_revision"')" -le "$cold_before" ]; then
    echo "::error::a create against old-revision members took path ${path} (Sandbox ${sandbox_uid}); want cold_revision"
    return 1
  fi
  if [ "$(warm_pool_state)" != "$state" ]; then
    echo "::error::the old-revision members changed while the reconciler was paused: $(warm_pool_state)"
    return 1
  fi
  log "stale revision refused: ${id} started cold; old member(s)${old_members}stay unclaimed"
  warm_pool_destroy "$id"

  warm_pool_set_orchestration "$rotated_profile" "$loops"
  deadline=$(( $(date +%s) + WARM_POOL_TIMEOUT_SECONDS ))
  new_revision=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    new_state="$(warm_pool_state)"
    new_revision="${new_state%% *}"
    if [ -n "$new_revision" ] && [ "$new_revision" != "$old_revision" ] &&
        [ "$(warm_pool_ready_count)" -ge "$WP_MEMBERS" ]; then
      gone=yes
      for uid in $old_members; do
        if kubectl -n "$SANDBOX_NS" get sandboxes -o json |
            jq -e --arg uid "$uid" 'any(.items[]; .metadata.uid == $uid)' >/dev/null; then
          gone=no
        fi
      done
      [ "$gone" = yes ] && break
    fi
    sleep 3
  done
  if [ -z "$new_revision" ] || [ "$new_revision" = "$old_revision" ] || [ "$gone" != yes ]; then
    echo "::error::the resumed reconciler did not replace the old members with a new revision"
    return 1
  fi
  warm_pool_timed_create rotated "$WP_CPU" "$WP_MEMORY" "$WP_DISK"
  id="$WP_ID"
  if [ "$(warm_pool_path "$id")" != warm ]; then
    echo "::error::the first create after the rotation was not a hit"
    return 1
  fi
  warm_pool_assert_bound_hit "$id" "$new_revision"
  log "rotation ${old_revision:0:12} -> ${new_revision:0:12}: old members replaced, new hit bound"
  warm_pool_destroy "$id"
  warm_pool_set_orchestration "$original" "$loops"
  WARM_POOL_RESTORE_CONFIG=""
  WP_POOL=""
  warm_pool_wait_ready_members "$WP_MEMBERS"
}

# Cordoning a member's node deletes the unclaimed members on it, and no
# member is Ready there until it is uncordoned; the pool then refills.
warm_pool_cordon_reap() {
  local state members uid node nodes=() deadline remaining reaped_series reaped_before
  warm_pool_wait_ready_members "$WP_MEMBERS"
  state="$(warm_pool_state)"
  members="${state#* }"
  for uid in $members; do
    node="$(kubectl -n "$SANDBOX_NS" get pods -l "$WARM_POOL_MEMBER_LABEL" -o json |
      jq -r --arg uid "$uid" '.items[] | select(any(.metadata.ownerReferences[]?; .uid == $uid)) | .spec.nodeName' | head -n1)"
    if [ -z "$node" ]; then
      node="$(kubectl -n "$SANDBOX_NS" get sandboxes -o json |
        jq -r --arg uid "$uid" '.items[] | select(.metadata.uid == $uid) | .metadata.name' |
        xargs -r -I{} kubectl -n "$SANDBOX_NS" get pod {} -o jsonpath='{.spec.nodeName}')"
    fi
    [ -n "$node" ] && [[ " ${nodes[*]} " != *" ${node} "* ]] && nodes+=("$node")
  done
  [ "${#nodes[@]}" -gt 0 ] || {
    echo "::error::cannot find the nodes of members ${members}"
    return 1
  }
  reaped_series="shape=\"${WP_CPU}m-${WP_MEMORY}mi-${WP_DISK}gi\""
  reaped_before="$(warm_pool_metric codewire_warm_pool_member_deletions_total 'reason="node_unfit"' "$reaped_series")"
  for node in "${nodes[@]}"; do
    WARM_POOL_CORDONED+=("$node")
    kubectl cordon "$node" >/dev/null
  done
  log "cordoned ${nodes[*]}; waiting for the reconciler to reap members ${members}"
  deadline=$(( $(date +%s) + 180 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    remaining="$(kubectl -n "$SANDBOX_NS" get sandboxes -o json |
      jq -r --arg old " ${members} " '[.items[] | select(.metadata.uid as $uid | $old | contains(" " + $uid + " "))] | length')"
    [ "$remaining" = 0 ] && break
    sleep 3
  done
  if [ "$remaining" != 0 ]; then
    echo "::error::${remaining} unclaimed member(s) survived on cordoned nodes"
    return 1
  fi
  sleep 20
  if [ "$(warm_pool_ready_count)" != 0 ]; then
    echo "::error::a member became Ready on a cordoned node"
    return 1
  fi
  if [ "$(warm_pool_metric codewire_warm_pool_member_deletions_total 'reason="node_unfit"' "$reaped_series")" -le "$reaped_before" ]; then
    echo "::error::the reconciler recorded no node_unfit member deletion"
    return 1
  fi
  for node in "${nodes[@]}"; do
    kubectl uncordon "$node" >/dev/null
  done
  WARM_POOL_CORDONED=()
  log "uncordoned ${nodes[*]}; waiting for the pool to refill"
  warm_pool_wait_ready_members "$WP_MEMBERS"
}

# Unclaimed members are never billed: no billing session names a member, and
# every session of this run's environments starts at or after the binding of
# the Sandbox it bills.
warm_pool_no_member_billed() {
  local members sessions uid ids
  members="$(kubectl -n "$SANDBOX_NS" get sandboxes -l "$WARM_POOL_MEMBER_LABEL" \
    -o jsonpath='{range .items[*]}{.metadata.uid}{"\n"}{end}')"
  sessions="$(warm_pool_sql "SELECT runtime_uid FROM sandbox_running_sessions")"
  for uid in $members; do
    if grep -Fxq "$uid" <<<"$sessions"; then
      echo "::error::unclaimed member ${uid} has a billing session"
      return 1
    fi
  done
  ids="$(printf "'%s'," "${WARM_POOL_CREATED[@]}")"
  if [ "$(warm_pool_sql "SELECT count(*) FROM sandbox_running_sessions s
      WHERE s.environment_id IN (${ids%,})
        AND NOT EXISTS (SELECT 1 FROM sandbox_workspace_bindings w
          WHERE w.sandbox_uid = s.runtime_uid AND w.bound_at <= s.started_at)")" != 0 ]; then
    echo "::error::a billing session of this run starts before its Sandbox was bound"
    return 1
  fi
  log "no unclaimed member is billed; $(warm_pool_sql "SELECT count(*) FROM sandbox_running_sessions WHERE environment_id IN (${ids%,})") session(s) of this run start at or after their binding"
}

warm_pool_report() {
  local row label path client complete
  log "warm pool start times (client: create request to setup complete; server: environment row to the complete log)"
  printf '%-12s %-10s %10s %10s\n' case path client_ms server_ms >&2
  for row in "${WARM_POOL_RESULTS[@]}"; do
    IFS='|' read -r label path client complete <<<"$row"
    printf '%-12s %-10s %10s %10s\n' "$label" "$path" "$client" "${complete:--}" >&2
  done
}
