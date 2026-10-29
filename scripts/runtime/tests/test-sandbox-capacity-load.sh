#!/usr/bin/env bash
# shellcheck disable=SC2016 # Single-quoted patterns match literal source text.
# Contract tests for the sandbox capacity load (#3583): it runs against Dev
# with the Dev smoke key, or against Production only with the explicit
# confirmation, the Prod server, kube-access's context and the Prod smoke key;
# refuses unsafe options before any network or build step; is read-only
# toward Kubernetes; deletes only environments it named; and computes
# milestone percentiles from histogram deltas and the cluster view from
# per-node records.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOAD="$ROOT/scripts/runtime/dev/load-dev-sandbox-capacity.sh"

fail() { printf 'sandbox capacity load tests: %s\n' "$*" >&2; exit 1; }

refuses() {
  local expected="$1"
  shift
  local output
  if output="$(env -u CODEWIRE_DEV_SMOKE_API_KEY -u CODEWIRE_PROD_SMOKE_API_KEY -u KUBE_CONTEXT \
    -u INFRA_TRANSIENT_KUBE_AUTH "$@" 2>&1)"; then
    fail "accepted: $*"
  fi
  [[ "$output" == *"$expected"* ]] || fail "unexpected refusal for $*: $output"
}

bash -n "$LOAD"
"$LOAD" --help | grep -q 'load-dev-sandbox-capacity.sh' || fail '--help does not describe the load'
"$LOAD" --help | grep -q 'proves that their environments' || fail '--help does not state the cleanup proof'

refuses 'only against Dev' env CODEWIRE_SERVER_URL=https://codewire.sh CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD"
refuses 'only against the codewire-dev context' env KUBE_CONTEXT=codewire-prod CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD"
refuses 'PROM_URL must name' env -u PROM_URL CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD"
export PROM_URL=http://prometheus.example.invalid:9090
refuses 'CODEWIRE_DEV_SMOKE_API_KEY is required' "$LOAD"
refuses '--shape must be' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --shape huge
refuses '--steps must be auto or a comma-separated' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --steps 10,,20
refuses '--steps must increase' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --steps 10,10
refuses '--steps exceeds --max-sandboxes' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --steps 10,300
refuses '--max-sandboxes must be 1-500' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --max-sandboxes 501
refuses 'WORKLOAD_CPU must be between 0 and 0.9' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --workload-cpu 1
refuses 'WORKLOAD_MEMORY must be between 0 and 0.9' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --workload-memory 0.95
refuses '--latency-factor must be at least 1' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --latency-factor 0.5
refuses 'MAX_NODE_MEMORY_PCT must be 1-100' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --max-node-memory-pct 0
refuses 'shell tracing is enabled' env CODEWIRE_DEV_SMOKE_API_KEY=x bash -x "$LOAD"
refuses 'unknown argument' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --keep

# Dev mode never takes the Prod key or kube-access's Prod context.
refuses 'CODEWIRE_DEV_SMOKE_API_KEY is required' env CODEWIRE_PROD_SMOKE_API_KEY=x "$LOAD"
refuses 'only against the codewire-dev context' env KUBE_CONTEXT=cw-prod-hz-eu-1 CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD"
# Production mode needs the exact confirmation, server, kube-access context
# and Prod smoke key, each checked before any network or build step.
prod_access=(KUBE_CONTEXT=cw-prod-hz-eu-1 KUBECONFIG=/nonexistent/kubeconfig INFRA_TRANSIENT_KUBE_AUTH=1)
refuses '--confirm-production must be cw-prod-hz-eu-1' env "${prod_access[@]}" CODEWIRE_PROD_SMOKE_API_KEY=x \
  "$LOAD" --confirm-production codewire-prod
refuses 'Production mode runs only against https://codewire.sh' env "${prod_access[@]}" CODEWIRE_PROD_SMOKE_API_KEY=x \
  CODEWIRE_SERVER_URL=https://codewire-dev.sh "$LOAD" --confirm-production cw-prod-hz-eu-1
refuses 'Production mode runs only through scripts/kube-access' env KUBE_CONTEXT=cw-prod-hz-eu-1 \
  CODEWIRE_PROD_SMOKE_API_KEY=x "$LOAD" --confirm-production cw-prod-hz-eu-1
refuses 'Production mode runs only through scripts/kube-access' env KUBE_CONTEXT=codewire-dev \
  KUBECONFIG=/nonexistent/kubeconfig INFRA_TRANSIENT_KUBE_AUTH=1 CODEWIRE_PROD_SMOKE_API_KEY=x \
  "$LOAD" --confirm-production cw-prod-hz-eu-1
refuses 'CODEWIRE_PROD_SMOKE_API_KEY is required' env "${prod_access[@]}" CODEWIRE_DEV_SMOKE_API_KEY=x \
  "$LOAD" --confirm-production cw-prod-hz-eu-1
# With every Production guard met, option validation is next.
refuses '--max-sandboxes must be 1-500' env "${prod_access[@]}" CODEWIRE_PROD_SMOKE_API_KEY=x \
  "$LOAD" --confirm-production cw-prod-hz-eu-1 --max-sandboxes 501
# Production's stop thresholds are stricter than Dev's.
grep -qF ': "${MAX_NODE_MEMORY_PCT:=85}" "${MAX_NODE_CPU_PCT:=80}" "${MAX_PSI_MEMORY_PCT:=5}"' "$LOAD" ||
  fail 'Production stop thresholds are not the conservative defaults'

# Kubernetes access is read-only: kubectl_ro is the only kubectl call, and it
# allows get alone.
mapfile -t direct < <(grep -nE '(^|[[:space:]])kubectl --' "$LOAD")
[[ "${#direct[@]}" -eq 1 ]] || fail "unexpected direct kubectl calls: ${direct[*]}"
grep -qF 'kubectl --request-timeout="${KUBECTL_TIMEOUT_SECONDS}s" --context "$KUBE_CONTEXT" "$@"' "$LOAD" ||
  fail 'kubectl_ro is not the read path'
if grep -nE 'kubectl_ro +(apply|create|patch|edit|delete|exec|scale|label|annotate|cordon|drain)' "$LOAD"; then
  fail 'kubectl_ro is called with a mutating verb'
fi

# The only deletion is cw rm of recorded or prefix-named environments.
mapfile -t removals < <(grep -nE '\bcw rm\b|"\$CW_BIN".* rm ' "$LOAD")
[[ "${#removals[@]}" -eq 1 ]] || fail "unexpected environment removals: ${removals[*]}"
grep -qF "readonly NAME_PREFIX=\"cap-\"" "$LOAD" || fail 'the run prefix is not fixed'
grep -qF 'name="${NAME_PREFIX}${RUN_ID}-${n}"' "$LOAD" || fail 'created environments do not carry the run prefix'
grep -qF "index(\$2, p) == 1 {print \$1}" "$LOAD" || fail 'leftover cleanup is not limited to the run prefix'
grep -qF 'nuke' "$LOAD" && fail 'the load must never nuke environments'

# Every environment is bounded twice: a TTL and a bounded workload.
grep -qF -- '--ttl "$LOAD_TTL"' "$LOAD" || fail 'creates carry no TTL'
grep -qF 'exec timeout $((seconds + 60)) python3' "$LOAD" || fail 'the workload is not bounded by timeout'
grep -qF 'run --detach --in "$id" --name cap-load' "$LOAD" || fail 'the workload does not run as a detached session'

# Run records are kept per environment, and start-up cleanup skips a run of
# another server.
grep -qF '"${LOAD_TMP_PARENT:=$ROOT/.tmp/sandbox-capacity-prod}"' "$LOAD" || fail 'Production runs share the Dev run records'
grep -qF 'printf '"'"'%s\n'"'"' "$CODEWIRE_SERVER_URL" >"$RUN_DIR/server"' "$LOAD" || fail 'a run does not record its server'
grep -qF '[[ "$run_server" != "$CODEWIRE_SERVER_URL" ]]' "$LOAD" || fail 'start-up cleanup does not check the run server'

# Milestone percentiles: interpolated within buckets over the delta of two
# snapshots, with an empty first snapshot still read as "before".
work="$(mktemp -d "${TMPDIR:-/tmp}/cw-capacity-tests.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
# Source the helpers between "# ---... inventory" and "# ---... main" only.
sed -n '/^# -* inventory/,/^# -* main/p' "$LOAD" >"$work/functions.sh"
printf 'setup_complete cold 5 0\nsetup_complete cold 10 0\nsetup_complete cold 20 0\nsetup_complete cold +Inf 0\n' >"$work/before"
printf '%s\n' \
  'setup_complete cold 5 0' 'setup_complete cold 10 10' 'setup_complete cold 20 20' 'setup_complete cold +Inf 20' \
  'setup_complete warm 5 10' 'setup_complete warm 10 10' 'setup_complete warm 20 10' 'setup_complete warm +Inf 10' \
  'access_ready cold 5 30' 'access_ready cold +Inf 30' >"$work/after"
: >"$work/empty"
result="$(bash -c 'source "$1"; milestone_quantiles "$2" "$3" setup_complete' _ "$work/functions.sh" "$work/before" "$work/after")"
[[ "$result" == '{"count":30,"p50_ms":7500,"p95_ms":18500,"p50_over_top":false,"p95_over_top":false}' ]] || fail "unexpected setup_complete quantiles: $result"
result="$(bash -c 'source "$1"; milestone_quantiles "$2" "$3" setup_complete' _ "$work/functions.sh" "$work/empty" "$work/after")"
[[ "$result" == '{"count":30,"p50_ms":7500,"p95_ms":18500,"p50_over_top":false,"p95_over_top":false}' ]] || fail "empty before snapshot mishandled: $result"
result="$(bash -c 'source "$1"; milestone_quantiles "$2" "$3" setup_complete' _ "$work/functions.sh" "$work/after" "$work/after")"
[[ "$result" == '{"count":0,"p50_ms":null,"p95_ms":null,"p50_over_top":false,"p95_over_top":false}' ]] || fail "no new creates should give no quantiles: $result"

# A quantile above the top finite bucket reports that bound, flagged as over.
printf '%s\n' 'setup_complete cold 30 2' 'setup_complete cold 60 15' 'setup_complete cold +Inf 20' >"$work/tail"
result="$(bash -c 'source "$1"; milestone_quantiles "$2" "$3" setup_complete' _ "$work/functions.sh" "$work/empty" "$work/tail")"
[[ "$result" == '{"count":20,"p50_ms":48461,"p95_ms":60000,"p50_over_top":false,"p95_over_top":true}' ]] ||
  fail "a p95 above the top bucket is not flagged: $result"

# Per-sandbox memory divides by the ready sandboxes, never by refused ones.
grep -qF '/ $running) end)' "$LOAD" || fail 'per-sandbox host memory does not divide by ready sandboxes'
grep -qF "running=\"\$({ grep -l '^ready ' \"\$RUN_DIR\"/ready-* 2>/dev/null || true; }" "$LOAD" || fail 'ready sandboxes are not counted from the ready records'

# The cluster view sums capacity and requests, takes the worst node for
# percentages and pressure, and names every degraded node.
printf '%s\n' \
  '{"node":"a","node_condition":"ok","allocatable_cpu_m":1000,"allocatable_memory_mib":100,"allocatable_pods":10,"requested_cpu_m":500,"requested_memory_mib":90,"pods":5,"node_cpu_pct":20,"node_memory_pct":40,"node_memory_total_gib":10,"node_memory_used_gib":4,"psi_memory_some_pct":0,"thin_pool":"t","thin_total_gib":100,"thin_used_gib":10,"thin_used_pct":10}' \
  '{"node":"b","node_condition":"MemoryPressure=True","allocatable_cpu_m":1000,"allocatable_memory_mib":100,"allocatable_pods":10,"requested_cpu_m":100,"requested_memory_mib":10,"pods":3,"node_cpu_pct":60,"node_memory_pct":10,"node_memory_total_gib":10,"node_memory_used_gib":1,"psi_memory_some_pct":3,"thin_pool":"t","thin_total_gib":100,"thin_used_gib":50,"thin_used_pct":50}' \
  >"$work/nodes.jsonl"
result="$(bash -c 'source "$1"; aggregate_nodes "$2" <"$3"' _ "$work/functions.sh" \
  '[{"volume_definitions":[{"size_kib":209715200}]}]' "$work/nodes.jsonl" | jq -c 'del(.nodes)')"
expected='{"node_condition":"b: MemoryPressure=True","allocatable_cpu_m":2000,"allocatable_memory_mib":200,"allocatable_pods":20,"requested_cpu_m":600,"requested_memory_mib":100,"pods":8,"node_cpu_pct":60,"node_memory_pct":40,"node_memory_total_gib":20,"node_memory_used_gib":5,"psi_cpu_some_pct":null,"psi_memory_some_pct":3,"psi_memory_full_pct":null,"psi_io_some_pct":null,"thin_pool":"t","thin_total_gib":200,"thin_used_gib":60,"thin_used_pct":50,"provisioned_gib":200,"overcommit":1,"resource_definitions":1}'
[[ "$result" == "$expected" ]] || fail "unexpected cluster view: $result"

# The prediction floors each node on its own, names what runs out first
# (ties included), and auto steps climb to two past the total.
printf '%s' '{"nodes":[{"node":"cpu-bound","allocatable_cpu_m":64000,"allocatable_memory_mib":1000000,"allocatable_pods":110,"requested_cpu_m":4000,"requested_memory_mib":15000,"pods":20},{"node":"memory-bound","allocatable_cpu_m":128000,"allocatable_memory_mib":500000,"allocatable_pods":110,"requested_cpu_m":4000,"requested_memory_mib":15000,"pods":20},{"node":"tie","allocatable_cpu_m":3500,"allocatable_memory_mib":67844,"allocatable_pods":110,"requested_cpu_m":0,"requested_memory_mib":0,"pods":0}]}' >"$work/base.json"
request='{"workspace":{"cpu_m":1000,"memory_mib":32768},"dind":{"cpu_m":500,"memory_mib":1024},"kata":{"cpu_m":250,"memory_mib":130},"cpu_m":1750,"memory_mib":33922}'
result="$(bash -c 'source "$1"; SHAPE=memory predict "$(cat "$2")" "$3"' _ "$work/functions.sh" "$work/base.json" "$request" |
  jq -c '{predicted_total, per_node: [.per_node[] | {node, by_cpu, by_memory, fits, first_limit}]}')"
expected='{"predicted_total":45,"per_node":[{"node":"cpu-bound","by_cpu":34,"by_memory":29,"fits":29,"first_limit":"memory requests"},{"node":"memory-bound","by_cpu":70,"by_memory":14,"fits":14,"first_limit":"memory requests"},{"node":"tie","by_cpu":2,"by_memory":2,"fits":2,"first_limit":"CPU requests and memory requests"}]}'
[[ "$result" == "$expected" ]] || fail "unexpected prediction: $result"
printf '%s' '{"predicted_total":24}' >"$work/p24.json"
printf '%s' '{"predicted_total":3}' >"$work/p3.json"
printf '%s' '{"predicted_total":0}' >"$work/p0.json"
[[ "$(bash -c 'source "$1"; MAX_SANDBOXES=200 auto_steps "$2"' _ "$work/functions.sh" "$work/p24.json")" == 6,12,18,24,26 ]] ||
  fail 'auto steps do not climb to two past the prediction'
[[ "$(bash -c 'source "$1"; MAX_SANDBOXES=200 auto_steps "$2"' _ "$work/functions.sh" "$work/p3.json")" == 1,2,3,5 ]] ||
  fail 'auto steps repeat a count for a small prediction'
[[ "$(bash -c 'source "$1"; MAX_SANDBOXES=20 auto_steps "$2"' _ "$work/functions.sh" "$work/p24.json")" == 6,12,18,20 ]] ||
  fail 'auto steps exceed --max-sandboxes'
[[ -z "$(bash -c 'source "$1"; MAX_SANDBOXES=200 auto_steps "$2"' _ "$work/functions.sh" "$work/p0.json")" ]] ||
  fail 'auto steps ramp when nothing fits'

# The summary shows the ready count, marks a quantile above the top bucket,
# and has one row per node with the run's sandboxes on it.
mkdir -p "$work/run"
printf '%s\n' '{"created":25,"ready_sandboxes":18,"failed_creates":7,"warm_hits":4,"new":15,"server_setup_complete":{"p50_ms":52500,"p95_ms":60000,"p50_over_top":false,"p95_over_top":true},"pods":37,"allocatable_pods":110,"requested_cpu_m":1,"allocatable_cpu_m":2,"requested_memory_mib":1,"allocatable_memory_mib":2,"placement":{"node-a":11},"nodes":[{"node":"node-a","pods":20,"allocatable_pods":110,"requested_cpu_m":1,"allocatable_cpu_m":2,"requested_memory_mib":1,"allocatable_memory_mib":2,"node_cpu_pct":12.34,"node_memory_pct":40,"psi_memory_some_pct":0,"psi_cpu_some_pct":1,"thin_used_pct":3},{"node":"node-b","pods":17,"allocatable_pods":110,"requested_cpu_m":1,"allocatable_cpu_m":2,"requested_memory_mib":1,"allocatable_memory_mib":2}]}' >"$work/run/steps.jsonl"
printf '%s' '{"sandbox_request":{"workspace":{"cpu_m":2000,"memory_mib":8192},"dind":{"cpu_m":500,"memory_mib":1024},"kata":{"cpu_m":250,"memory_mib":130},"cpu_m":2750,"memory_mib":9346},"predicted_total":24,"per_node":[{"node":"node-a","allocatable_cpu_m":127950,"allocatable_memory_mib":256041,"allocatable_pods":110,"requested_cpu_m":9154,"requested_memory_mib":29845,"pods":13,"by_cpu":43,"by_memory":24,"by_pods":97,"fits":24,"first_limit":"memory requests"}]}' >"$work/run/prediction.json"
bash -c 'source "$1"; NODES=(node-a node-b); RUN_DIR="$2" SHAPE=default CPU_M=2000 MEMORY_MIB=8192 DISK_GIB=80 RUN_ID=r WORKLOAD_CPU=0.5 WORKLOAD_MEMORY=0.5 HOLD_SECONDS=180 write_summary' _ "$work/functions.sh" "$work/run"
grep -qF '| 25 | 18 | 7 | 4/15 |' "$work/run/summary.md" || fail "summary lacks the ready count: $(cat "$work/run/summary.md")"
grep -qF '| 52500/>60000 |' "$work/run/summary.md" || fail "summary does not mark a p95 above the top bucket: $(cat "$work/run/summary.md")"
grep -qF '| 25 | node-a | 11 | 20/110 | 50 | 50 | 12.3 | 40 | 0/1 | 3 |' "$work/run/summary.md" ||
  fail "summary lacks the per-node row: $(cat "$work/run/summary.md")"
grep -qF '| 25 | node-b | 0 | 17/110 |' "$work/run/summary.md" || fail "summary lacks a node without run sandboxes"
grep -qF '# Sandbox capacity: node-a node-b,' "$work/run/summary.md" || fail "summary does not name both nodes"
grep -qF 'Each sandbox reserves 2.75 CPU and 9.1 GiB: workspace 2 CPU / 8 GiB, DinD 0.5 / 1, Kata 0.25 / 0.1.' "$work/run/summary.md" ||
  fail "summary lacks the reservation breakdown: $(cat "$work/run/summary.md")"
grep -qF '| node-a | 127.95 / 250 / 110 | 9.15 / 29.1 / 13 | 43 / 24 / 97 | 24 | memory requests |' "$work/run/summary.md" ||
  fail "summary lacks the per-node prediction: $(cat "$work/run/summary.md")"

# Start-up cleanup retries a Dev run that never proved cleanup, including one
# from before runs named their server, and leaves a Production run alone.
mkdir -p "$work/parent/old-dev" "$work/parent/prod-run" "$work/parent/done"
: >"$work/parent/old-dev/envs.tsv"
: >"$work/parent/prod-run/envs.tsv"
printf 'https://codewire.sh\n' >"$work/parent/prod-run/server"
: >"$work/parent/done/envs.tsv"
: >"$work/parent/done/cleaned"
result="$(bash -c 'source "$1"
  list_envs() { :; }
  clean_run_dir() { printf "cleaned %s\n" "$(basename "$1")"; }
  log() { :; }
  NAME_PREFIX=cap- LOAD_TMP_PARENT="$2" RUN_DIR="$2/current" RUN_ID=r CODEWIRE_SERVER_URL=https://codewire-dev.sh clean_leftovers' \
  _ "$work/functions.sh" "$work/parent")"
[[ "$result" == 'cleaned old-dev' ]] || fail "start-up cleanup crossed environments: $result"

# A hung kubectl (or credential plugin) fails within the bound instead of
# stalling the run.
mkdir -p "$work/bin"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >"%s/kubectl-args"\nexec sleep 600\n' "$work" >"$work/bin/kubectl"
chmod +x "$work/bin/kubectl"
sed -n '/^kubectl_ro() {/,/^}/p' "$LOAD" >"$work/kubectl_ro.sh"
started=$SECONDS
if PATH="$work/bin:$PATH" bash -c 'die() { exit 3; }; source "$1"; KUBE_CONTEXT=ctx KUBECTL_TIMEOUT_SECONDS=2 kubectl_ro get nodes' \
  _ "$work/kubectl_ro.sh"; then
  fail 'a hung kubectl succeeded'
fi
(( SECONDS - started <= 10 )) || fail "a hung kubectl took $((SECONDS - started)) s, past its 2 s bound"
grep -qF -- '--request-timeout=2s --context ctx get nodes' "$work/kubectl-args" || fail "kubectl_ro does not pass its request timeout: $(cat "$work/kubectl-args")"

# A step past its wall-clock limit records why and signals the run.
mkdir -p "$work/watchdog"
result="$(bash -c 'source "$1"; MAIN_PID=$$; RUN_DIR="$2"; MAX_STEP_MINUTES=0
  trap "echo signalled; exit 0" TERM
  start_watchdog 3; sleep 10 & wait $!; echo "not signalled"' _ "$work/functions.sh" "$work/watchdog")"
[[ "$result" == signalled ]] || fail "the step watchdog did not signal the run: $result"
[[ "$(cat "$work/watchdog/watchdog")" == 'step 3 exceeded its 0-minute limit' ]] || fail 'the step watchdog did not record why'
grep -qF 'start_watchdog "$step"' "$LOAD" || fail 'steps do not arm the watchdog'
grep -qF '  stop_watchdog' "$LOAD" || fail 'exit does not disarm the watchdog'

# Creates retry once after a client-side deadline, record an environment
# that was created anyway, and never retry a server refusal.
create_case() { # SCRIPT_OF_CW_OUTCOMES EXISTING_NAME -> "id calls retries"
  local dir
  dir="$(mktemp -d "$work/create.XXXXXX")"
  printf '%s\n' "$1" >"$dir/outcomes"
  bash -c 'source "$1"; RUN_DIR="$2"; NAME_PREFIX=cap-; RUN_ID=r; CPU_M=1000; MEMORY_MIB=4096; DISK_GIB=80
    LOAD_IMAGE=workspace; LOAD_TTL=4h; existing_name="$3"
    log() { :; }; pause() { :; }; now_ms() { echo 0; }
    list_envs() { [[ -z "$existing_name" ]] || printf "%s\t%s\n" 11111111-1111-1111-1111-111111111111 "$existing_name"; }
    cw() { local outcome; outcome="$(sed -n "$(( $(wc -l <"$RUN_DIR/calls" 2>/dev/null || echo 0) + 1 ))p" "$RUN_DIR/outcomes")"
      echo call >>"$RUN_DIR/calls"
      case "$outcome" in
        ok) printf "{\"id\":\"22222222-2222-2222-2222-222222222222\"}" ;;
        deadline) echo "list orgs: client-side deadline exceeded" >&2; return 1 ;;
        *) echo "$outcome" >&2; return 1 ;;
      esac; }
    id="$(create_env 1 2>/dev/null)" || id=failed
    echo "$id $(grep -c . "$RUN_DIR/calls") $(grep -c . "$RUN_DIR/create-retries" 2>/dev/null || echo 0)"' \
    _ "$work/functions.sh" "$dir" "$2"
}
[[ "$(create_case $'deadline\nok' '')" == '22222222-2222-2222-2222-222222222222 2 1' ]] || fail 'a client-side deadline is not retried once'
[[ "$(create_case 'deadline' cap-r-1)" == '11111111-1111-1111-1111-111111111111 1 1' ]] || fail 'an environment created despite a deadline is not recorded'
[[ "$(create_case $'deadline\ndeadline\nok' '')" == 'failed 2 1' ]] || fail 'a second client-side deadline is retried'
[[ "$(create_case $'environment quota exceeded\nok' '')" == 'failed 1 0' ]] || fail 'a server refusal is retried'

printf 'sandbox capacity load tests: ok\n'
