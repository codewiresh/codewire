#!/usr/bin/env bash
# shellcheck disable=SC2016 # Single-quoted patterns match literal source text.
# Contract tests for the Dev sandbox capacity load (#3583): it runs only
# against Dev with the smoke key, refuses unsafe options before any network or
# build step, is read-only toward Kubernetes, deletes only environments it
# named, and computes milestone percentiles from histogram deltas.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LOAD="$ROOT/scripts/runtime/dev/load-dev-sandbox-capacity.sh"

fail() { printf 'sandbox capacity load tests: %s\n' "$*" >&2; exit 1; }

refuses() {
  local expected="$1"
  shift
  local output
  if output="$(env -u CODEWIRE_DEV_SMOKE_API_KEY "$@" 2>&1)"; then
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
refuses '--steps must be a comma-separated' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --steps 10,,20
refuses '--steps must increase' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --steps 10,10
refuses '--steps exceeds --max-sandboxes' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --steps 10,300
refuses '--max-sandboxes must be 1-500' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --max-sandboxes 501
refuses 'WORKLOAD_CPU must be between 0 and 0.9' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --workload-cpu 1
refuses 'WORKLOAD_MEMORY must be between 0 and 0.9' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --workload-memory 0.95
refuses '--latency-factor must be at least 1' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --latency-factor 0.5
refuses 'MAX_NODE_MEMORY_PCT must be 1-100' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --max-node-memory-pct 0
refuses 'shell tracing is enabled' env CODEWIRE_DEV_SMOKE_API_KEY=x bash -x "$LOAD"
refuses 'unknown argument' env CODEWIRE_DEV_SMOKE_API_KEY=x "$LOAD" --keep

# Kubernetes access is read-only: kubectl_ro is the only kubectl call, and it
# allows get alone.
mapfile -t direct < <(grep -n 'kubectl --context' "$LOAD")
[[ "${#direct[@]}" -eq 1 ]] || fail "unexpected direct kubectl calls: ${direct[*]}"
grep -qF "kubectl --context \"\$KUBE_CONTEXT\" \"\$@\"" "$LOAD" || fail 'kubectl_ro is not the read path'
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

# The summary shows the ready count and marks a quantile above the top bucket.
mkdir -p "$work/run"
printf '%s\n' '{"created":25,"ready_sandboxes":18,"failed_creates":7,"warm_hits":4,"new":15,"server_setup_complete":{"p50_ms":52500,"p95_ms":60000,"p50_over_top":false,"p95_over_top":true},"pods":37,"allocatable_pods":110,"requested_cpu_m":1,"allocatable_cpu_m":2,"requested_memory_mib":1,"allocatable_memory_mib":2}' >"$work/run/steps.jsonl"
bash -c 'source "$1"; RUN_DIR="$2" NODE=n SHAPE=default CPU_M=2000 MEMORY_MIB=8192 DISK_GIB=80 RUN_ID=r WORKLOAD_CPU=0.5 WORKLOAD_MEMORY=0.5 HOLD_SECONDS=180 write_summary' _ "$work/functions.sh" "$work/run"
grep -qF '| 25 | 18 | 7 | 4/15 |' "$work/run/summary.md" || fail "summary lacks the ready count: $(cat "$work/run/summary.md")"
grep -qF '| 52500/>60000 |' "$work/run/summary.md" || fail "summary does not mark a p95 above the top bucket: $(cat "$work/run/summary.md")"

printf 'sandbox capacity load tests: ok\n'
