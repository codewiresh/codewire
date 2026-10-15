#!/usr/bin/env bash
# Measure what the credential proxy adds to one provider request, from inside
# one running Sandbox. Prints p50/p95 time to first byte for the proxied path
# and for the same request sent directly, and optionally the broker's per-phase
# timing lines for the same window.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

ENV_ID=""
REQUESTS=30
WARMUP=2
CW_BIN="${CW_BIN:-cw}"
SERVER=""
PHASES=0
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
SERVICE_NAMESPACE="${SERVICE_NAMESPACE:-dev}"
OUT_DIR=""
RUN_TIMEOUT_SECONDS=900

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/measure-credential-proxy-latency.sh --env <environment> [options]

Sends N proxied OpenAI Responses requests and the same N requests directly,
alternating, from inside one running Sandbox (one `cw run`), and prints p50/p95
time to first byte (curl %{time_starttransfer}) for both and their difference.

  proxied: POST $OPENAI_BASE_URL/responses  (127.0.0.1:38081 -> cw daemon ->
           bridge epoch -> gateway -> credential broker -> api.openai.com)
  direct:  POST https://api.openai.com/v1/responses

Both fail fast with 401 at OpenAI, so no real key or spend is involved.

Requirements:
  - The environment's credential profile selects an OpenAI API key for the
    `openai` slot. A synthetic key is fine (any token-shaped value, for
    example sk-synthetic-latency-probe): OpenAI rejects it with 401, the same
    work as a real request until the first byte. For example:
      cw credentials --cloud add openai --name latency-probe
      cw credentials --cloud --profile latency-probe set openai id:<credential-id>
    then create and start an environment with that profile.
  - `cw` is signed in to the target server (or CODEWIRE_API_KEY is set).
  - The Sandbox has curl and egress to api.openai.com.
  - --phases also reads the credential service's secret-free timing lines for
    the run window with kubectl (read-only). Every proxied OpenAI API-key
    request the service handled in that window is included. Its summary
    counts the requests whose material cache use was hit, miss or bypass, and
    those that reused their epoch's authority decision (reused: no resolve or
    grant evaluation, one record read) or evaluated it (evaluated).

Options:
  --env ID              Environment to run in (required)
  --requests N          Measured requests per path (default 30)
  --warmup N            Unmeasured request pairs first (default 2)
  --cw-bin PATH         cw binary (default: cw on PATH, or $CW_BIN)
  --server URL          Passed to cw --server (default: cw's configured server)
  --phases              Summarize broker phase timing lines with kubectl
  --kube-context CTX    kubectl context for --phases (or $KUBE_CONTEXT)
  --namespace NS        Credential service namespace (default dev)
  --out DIR             Evidence directory (default: repo .tmp/credential-proxy-latency.*)
  -h, --help            Show this help
USAGE
}

log() { printf '[proxy-latency] %s\n' "$*" >&2; }
die() { printf '[proxy-latency] ERROR: %s\n' "$*" >&2; exit 1; }

while (($# > 0)); do
  case "$1" in
    --env) [[ $# -ge 2 ]] || die '--env requires a value'; ENV_ID="$2"; shift 2 ;;
    --requests) [[ $# -ge 2 ]] || die '--requests requires a value'; REQUESTS="$2"; shift 2 ;;
    --warmup) [[ $# -ge 2 ]] || die '--warmup requires a value'; WARMUP="$2"; shift 2 ;;
    --cw-bin) [[ $# -ge 2 ]] || die '--cw-bin requires a value'; CW_BIN="$2"; shift 2 ;;
    --server) [[ $# -ge 2 ]] || die '--server requires a value'; SERVER="$2"; shift 2 ;;
    --phases) PHASES=1; shift ;;
    --kube-context) [[ $# -ge 2 ]] || die '--kube-context requires a value'; KUBE_CONTEXT="$2"; shift 2 ;;
    --namespace) [[ $# -ge 2 ]] || die '--namespace requires a value'; SERVICE_NAMESPACE="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || die '--out requires a value'; OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$ENV_ID" ]] || { usage >&2; die '--env is required'; }
[[ "$ENV_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die '--env must be an environment ID or name'
if ! [[ "$REQUESTS" =~ ^[0-9]{1,4}$ ]] || ((REQUESTS < 1 || REQUESTS > 1000)); then
  die '--requests must be an integer from 1 to 1000'
fi
if ! [[ "$WARMUP" =~ ^[0-9]{1,2}$ ]] || ((WARMUP > 20)); then
  die '--warmup must be an integer from 0 to 20'
fi
for command in jq awk sort timeout; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
command -v "$CW_BIN" >/dev/null 2>&1 || die "cw binary not found: $CW_BIN (use --cw-bin)"
if [[ "$PHASES" == 1 ]]; then
  command -v kubectl >/dev/null 2>&1 || die 'missing required command for --phases: kubectl'
fi

if [[ -z "$OUT_DIR" ]]; then
  mkdir -p "$ROOT/.tmp"
  OUT_DIR="$(mktemp -d "$ROOT/.tmp/credential-proxy-latency.XXXXXX")"
else
  mkdir -p "$OUT_DIR"
fi

cw_command=("$CW_BIN")
[[ -z "$SERVER" ]] || cw_command+=(--server "$SERVER")

# Runs inside the Sandbox. It prints only path, iteration, HTTP status and
# curl's timings; response bodies are discarded.
# shellcheck disable=SC2016 # Expanded by the Sandbox shell, not here.
SANDBOX_SCRIPT='
set -u
requests="$1"
warmup="$2"
command -v curl >/dev/null 2>&1 || { echo "curl is not installed in this Sandbox" >&2; exit 4; }
case "${OPENAI_BASE_URL:-}" in
  http://127.0.0.1:*) ;;
  *) echo "OPENAI_BASE_URL is not the Codewire proxy: select a profile with an OpenAI API key for this environment" >&2; exit 3 ;;
esac
[ "${OPENAI_API_KEY:-}" = codewire-managed ] || {
  echo "OPENAI_API_KEY is not the Codewire placeholder: select a profile with an OpenAI API key" >&2; exit 3; }
body="{\"model\":\"gpt-4o-mini\",\"input\":\"codewire latency probe\"}"
probe() {
  curl -sS -o /dev/null --max-time 30 -X POST \
    -H "content-type: application/json" -H "authorization: Bearer $OPENAI_API_KEY" \
    --data "$body" -w "%{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}" \
    "$1" 2>/dev/null || true
}
proxied="${OPENAI_BASE_URL%/}/responses"
direct="https://api.openai.com/v1/responses"
i=0
while [ "$i" -lt "$warmup" ]; do
  probe "$proxied" >/dev/null; probe "$direct" >/dev/null
  i=$((i + 1))
done
i=1
while [ "$i" -le "$requests" ]; do
  # Alternate which path goes first so neither always runs on a warmer path.
  if [ $((i % 2)) -eq 1 ]; then
    printf "proxied %s %s\n" "$i" "$(probe "$proxied")"
    printf "direct %s %s\n" "$i" "$(probe "$direct")"
  else
    printf "direct %s %s\n" "$i" "$(probe "$direct")"
    printf "proxied %s %s\n" "$i" "$(probe "$proxied")"
  fi
  i=$((i + 1))
done
'

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "environment=$ENV_ID requests=$REQUESTS warmup=$WARMUP out=$OUT_DIR"
set +e
timeout "$RUN_TIMEOUT_SECONDS" "${cw_command[@]}" run --no-tty "$ENV_ID" -- sh -c "$SANDBOX_SCRIPT" \
  codewire-proxy-latency "$REQUESTS" "$WARMUP" >"$OUT_DIR/samples.txt" 2>"$OUT_DIR/cw-run.err"
status=$?
set -e
finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ "$status" != 0 ]]; then
  sed 's/[[:cntrl:]]//g' "$OUT_DIR/cw-run.err" | tail -n 5 >&2 || true
  case "$status" in
    3) die 'the environment does not project the OpenAI proxy: it needs a profile with an OpenAI API key' ;;
    4) die 'curl is not installed in the Sandbox' ;;
    *) die "cw run failed with exit status $status" ;;
  esac
fi

# Nearest-rank percentiles over the measured requests, in milliseconds.
summarize() {
  local path="$1"
  awk -v path="$path" '$1 == path && $3 != "000" { printf "%.3f\n", $6 * 1000 }' "$OUT_DIR/samples.txt" |
    sort -n | awk -v path="$path" '
      { value[NR] = $1; sum += $1 }
      END {
        if (NR == 0) { printf "%-8s no successful requests\n", path; exit }
        p50 = value[int(NR * 0.50 + 0.999999)]; p95 = value[int(NR * 0.95 + 0.999999)]
        printf "%-8s n=%-4d p50=%8.1f ms  p95=%8.1f ms  min=%8.1f  max=%8.1f  mean=%8.1f\n",
          path, NR, p50, p95, value[1], value[NR], sum / NR
      }'
}

percentile() {
  awk -v path="$1" -v q="$2" '$1 == path && $3 != "000" { print $6 * 1000 }' "$OUT_DIR/samples.txt" |
    sort -n | awk -v q="$2" '{ value[NR] = $1 } END { if (NR) print value[int(NR * q + 0.999999)]; else print "nan" }'
}

{
  printf 'credential proxy latency: environment=%s requests=%s warmup=%s\n' "$ENV_ID" "$REQUESTS" "$WARMUP"
  printf 'window: %s .. %s\n' "$started_at" "$finished_at"
  printf 'time to first byte (curl time_starttransfer):\n'
  summarize proxied
  summarize direct
  awk -v p="$(percentile proxied 0.50)" -v d="$(percentile direct 0.50)" \
    -v p95="$(percentile proxied 0.95)" -v d95="$(percentile direct 0.95)" \
    'BEGIN { printf "overhead p50=%.1f ms  p95=%.1f ms (proxied minus direct)\n", p - d, p95 - d95 }'
  printf 'HTTP status counts:\n'
  awk '{ count[$1 " " $3]++ } END { for (key in count) printf "  %s x%d\n", key, count[key] }' \
    "$OUT_DIR/samples.txt" | sort
} | tee "$OUT_DIR/summary.txt"

if awk '$1 == "proxied" && $3 != "401" { bad = 1 } END { exit !bad }' "$OUT_DIR/samples.txt"; then
  log 'some proxied requests did not get 401: check the profile selects an active OpenAI API key'
fi

[[ "$PHASES" == 1 ]] || exit 0

kubectl_service() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

# Secret-free by construction: durations, counts, closed labels and an opaque
# request UUID on the dedicated codewire_credential_broker::timing target.
kubectl_service -n "$SERVICE_NAMESPACE" logs \
  -l app.kubernetes.io/name=codewire,app.kubernetes.io/component=credential-service \
  -c credential-service --since-time="$started_at" --tail=-1 --max-log-requests=10 \
  >"$OUT_DIR/credential-service.log" 2>"$OUT_DIR/credential-service.err" ||
  die 'cannot read credential service logs for --phases'
jq -Rc 'fromjson? | select(.target == "codewire_credential_broker::timing") | .fields' \
  "$OUT_DIR/credential-service.log" >"$OUT_DIR/timing.jsonl"
jq -s --arg finished "$finished_at" '
  def pct($q): sort | if length == 0 then null else .[(($q * length) | ceil) - 1] end;
  def round1: if . == null then null else (. * 10 | round) / 10 end;
  [.[] | select(.event == "proxied_request" and .slot == "openai" and .route == "openai-api")] as $requests
  | ["total_ms", "lease_wait_ms", "authority_ms", "resolve_kubernetes_ms", "resolve_sql_ms",
     "grants_ms", "record_ms", "read_db_ms", "unwrap_ms", "provider_connect_ttfb_ms",
     "refresh_ms"] as $phases
  | {
      proxied_requests: ($requests | length),
      counts_p50: ({
        authority_checks: ($requests | map(.authority_checks) | pct(0.5)),
        resolves: ($requests | map(.resolves) | pct(0.5)),
        grant_evaluations: ($requests | map(.grant_evaluations) | pct(0.5)),
        record_reads: ($requests | map(.record_reads) | pct(0.5)),
        material_reads: ($requests | map(.material_reads) | pct(0.5)),
        provider_requests: ($requests | map(.provider_requests) | pct(0.5))
      }),
      # How many requests reused decrypted material from their epoch (hit),
      # read it through the store (miss) or never consulted a cache (bypass).
      cache: ($requests | group_by(.cache // "unreported")
        | map({key: (.[0].cache // "unreported"), value: length}) | from_entries),
      # How many requests reused the authority decision of their epoch (reused),
      # ran or waited for an evaluation (evaluated), or never leased (none).
      authority: ($requests | group_by(.authority // "unreported")
        | map({key: (.[0].authority // "unreported"), value: length}) | from_entries),
      phases_ms: ([$phases[] as $phase | {
        key: $phase,
        value: {p50: ($requests | map(.[$phase]) | pct(0.5) | round1),
                p95: ($requests | map(.[$phase]) | pct(0.95) | round1)}
      }] | from_entries),
      outcomes: ($requests | group_by(.outcome + " " + (.status | tostring))
        | map({key: .[0].outcome + " " + (.[0].status | tostring), value: length}) | from_entries),
      epoch_admissions: ([.[] | select(.event == "epoch_admission")] | length),
      max_streams_in_use: ([.[] | select(.event == "epoch_admission") | .streams_in_use] | max),
      capacity_rejections: ([.[] | select(.event == "capacity_rejected")] | length)
    }
' "$OUT_DIR/timing.jsonl" | tee "$OUT_DIR/phases.json"
