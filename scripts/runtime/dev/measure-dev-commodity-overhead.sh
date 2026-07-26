#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
MEASURE_ENV_ID="${MEASURE_ENV_ID:-}"
MEASURE_TMP_PARENT="${MEASURE_TMP_PARENT:-$ROOT/.tmp}"
MEASURE_RUN_LOAD="${MEASURE_RUN_LOAD:-0}"
MEASURE_POSTGRES_ROWS="${MEASURE_POSTGRES_ROWS:-5000}"
MEASURE_TIMEOUT_SECONDS="${MEASURE_TIMEOUT_SECONDS:-900}"
MEASURE_CW_BUILD_TIMEOUT="${MEASURE_CW_BUILD_TIMEOUT:-600s}"
ALLOW_NON_DEV="${ALLOW_NON_DEV:-0}"
ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE="${ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE:-0}"
CW_BIN="${CW_BIN:-}"

OUT_DIR=""
WORKSPACE_POD=""
GATEWAY_POD=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/measure-dev-commodity-overhead.sh --env <environment-id> [options]

Collect real-node commodity resource evidence for a kept Codewire environment.
For local auth, wrap this with scripts/runtime/dev/with-dev-smoke-auth.sh.

Options:
  --env ID              Environment ID to measure (or MEASURE_ENV_ID)
  --run-load            Run Docker build/compose/Postgres load observations
  --postgres-rows N     Row count for the Postgres load phase (default: 5000)
  --out DIR             Evidence directory (default: repo .tmp/commodity-overhead.*)
  --cw-bin PATH         Use an existing cw binary instead of building one
  --timeout-seconds N   cw run timeout for load phases (default: 900)
  -h, --help            Show this help

Environment:
  CODEWIRE_SERVER_URL   Defaults to https://codewire-dev.sh
  CODEWIRE_DEV_SMOKE_API_KEY
                        Required by default; copied to CODEWIRE_API_KEY for cw
  KUBECONFIG            Optional; defaults to ~/src/infra/kubeconfig-oidc.yaml
  KUBE_CONTEXT          Optional; if unset, prefers codewire-dev, then default,
                        then current-context
USAGE
}

log() {
  printf '[runtime-measure] %s\n' "$*" >&2
}

die() {
  printf '[runtime-measure] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
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

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

kubectl_dev() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

cw() {
  "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"
}

cw_with_timeout() {
  local duration="$1"
  shift
  timeout "$duration" "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"
}

while (($# > 0)); do
  case "$1" in
    --env)
      [[ $# -ge 2 ]] || die "--env requires a value"
      MEASURE_ENV_ID="$2"
      shift 2
      ;;
    --run-load)
      MEASURE_RUN_LOAD=1
      shift
      ;;
    --postgres-rows)
      [[ $# -ge 2 ]] || die "--postgres-rows requires a value"
      MEASURE_POSTGRES_ROWS="$2"
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || die "--out requires a value"
      OUT_DIR="$2"
      shift 2
      ;;
    --cw-bin)
      [[ $# -ge 2 ]] || die "--cw-bin requires a value"
      CW_BIN="$2"
      shift 2
      ;;
    --timeout-seconds)
      [[ $# -ge 2 ]] || die "--timeout-seconds requires a value"
      MEASURE_TIMEOUT_SECONDS="$2"
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

maybe_default_kubeconfig() {
  if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
    export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
  fi
}

select_kube_context() {
  local contexts current_context candidate

  contexts="$(kubectl config get-contexts -o name)"
  if [[ -n "$KUBE_CONTEXT" ]]; then
    grep -Fxq "$KUBE_CONTEXT" <<<"$contexts" || die "KUBE_CONTEXT=$KUBE_CONTEXT is not present in the active kubeconfig"
    log "using Kubernetes context $KUBE_CONTEXT"
    return
  fi

  for candidate in codewire-dev default; do
    if grep -Fxq "$candidate" <<<"$contexts"; then
      KUBE_CONTEXT="$candidate"
      export KUBE_CONTEXT
      log "using Kubernetes context $KUBE_CONTEXT"
      return
    fi
  done

  current_context="$(kubectl config current-context)"
  [[ -n "$current_context" ]] || die "failed to select Kubernetes context"
  KUBE_CONTEXT="$current_context"
  export KUBE_CONTEXT
  log "using Kubernetes context $KUBE_CONTEXT"
}

prepare() {
  [[ "$CODEWIRE_SERVER_URL" == "https://codewire-dev.sh" || "$ALLOW_NON_DEV" == "1" ]] || \
    die "refusing to run against $CODEWIRE_SERVER_URL without ALLOW_NON_DEV=1"
  [[ -n "$MEASURE_ENV_ID" ]] || die "--env or MEASURE_ENV_ID is required"
  require_bool01 MEASURE_RUN_LOAD "$MEASURE_RUN_LOAD"
  require_uint MEASURE_POSTGRES_ROWS "$MEASURE_POSTGRES_ROWS"
  require_uint MEASURE_TIMEOUT_SECONDS "$MEASURE_TIMEOUT_SECONDS"
  require_cmd jq
  require_cmd kubectl
  require_cmd timeout

  if [[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]]; then
    export CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"
  elif [[ "$ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE" == "1" && -n "${CODEWIRE_API_KEY:-}" ]]; then
    :
  else
    die "CODEWIRE_DEV_SMOKE_API_KEY is required; use scripts/runtime/dev/with-dev-smoke-auth.sh"
  fi

  mkdir -p "$MEASURE_TMP_PARENT"
  if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="$(mktemp -d "$MEASURE_TMP_PARENT/codewire-commodity-overhead.XXXXXX")"
  else
    mkdir -p "$OUT_DIR"
  fi
  export CW_CONFIG_DIR="$OUT_DIR/cw-config"
  mkdir -p "$CW_CONFIG_DIR"

  if [[ -z "$CW_BIN" ]]; then
    require_cmd cargo
    CW_BIN="$OUT_DIR/cw"
    log "building cw CLI with timeout $MEASURE_CW_BUILD_TIMEOUT"
    if ! (cd "$ROOT" && timeout "$MEASURE_CW_BUILD_TIMEOUT" cargo build --locked --profile ci -p codewire-cli-bin --bin cw) >"$OUT_DIR/rust-build-cw.log" 2>&1; then
      sed 's/[[:cntrl:]]//g' "$OUT_DIR/rust-build-cw.log" >&2 || true
      die "failed to build cw CLI"
    fi
    cp "$ROOT/target/ci/cw" "$CW_BIN"
  fi

  maybe_default_kubeconfig
  select_kube_context
}

discover_pods() {
  local pods_json="$OUT_DIR/pods.json"

  kubectl_dev -n "$SANDBOX_NAMESPACE" get pods \
    -l "codewire.sh/environment-id=$MEASURE_ENV_ID" \
    -o json >"$pods_json"

  WORKSPACE_POD="$(jq -r 'first(.items[] | select([.spec.containers[].name] | index("workspace")) | .metadata.name) // empty' "$pods_json")"
  GATEWAY_POD="$(jq -r 'first(.items[] | select([.spec.containers[].name] | index("codewire-gateway")) | .metadata.name) // empty' "$pods_json")"

  [[ -n "$WORKSPACE_POD" ]] || die "workspace pod not found for environment $MEASURE_ENV_ID"
  [[ -n "$GATEWAY_POD" ]] || die "gateway pod not found for environment $MEASURE_ENV_ID"

  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$WORKSPACE_POD" -o json >"$OUT_DIR/workspace-pod.json"
  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$GATEWAY_POD" -o json >"$OUT_DIR/gateway-pod.json"
  kubectl_dev get node "$(jq -r '.spec.nodeName' "$OUT_DIR/workspace-pod.json")" -o json >"$OUT_DIR/workspace-node.json"
  kubectl_dev get node "$(jq -r '.spec.nodeName' "$OUT_DIR/gateway-pod.json")" -o json >"$OUT_DIR/gateway-node.json"

  log "workspace pod=$WORKSPACE_POD gateway pod=$GATEWAY_POD"
  kubectl_dev -n "$SANDBOX_NAMESPACE" wait "pod/$WORKSPACE_POD" \
    --for=condition=Ready --timeout="${MEASURE_TIMEOUT_SECONDS}s"
  kubectl_dev -n "$SANDBOX_NAMESPACE" wait "pod/$GATEWAY_POD" \
    --for=condition=Ready --timeout="${MEASURE_TIMEOUT_SECONDS}s"
}

wait_for_cw_run() {
  local deadline out last

  out="$OUT_DIR/cw-run-ready.err"
  deadline=$(( "$(date +%s)" + MEASURE_TIMEOUT_SECONDS ))
  while (( "$(date +%s)" < deadline )); do
    if cw_with_timeout 30 run --no-tty "$MEASURE_ENV_ID" -- true > /dev/null 2>"$out"; then
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

capture_top() {
  local phase="$1"
  {
    printf '# kubectl top nodes (%s)\n' "$phase"
    kubectl_dev top nodes
  } >"$OUT_DIR/top-nodes-$phase.txt" 2>"$OUT_DIR/top-nodes-$phase.err" || true

  {
    printf '# kubectl top pod containers (%s)\n' "$phase"
    kubectl_dev -n "$SANDBOX_NAMESPACE" top pod "$WORKSPACE_POD" --containers
    kubectl_dev -n "$SANDBOX_NAMESPACE" top pod "$GATEWAY_POD" --containers
  } >"$OUT_DIR/top-pods-$phase.txt" 2>"$OUT_DIR/top-pods-$phase.err" || true
}

capture_kube_summary() {
  local table="$OUT_DIR/container-resources.tsv"

  jq -r '
    . as $pod
    | .spec.containers[]
    | [
        $pod.metadata.name,
        $pod.spec.nodeName,
        $pod.spec.runtimeClassName,
        .name,
        (.resources.requests.cpu // ""),
        (.resources.requests.memory // ""),
        (.resources.requests["ephemeral-storage"] // ""),
        (.resources.limits.cpu // ""),
        (.resources.limits.memory // ""),
        (.resources.limits["ephemeral-storage"] // "")
      ]
    | @tsv
  ' "$OUT_DIR/workspace-pod.json" "$OUT_DIR/gateway-pod.json" >"$table"

  {
    printf 'pod\tnode\truntimeClass\tcontainer\trequest_cpu\trequest_memory\trequest_ephemeral\tlimit_cpu\tlimit_memory\tlimit_ephemeral\n'
    cat "$table"
  } >"$OUT_DIR/container-resources-with-header.tsv"
}

capture_idle_guest() {
  local workspace_script dind_script

  workspace_script='
set -eu
printf "=== workspace identity ===\n"
id
printf "=== docker version ===\n"
docker version --format "client={{.Client.Version}} server={{.Server.Version}}"
printf "=== docker info ===\n"
docker info --format "driver={{.Driver}} containers={{.Containers}} images={{.Images}} server={{.ServerVersion}}"
printf "=== workspace disk ===\n"
df -h /workspace /var/run/docker 2>/dev/null || df -h /workspace
printf "=== docker system df ===\n"
docker system df || true
'
  cw_with_timeout "$MEASURE_TIMEOUT_SECONDS" \
    run --no-tty "$MEASURE_ENV_ID" -- sh -lc "$workspace_script" \
    >"$OUT_DIR/workspace-idle.txt" 2>"$OUT_DIR/workspace-idle.err"

  dind_script='
set -eu
printf "=== dind process ===\n"
ps -o pid,ppid,pcpu,rss,comm,args 2>/dev/null | head -n 20 || ps
printf "=== dind pid1 status ===\n"
grep -E "^(Name|State|VmRSS|VmHWM|Threads|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):" /proc/1/status || true
printf "=== dind mounts ===\n"
grep " /var/lib/docker " /proc/mounts || true
printf "=== dind disk ===\n"
df -h /var/lib/docker
du -sh /var/lib/docker 2>/dev/null || true
'
  kubectl_dev -n "$SANDBOX_NAMESPACE" exec "$WORKSPACE_POD" -c dind -- sh -lc "$dind_script" \
    >"$OUT_DIR/dind-idle.txt" 2>"$OUT_DIR/dind-idle.err"
}

run_load_observations() {
  local load_script

  [[ "$MEASURE_RUN_LOAD" == "1" ]] || return 0

  load_script="$(cat <<SCRIPT
set -eu
rows=$MEASURE_POSTGRES_ROWS
work="/tmp/codewire-commodity-measure"
pg="codewire-measure-postgres"
vol="codewire-measure-postgres-data"
compose_project="codewiremeasure"

cleanup() {
  docker rm -f "\$pg" >/dev/null 2>&1 || true
  docker volume rm "\$vol" >/dev/null 2>&1 || true
  docker compose -p "\$compose_project" -f "\$work/compose.yaml" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "\$work"
}

measure() {
  name="\$1"
  shift
  start="\$(date +%s)"
  printf "BEGIN %s %s\\n" "\$name" "\$start"
  "\$@"
  end="\$(date +%s)"
  printf "END %s %s elapsed=%ss\\n" "\$name" "\$end" "\$((end - start))"
  docker stats --no-stream --format "{{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.BlockIO}}" 2>/dev/null || true
  docker system df || true
}

cleanup
mkdir -p "\$work"
trap cleanup EXIT

cat > "\$work/Dockerfile" <<'EOF'
FROM busybox:1.36
RUN echo build-unpack-ok > /build-unpack.txt
CMD ["cat", "/build-unpack.txt"]
EOF

measure docker-version docker version
measure image-pull docker pull busybox:1.36
measure image-build docker build -t codewire-measure-build:latest "\$work"
measure image-run docker run --rm codewire-measure-build:latest

cat > "\$work/compose.yaml" <<'EOF'
services:
  app:
    image: busybox:1.36
    command: sh -c "echo compose-measure-ok"
EOF
measure compose-up docker compose -p "\$compose_project" -f "\$work/compose.yaml" up --abort-on-container-exit --exit-code-from app
docker compose -p "\$compose_project" -f "\$work/compose.yaml" down -v --remove-orphans >/dev/null

docker volume create "\$vol" >/dev/null
measure postgres-start docker run -d --name "\$pg" -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=smoke -v "\$vol:/var/lib/postgresql/data" postgres:17-alpine
for i in \$(seq 1 60); do
  if docker exec "\$pg" pg_isready -h 127.0.0.1 -U postgres -d smoke >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "\$pg" pg_isready -h 127.0.0.1 -U postgres -d smoke >/dev/null
measure postgres-write docker exec "\$pg" psql -h 127.0.0.1 -U postgres -d smoke -v ON_ERROR_STOP=1 \
  -c "CREATE TABLE IF NOT EXISTS runtime_rows (id integer PRIMARY KEY, payload text);" \
  -c "TRUNCATE runtime_rows;" \
  -c "INSERT INTO runtime_rows SELECT g, md5(g::text) FROM generate_series(1,\${rows}) g;"
count="\$(docker exec "\$pg" psql -h 127.0.0.1 -U postgres -d smoke -tAc "SELECT count(*) FROM runtime_rows")"
test "\$count" = "\$rows"
printf "postgres_rows=%s\\n" "\$count"
SCRIPT
)"

  cw_with_timeout "$MEASURE_TIMEOUT_SECONDS" \
    run --no-tty "$MEASURE_ENV_ID" -- sh -lc "$load_script" \
    >"$OUT_DIR/docker-load.txt" 2>"$OUT_DIR/docker-load.err"
}

write_summary() {
  local summary="$OUT_DIR/summary.md"
  local workspace_node gateway_node runtime_class started_at

  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  workspace_node="$(jq -r '.spec.nodeName' "$OUT_DIR/workspace-pod.json")"
  gateway_node="$(jq -r '.spec.nodeName' "$OUT_DIR/gateway-pod.json")"
  runtime_class="$(jq -r '.spec.runtimeClassName // ""' "$OUT_DIR/workspace-pod.json")"

  {
    printf '# Commodity Runtime Overhead Evidence\n\n'
    printf '%s\n' "- captured: \`$started_at\`"
    printf '%s\n' "- environment: \`$MEASURE_ENV_ID\`"
    printf '%s\n' "- server: \`$CODEWIRE_SERVER_URL\`"
    printf '%s\n' "- namespace: \`$SANDBOX_NAMESPACE\`"
    printf '%s\n' "- runtimeClass: \`$runtime_class\`"
    printf '%s\n' "- workspace pod: \`$WORKSPACE_POD\` on \`$workspace_node\`"
    printf '%s\n' "- gateway pod: \`$GATEWAY_POD\` on \`$gateway_node\`"
    printf '%s\n\n' "- Docker load phase: \`$MEASURE_RUN_LOAD\`"

    printf '## Container Requests And Limits\n\n'
    printf '```tsv\n'
    cat "$OUT_DIR/container-resources-with-header.tsv"
    printf '```\n\n'

    printf '## Live Metrics\n\n'
    printf 'Node and container metrics are captured when the cluster metrics API is available:\n\n'
    printf '%s\n' '- `top-nodes-idle.txt`'
    printf '%s\n' '- `top-pods-idle.txt`'
    if [[ "$MEASURE_RUN_LOAD" == "1" ]]; then
      printf '%s\n' '- `top-nodes-after-load.txt`'
      printf '%s\n' '- `top-pods-after-load.txt`'
    fi
    printf '\n'

    printf '## Guest Docker Observations\n\n'
    printf '%s\n' '- `workspace-idle.txt` captures `docker version`, `docker info`, workspace disk, and `docker system df`.'
    printf '%s\n' '- `dind-idle.txt` captures the dind process table, `/var/lib/docker` mount, and data-root disk usage.'
    if [[ "$MEASURE_RUN_LOAD" == "1" ]]; then
      printf '%s\n' '- `docker-load.txt` captures image pull/build/run, compose, Postgres start/write, elapsed seconds, and `docker stats --no-stream` samples after each phase.'
    fi
    printf '\n'

    printf '## Current P1 Recommendation\n\n'
    printf 'Keep commodity on explicit support-container resources while P1 remains on the tactical guest ext4 Docker data root:\n\n'
    printf '%s\n' '- gateway request/limit remains `100m`/`128Mi` request and `500m`/`256Mi` limit unless measured gateway idle/load exceeds that headroom.'
    printf '%s\n' '- workspace CPU/memory/disk remain SKU-owned through the environment request.'
    printf '%s\n' '- dind overhead remains explicit in the pod and must be compared with `dind-idle.txt`, `docker-load.txt`, and the SKU budget before changing defaults.'
    printf '%s\n' '- Longhorn/raw block Docker storage is intentionally outside P1 and stays tracked in the Storage v2 milestone.'
  } >"$summary"

  log "wrote evidence summary $summary"
}

main() {
  prepare
  discover_pods
  capture_kube_summary
  capture_top idle
  wait_for_cw_run
  capture_idle_guest
  run_load_observations
  if [[ "$MEASURE_RUN_LOAD" == "1" ]]; then
    capture_top after-load
  fi
  write_summary
  log "evidence directory: $OUT_DIR"
}

main "$@"
