#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ALLOW_MIXED=0
SKIP_STATIC=0
SKIP_SOURCES=0
SKIP_LIVE=0
REQUIRE_LIVE=0
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-codewire}"
NAMESPACE="${NAMESPACE:-default}"

OVERLAYS=(
  deployments/k8s/overlays/local-kind
  deployments/k8s/overlays/local-kind-static
  deployments/k8s/overlays/dev
  deployments/k8s/overlays/production
)

usage() {
  cat <<'USAGE'
Usage: scripts/checks/security/audit-rust-only-runtime.sh [options]

Audits retired Go runtime paths and unaccepted NATS wiring for the Rust-only
release gate. Strict mode exits non-zero when blockers are found. `--allow-mixed`
is retained only for diagnosing an intentionally old deployed revision.

Options:
  --allow-mixed          Report blockers but exit 0
  --overlay PATH         Audit an additional or replacement kustomize overlay
  --skip-static          Skip rendered kustomize overlay checks
  --skip-sources         Skip source-tree blocker checks
  --skip-live            Skip live cluster checks
  --live                 Require live cluster checks to run
  --context NAME         Kubernetes context for live checks
  --namespace NAME       Kubernetes namespace for live checks
  -h, --help             Show this help
USAGE
}

if [ "$#" -gt 0 ]; then
  custom_overlays=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --allow-mixed)
        ALLOW_MIXED=1
        ;;
      --overlay)
        [ "$#" -ge 2 ] || { echo "--overlay requires a path" >&2; exit 2; }
        custom_overlays+=("$2")
        shift
        ;;
      --skip-static)
        SKIP_STATIC=1
        ;;
      --skip-sources)
        SKIP_SOURCES=1
        ;;
      --skip-live)
        SKIP_LIVE=1
        ;;
      --live)
        REQUIRE_LIVE=1
        ;;
      --context)
        [ "$#" -ge 2 ] || { echo "--context requires a value" >&2; exit 2; }
        KUBE_CONTEXT="$2"
        shift
        ;;
      --namespace)
        [ "$#" -ge 2 ] || { echo "--namespace requires a value" >&2; exit 2; }
        NAMESPACE="$2"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "unknown argument: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
  done
  if [ "${#custom_overlays[@]}" -gt 0 ]; then
    OVERLAYS=("${custom_overlays[@]}")
  fi
fi

TMP_DIR="$(mktemp -d)"
FINDINGS="$TMP_DIR/findings"
touch "$FINDINGS"
trap 'rm -rf "$TMP_DIR"' EXIT

log() {
  printf '[rust-only-audit] %s\n' "$*"
}

record() {
  local scope="$1" label="$2" detail="${3:-}"
  {
    printf '[%s] %s\n' "$scope" "$label"
    if [ -n "$detail" ]; then
      printf '%s\n' "$detail" | sed 's/^/  /'
    fi
  } >> "$FINDINGS"
}

record_grep() {
  local scope="$1" label="$2" pattern="$3" file="$4"
  local matches
  matches="$(grep -En "$pattern" "$file" 2>/dev/null | head -20 || true)"
  if [ -n "$matches" ]; then
    record "$scope" "$label" "$matches"
  fi
}

record_static_unaccepted_nats_env() {
  local scope="$1" file="$2" matches
  matches="$(awk '
    function reset_doc() {
      kind = "";
      name = "";
      in_metadata = 0;
      has_nats_env = 0;
    }
    function flush_doc() {
      if (has_nats_env && kind ~ /^(Deployment|StatefulSet|DaemonSet)$/ &&
          name != "codewire-coordinator" && name != "codewire-mesh") {
        print kind "/" name " contains NATS_URL env";
      }
    }
    BEGIN { reset_doc(); }
    /^---[[:space:]]*$/ { flush_doc(); reset_doc(); next; }
    $1 == "kind:" { kind = $2; next; }
    $1 == "metadata:" { in_metadata = 1; next; }
    in_metadata && $1 == "name:" { name = $2; in_metadata = 0; next; }
    in_metadata && $1 !~ /^[[:space:]]/ { in_metadata = 0; }
    ($1 == "name:" && $2 == "NATS_URL") || ($1 == "-" && $2 == "name:" && $3 == "NATS_URL") {
      has_nats_env = 1;
    }
    END { flush_doc(); }
  ' "$file" | head -20 || true)"
  if [ -n "$matches" ]; then
    record "$scope" "unaccepted service NATS_URL env remains" "$matches"
  fi
}

render_overlay() {
  local overlay="$1" out="$2"
  if command -v kustomize >/dev/null 2>&1; then
    kustomize build "$ROOT/$overlay" > "$out"
  elif command -v kubectl >/dev/null 2>&1; then
    kubectl kustomize "$ROOT/$overlay" > "$out"
  else
    echo "missing kustomize or kubectl for static overlay audit" >&2
    exit 1
  fi
}

audit_static_overlay() {
  local overlay="$1" rendered
  rendered="$TMP_DIR/$(printf '%s' "$overlay" | tr '/.' '__').yaml"

  if [ ! -d "$ROOT/$overlay" ]; then
    record "$overlay" "overlay path does not exist"
    return
  fi

  log "rendering $overlay"
  if ! render_overlay "$overlay" "$rendered"; then
    record "$overlay" "kustomize render failed"
    return
  fi

  record_grep "$overlay" "Go fallback service/deployment marker: codewire-server" \
    '(^|[[:space:]])name:[[:space:]]+codewire-server([[:space:]]|$)' "$rendered"
  record_grep "$overlay" "Go fallback server image/reference" \
    'image:[[:space:]]+.*(codewire[-/]server|codewire-server)|codewire-server\.' "$rendered"
  record_grep "$overlay" "Go worker fallback enabled" \
    'WORKER_ENABLED:[[:space:]]*"?true"?' "$rendered"
  record_grep "$overlay" "global NATS_URL config remains" \
    '(^|[[:space:]])NATS_URL:[[:space:]]' "$rendered"
  record_static_unaccepted_nats_env "$overlay" "$rendered"

  if [ "${overlay##*/}" = "local-kind-static" ]; then
    record_grep "$overlay" "static local-kind overlay mounts mutable source path" \
      'path:[[:space:]]+/src/(codewire/apps/dashboard|dashboard|docs)(/|$)' "$rendered"
  fi
}

audit_sources() {
  local paths=(
    apps/api
    autoagent
    apps/cli/go.mod
    apps/cli/cmd/cw
    apps/cli/cmd/codewire-relay
    apps/cli/cwshell
    apps/cli/demo/broker
    apps/cli/internal
    apps/cli/internal/relay
    libs/daemon-proto/buf.gen.yaml
    libs/daemon-proto/gen
    libs/daemon-proto/go.mod
    libs/daemon-proto/go.sum
    libs/gatewayauth
    tests/contract/coordinator
    tests/contract/file
    tests/contract/orchestration
  )

  local path
  for path in "${paths[@]}"; do
    if [ -e "$ROOT/$path" ]; then
      record "sources" "Go runtime/tunnel source remains: $path"
    fi
  done

  local packaging_files=(
    apps/cli/Dockerfile
    images/workspace/Dockerfile
    .github/workflows/build-test.yml
    scripts/runtime/dev/smoke-dev-commodity.sh
    scripts/runtime/dev/measure-dev-commodity-overhead.sh
  )

  local file matches
  for file in "${packaging_files[@]}"; do
    [ -f "$ROOT/$file" ] || continue
    matches="$(grep -En 'go build .*([.]?/)?cmd/cw|cd apps/cli && go build|go -C apps/cli build' "$ROOT/$file" 2>/dev/null | head -20 || true)"
    if [ -n "$matches" ]; then
      record "sources" "Go cw packaging/runtime build remains: $file" "$matches"
    fi
  done
}

live_reachable() {
  command -v kubectl >/dev/null 2>&1 &&
    kubectl --context "$KUBE_CONTEXT" get namespace "$NAMESPACE" >/dev/null 2>&1
}

audit_live_cluster() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "live audit requires jq" >&2
    exit 1
  fi

  local json env_json deploys images
  json="$TMP_DIR/live-deployments.json"
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get deploy -o json > "$json"

  deploys="$(jq -r '.items[] | select(.metadata.name == "codewire-server") | .metadata.name' "$json")"
  if [ -n "$deploys" ]; then
    record "live:$KUBE_CONTEXT/$NAMESPACE" "legacy runtime deployments are present" "$deploys"
  fi

  images="$(jq -r '
    .items[]
    | .metadata.name as $deploy
    | .spec.template.spec.containers[]?
    | select(.image | test("(^|/|:)codewire-server(:|$)|/server:"))
    | "\($deploy) image \(.image)"
  ' "$json")"
  if [ -n "$images" ]; then
    record "live:$KUBE_CONTEXT/$NAMESPACE" "legacy runtime images are present" "$images"
  fi

  env_json="$(jq -r '
    .items[]
    | .metadata.name as $deploy
    | .spec.template.spec.containers[]?
    | .env[]?
    | select(
        (.name == "WORKER_ENABLED" and .value == "true")
        or
        (.name == "NATS_URL" and ($deploy != "codewire-coordinator" and $deploy != "codewire-mesh"))
      )
    | "\($deploy) env \(.name)=\(.value // "<valueFrom>")"
  ' "$json")"
  if [ -n "$env_json" ]; then
    record "live:$KUBE_CONTEXT/$NAMESPACE" "Go worker/unaccepted NATS env remains" "$env_json"
  fi
}

if [ "$SKIP_STATIC" != "1" ]; then
  for overlay in "${OVERLAYS[@]}"; do
    audit_static_overlay "$overlay"
  done
fi

if [ "$SKIP_SOURCES" != "1" ]; then
  audit_sources
fi

if [ "$SKIP_LIVE" != "1" ]; then
  if live_reachable; then
    log "auditing live cluster $KUBE_CONTEXT/$NAMESPACE"
    audit_live_cluster
  elif [ "$REQUIRE_LIVE" = "1" ]; then
    echo "live audit requested but $KUBE_CONTEXT/$NAMESPACE is not reachable" >&2
    exit 1
  else
    log "live cluster $KUBE_CONTEXT/$NAMESPACE not reachable; skipping live audit"
  fi
fi

if [ ! -s "$FINDINGS" ]; then
  log "green: no Go runtime or unaccepted NATS blockers found"
  exit 0
fi

log "found Rust-only runtime blockers:"
cat "$FINDINGS"

if [ "$ALLOW_MIXED" = "1" ]; then
  log "allow-mixed set; reporting blockers without failing"
  exit 0
fi

echo "::error::Rust-only runtime audit found blockers. Use --allow-mixed only while #51/#70 are still open." >&2
exit 1
