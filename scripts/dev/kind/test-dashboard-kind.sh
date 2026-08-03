#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-${KIND_CLUSTER_NAME}}"
export KUBE_CONTEXT
NAMESPACE="${NAMESPACE:-default}"
PLAYWRIGHT_BASE_URL="${PLAYWRIGHT_BASE_URL:-http://127.0.0.1:8080}"
SERVER_URL="${SERVER_URL:-$PLAYWRIGHT_BASE_URL}"
DATABASE_URL="${DATABASE_URL:-postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable}"
PLAYWRIGHT="$ROOT/apps/dashboard/node_modules/.bin/playwright"

if ! kind get clusters | grep -Fxq "$KIND_CLUSTER_NAME"; then
  echo "interactive Kind cluster ${KIND_CLUSTER_NAME} is not running; run make up first" >&2
  exit 1
fi
if [ ! -x "$PLAYWRIGHT" ]; then
  echo "dashboard Playwright dependencies are missing; run PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 bun install --frozen-lockfile --ignore-scripts" >&2
  exit 1
fi

for deployment in codewire-dashboard codewire-idp codewire-orchestration; do
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" rollout status \
    "deployment/$deployment" --timeout=120s
done

configured_origin="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get \
  deployment/codewire-dashboard -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="CODEWIRE_PUBLIC_ORIGIN")].value}')"
if [ "$configured_origin" != "$PLAYWRIGHT_BASE_URL" ]; then
  echo "dashboard origin mismatch: deployment=${configured_origin:-missing} test=$PLAYWRIGHT_BASE_URL" >&2
  exit 1
fi

KUBE_CONTEXT="$KUBE_CONTEXT" NAMESPACE="$NAMESPACE" \
  "$ROOT/scripts/dev/kind/kind-forwards.sh" start postgres

chromium="${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}"
if [ -z "$chromium" ]; then
  chromium="$(command -v chromium || command -v google-chrome || command -v google-chrome-stable || true)"
fi
if [ -z "$chromium" ] || [ ! -x "$chromium" ]; then
  echo "set PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH to a trusted system Chromium" >&2
  exit 1
fi

curl -fsS "$PLAYWRIGHT_BASE_URL/login" >/dev/null
cd "$ROOT"
DATABASE_URL="$DATABASE_URL" \
  SERVER_URL="$SERVER_URL" \
  PLAYWRIGHT_BASE_URL="$PLAYWRIGHT_BASE_URL" \
  PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chromium" \
  PLAYWRIGHT_KUBE_CONTEXT="$KUBE_CONTEXT" \
  PLAYWRIGHT_SANDBOX_NAMESPACE="${PLAYWRIGHT_SANDBOX_NAMESPACE:-dev-sandboxes}" \
  "$PLAYWRIGHT" test --config apps/dashboard/playwright.config.ts "$@"
