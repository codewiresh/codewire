#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

KUBE_CONTEXT="${KUBE_CONTEXT:-kind-codewire}"
NAMESPACE="${NAMESPACE:-default}"
FORWARD_TO="${FORWARD_TO:-http://127.0.0.1:8080/api/webhooks/stripe}"
XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-/tmp/stripe-config}"
SESSION_SECRET_VALUE="${SESSION_SECRET_VALUE:-local-dev-session-secret-not-for-production}"

if ! command -v stripe >/dev/null 2>&1; then
  echo "stripe CLI is required"
  exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required"
  exit 1
fi

if [ -z "${STRIPE_SECRET_KEY:-}" ]; then
  echo "STRIPE_SECRET_KEY must be set"
  exit 1
fi

mkdir -p "$XDG_CONFIG_HOME"

LOG_FILE="${LOG_FILE:-$(mktemp /tmp/codewire-stripe-listen.XXXXXX.log)}"
STRIPE_PID=""

cleanup() {
  if [ -n "$STRIPE_PID" ]; then
    kill "$STRIPE_PID" 2>/dev/null || true
    wait "$STRIPE_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

echo "Starting Stripe listener for $FORWARD_TO"
XDG_CONFIG_HOME="$XDG_CONFIG_HOME" stripe listen \
  --skip-update \
  --api-key "$STRIPE_SECRET_KEY" \
  --forward-to "$FORWARD_TO" >"$LOG_FILE" 2>&1 &
STRIPE_PID=$!

WEBHOOK_SECRET=""
for _ in $(seq 1 60); do
  if ! kill -0 "$STRIPE_PID" 2>/dev/null; then
    echo "stripe listen exited unexpectedly"
    cat "$LOG_FILE"
    exit 1
  fi

  WEBHOOK_SECRET="$(grep -o 'whsec_[A-Za-z0-9]\+' "$LOG_FILE" | head -n 1 || true)"
  if [ -n "$WEBHOOK_SECRET" ]; then
    break
  fi
  sleep 1
done

if [ -z "$WEBHOOK_SECRET" ]; then
  echo "failed to extract Stripe webhook secret from listener output"
  cat "$LOG_FILE"
  exit 1
fi

echo "Updating kind secret with Stripe billing values"
secret_args=(
  --from-literal=SESSION_SECRET="$SESSION_SECRET_VALUE"
  --from-literal=STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"
  --from-literal=STRIPE_WEBHOOK_SECRET="$WEBHOOK_SECRET"
)

if [ -n "${RESEND_API_KEY:-}" ]; then
  secret_args+=(--from-literal=RESEND_API_KEY="$RESEND_API_KEY")
fi

kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" create secret generic codewire-local-secrets \
  --dry-run=client \
  -o yaml \
  "${secret_args[@]}" | \
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" apply -f -

echo "Restarting codewire-billing so webhook secret matches listener"
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" rollout restart deployment codewire-billing
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" rollout status deployment codewire-billing --timeout=120s

echo ""
echo "Stripe listener ready"
echo "  log file: $LOG_FILE"
echo "  forward to: $FORWARD_TO"
echo ""

if [ "$#" -gt 0 ]; then
  echo "Running command: $*"
  BILLING_RUNTIME_WEBHOOK_SECRET="$WEBHOOK_SECRET" "$@"
else
  echo "Listener is running. Press Ctrl-C to stop."
  wait "$STRIPE_PID"
fi
