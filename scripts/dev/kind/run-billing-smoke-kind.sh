#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

KIND_PLAYWRIGHT_BASE_URL="${KIND_PLAYWRIGHT_BASE_URL:-http://127.0.0.1:8080}"
KIND_SERVER_URL="${KIND_SERVER_URL:-http://127.0.0.1:8080}"
KIND_DATABASE_URL="${KIND_DATABASE_URL:-postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable}"

if [ -z "${BILLING_RUNTIME_WEBHOOK_SECRET:-}" ]; then
  echo "BILLING_RUNTIME_WEBHOOK_SECRET must be supplied by kind-billing-listen.sh"
  exit 1
fi

cd "$PROJECT_ROOT"
export CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh)"
DATABASE_URL="$KIND_DATABASE_URL" \
BILLING_RUNTIME_BASE_URL="$KIND_SERVER_URL" \
cargo run --locked --profile ci -p codewire-billing --bin billing-runtime-smoke

DATABASE_URL="$KIND_DATABASE_URL" \
SERVER_URL="$KIND_SERVER_URL" \
PLAYWRIGHT_BASE_URL="$KIND_PLAYWRIGHT_BASE_URL" \
./apps/dashboard/node_modules/.bin/playwright test \
  --config apps/dashboard/playwright.config.ts \
  --project=setup \
  --project=billing
