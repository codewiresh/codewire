#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

KIND_PLAYWRIGHT_BASE_URL="${KIND_PLAYWRIGHT_BASE_URL:-http://127.0.0.1:8080}"
KIND_SERVER_URL="${KIND_SERVER_URL:-http://127.0.0.1:8080}"
KIND_DATABASE_URL="${KIND_DATABASE_URL:-postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable}"

cd "$PROJECT_ROOT"

if [ ! -x "./scripts/dev/kind/kind-billing-listen.sh" ]; then
  echo "./scripts/dev/kind/kind-billing-listen.sh is missing or not executable"
  exit 1
fi

if [ ! -x "./scripts/dev/kind/kind-forwards.sh" ]; then
  echo "./scripts/dev/kind/kind-forwards.sh is missing or not executable"
  exit 1
fi

echo "Running Playwright billing suite against local kind"
./scripts/dev/kind/kind-forwards.sh start postgres
trap './scripts/dev/kind/kind-forwards.sh stop postgres' EXIT INT TERM

./scripts/dev/kind/kind-billing-listen.sh \
  env \
    DATABASE_URL="$KIND_DATABASE_URL" \
    SERVER_URL="$KIND_SERVER_URL" \
    PLAYWRIGHT_BASE_URL="$KIND_PLAYWRIGHT_BASE_URL" \
    ./apps/dashboard/node_modules/.bin/playwright test \
      --config apps/dashboard/playwright.config.ts \
      --project=setup \
      --project=billing \
      "$@"
