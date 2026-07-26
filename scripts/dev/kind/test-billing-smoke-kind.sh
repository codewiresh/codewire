#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$PROJECT_ROOT"

if [ ! -x "./scripts/dev/kind/kind-billing-listen.sh" ]; then
  echo "./scripts/dev/kind/kind-billing-listen.sh is missing or not executable"
  exit 1
fi

if [ ! -x "./scripts/dev/kind/kind-forwards.sh" ]; then
  echo "./scripts/dev/kind/kind-forwards.sh is missing or not executable"
  exit 1
fi

if [ ! -x "./scripts/dev/kind/run-billing-smoke-kind.sh" ]; then
  echo "./scripts/dev/kind/run-billing-smoke-kind.sh is missing or not executable"
  exit 1
fi

echo "Running focused billing smoke suite against local kind"
./scripts/dev/kind/kind-forwards.sh start postgres
trap './scripts/dev/kind/kind-forwards.sh stop postgres' EXIT INT TERM

./scripts/dev/kind/kind-billing-listen.sh ./scripts/dev/kind/run-billing-smoke-kind.sh
