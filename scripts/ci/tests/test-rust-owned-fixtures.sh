#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

sha256sum --strict --quiet -c tests/fixtures/accepted-bytes.sha256
scripts/ci/tests/test-agent-sandbox-pin.sh

echo 'rust-owned fixtures: OK'
