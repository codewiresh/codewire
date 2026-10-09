#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
python3 -B "$ROOT/scripts/ci/release/generate-cw-bootstrap.py" --check
exec python3 -B "$ROOT/scripts/ci/tests/test-cw-bootstrap.py"
