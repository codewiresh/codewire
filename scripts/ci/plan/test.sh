#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

export CARGO_NET_OFFLINE=true
python3 -m unittest discover -s scripts/ci/plan/tests -p 'test_*.py' -v
python3 scripts/ci/plan/planner.py --repository . --target-base HEAD --head HEAD --check-cargo-oracle >/dev/null
scripts/ci/tests/test-admin-proto-boundary.sh

if git rev-parse --verify HEAD^ >/dev/null 2>&1; then
  first="$(python3 scripts/ci/plan/planner.py --repository . --target-base HEAD^ --head HEAD --trusted-policy HEAD)"
  second="$(python3 scripts/ci/plan/planner.py --repository . --target-base HEAD^ --head HEAD --trusted-policy HEAD)"
  test "$first" = "$second"
fi
