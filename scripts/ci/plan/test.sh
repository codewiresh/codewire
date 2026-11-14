#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

mapfile -t rust_artifacts < <(python3 - <<'PY'
import json

with open("scripts/ci/plan/artifact-graph.json") as source:
    graph = json.load(source)

roots = set()
for spec in graph["artifacts"].values():
    if spec.get("kind") == "rust-package":
        roots.add((spec["package"], spec["manifest"]))

for package, manifest in sorted(roots):
    print(f"{package}\t{manifest}")
PY
)

if [ "${#rust_artifacts[@]}" -eq 0 ]; then
  echo 'planner Cargo oracle has no Rust artifact roots' >&2
  exit 1
fi

# shellcheck source=scripts/ci/plan/cargo-oracle-inputs.sh
source scripts/ci/plan/cargo-oracle-inputs.sh

# The Cargo oracle reads the exact lock-pinned Cargo inputs. When they are
# missing, they are fetched beside the unit tests and the first planner run,
# which never read them: those run Cargo only offline, with --no-deps (the
# selector) or in an isolated, empty CARGO_HOME (the planner), so neither
# reads the registry or Git sources the fetch writes. The oracle waits for
# the fetch; a fetch that fails or outlasts planner_fetch_seconds fails this
# script, and an early exit stops it.
planner_fetch_seconds=900
fetch_pid=''
fetch_log=''
stop_fetch() {
  if [ -n "$fetch_pid" ]; then
    # timeout passes the signal on to every process it started.
    kill "$fetch_pid" 2>/dev/null || true
    wait "$fetch_pid" 2>/dev/null || true
  fi
  if [ -n "$fetch_log" ]; then
    rm -f "$fetch_log"
  fi
}
trap stop_fetch EXIT

export CARGO_NET_OFFLINE=true
if ! cargo_oracle_inputs_available; then
  echo 'planner Cargo oracle: populating exact lock-pinned Cargo inputs beside the unit tests'
  fetch_log="$(mktemp)"
  timeout "$planner_fetch_seconds" bash -c "set -euo pipefail
$(declare -p rust_artifacts)
$(declare -f hydrate_cargo_oracle_inputs)
hydrate_cargo_oracle_inputs" </dev/null >"$fetch_log" 2>&1 &
  fetch_pid=$!
fi

# The unit tests run in parallel workers, one per CPU this job may assume
# (cpu-share.sh), at most eight; every test runs exactly once.
# shellcheck source=scripts/ci/setup/cpu-share.sh
source scripts/ci/setup/cpu-share.sh
workers="$(ci_cpu_share)"
if [ -z "$workers" ]; then
  workers="$(nproc)"
fi
if [ "$workers" -gt 8 ]; then
  workers=8
fi
python3 scripts/ci/plan/tests/run_parallel.py "$workers"
python3 scripts/ci/plan/planner.py --repository . --target-base HEAD --head HEAD >/dev/null

if [ -n "$fetch_pid" ]; then
  fetch_status=0
  wait "$fetch_pid" || fetch_status=$?
  fetch_pid=''
  cat "$fetch_log"
  if [ "$fetch_status" -ne 0 ]; then
    if [ "$fetch_status" -eq 124 ]; then
      echo "planner Cargo oracle: fetching Cargo inputs took over ${planner_fetch_seconds}s" >&2
    else
      echo "planner Cargo oracle: fetching Cargo inputs failed (exit $fetch_status)" >&2
    fi
    exit "$fetch_status"
  fi
fi

python3 scripts/ci/plan/planner.py --repository . --target-base HEAD --head HEAD --check-cargo-oracle >/dev/null
scripts/ci/tests/test-admin-proto-boundary.sh

if git rev-parse --verify HEAD^ >/dev/null 2>&1; then
  first="$(python3 scripts/ci/plan/planner.py --repository . --target-base HEAD^ --head HEAD --trusted-policy HEAD)"
  second="$(python3 scripts/ci/plan/planner.py --repository . --target-base HEAD^ --head HEAD --trusted-policy HEAD)"
  test "$first" = "$second"
fi
