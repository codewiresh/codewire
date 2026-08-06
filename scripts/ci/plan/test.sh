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

cargo_oracle_inputs_available() {
  local artifact package manifest
  for artifact in "${rust_artifacts[@]}"; do
    IFS=$'\t' read -r package manifest <<<"$artifact"
    local -a command=(
      cargo tree --locked --offline --edges "normal,build" --prefix none --format="{p}" -p "$package"
    )
    if [ "$manifest" != Cargo.toml ]; then
      command+=(--manifest-path "$manifest")
    fi
    "${command[@]}" >/dev/null 2>&1
  done
}

hydrate_cargo_oracle_inputs() {
  local artifact package manifest
  for artifact in "${rust_artifacts[@]}"; do
    IFS=$'\t' read -r package manifest <<<"$artifact"
    local -a command=(env -u CARGO_NET_OFFLINE cargo fetch --locked --config net.offline=false)
    if [ "$manifest" != Cargo.toml ]; then
      command+=(--manifest-path "$manifest")
    fi
    "${command[@]}"
  done
}

export CARGO_NET_OFFLINE=true
python3 -m unittest discover -s scripts/ci/plan/tests -p 'test_*.py' -v
python3 scripts/ci/plan/planner.py --repository . --target-base HEAD --head HEAD >/dev/null

if ! cargo_oracle_inputs_available; then
  echo 'planner Cargo oracle: populating exact lock-pinned Cargo inputs'
  hydrate_cargo_oracle_inputs
fi

python3 scripts/ci/plan/planner.py --repository . --target-base HEAD --head HEAD --check-cargo-oracle >/dev/null
scripts/ci/tests/test-admin-proto-boundary.sh

if git rev-parse --verify HEAD^ >/dev/null 2>&1; then
  first="$(python3 scripts/ci/plan/planner.py --repository . --target-base HEAD^ --head HEAD --trusted-policy HEAD)"
  second="$(python3 scripts/ci/plan/planner.py --repository . --target-base HEAD^ --head HEAD --trusted-policy HEAD)"
  test "$first" = "$second"
fi
