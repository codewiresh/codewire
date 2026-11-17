#!/usr/bin/env bash
# #5154: a fresh worktree's first `make kind-up` holds the source tree in an
# image context, then adds to it: Python writes __pycache__ beside a script it
# imports, and a later step creates the root .tmp. The hold refuses the
# changed directory after the build has run for a long time. The Kind
# dispatcher writes no bytecode and creates .tmp before anything holds the
# tree. This test holds a fresh tree with the real image source and does both
# things: without the dispatcher each is refused, naming the directory; under
# the dispatcher's `up` the same steps leave the held tree unchanged.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
umask 022
# Outside the checkout: the hold refuses a group-writable ancestor, and a
# checkout's .tmp may be one.
TMP="$(mktemp -d "${TMPDIR:-/tmp}/kind-e2e-fresh-tree.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "test-kind-e2e-fresh-tree: $*" >&2
  exit 1
}

# hold.py SOURCE_TREE STEP...: hold SOURCE_TREE, take each step, then
# revalidate the hold. Exit 3 with the refusal if the held tree changed.
HOLD="$TMP/hold.py"
cat >"$HOLD" <<'PY'
import importlib.util
import os
import subprocess
import sys

spec = importlib.util.spec_from_file_location("cw_image_source_fresh_tree", sys.argv[1])
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
tree = sys.argv[2]
with source.ImageSource(tree, ["Dockerfile"]) as held:
    for step in sys.argv[3:]:
        if step == "python":
            subprocess.run([sys.executable, "probe/main.py"], cwd=tree, check=True, stdout=subprocess.DEVNULL)
        elif step == "tmp":
            os.makedirs(os.path.join(tree, ".tmp", "kind-dev"), exist_ok=True)
        else:
            sys.exit(f"unknown step {step}")
    try:
        held.revalidate()
    except source.Refused as refusal:
        print(f"refused: {refusal}")
        sys.exit(3)
print("held tree unchanged")
PY

# A fresh tree: no .tmp and no __pycache__, with the dispatcher and stubs for
# the files it sources. The stub `up` holds the tree and takes both steps.
fresh_tree() {
  local tree="$TMP/tree" sourced
  rm -rf "$tree"
  mkdir -m 0700 "$tree"
  mkdir -p "$tree/probe" "$tree/scripts/ci/verify"
  printf 'FROM scratch\nCOPY probe /probe\n' >"$tree/Dockerfile"
  printf '**/.tmp\n**/__pycache__\n**/*.pyc\n' >"$tree/.dockerignore"
  printf 'import helper\nprint("probe ran", helper.VALUE)\n' >"$tree/probe/main.py"
  printf 'VALUE = 1\n' >"$tree/probe/helper.py"
  cp "$ROOT/scripts/ci/verify/kind-e2e.sh" "$tree/scripts/ci/verify/"
  while IFS= read -r sourced; do
    mkdir -p "$(dirname "$tree/$sourced")"
    : >"$tree/$sourced"
  done < <(sed -n 's|^source "\$ROOT/\(.*\)"$|\1|p' "$ROOT/scripts/ci/verify/kind-e2e.sh")
  [ -e "$tree/scripts/ci/verify/kind/suites/up.sh" ] || fail 'the dispatcher no longer sources suites/up.sh'
  printf 'log() { printf "%%s\\n" "$*"; }\n' >"$tree/scripts/ci/verify/kind/common.sh"
  # shellcheck disable=SC2016 # expanded when the dispatcher sources the stub
  printf 'run_kind_up() { python3 -B "$HOLD" "$IMAGE_SOURCE" "$ROOT" python tmp; }\n' \
    >"$tree/scripts/ci/verify/kind/suites/up.sh"
  printf '%s\n' "$tree"
}

pycache() {
  find "$1" -name __pycache__ -print
}

held() {
  env -u PYTHONDONTWRITEBYTECODE python3 -B "$HOLD" "$ROOT/scripts/ci/images/cw-image-source.py" "$@"
}

# Without the dispatcher, Python's bytecode changes the held probe directory,
# and the refusal names it.
tree="$(fresh_tree)"
status=0
output="$(held "$tree" python)" || status=$?
[ "$status" = 3 ] || fail "bytecode in a held directory was not refused (exit $status): $output"
[ -n "$(pycache "$tree")" ] || fail 'the probe wrote no bytecode by default; the fixture proves nothing'
[ "$output" = 'refused: held image-source directory name/identity changed: probe' ] ||
  fail "the bytecode refusal does not name the directory: $output"

# Without the dispatcher, a .tmp created after the hold changes the root.
tree="$(fresh_tree)"
status=0
output="$(held "$tree" tmp)" || status=$?
[ "$status" = 3 ] || fail "a new root .tmp was not refused (exit $status): $output"
[ "$output" = 'refused: held image-source directory name/identity changed: .' ] ||
  fail "the .tmp refusal does not name the root: $output"

# Under the dispatcher's `up`, a fresh tree's hold survives both steps.
tree="$(fresh_tree)"
output="$(cd "$tree" && env -u PYTHONDONTWRITEBYTECODE -u CLUSTER -u KIND_CREDENTIAL_STAGES \
  -u KIND_DASHBOARD_SELECTION KIND_CLUSTER_NAME=fresh-tree-fixture HOLD="$HOLD" \
  IMAGE_SOURCE="$ROOT/scripts/ci/images/cw-image-source.py" bash scripts/ci/verify/kind-e2e.sh up 2>&1)" ||
  fail "kind-e2e.sh up refused the fresh tree: $output"
[[ "$output" == *'held tree unchanged'* ]] || fail "the hold did not run: $output"
[ -z "$(pycache "$tree")" ] || fail "kind-e2e.sh up left bytecode in the tree: $(pycache "$tree")"
[ -d "$tree/.tmp/kind-dev" ] || fail 'the stub up did not create .tmp/kind-dev'
echo "test-kind-e2e-fresh-tree: ok"
