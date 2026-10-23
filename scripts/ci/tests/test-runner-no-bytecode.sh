#!/usr/bin/env bash
# #3071: a verification family's Python never writes bytecode into the source
# tree, whatever the caller's environment, so the next image context finds no
# __pycache__ to refuse. The real runner drives a policy part whose one step
# is a Python script that imports a sibling module.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/runner-no-bytecode.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "test-runner-no-bytecode: $*" >&2
  exit 1
}

fixture="$TMP/root"
mkdir -p "$fixture/scripts/ci/verify" "$fixture/probe"
cp "$ROOT/scripts/ci/verify/run-product-verification.sh" "$fixture/scripts/ci/verify/"
cat >"$fixture/scripts/ci/verify/resolve-cargo-target-dir.sh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$1/target"
SH
chmod 0755 "$fixture/scripts/ci/verify/resolve-cargo-target-dir.sh"
: >"$fixture/scripts/ci/verify/local-rust-cache.sh"
# Every step of the part is replaced by the probe.
cat >"$fixture/scripts/ci/verify/side-by-side.sh" <<'SH'
run_side_by_side() {
  cat >/dev/null
  python3 probe/main.py
}
SH
printf 'import helper\nprint("probe ran", helper.VALUE)\n' >"$fixture/probe/main.py"
printf 'VALUE = 1\n' >"$fixture/probe/helper.py"

pycache() {
  find "$fixture" -name __pycache__ -print
}

# The probe does write bytecode by default, so the check below can fail.
(cd "$fixture" && env -u PYTHONDONTWRITEBYTECODE python3 probe/main.py >/dev/null)
[ -n "$(pycache)" ] || fail "the probe wrote no bytecode by default; the fixture proves nothing"
find "$fixture" -name __pycache__ -prune -exec rm -rf {} +

output="$(cd "$fixture" && env -u PYTHONDONTWRITEBYTECODE \
  bash scripts/ci/verify/run-product-verification.sh policy-repo-rules 2>&1)" ||
  fail "the policy part failed: $output"
[[ "$output" == *'probe ran 1'* ]] || fail "the probe did not run: $output"
left="$(pycache)"
[ -z "$left" ] || fail "the runner left bytecode in the tree: $left"
echo "test-runner-no-bytecode: ok"
