#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/cargo-target-runner-failures.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "test-cargo-target-runner-failures: $*" >&2
  exit 1
}

fixture_root="$TMP/root"
mkdir -p "$fixture_root/scripts/ci/verify"

for runner in \
  scripts/ci/verify/run-product-verification.sh \
  scripts/ci/verify/run-integration-verification.sh \
  scripts/ci/verify/rust-stack-rehearsal.sh; do
  cp "$ROOT/$runner" "$fixture_root/$runner"
done

cat >"$fixture_root/scripts/ci/verify/resolve-cargo-target-dir.sh" <<'SH'
#!/usr/bin/env bash
printf 'fixture resolver failure\n' >&2
exit 42
SH
chmod 0755 "$fixture_root/scripts/ci/verify/resolve-cargo-target-dir.sh"

assert_resolver_failure() {
  local runner="$1" output status

  set +e
  output="$(bash "$fixture_root/$runner" 2>&1)"
  status=$?
  set -e

  [[ "$status" == 42 ]] ||
    fail "$runner: expected resolver status 42, got $status"
  [[ "$output" == *'fixture resolver failure'* ]] ||
    fail "$runner: resolver diagnostic was not preserved"
}

assert_resolver_failure scripts/ci/verify/run-product-verification.sh
assert_resolver_failure scripts/ci/verify/run-integration-verification.sh
assert_resolver_failure scripts/ci/verify/rust-stack-rehearsal.sh

integration_runner="$ROOT/scripts/ci/verify/run-integration-verification.sh"
grep -Fq 'CARGO_CI_TARGET_DIR="${CODEWIRE_CARGO_CI_TARGET_DIR:-$CARGO_TARGET_DIR}"' \
  "$integration_runner" \
  || fail 'integration runner does not support an isolated CI-profile target directory'
grep -Fq 'CARGO_TARGET_DIR="$CARGO_CI_TARGET_DIR" cargo "$@"' \
  "$integration_runner" \
  || fail 'integration runner does not route CI-profile commands through its isolated target directory'
if rg -n '^\s*(?:[A-Z_]+="[^" ]*"\s+)?cargo (?:build|test|check|run).*--profile ci' \
    "$integration_runner" >/dev/null; then
  fail 'a CI-profile integration command bypasses the isolated Cargo target directory'
fi

printf 'Cargo target runner resolver failures: green\n'
