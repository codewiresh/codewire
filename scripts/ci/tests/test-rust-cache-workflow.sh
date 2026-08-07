#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKFLOW="$ROOT/.gitea/workflows/rust-cache-refresh.yaml"
CI_WORKFLOW="$ROOT/.gitea/workflows/ci.yaml"
CACHE_ACTION='6849a6489940f00c2f30c0fb92c6274307ccb58a'
mkdir -p "$ROOT/.tmp" "$ROOT/target/ci-cache"
work="$(mktemp -d "$ROOT/.tmp/rust-cache-workflow.XXXXXX")"
cache_dir="$(mktemp -d "$ROOT/target/ci-cache/contract.XXXXXX")"
trap 'rm -rf "$work" "$cache_dir"' EXIT

fail() {
  printf 'Rust cache workflow contract: %s\n' "$*" >&2
  exit 1
}

grep -Fq '    branches: [main]' "$WORKFLOW" || fail 'push is not main-only'
grep -Fq '  workflow_dispatch:' "$WORKFLOW" || fail 'manual refresh is unavailable'
if grep -Fq 'pull_request:' "$WORKFLOW"; then
  fail 'untrusted pull requests may invoke the cache producer'
fi
[ "$(grep -Fc '      actions: write' "$WORKFLOW")" -eq 5 ] \
  || fail 'cache builders do not own narrowly scoped save authority'
if sed -n '/^permissions:/,/^[^ ]/p' "$WORKFLOW" | grep -Fq 'actions: write'; then
  fail 'cache write authority is overly broad at workflow scope'
fi
[ "$(grep -Fc "uses: actions/cache/save@$CACHE_ACTION" "$WORKFLOW")" -eq 5 ] \
  || fail 'each flavor must use the pinned cache save action exactly once'
if grep -Eq 'actions/cache/restore|restore-keys:' "$WORKFLOW"; then
  fail 'producer must not use mutable or prefix cache restoration'
fi
if grep -Fq 'codewire-rust-deps-v1-' "$CI_WORKFLOW"; then
  fail 'consumer activation leaked into the producer PR'
fi
grep -Fq 'name: Publish Rust cache receipt' "$WORKFLOW" \
  || fail 'workflow omits its provenance receipt'
grep -Fq 'scripts/ci/plan/planner.py' "$WORKFLOW" \
  || fail 'workflow bypasses the canonical artifact planner'
grep -Fq 'scripts/ci/cache/prepare-rust-dependency-cache.sh' "$WORKFLOW" \
  || fail 'workflow bypasses first-party pruning'
[ "$(grep -Fc 'run: scripts/ci/setup/assert-ci-runner-image.sh' "$WORKFLOW")" -eq 6 ] \
  || fail 'planner and cache builders do not verify the runner contract'

selector_paths="$work/cache-producer.paths"
printf '%s\n' \
  .gitea/workflows/rust-cache-refresh.yaml \
  scripts/ci/cache/prepare-rust-dependency-cache.sh \
  scripts/ci/cache/select-rust-cache-key.sh \
  scripts/ci/receipts/emit-rust-cache-receipt.py \
  scripts/ci/receipts/verify-rust-cache-receipt.sh \
  scripts/ci/tests/test-rust-cache-workflow.sh \
  scripts/ci/tests/test-rust-cache-receipts.sh > "$selector_paths"
selector_output="$(env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH \
  GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/head \
  "$ROOT/scripts/ci/select/select-verification.sh" "$selector_paths")"
grep -Fxq 'selection=|valid:v3|policy|complete|' <<<"$selector_output" \
  || fail 'cache-producer inputs do not select policy-only verification'

compatibility="$(printf fixture | sha256sum | cut -d' ' -f1)"
reuse_key="codewire-rust-deps-v1-generic-host-ci-${compatibility}-0123456789abcdef0123456789abcdef"
reuse="$("$ROOT/scripts/ci/cache/select-rust-cache-key.sh" \
  host-ci generic "$compatibility" "$compatibility" "$reuse_key")"
grep -Fxq 'refresh=false' <<< "$reuse" || fail 'exact key was not reused'
grep -Fxq "key=$reuse_key" <<< "$reuse" || fail 'reused key changed'

fresh="$("$ROOT/scripts/ci/cache/select-rust-cache-key.sh" \
  host-ci generic "$compatibility" "$(printf old | sha256sum | cut -d' ' -f1)" "$reuse_key")"
grep -Fxq 'refresh=true' <<< "$fresh" || fail 'compatibility change did not refresh'
fresh_key="$(sed -n 's/^key=//p' <<< "$fresh")"
[[ "$fresh_key" =~ ^codewire-rust-deps-v1-generic-host-ci-${compatibility}-[0-9a-f]{32}$ ]] \
  || fail 'fresh key is not exact and immutable'
[ "$fresh_key" != "$reuse_key" ] || fail 'fresh key reused the old identity'

if "$ROOT/scripts/ci/cache/select-rust-cache-key.sh" \
    kind-ci generic "$compatibility" '' '' >/dev/null 2>&1; then
  fail 'runner-pool mismatch was accepted'
fi

grep -Fq 'cargo clean' "$ROOT/scripts/ci/cache/prepare-rust-dependency-cache.sh" \
  || fail 'first-party outputs are not pruned'
grep -Fq '4294967296' "$ROOT/scripts/ci/cache/prepare-rust-dependency-cache.sh" \
  || fail 'cache size ceiling is absent'
grep -Fq 'cargo zigbuild --locked --profile ci' \
  "$ROOT/scripts/ci/cache/prepare-rust-dependency-cache.sh" \
  || fail 'cross-target flavor does not warm its actual Cargo build inputs'
if grep -Fq 'package-cw-release.sh' \
    "$ROOT/scripts/ci/cache/prepare-rust-dependency-cache.sh"; then
  fail 'dependency-cache warmup must not select release packaging verification'
fi

mkdir -p "$work/bin"
cat > "$work/bin/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  test)
    mkdir -p "$CARGO_TARGET_DIR/debug/.fingerprint/codewire-fixture-123" \
      "$CARGO_TARGET_DIR/debug/deps"
    : > "$CARGO_TARGET_DIR/debug/deps/libcodewire_fixture.rlib"
    : > "$CARGO_TARGET_DIR/debug/deps/libserde_fixture.rlib"
    ;;
  metadata)
    printf '%s\n' '{"packages":[{"name":"codewire-fixture","source":null}]}'
    ;;
  clean)
    rm -rf "$CARGO_TARGET_DIR/debug/.fingerprint/codewire-fixture-123"
    rm -f "$CARGO_TARGET_DIR/debug/deps/libcodewire_fixture.rlib"
    ;;
  *)
    printf 'unexpected fake Cargo invocation: %s\n' "$*" >&2
    exit 2
    ;;
esac
FAKE_CARGO
chmod +x "$work/bin/cargo"
PATH="$work/bin:$PATH" CARGO_TARGET_DIR="$cache_dir" \
  "$ROOT/scripts/ci/cache/prepare-rust-dependency-cache.sh" host-debug >/dev/null
test -f "$cache_dir/debug/deps/libserde_fixture.rlib" \
  || fail 'dependency output was pruned'
if find "$cache_dir" -name 'libcodewire_*' -print -quit | grep -q .; then
  fail 'first-party output survived pruning fixture'
fi

echo 'Rust cache workflow contract: OK'
