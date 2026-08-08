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
[ "$(grep -Fc "uses: actions/cache/restore@$CACHE_ACTION" "$WORKFLOW")" -eq 10 ] \
  || fail 'producers and post-producer finalizers must probe each exact key'
[ "$(grep -Fc '      actions: read' "$WORKFLOW")" -eq 2 ] \
  || fail 'post-producer finalizers do not own narrow cache read authority'
[ "$(grep -Fc "uses: actions/cache/restore@$CACHE_ACTION" "$CI_WORKFLOW")" -eq 7 ] \
  || fail 'consumer jobs must restore their exact cache flavors'
if grep -Eq 'restore-keys:' "$WORKFLOW" "$CI_WORKFLOW"; then
  fail 'cache restoration must never use mutable or prefix keys'
fi
if grep -Fq "uses: actions/cache/save@$CACHE_ACTION" "$CI_WORKFLOW"; then
  fail 'PR-capable consumer workflow must not save Rust dependency caches'
fi
grep -Fq 'lookup-only: true' "$WORKFLOW" \
  || fail 'cache availability must be proven by exact lookup'
grep -Fq '  generic-availability:' "$WORKFLOW" \
  || fail 'generic cache availability lacks a post-producer finalizer'
grep -Fq '  kind-availability:' "$WORKFLOW" \
  || fail 'Kind cache availability lacks a same-pool finalizer'
grep -Fq '    needs: [plan, generic-availability, kind-availability]' "$WORKFLOW" \
  || fail 'receipt does not depend on post-producer availability proof'
grep -Fq "false|'') printf" "$WORKFLOW" \
  || fail 'unproven exact cache probes do not fall back cold'
grep -Fq 'unexpected exact cache probe state for $name' "$WORKFLOW" \
  || fail 'generic cache proof does not fail closed on an unknown probe state'
grep -Fq 'unexpected exact cache probe state for kind_ci' "$WORKFLOW" \
  || fail 'Kind cache proof does not fail closed on an unknown probe state'
if grep -Fq 'POST_SAVE_CACHE_HIT' "$WORKFLOW"; then
  fail 'same-job cache visibility is still treated as publication proof'
fi
if grep -Fq 'needs.host-debug.outputs.available' "$WORKFLOW"; then
  fail 'receipt still trusts producer-local availability output'
fi
grep -Fq 'rust_cache_cw_cross_ci_available' "$CI_WORKFLOW" \
  || fail 'consumer activation is not receipt-availability bound'
grep -Fq 'rust_cache_cw_cross_ci_receipt_compatibility' "$CI_WORKFLOW" \
  || fail 'consumer activation is not compatibility bound'
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
selector_selection="$(sed -n 's/^selection=//p' <<<"$selector_output")"
[[ "$selector_selection" == '|valid:v3|'*'|complete|' ]] \
  || fail 'cache-producer selection is malformed'
IFS='|' read -r -a selector_tokens <<<"$selector_selection"
for selector_token in "${selector_tokens[@]}"; do
  case "$selector_token" in
    ''|valid:v3|complete|policy|policy_shell|policy_shell_omittable) ;;
    *) fail "cache-producer inputs selected product capability $selector_token" ;;
  esac
done
[[ "$selector_selection" == *'|policy|'* ]] \
  || fail 'cache-producer inputs omitted the policy domain'
[[ "$selector_selection" == *'|policy_shell|'* ]] \
  || fail 'cache-producer shell inputs omitted the ShellCheck policy domain'
[[ "$selector_selection" == *'|policy_shell_omittable|'* ]] \
  || fail 'cache-producer inputs omitted authoritative ShellCheck routing'

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
grep -Fq 'clean_profiles=(release)' \
  "$ROOT/scripts/ci/cache/prepare-rust-dependency-cache.sh" \
  || fail 'desktop release cache does not prune its release profile'
jq -e '.artifacts.rust_cache_desktop_release.profiles == ["release"]' \
  "$ROOT/scripts/ci/plan/artifact-graph.json" >/dev/null \
  || fail 'desktop release cache graph includes a non-release profile'
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
[ -z "${FAKE_CARGO_LOG:-}" ] || printf '%s\n' "$*" >> "$FAKE_CARGO_LOG"
profile_for_args() {
  local profile=debug argument previous=''
  for argument in "$@"; do
    if [ "$previous" = --profile ]; then
      profile="$argument"
      break
    fi
    previous="$argument"
  done
  printf '%s\n' "$profile"
}

case "${1:-}" in
  test)
    profile="$(profile_for_args "$@")"
    packages=(codewire-cli-bin)
    mkdir -p "$CARGO_TARGET_DIR/$profile/deps"
    for package in "${packages[@]}"; do
      mkdir -p "$CARGO_TARGET_DIR/$profile/.fingerprint/$package-123"
      : > "$CARGO_TARGET_DIR/$profile/deps/lib${package//-/_}_fixture.rlib"
    done
    : > "$CARGO_TARGET_DIR/$profile/deps/libserde_fixture.rlib"
    ;;
  build)
    profile="$(profile_for_args "$@")"
    if [[ " $* " = *' --release '* ]]; then
      profile=release
    fi
    if [[ " $* " = *codewire-desktop/Cargo.toml* ]] || [ "$profile" = release ]; then
      packages=(
        codewire-client
        codewire-desktop
        codewire-platform-native
        codewire-proto
        codewire-tailnet
        codewire-types
        codewire-ui
      )
    else
      package=''
      previous=''
      for argument in "$@"; do
        if [ "$previous" = -p ]; then
          package="$argument"
          break
        fi
        previous="$argument"
      done
      [ -n "$package" ] || exit 2
      packages=("$package")
    fi
    mkdir -p "$CARGO_TARGET_DIR/$profile/deps"
    for package in "${packages[@]}"; do
      mkdir -p "$CARGO_TARGET_DIR/$profile/.fingerprint/$package-123"
      : > "$CARGO_TARGET_DIR/$profile/deps/lib${package//-/_}_fixture.rlib"
    done
    : > "$CARGO_TARGET_DIR/$profile/deps/libserde_fixture.rlib"
    if [[ " ${packages[*]} " = *' codewire-desktop '* ]]; then
      printf '#!/usr/bin/env sh\nexit 0\n' > "$CARGO_TARGET_DIR/$profile/codewire"
      chmod +x "$CARGO_TARGET_DIR/$profile/codewire"
    fi
    ;;
  install)
    install_root=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = --root ]; then
        install_root="$argument"
        break
      fi
      previous="$argument"
    done
    [ -n "$install_root" ] || exit 2
    mkdir -p "$install_root/bin"
    cat > "$install_root/bin/cargo-zigbuild" <<'FAKE_ZIGBUILD'
#!/usr/bin/env bash
set -euo pipefail
profile=debug
target=''
previous=''
for argument in "$@"; do
  case "$previous" in
    --profile) profile="$argument" ;;
    --target) target="$argument" ;;
  esac
  previous="$argument"
done
[ -n "$target" ] || exit 2
output="$CARGO_TARGET_DIR/$target/$profile"
mkdir -p "$output/.fingerprint/codewire-cli-bin-123" "$output/deps"
: > "$output/deps/libcodewire_cli_bin.rlib"
: > "$output/deps/libserde_fixture.rlib"
FAKE_ZIGBUILD
    chmod +x "$install_root/bin/cargo-zigbuild"
    ;;
  zigbuild)
    profile="$(profile_for_args "$@")"
    target=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = --target ]; then
        target="$argument"
        break
      fi
      previous="$argument"
    done
    [ -n "$target" ] || exit 2
    output="$CARGO_TARGET_DIR/$target/$profile"
    mkdir -p "$output/.fingerprint/codewire-cli-bin-123" "$output/deps"
    : > "$output/deps/libcodewire_cli_bin_fixture.rlib"
    : > "$output/deps/libserde_fixture.rlib"
    printf '#!/usr/bin/env sh\nexit 0\n' > "$output/cw"
    chmod +x "$output/cw"
    ;;
  clean)
    profile="$(profile_for_args "$@")"
    if [ "$profile" = dev ]; then
      profile=debug
    fi
    target=''
    previous=''
    for argument in "$@"; do
      if [ "$previous" = --target ]; then
        target="$argument"
        break
      fi
      previous="$argument"
    done
    output="$CARGO_TARGET_DIR/${target:+$target/}$profile"
    packages=()
    previous=''
    for argument in "$@"; do
      if [ "$previous" = -p ]; then
        packages+=("$argument")
      fi
      previous="$argument"
    done
    for package in "${packages[@]}"; do
      rm -rf "$output/.fingerprint/$package-"*
      rm -f "$output/deps/lib${package//-/_}_"*.rlib
      if [ "$package" = codewire-desktop ]; then
        rm -f "$output/codewire"
      fi
    done
    ;;
  *)
    printf 'unexpected fake Cargo invocation: %s\n' "$*" >&2
    exit 2
    ;;
esac
FAKE_CARGO
chmod +x "$work/bin/cargo"
cat > "$work/bin/rustc" <<'FAKE_RUSTC'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = -vV ]; then
  printf 'host: x86_64-unknown-linux-gnu\n'
  exit 0
fi
exit 2
FAKE_RUSTC
chmod +x "$work/bin/rustc"
empty_cargo_home="$work/empty-cargo-home"
mkdir -p "$empty_cargo_home"
for fixture_flavor in host-debug host-ci kind-ci cw-cross-ci desktop-release; do
  case "$fixture_flavor" in
    host-debug) fixture_profile=debug ;;
    host-ci) fixture_profile=ci ;;
    kind-ci) fixture_profile=ci ;;
    cw-cross-ci) fixture_profile=x86_64-unknown-linux-musl/ci ;;
    desktop-release) fixture_profile=release ;;
  esac
  fixture_target="$cache_dir/$fixture_flavor"
  fixture_log="$work/$fixture_flavor.cargo.log"
  PATH="$work/bin:$PATH" CARGO_HOME="$empty_cargo_home" \
    FAKE_CARGO_LOG="$fixture_log" CARGO_TARGET_DIR="$fixture_target" \
    "$ROOT/scripts/ci/cache/prepare-rust-dependency-cache.sh" "$fixture_flavor" >/dev/null
  test -f "$fixture_target/$fixture_profile/deps/libserde_fixture.rlib" \
    || fail "dependency output was pruned for $fixture_flavor"
  if find "$fixture_target" -name 'libcodewire_*' -print -quit | grep -q .; then
    fail "first-party output survived pruning fixture for $fixture_flavor"
  fi
  if grep -Eq '^metadata( |$)' "$fixture_log"; then
    fail "pruning resolved Cargo metadata for $fixture_flavor"
  fi
done
if grep -Eq '^test( |$)' "$work/desktop-release.cargo.log"; then
  fail 'desktop release cache unexpectedly warms the test/debug profile'
fi
grep -Fq -- '-p codewire-platform-native' "$work/desktop-release.cargo.log" \
  || fail 'desktop pruning omitted its excluded platform path dependency'
grep -Fq -- '-p codewire-ui' "$work/desktop-release.cargo.log" \
  || fail 'desktop pruning omitted its excluded UI path dependency'

private_cw_target="$work/private-cw-target"
private_cw_dist="$work/private-cw-dist"
PATH="$work/bin:$PATH" CARGO_TARGET_DIR="$private_cw_target" \
  CW_RELEASE_PROFILE=ci \
  CW_RELEASE_BUILD_CMD='cargo zigbuild' \
  CW_RELEASE_REQUIRE_SIGNATURE=0 \
  CW_RELEASE_TARGETS='x86_64-unknown-linux-musl' \
  CW_RELEASE_DIST_DIR="$private_cw_dist" \
  "$ROOT/scripts/ci/release/package-cw-release.sh" v0.0.0-ci >/dev/null
test -x "$private_cw_target/x86_64-unknown-linux-musl/ci/cw" \
  || fail 'CW packaging ignored its private Cargo target directory'
test -f "$private_cw_dist/cw-v0.0.0-ci-x86_64-unknown-linux-musl" \
  || fail 'CW packaging did not copy the private-target binary'

echo 'Rust cache workflow contract: OK'
