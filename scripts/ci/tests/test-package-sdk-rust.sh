#!/usr/bin/env bash
# package-sdk-rust.sh in a kept target (CI's sdk_package folder) rebuilds the
# two SDK crates from this tree: before `cargo package` it removes their
# unpacked copies from Cargo's local registries only, and cleans only those two
# crates from the target. A temporary target is left to Cargo alone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/release/package-sdk-rust.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/test-package-sdk-rust.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-package-sdk-rust] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir "$TMP/bin"
cat >"$TMP/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$CARGO_CALLS"
if [[ "$1" == package ]]; then
  printf 'CARGO_PROFILE_DEV_DEBUG=%s\n' "${CARGO_PROFILE_DEV_DEBUG-unset}" >>"$CARGO_CALLS.env"
fi
case "$1" in
  metadata)
    printf '{"packages":[{"name":"codewire","version":"0.1.0"},{"name":"codewire-proto","version":"0.1.0"}]}\n'
    ;;
  clean) ;;
  package)
    if [[ -n "${CARGO_ENV_LOG:-}" ]]; then
      printf 'RUSTC_WRAPPER=%s SCCACHE_DIR=%s SCCACHE_CONF=%s SCCACHE_SERVER_UDS=%s SCCACHE_BUCKET=%s AWS_ACCESS_KEY_ID=%s CARGO_INCREMENTAL=%s CARGO_PROFILE_DEV_DEBUG=%s CARGO_PROFILE_DEV_BUILD_OVERRIDE_OPT_LEVEL=%s\n' \
        "${RUSTC_WRAPPER-unset}" "${SCCACHE_DIR-unset}" "${SCCACHE_CONF-unset}" \
        "${SCCACHE_SERVER_UDS-unset}" "${SCCACHE_BUCKET-unset}" "${AWS_ACCESS_KEY_ID-unset}" \
        "${CARGO_INCREMENTAL-unset}" "${CARGO_PROFILE_DEV_DEBUG-unset}" \
        "${CARGO_PROFILE_DEV_BUILD_OVERRIDE_OPT_LEVEL-unset}" >"$CARGO_ENV_LOG"
    fi
    target="${*: -1}"
    mkdir -p "$target/package"
    for crate in codewire-proto codewire; do
      mkdir -p "$target/stage/$crate-0.1.0/src"
      : >"$target/stage/$crate-0.1.0/LICENSE"
      : >"$target/stage/$crate-0.1.0/Cargo.toml"
      : >"$target/stage/$crate-0.1.0/src/lib.rs"
      tar -czf "$target/package/$crate-0.1.0.crate" -C "$target/stage" \
        "$crate-0.1.0/LICENSE" "$crate-0.1.0/Cargo.toml" "$crate-0.1.0/src/lib.rs"
    done
    ;;
  *) exit 3 ;;
esac
EOF
chmod +x "$TMP/bin/cargo"
export PATH="$TMP/bin:$PATH" CARGO_CALLS="$TMP/calls"

home="$TMP/cargo-home"
stale=("$home/registry/src/-0123abcd/codewire-proto-0.1.0" "$home/registry/src/-0123abcd/codewire-0.1.0")
kept=("$home/registry/src/-0123abcd/codewire-proto-0.2.0" "$home/registry/src/-0123abcd/tokio-1.0.0"
  "$home/registry/src/index.crates.io-1949cf8c6b5b557f/codewire-proto-0.1.0")
mkdir -p "${stale[@]}" "${kept[@]}"
export CARGO_HOME="$home"

# A temporary target: nothing is cleaned or removed.
: >"$CARGO_CALLS"
unset CODEWIRE_SDK_PACKAGE_TARGET_DIR
"$SCRIPT" "$TMP/out-fresh" >"$TMP/fresh.log" 2>&1 || fail "a temporary target failed: $(cat "$TMP/fresh.log")"
! grep -q '^clean' "$CARGO_CALLS" || fail 'a temporary target was cleaned'
for dir in "${stale[@]}" "${kept[@]}"; do
  [[ -d "$dir" ]] || fail "a temporary target removed $dir"
done

# A kept target made before its first build: tagged as Cargo's cache, the two
# crates cleaned before packaging, and only their local-registry copies removed.
target="$TMP/kept-target"
mkdir "$target"
: >"$CARGO_CALLS"
CODEWIRE_SDK_PACKAGE_TARGET_DIR="$target" "$SCRIPT" "$TMP/out-kept" >"$TMP/kept.log" 2>&1 ||
  fail "a kept target failed: $(cat "$TMP/kept.log")"
head -n1 "$target/CACHEDIR.TAG" | grep -qx 'Signature: 8a477f597d28d172789f06886806bc55' ||
  fail 'the kept target is not tagged as a Cargo cache'
grep -qx "clean --locked -p codewire-proto -p codewire --target-dir $target" "$CARGO_CALLS" ||
  fail "the two crates were not cleaned: $(cat "$CARGO_CALLS")"
[[ "$(grep -nE '^(clean|package)' "$CARGO_CALLS" | cut -d: -f2 | cut -d' ' -f1 | tr '\n' ' ')" == 'clean package ' ]] ||
  fail 'the clean did not run once, before packaging'
for dir in "${stale[@]}"; do
  [[ ! -e "$dir" ]] || fail "the stale unpacked copy survived: $dir"
done
for dir in "${kept[@]}"; do
  [[ -d "$dir" ]] || fail "a crate that is not this SDK version, or crates.io's copy, was removed: $dir"
done
[[ -f "$TMP/out-kept/codewire-proto-0.1.0.crate" && -f "$TMP/out-kept/codewire-0.1.0.crate" ]] ||
  fail 'the kept target wrote no crates'

# A tag Cargo already wrote is left as it is.
printf 'Signature: 8a477f597d28d172789f06886806bc55\n# cargo wrote this\n' >"$target/CACHEDIR.TAG"
# Caller-set line-tables-only (e.g. from local-rust-cache.sh) is still overridden
# to 0 for the verify-only cargo package compile.
CARGO_PROFILE_DEV_DEBUG=line-tables-only CODEWIRE_SDK_PACKAGE_TARGET_DIR="$target" \
  "$SCRIPT" "$TMP/out-again" >"$TMP/again.log" 2>&1 ||
  fail "a second kept run failed: $(cat "$TMP/again.log")"
grep -qx '# cargo wrote this' "$target/CACHEDIR.TAG" || fail "Cargo's own cache tag was rewritten"

[[ "$(grep -cx 'CARGO_PROFILE_DEV_DEBUG=0' "$CARGO_CALLS.env")" -eq 3 ]] ||
  fail "cargo package did not force CARGO_PROFILE_DEV_DEBUG=0: $(cat "$CARGO_CALLS.env")"

# Local-only sccache wiring for a kept target: starts an isolated server, strips
# ambient remote SCCACHE_*/AWS_* vars, sets SCCACHE_CONF=/dev/null, and stops
# the server on exit. Temporary targets and explicit RUSTC_WRAPPER stay untouched.
cat >"$TMP/bin/sccache" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s uds=%s dir=%s conf=%s bucket=%s aws=%s\n' \
  "$*" "${SCCACHE_SERVER_UDS-unset}" "${SCCACHE_DIR-unset}" "${SCCACHE_CONF-unset}" \
  "${SCCACHE_BUCKET-unset}" "${AWS_ACCESS_KEY_ID-unset}" >>"$STUB_SCCACHE_LOG"
EOF
chmod +x "$TMP/bin/sccache"
export STUB_SCCACHE_LOG="$TMP/sccache-calls" CARGO_ENV_LOG="$TMP/cargo-env"

: >"$STUB_SCCACHE_LOG"
: >"$CARGO_ENV_LOG"
(
  unset RUSTC_WRAPPER
  SCCACHE_BUCKET=leaked-bucket AWS_ACCESS_KEY_ID=leaked-key \
    CODEWIRE_SDK_PACKAGE_SCCACHE_BIN="$TMP/bin/sccache" \
    CODEWIRE_SDK_PACKAGE_TARGET_DIR="$target" \
    "$SCRIPT" "$TMP/out-sccache" >"$TMP/sccache.log" 2>&1
) || fail "kept target with sccache failed: $(cat "$TMP/sccache.log")"
grep -q "^--start-server .* dir=$target/\.sccache conf=/dev/null bucket=unset aws=unset$" "$STUB_SCCACHE_LOG" ||
  fail "sccache start did not enforce local-only isolation: $(cat "$STUB_SCCACHE_LOG")"
grep -q '^--stop-server ' "$STUB_SCCACHE_LOG" ||
  fail "sccache server was not stopped on exit: $(cat "$STUB_SCCACHE_LOG")"
grep -q "RUSTC_WRAPPER=$TMP/bin/sccache SCCACHE_DIR=$target/\.sccache SCCACHE_CONF=/dev/null .* SCCACHE_BUCKET=unset AWS_ACCESS_KEY_ID=unset CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_BUILD_OVERRIDE_OPT_LEVEL=2" "$CARGO_ENV_LOG" ||
  fail "cargo package did not receive expected local sccache env: $(cat "$CARGO_ENV_LOG")"

# A temporary target never starts the kept-target sccache server.
: >"$STUB_SCCACHE_LOG"
: >"$CARGO_ENV_LOG"
(
  unset RUSTC_WRAPPER CODEWIRE_SDK_PACKAGE_TARGET_DIR
  CODEWIRE_SDK_PACKAGE_SCCACHE_BIN="$TMP/bin/sccache" \
    "$SCRIPT" "$TMP/out-tmp-no-sccache" >"$TMP/tmp-no-sccache.log" 2>&1
) || fail "temporary target with sccache present failed: $(cat "$TMP/tmp-no-sccache.log")"
[[ ! -s "$STUB_SCCACHE_LOG" ]] || fail "temporary target unexpectedly started sccache: $(cat "$STUB_SCCACHE_LOG")"
grep -q 'RUSTC_WRAPPER=unset SCCACHE_DIR=unset ' "$CARGO_ENV_LOG" ||
  fail "temporary target set RUSTC_WRAPPER/SCCACHE_DIR: $(cat "$CARGO_ENV_LOG")"

# An explicit caller RUSTC_WRAPPER is preserved without starting a private server.
: >"$STUB_SCCACHE_LOG"
: >"$CARGO_ENV_LOG"
(
  RUSTC_WRAPPER=/custom/wrapper \
    CODEWIRE_SDK_PACKAGE_SCCACHE_BIN="$TMP/bin/sccache" \
    CODEWIRE_SDK_PACKAGE_TARGET_DIR="$target" \
    "$SCRIPT" "$TMP/out-custom-wrapper" >"$TMP/custom-wrapper.log" 2>&1
) || fail "kept target with explicit RUSTC_WRAPPER failed: $(cat "$TMP/custom-wrapper.log")"
[[ ! -s "$STUB_SCCACHE_LOG" ]] || fail "explicit RUSTC_WRAPPER unexpectedly started private sccache: $(cat "$STUB_SCCACHE_LOG")"
grep -q 'RUSTC_WRAPPER=/custom/wrapper ' "$CARGO_ENV_LOG" ||
  fail "explicit RUSTC_WRAPPER was not preserved: $(cat "$CARGO_ENV_LOG")"

printf '[test-package-sdk-rust] a kept target rebuilds only the two SDK crates from this tree\n'
