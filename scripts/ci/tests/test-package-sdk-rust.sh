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

printf '[test-package-sdk-rust] a kept target rebuilds only the two SDK crates from this tree\n'
