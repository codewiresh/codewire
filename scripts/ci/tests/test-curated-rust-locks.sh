#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GUARD="$ROOT/scripts/ci/verify/check-curated-rust-locks.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/codewire-test-curated-rust-locks.XXXXXX")"
mkdir -p "$ROOT/target"
EXEC_TMP="$(mktemp -d "$ROOT/target/codewire-test-curated-rust-locks-bin.XXXXXX")"

cleanup() {
  rm -rf -- "$TMP" "$EXEC_TMP"
}
trap cleanup EXIT

pass_log="$TMP/pass.log"
"$GUARD" >"$pass_log"
grep -qF '[curated-rust-locks] derp: OK' "$pass_log"

fixture_dir="$TMP/fixture"
mkdir -p "$fixture_dir"
cp "$ROOT"/deployments/docker/*.Cargo.toml "$fixture_dir/"
cp "$ROOT"/deployments/docker/*.Cargo.lock "$fixture_dir/"

stale_lock="$fixture_dir/derp.Cargo.lock"
sed '/^name = "codewire-derp"$/,/^]$/ {
  /^ "crc32fast",$/d
}' "$ROOT/deployments/docker/derp.Cargo.lock" >"$stale_lock"

stale_log="$TMP/stale.log"
if CURATED_RUST_MANIFEST_DIR="$fixture_dir" "$GUARD" >"$stale_log" 2>&1; then
  echo 'curated Rust lock guard accepted a stale derp lock' >&2
  exit 1
fi

assert_stale_log_contains() {
  local expected="$1"
  if ! grep -qF -- "$expected" "$stale_log"; then
    printf 'stale-lock rejection omitted expected diagnostic: %s\n' "$expected" >&2
    sed -n '1,80p' "$stale_log" >&2
    exit 1
  fi
}

assert_stale_log_contains_any() {
  local expected
  for expected in "$@"; do
    if grep -qF -- "$expected" "$stale_log"; then
      return
    fi
  done
  printf 'stale-lock rejection omitted every accepted Cargo diagnostic form\n' >&2
  sed -n '1,80p' "$stale_log" >&2
  exit 1
}

assert_stale_log_contains 'curated Rust workspace derp has manifest/lock drift'
assert_stale_log_contains 'lock file'
assert_stale_log_contains '--locked was passed'
assert_stale_log_contains_any \
  'needs to be updated' \
  'cannot update the lock file'

fake_cargo="$EXEC_TMP/fake-cargo"
fake_state="$TMP/fake-cargo-git-state"
cat >"$fake_cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"$FAKE_CARGO_STATE.calls"
case "${1:-}" in
  metadata)
    if [ ! -f "$FAKE_CARGO_STATE.fetched" ]; then
      if [ "${FAKE_CARGO_OFFLINE_ERROR:-git}" = registry ]; then
        printf '%s\n\n%s\n' \
          'error: failed to download `exact-registry-crate v1.2.3`' \
          'Caused by: attempting to make an HTTP request, but --offline was specified' >&2
      else
        printf '%s\n' \
          "can't checkout from 'https://example.invalid/exact.git': you are in the offline mode (--offline)" >&2
      fi
      exit 101
    fi
    ;;
  fetch)
    touch "$FAKE_CARGO_STATE.fetched"
    ;;
  *)
    printf 'unexpected fake Cargo command: %s\n' "$*" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$fake_cargo"

cold_git_dir="$TMP/cold-git"
mkdir -p "$cold_git_dir"
cp "$ROOT/deployments/docker/derp.Cargo.toml" "$cold_git_dir/cold-git.Cargo.toml"
cp "$ROOT/deployments/docker/derp.Cargo.lock" "$cold_git_dir/cold-git.Cargo.lock"
cold_git_log="$TMP/cold-git.log"
FAKE_CARGO_STATE="$fake_state" \
  CARGO_BIN="$fake_cargo" \
  CURATED_RUST_MANIFEST_DIR="$cold_git_dir" \
  "$GUARD" >"$cold_git_log"
grep -qF '[curated-rust-locks] cold-git: populating exact locked Cargo inputs' "$cold_git_log"
grep -qF '[curated-rust-locks] cold-git: OK' "$cold_git_log"
grep -qF 'metadata --locked --offline' "$fake_state.calls"
grep -qF 'fetch --locked' "$fake_state.calls"
test "$(grep -cF 'metadata --locked --offline' "$fake_state.calls")" -eq 2
test "$(grep -cF 'fetch --locked' "$fake_state.calls")" -eq 1

fake_state="$TMP/fake-cargo-registry-state"
cold_registry_dir="$TMP/cold-registry"
mkdir -p "$cold_registry_dir"
cp "$ROOT/deployments/docker/derp.Cargo.toml" "$cold_registry_dir/cold-registry.Cargo.toml"
cp "$ROOT/deployments/docker/derp.Cargo.lock" "$cold_registry_dir/cold-registry.Cargo.lock"
cold_registry_log="$TMP/cold-registry.log"
FAKE_CARGO_STATE="$fake_state" \
  FAKE_CARGO_OFFLINE_ERROR=registry \
  CARGO_BIN="$fake_cargo" \
  CURATED_RUST_MANIFEST_DIR="$cold_registry_dir" \
  "$GUARD" >"$cold_registry_log"
grep -qF '[curated-rust-locks] cold-registry: populating exact locked Cargo inputs' "$cold_registry_log"
grep -qF '[curated-rust-locks] cold-registry: OK' "$cold_registry_log"
grep -qF 'metadata --locked --offline' "$fake_state.calls"
grep -qF 'fetch --locked' "$fake_state.calls"
test "$(grep -cF 'metadata --locked --offline' "$fake_state.calls")" -eq 2
test "$(grep -cF 'fetch --locked' "$fake_state.calls")" -eq 1

# A curated lock that selects a version the root lock does not select is drift,
# even when it is internally consistent with its own manifest.
drift_dir="$TMP/drift"
mkdir -p "$drift_dir"
cp "$ROOT/deployments/docker/derp.Cargo.toml" "$drift_dir/derp.Cargo.toml"
cp "$ROOT/deployments/docker/derp.Cargo.lock" "$drift_dir/derp.Cargo.lock"
drift_package="$(awk '/^name = /{name=$3} /^source = "registry/{print name; exit}' \
  "$drift_dir/derp.Cargo.lock" | tr -d '"')"
[ -n "$drift_package" ] || {
  printf 'no registry package found for the drift fixture\n' >&2
  exit 1
}
drift_root="$TMP/drift-root.Cargo.lock"
awk -v target="$drift_package" '
  /^name = / { current = $3; gsub(/"/, "", current) }
  current == target && /^version = / { print "version = \"0.0.0-drift\""; current = ""; next }
  { print }
' "$ROOT/Cargo.lock" >"$drift_root"
drift_log="$TMP/drift.log"
if CURATED_RUST_MANIFEST_DIR="$drift_dir" CURATED_RUST_ROOT_LOCK="$drift_root" \
    "$GUARD" >"$drift_log" 2>&1; then
  printf 'curated-lock guard accepted a version the root lock does not select\n' >&2
  exit 1
fi
grep -qF "  $drift_package " "$drift_log"
grep -qF 'curated Rust workspace derp drifted from the root lock' "$drift_log"

printf 'curated Rust workspace lock fixtures: stale and root drift rejected; current derp and cold-cache forms green\n'
