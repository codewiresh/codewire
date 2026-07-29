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
grep -qF '[curated-rust-locks] gateway: OK' "$pass_log"
grep -qF '[curated-rust-locks] derp: OK' "$pass_log"

fixture_dir="$TMP/fixture"
mkdir -p "$fixture_dir"
cp "$ROOT"/deployments/docker/*.Cargo.toml "$fixture_dir/"
cp "$ROOT"/deployments/docker/*.Cargo.lock "$fixture_dir/"

stale_lock="$fixture_dir/gateway.Cargo.lock"
sed '/^name = "codewire-gateway"$/,/^]$/ {
  /^ "uuid",$/d
}' "$ROOT/deployments/docker/gateway.Cargo.lock" >"$stale_lock"

stale_log="$TMP/stale.log"
if CURATED_RUST_MANIFEST_DIR="$fixture_dir" "$GUARD" >"$stale_log" 2>&1; then
  echo 'curated Rust lock guard accepted a stale gateway lock' >&2
  exit 1
fi
grep -qF 'curated Rust workspace gateway has manifest/lock drift' "$stale_log"
grep -qF 'cannot update the lock file' "$stale_log"
grep -qF -- '--locked was passed' "$stale_log"

fake_cargo="$EXEC_TMP/fake-cargo"
fake_state="$TMP/fake-cargo-state"
cat >"$fake_cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"$FAKE_CARGO_STATE.calls"
case "${1:-}" in
  metadata)
    if [ ! -f "$FAKE_CARGO_STATE.fetched" ]; then
      printf '%s\n' \
        "can't checkout from 'https://example.invalid/exact.git': you are in the offline mode (--offline)" >&2
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
cp "$ROOT/deployments/docker/gateway.Cargo.toml" "$cold_git_dir/cold-git.Cargo.toml"
cp "$ROOT/deployments/docker/gateway.Cargo.lock" "$cold_git_dir/cold-git.Cargo.lock"
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

printf 'curated Rust workspace lock fixtures: stale gateway rejected; current derp/gateway green\n'
