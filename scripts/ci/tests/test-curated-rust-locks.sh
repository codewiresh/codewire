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

# compile-all-targets.sh stages each curated workspace at one path under its
# target folder on every run, so Cargo reuses the previous run's build, and
# stages it afresh there, under a lock, so it is exactly the checked-in
# workspace. A fixture root runs the real script with a fake Cargo.
compile_root="$EXEC_TMP/compile-root"
mkdir -p "$compile_root/scripts/ci/verify" "$compile_root/crates" "$compile_root/proto" \
  "$compile_root/libs" "$compile_root/manifests"
cp "$ROOT/scripts/ci/verify/compile-all-targets.sh" "$compile_root/scripts/ci/verify/"
printf '#!/usr/bin/env bash\nexit 0\n' >"$compile_root/scripts/ci/verify/check-workspace-hack.sh"
chmod +x "$compile_root/scripts/ci/verify/check-workspace-hack.sh"
printf 'select_local_rust_cache() { return 0; }\n' >"$compile_root/scripts/ci/verify/local-rust-cache.sh"
compile_cargo="$EXEC_TMP/compile-cargo"
cat >"$compile_cargo" <<'EOF'
#!/usr/bin/env bash
# Records each curated check: its target folder, its staged manifest, whether
# the staging lock is held, the staged entries and the staged manifest.
set -euo pipefail
[ "$1" = check ] || exit 0
args="$*"
manifest="${args##*--manifest-path }"
stage="${manifest%/Cargo.toml}"
# flock exits 75 only when another holder has the lock.
status=0
flock -n -E 75 "${stage%/*}.lock" true || status=$?
case "$status" in 0) locked=free ;; 75) locked=held ;; *) exit 2 ;; esac
{
  printf 'check %s %s %s\n' "$CARGO_TARGET_DIR" "$manifest" "$locked"
  (cd "$stage" && find . -mindepth 1 -maxdepth 1 | LC_ALL=C sort | tr '\n' ' ' && echo)
  cat "$manifest"
} >>"$COMPILE_CALLS"
EOF
chmod +x "$compile_cargo"
compile_run() {
  # compile_run LOG [TARGET_DIR]: one run; without TARGET_DIR, Cargo's default.
  local log="$1"
  : >"$TMP/compile.calls"
  (
    if [ -n "${2:-}" ]; then export CARGO_TARGET_DIR="$2"; else unset CARGO_TARGET_DIR; fi
    COMPILE_CALLS="$TMP/compile.calls" CARGO_BIN="$compile_cargo" \
      CURATED_RUST_MANIFEST_DIR="$compile_root/manifests" \
      "$compile_root/scripts/ci/verify/compile-all-targets.sh" >"$log" 2>&1
  )
}
compile_fail() {
  printf 'compile-all-targets staging: %s\n' "$1" >&2
  sed -n '1,40p' "$TMP/compile.calls" >&2
  exit 1
}
staged_entries='./Cargo.lock ./Cargo.toml ./crates ./libs ./proto '
targets="$TMP/warm/targets/clippy"
for name in one two; do
  printf '[workspace] # %s v1\n' "$name" >"$compile_root/manifests/$name.Cargo.toml"
  printf '# %s lock\n' "$name" >"$compile_root/manifests/$name.Cargo.lock"
done
compile_run "$TMP/compile1.log" "$targets" || compile_fail "the first run failed: $(cat "$TMP/compile1.log")"
grep -qxF "check $targets/curated-one $targets/curated/one/Cargo.toml held" "$TMP/compile.calls" ||
  compile_fail 'the first run did not check one at its stable path, in its own target folder, under the lock'
grep -qxF "check $targets/curated-two $targets/curated/two/Cargo.toml held" "$TMP/compile.calls" ||
  compile_fail 'the first run did not check two at its stable path'
grep -qxF "$staged_entries" "$TMP/compile.calls" ||
  compile_fail 'the staged workspace is not exactly the manifest, the lock and the source links'
[ "$(readlink "$targets/curated/one/crates")" = "$compile_root/crates" ] ||
  compile_fail 'the staged crates link does not name the checkout'
# An earlier run's leftovers, a changed manifest and a removed workspace.
touch "$targets/curated/one/stale.rs"
mkdir -p "$targets/curated/gone"
printf '[workspace] # one v2\n' >"$compile_root/manifests/one.Cargo.toml"
rm "$compile_root/manifests/two.Cargo.toml" "$compile_root/manifests/two.Cargo.lock"
compile_run "$TMP/compile2.log" "$targets" || compile_fail "the second run failed: $(cat "$TMP/compile2.log")"
grep -qxF "check $targets/curated-one $targets/curated/one/Cargo.toml held" "$TMP/compile.calls" ||
  compile_fail 'the second run did not stage one at the same path as the first'
grep -qxF "$staged_entries" "$TMP/compile.calls" ||
  compile_fail 'a stale file from an earlier run stayed in the staged workspace'
grep -qxF '[workspace] # one v2' "$TMP/compile.calls" || compile_fail 'the changed manifest was not staged'
if grep -qF 'v1' "$TMP/compile.calls"; then compile_fail 'the earlier manifest stayed staged'; fi
[ "$(grep -c '^check ' "$TMP/compile.calls")" -eq 1 ] || compile_fail 'a removed workspace was checked'
[ "$(cd "$targets/curated" && find . -mindepth 1 -maxdepth 1 | LC_ALL=C sort | tr '\n' ' ')" = './one ' ] ||
  compile_fail 'a removed or unknown workspace stayed staged'
# A link left at the staging folder is replaced, never followed.
mkdir -p "$TMP/elsewhere"
touch "$TMP/elsewhere/kept"
rm -rf "$targets/curated"
ln -s "$TMP/elsewhere" "$targets/curated"
compile_run "$TMP/compile-link.log" "$targets" || compile_fail "the run after a link failed: $(cat "$TMP/compile-link.log")"
[ -d "$targets/curated" ] && [ ! -L "$targets/curated" ] || compile_fail 'the staging folder stayed a link'
[ -e "$TMP/elsewhere/kept" ] && [ ! -e "$TMP/elsewhere/one" ] || compile_fail 'the run followed a link at the staging folder'
# Without CARGO_TARGET_DIR, the checkout's target folder, Cargo's default.
compile_run "$TMP/compile3.log" || compile_fail "the default run failed: $(cat "$TMP/compile3.log")"
grep -qxF "check $compile_root/target/curated-one $compile_root/target/curated/one/Cargo.toml held" \
  "$TMP/compile.calls" || compile_fail 'the default run did not stage under the checkout target folder'

printf 'curated Rust workspace lock fixtures: stale and root drift rejected; current derp and cold-cache forms green; compile-all-targets stages each workspace afresh at one path under its target folder, locked\n'
