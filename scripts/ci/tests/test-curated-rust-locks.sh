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
      elif [ "${FAKE_CARGO_OFFLINE_ERROR:-git}" = stale-index ]; then
        printf '%s\n%s\n%s\n' \
          'error: failed to select a version for the requirement `heapless = "^0.9"` (locked to 0.9.4)' \
          'candidate versions found which didn'"'"'t match: 0.9.3' \
          'note: offline mode (via `--offline`) can sometimes cause surprising resolution failures' >&2
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

# A locked version newer than the cached index fetches the index, then passes.
fake_state="$TMP/fake-cargo-stale-index-state"
stale_index_dir="$TMP/stale-index"
mkdir -p "$stale_index_dir"
cp "$ROOT/deployments/docker/derp.Cargo.toml" "$stale_index_dir/stale-index.Cargo.toml"
cp "$ROOT/deployments/docker/derp.Cargo.lock" "$stale_index_dir/stale-index.Cargo.lock"
stale_index_log="$TMP/stale-index.log"
FAKE_CARGO_STATE="$fake_state" \
  FAKE_CARGO_OFFLINE_ERROR=stale-index \
  CARGO_BIN="$fake_cargo" \
  CURATED_RUST_MANIFEST_DIR="$stale_index_dir" \
  "$GUARD" >"$stale_index_log"
grep -qF '[curated-rust-locks] stale-index: populating exact locked Cargo inputs' "$stale_index_log"
grep -qF '[curated-rust-locks] stale-index: OK' "$stale_index_log"
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

# Under a shared jobserver the two root clippy builds and the curated checks
# run at once, each in its own target folder; each build's output is printed
# whole, and the first failure is the exit status (infra#1534, step A).
# Without one they run one after another and stop at the first failure.
timed_cargo="$EXEC_TMP/timed-cargo"
cat >"$timed_cargo" <<'EOF'
#!/usr/bin/env bash
# Records when each build starts and ends, with its target folder; a clippy
# build takes a second, and FAIL_ALL_FEATURES fails the all-features one.
set -euo pipefail
case "$*" in
  *--all-features*) build=all-features ;;
  clippy*) build=default ;;
  check*) build=curated ;;
  *) exit 0 ;;
esac
printf 'start %s %s %s\n' "$build" "$CARGO_TARGET_DIR" "$(date +%s.%N)" >>"$COMPILE_CALLS"
[ "$build" = curated ] || sleep 1
printf 'end %s %s\n' "$build" "$(date +%s.%N)" >>"$COMPILE_CALLS"
printf 'fake %s output\n' "$build"
[ "$build" != all-features ] || exit "${FAIL_ALL_FEATURES:-0}"
EOF
chmod +x "$timed_cargo"
timed_run() {
  # timed_run LOG [FAIL_ALL_FEATURES] [CARGO_MAKEFLAGS]: one run with the timed
  # Cargo, under a fake shared jobserver unless the third argument is empty.
  : >"$TMP/compile.calls"
  CARGO_TARGET_DIR="$targets" COMPILE_CALLS="$TMP/compile.calls" CARGO_BIN="$timed_cargo" \
    CURATED_RUST_MANIFEST_DIR="$compile_root/manifests" FAIL_ALL_FEATURES="${2:-0}" \
    CARGO_MAKEFLAGS="${3---jobserver-auth=3,4}" \
    "$compile_root/scripts/ci/verify/compile-all-targets.sh" >"$1" 2>&1
}
cp "$ROOT/scripts/ci/verify/compile-all-targets.sh" "$compile_root/scripts/ci/verify/"
timed_run "$TMP/compile-timed.log" || compile_fail "the timed run failed: $(cat "$TMP/compile-timed.log")"
grep -qE "^start default $targets [0-9.]+\$" "$TMP/compile.calls" ||
  compile_fail 'default-features clippy did not build in the target folder'
grep -qE "^start all-features $targets/all-features [0-9.]+\$" "$TMP/compile.calls" ||
  compile_fail 'all-features clippy did not build in its own target folder'
# Every build starts before the first clippy build ends.
first_end="$(awk '$1 == "end" && $2 != "curated" { print $3 }' "$TMP/compile.calls" | sort -n | head -1)"
last_start="$(awk '$1 == "start" { print $4 }' "$TMP/compile.calls" | sort -n | tail -1)"
awk -v start="$last_start" -v end="$first_end" 'BEGIN { exit !(start < end) }' ||
  compile_fail "the builds ran one after another: $(cat "$TMP/compile.calls")"
for build in default all-features curated; do
  grep -qxF "fake $build output" "$TMP/compile-timed.log" || compile_fail "the $build output was not printed"
done
grep -qxF '[compile-all-targets] every Rust target compiles' "$TMP/compile-timed.log" ||
  compile_fail 'a green run did not say every target compiles'
status=0
timed_run "$TMP/compile-fail.log" 3 || status=$?
[ "$status" = 3 ] || compile_fail "a failing all-features build exited $status, not 3"
grep -qF '[compile-all-targets] root clippy (all features): finish (status=3' "$TMP/compile-fail.log" ||
  compile_fail 'the failing build was not reported'
grep -qxF 'fake default output' "$TMP/compile-fail.log" || compile_fail 'the other builds were not printed'
if grep -qF 'every Rust target compiles' "$TMP/compile-fail.log"; then
  compile_fail 'a failing run said every target compiles'
fi
# Without a shared jobserver: one after another, in order, each in its folder.
timed_run "$TMP/compile-serial.log" 0 '' || compile_fail "the serial run failed: $(cat "$TMP/compile-serial.log")"
[ "$(awk '{ print $1, $2 }' "$TMP/compile.calls" | tr '\n' ' ')" = \
  'start default end default start all-features end all-features start curated end curated ' ] ||
  compile_fail "without a jobserver the builds did not run one after another: $(cat "$TMP/compile.calls")"
grep -qE "^start all-features $targets/all-features [0-9.]+\$" "$TMP/compile.calls" ||
  compile_fail 'without a jobserver all-features did not build in its own target folder'
status=0
timed_run "$TMP/compile-serial-fail.log" 3 '' || status=$?
[ "$status" = 3 ] || compile_fail "a failing serial all-features build exited $status, not 3"
if grep -qF 'start curated' "$TMP/compile.calls"; then
  compile_fail 'a serial run went on after a failing build'
fi

printf 'curated Rust workspace lock fixtures: stale and root drift rejected; current derp and cold-cache forms green; compile-all-targets stages each workspace afresh at one path under its target folder, locked, and runs its three builds in their own folders, at once under a shared jobserver\n'
