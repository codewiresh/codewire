#!/usr/bin/env bash
# build-once.sh (compile once, infra#1632) brings its persistent clone to a
# depth-1 job checkout: the first fetch into an empty clone and a later one
# to a newer commit both land on the checkout's commit. Bad input is refused
# before the build folder is touched.
# shellcheck disable=SC2016 # The checks match literal shell text.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly SCRIPT="$ROOT/scripts/ci/setup/build-once.sh"
# The leg table reads the run's selection, publish its store, and prepare its
# event (main or pr build folder); a CI job running
# this test may have its own in the environment, so each case states its own.
unset VERIFICATION_SELECTION ARCHIVE_STORE_URL GITHUB_EVENT_NAME GITHUB_REF BUILD_ONCE_LOCAL_VMM

fail() {
  echo "test-build-once: $*" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/test-build-once.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
git init -q "$work/origin"
commit() {
  echo "$1" > "$work/origin/file"
  git -C "$work/origin" add file
  git -C "$work/origin" -c user.name=t -c user.email=t@example.invalid commit -q -m "$1"
  git -C "$work/origin" rev-parse HEAD
}
first="$(commit one)"
git clone -q --depth 1 "file://$work/origin" "$work/checkout1"
second="$(commit two)"
git clone -q --depth 1 "file://$work/origin" "$work/checkout2"

# The git half of prepare, as the script runs it.
sync_clone() {
  # shellcheck disable=SC2034 # The fetch line read from the script uses it.
  local checkout="$1" src="$work/root/pr/src"
  local git_src=(git -c core.hooksPath=/dev/null -C "$src")
  [ -d "$src/.git" ] || git init -q "$src"
  eval "$(sed -nE 's/^  "\$\{git_src\[@\]\}" (fetch .*)$/"${git_src[@]}" \1/p' "$SCRIPT")"
  "${git_src[@]}" checkout -q --force --detach FETCH_HEAD
  "${git_src[@]}" rev-parse HEAD
}
mkdir -p "$work/root/pr"
[ "$(sync_clone "$work/checkout1")" = "$first" ] || fail 'the first fetch into an empty clone did not land on the commit'
[ "$(sync_clone "$work/checkout2")" = "$second" ] || fail 'a later fetch did not land on the newer commit'
grep -Fq -- '--update-shallow "$checkout" HEAD' "$SCRIPT" || fail 'the fetch must update the shallow boundary'

for args in '' 'archive' 'publish x' 'publish x Bad-Name' 'leg nothing x' 'nothing'; do
  # shellcheck disable=SC2086 # Word splitting builds each case's arguments.
  if BUILD_ONCE_ROOT="$work/root" "$SCRIPT" $args >/dev/null 2>&1; then
    fail "build-once.sh accepted: ${args:-no arguments}"
  fi
done
# The leg table: every test archive, in table order; the checks that build
# no archive are Rust checks' (run-rust-checks.sh), not legs.
[ "$("$SCRIPT" legs | tr '\n' ' ')" = 'archive ' ] || fail 'unexpected wanted legs'
[ "$(VERIFICATION_SELECTION='|policy|database|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive database ' ] ||
  fail 'a selected database family did not want the database leg'
[ "$(VERIFICATION_SELECTION='|policy|rust|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive features ' ] ||
  fail 'a selected Rust family did not want the feature-graph leg'
[ "$(VERIFICATION_SELECTION='|transport|' BUILD_ONCE_LOCAL_VMM=true "$SCRIPT" legs | tr '\n' ' ')" = 'archive local_vmm ' ] ||
  fail 'the local-vmm shard did not want its leg'
[ "$(VERIFICATION_SELECTION='|transport|' BUILD_ONCE_LOCAL_VMM=false "$SCRIPT" legs | tr '\n' ' ')" = 'archive ' ] ||
  fail 'the local-vmm leg ran without BUILD_ONCE_LOCAL_VMM'
[ "$(VERIFICATION_SELECTION='|rust|database|' BUILD_ONCE_LOCAL_VMM=true "$SCRIPT" legs | tr '\n' ' ')" = 'archive local_vmm features database ' ] ||
  fail 'unexpected legs for every family'
grep -Eq '^  "[a-z0-9_]+ (always|selected:[a-z0-9_,-]+|env:[A-Z0-9_]+)"$' "$SCRIPT" ||
  fail 'the leg table is missing'
for retired in compile feature_checks local_vmm_checks; do
  if grep -Eq "^leg_$retired\(\) \{" "$SCRIPT"; then fail "the $retired check is still a build-runner leg"; fi
done
if "$SCRIPT" legs tests >/dev/null 2>&1; then fail 'legs accepted a lane'; fi
# A selected leg runs when any of its tokens is selected.
all='|database|service_idp|service_coordinator|service_billing|service_connectcore|service_orchestration|service_nats|'
[ "$(VERIFICATION_SELECTION="$all" "$SCRIPT" legs | tr '\n' ' ')" = \
  'archive database services_control services_runtime ' ] || fail 'unexpected legs with every family'
[ "$(VERIFICATION_SELECTION='|service_nats|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive services_runtime ' ] ||
  fail 'service_nats alone must select the runtime plane leg only'
[ "$(VERIFICATION_SELECTION='|service_billing|service_temporal|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive services_control ' ] ||
  fail 'service_billing alone must select the control plane leg only'
[ "$(VERIFICATION_SELECTION='|service_temporal|service_nats_extra|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive ' ] ||
  fail 'a selected leg matched a token it does not name'
while read -r name; do
  grep -Eq "^leg_$name\(\) \{" "$SCRIPT" || fail "the $name leg has no function"
  # Each leg builds in its own target folder.
  grep -A12 -E "^leg_$name\(\) \{" "$SCRIPT" | grep -q "targets/$name\b\|service_plane_leg" ||
    fail "the $name leg does not build in targets/$name"
done < <(VERIFICATION_SELECTION="${all}rust|transport|" BUILD_ONCE_LOCAL_VMM=true "$SCRIPT" legs)

# The build folder follows the event: main only for a push to main.
tree() {
  # shellcheck source=scripts/ci/setup/build-once-tree.sh
  ( source "$ROOT/scripts/ci/setup/build-once-tree.sh"; GITHUB_EVENT_NAME="$1" GITHUB_REF="$2" build_once_tree /d )
}
[ "$(tree push refs/heads/main)" = /d/main ] || fail 'a push to main must build in main'
[ "$(tree pull_request refs/pull/1/head)" = /d/pr ] || fail 'a pull request must build in pr'
[ "$(tree push refs/heads/other)" = /d/pr ] || fail 'a push to another branch must build in pr'
[ "$(tree workflow_dispatch refs/heads/main)" = /d/pr ] || fail 'a dispatched run must build in pr'

# prepare refuses a disk that holds the other kind's folder, and a workflow
# that names another folder, before it touches anything.
mkdir -p "$work/disk/main/src" "$work/env"
if GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/head BUILD_ONCE_ROOT="$work/disk" \
    GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
    "$SCRIPT" prepare "$work/checkout1" > "$work/refused.log" 2>&1; then
  fail 'a pull request prepared on a disk holding main'
fi
grep -q 'holds .*/main; a pr run does not build here' "$work/refused.log" || fail 'no reason for the refusal'
[ -d "$work/disk/main/src" ] || fail 'the refused prepare touched the main folder'
if GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main BUILD_ONCE_ROOT="$work/disk" BUILD_ONCE_TREE=/ci-cache/pr \
    GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
    "$SCRIPT" prepare "$work/checkout1" > "$work/refused.log" 2>&1; then
  fail 'prepare accepted a workflow folder that differs from the run kind'
fi
grep -q 'BUILD_ONCE_TREE=/ci-cache/pr, but this run builds in' "$work/refused.log" || fail 'no reason for the folder refusal'

# A test job's fetch: verified bytes are ready; with --or-build, a missing
# digest, store or archive is a miss the job builds through (ready=false, a
# warning, success); without it a missing archive fails; a corrupt archive
# always fails.
FETCH="$ROOT/scripts/ci/setup/fetch-test-archive.sh"
mkdir -p "$work/fetch-store/v1/archives"
printf 'archive' > "$work/fetch-src"
good="$(sha256sum "$work/fetch-src" | cut -d' ' -f1)"
cp "$work/fetch-src" "$work/fetch-store/v1/archives/$good"
absent="$(printf 'absent' | sha256sum | cut -d' ' -f1)"
fetch() {
  : > "$work/fetch-out"
  GITHUB_OUTPUT="$work/fetch-out" ARCHIVE_STORE_URL="${STORE-file://$work/fetch-store}" \
    "$FETCH" "$@" > "$work/fetch.log" 2>&1
}
fetch --or-build "$good" "$work/fetched/a.tar" || fail 'a stored archive did not fetch'
grep -qx 'ready=true' "$work/fetch-out" || fail 'a fetched archive is not ready'
cmp -s "$work/fetch-src" "$work/fetched/a.tar" || fail 'a fetched archive differs'
fetch --or-build "$absent" "$work/fetched/b.tar" || fail 'an evicted archive failed the job instead of building'
grep -qx 'ready=false' "$work/fetch-out" || fail 'an evicted archive was not a miss'
grep -q '::warning::.*no archive .*builds its tests itself' "$work/fetch.log" || fail 'an evicted archive gave no warning'
[ ! -e "$work/fetched/b.tar" ] && [ ! -e "$work/fetched/b.tar.partial" ] || fail 'a miss left a file behind'
fetch --or-build '' "$work/fetched/c.tar" || fail 'a run with no archive failed instead of building'
grep -qx 'ready=false' "$work/fetch-out" || fail 'a run with no archive was not a miss'
STORE='' fetch --or-build "$good" "$work/fetched/d.tar" || fail 'no store failed the job instead of building'
grep -qx 'ready=false' "$work/fetch-out" || fail 'no store was not a miss'
if fetch "$absent" "$work/fetched/e.tar"; then fail 'an evicted archive passed without --or-build'; fi
printf 'tampered' > "$work/fetch-store/v1/archives/$absent"
if fetch --or-build "$absent" "$work/fetched/f.tar"; then fail 'a corrupt archive was accepted'; fi
grep -q 'hashes to' "$work/fetch.log" || fail 'a corrupt archive gave no reason'
grep -q 'ready=' "$work/fetch-out" && fail 'a corrupt archive reported readiness'

# A folder left by a cancelled job keeps its targets (a corrupt output is the
# reading leg's to wipe, below); a stale marker from the earlier layout goes;
# a lockfile change keeps the targets (Cargo's fingerprints rebuild what it
# changed); only a new layout version wipes them, and a folder from before the
# layout file keeps them.
git init -q "$work/lock-origin"
mkdir -p "$work/lock-origin/deployments/docker"
printf 'lock one\n' > "$work/lock-origin/Cargo.lock"
printf '[toolchain]\n' > "$work/lock-origin/rust-toolchain.toml"
printf 'derp\n' > "$work/lock-origin/deployments/docker/derp.Cargo.lock"
git -C "$work/lock-origin" add -A
git -C "$work/lock-origin" -c user.name=t -c user.email=t@example.invalid commit -q -m one
git clone -q --depth 1 "file://$work/lock-origin" "$work/lock-checkout"
# A fake df: the build disk is 10 % used, plus 20 % for each leg folder when
# FAKE_DF_PER_LEG is set.
cat > "$work/fake-df" <<'DF'
#!/usr/bin/env bash
used=10
if [ -n "${FAKE_DF_PER_LEG:-}" ]; then
  legs="$(find "$FAKE_DF_TARGETS" -mindepth 1 -maxdepth 1 -type d ! -name '*_desktop' | wc -l)"
  used=$(( 10 + 20 * legs ))
fi
printf 'Filesystem 1024-blocks Used Available Capacity Mounted\nfake 100 %s %s %s%% /x\n' "$used" "$((100 - used))" "$used"
DF
chmod +x "$work/fake-df"
targets_prepare() {
  BUILD_ONCE_DF="$work/fake-df" FAKE_DF_TARGETS="$work/marker-root/pr/targets" \
  BUILD_ONCE_ROOT="$work/marker-root" BUILD_ONCE_TEST_STOP_AFTER_TARGETS=1 \
    GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
    "$SCRIPT" prepare "$work/lock-checkout" > "$work/prepare.log" 2>&1 || fail "prepare failed: $(cat "$work/prepare.log")"
}
marker_root="$work/marker-root/pr"
targets_prepare
mkdir -p "$marker_root/targets/archive"
printf 'kept' > "$marker_root/targets/archive/lib.rlib"
: > "$marker_root/unfinished"
targets_prepare
[ -f "$marker_root/targets/archive/lib.rlib" ] || fail 'a folder left by an interrupted job lost its targets'
[ ! -e "$marker_root/unfinished" ] || fail 'prepare kept a stale unfinished marker'
printf 'lock two\n' > "$work/lock-origin/Cargo.lock"
git -C "$work/lock-origin" -c user.name=t -c user.email=t@example.invalid commit -q -am two
rm -rf "$work/lock-checkout"
git clone -q --depth 1 "file://$work/lock-origin" "$work/lock-checkout"
targets_prepare
[ -f "$marker_root/targets/archive/lib.rlib" ] || fail 'a lockfile change wiped the targets'
grep -qx 2 "$marker_root/layout" || fail 'prepare did not record the folder layout'
[ ! -e "$marker_root/lock-stamp" ] || fail 'prepare kept the retired lock-stamp'
printf '1\n' > "$marker_root/layout"
targets_prepare
[ ! -e "$marker_root/targets/archive/lib.rlib" ] || fail 'a new folder layout kept the targets'
grep -q 'the folder layout changed; the target folders are wiped' "$work/prepare.log" || fail 'the layout wipe gave no reason'
mkdir -p "$marker_root/targets/archive"
printf 'kept' > "$marker_root/targets/archive/lib.rlib"
rm -f "$marker_root/layout"
printf 'old-stamp\n' > "$marker_root/lock-stamp"
targets_prepare
[ -f "$marker_root/targets/archive/lib.rlib" ] || fail 'the move to the layout file wiped the targets'
# Builds are not incremental (their sessions filled the disk, main run 22822),
# and prepare removes the sessions earlier builds left.
grep -q "^    echo 'CARGO_INCREMENTAL=0'$" "$SCRIPT" || fail 'build runner builds are incremental'
mkdir -p "$marker_root/targets/archive/debug/incremental/codewire_proto-x/s-1" "$marker_root/targets/archive/debug/deps"
printf 'x' > "$marker_root/targets/archive/debug/incremental/codewire_proto-x/s-1/dep-graph.bin"
printf 'keep' > "$marker_root/targets/archive/debug/deps/libkeep.rlib"
targets_prepare
[ ! -e "$marker_root/targets/archive/debug/incremental" ] || fail 'prepare kept incremental sessions'
[ -f "$marker_root/targets/archive/debug/deps/libkeep.rlib" ] || fail 'removing incremental sessions removed an artifact'

# The disk bound: target files no build read for 3 days go; above 65 % of the
# disk, whole leg folders go, least recently used first (a folder with no use
# mark first), and a leg's desktop folder with it.
rm -rf "$marker_root/targets"
mkdir -p "$marker_root/targets/archive/debug/deps" "$marker_root/targets/database" \
  "$marker_root/targets/features" "$marker_root/targets/database_desktop"
printf 'stale' > "$marker_root/targets/archive/debug/deps/libold.rlib"
printf 'fresh' > "$marker_root/targets/archive/debug/deps/libnew.rlib"
touch -a -d '5 days ago' "$marker_root/targets/archive/debug/deps/libold.rlib"
touch -d '2 hours ago' "$marker_root/targets/database/.build-once-used"
touch "$marker_root/targets/archive/.build-once-used"
FAKE_DF_PER_LEG=1 targets_prepare
[ ! -e "$marker_root/targets/archive/debug/deps/libold.rlib" ] || fail 'a target file unread for 5 days was kept'
[ -f "$marker_root/targets/archive/debug/deps/libnew.rlib" ] || fail 'a fresh target file was swept'
grep -q 'removed 1 target files no build read for 3 days' "$work/prepare.log" || fail 'the sweep gave no count'
[ ! -e "$marker_root/targets/features" ] || fail 'the never-used leg folder was kept over the disk bound'
[ -d "$marker_root/targets/database" ] && [ -d "$marker_root/targets/archive" ] ||
  fail 'the bound removed more than it needed'
grep -q 'disk 70% used (limit 65%); removing the least recently used target folder features' "$work/prepare.log" ||
  fail 'the bound gave no reason'
FAKE_DF_PER_LEG=1 BUILD_ONCE_DISK_PERCENT=35 targets_prepare
[ ! -e "$marker_root/targets/database" ] && [ ! -e "$marker_root/targets/database_desktop" ] ||
  fail 'the older leg and its desktop folder were kept'
[ -d "$marker_root/targets/archive" ] || fail 'the most recently used leg was removed'
grep -q "^  touch \"\$work/targets/\$name/.build-once-used\"$" "$SCRIPT" || fail 'a leg does not mark its folder used'
if "$SCRIPT" finish >/dev/null 2>&1; then fail 'the retired finish subcommand was accepted'; fi

# A leg that reads a corrupt output from its warm target folder wipes the
# folder its error names and builds once more in the same job; any other
# failure fails at once, with no rebuild.
legs_src="$work/legs-src"
git init -q "$legs_src"
mkdir -p "$legs_src/scripts/ci/verify" "$work/legs-bin" "$work/legs-out"
cat > "$legs_src/scripts/ci/verify/run-product-verification.sh" <<'FEATURES'
#!/bin/sh
# The feature-graph leg's stage: records its time and the jobserver it sees.
echo "features-start $(date +%s%N)" >> "$LEGS_STATE/times"; sleep 1
echo "features-end $(date +%s%N)" >> "$LEGS_STATE/times"
echo "features-makeflags ${CARGO_MAKEFLAGS:-none}" >> "$LEGS_STATE/times"
FEATURES
chmod +x "$legs_src/scripts/ci/verify/run-product-verification.sh"
cat > "$work/legs-bin/cargo" <<'CARGO'
#!/usr/bin/env bash
# The archive leg's cargo: fails as LEGS_CARGO_MODE says while its marker
# file exists, then writes the archive.
calls="$LEGS_STATE/calls"; echo x >> "$calls"
if [ -e "$CARGO_TARGET_DIR/debug/deps/libbroken.rlib" ]; then
  case "$LEGS_CARGO_MODE" in
    corrupt) echo "rust-lld: error: $CARGO_TARGET_DIR/debug/deps/libbroken.rlib: Archive::children failed: truncated or malformed archive"; exit 101 ;;
    compile) echo "error[E0308]: mismatched types"; exit 101 ;;
    missing) echo "error[E0463]: can't find crate for \`sqlx\`"; exit 101 ;;
  esac
fi
echo "archive-start $(date +%s%N)" >> "$LEGS_STATE/times"; sleep 1
echo "archive-end $(date +%s%N)" >> "$LEGS_STATE/times"
echo "archive-makeflags ${CARGO_MAKEFLAGS:-none}" >> "$LEGS_STATE/times"
while [ "$#" -gt 0 ]; do [ "$1" = --archive-file ] && { shift; printf 'archive' > "$1"; }; shift; done
CARGO
chmod +x "$work/legs-bin/cargo"
legs_build() {
  rm -rf "$work/legs-out" "$work/legs-state"; mkdir -p "$work/legs-out" "$work/legs-state"
  mkdir -p "$work/legs-root/pr/targets/archive/debug/deps"
  printf 'half' > "$work/legs-root/pr/targets/archive/debug/deps/libbroken.rlib"
  PATH="$work/legs-bin:$PATH" BUILD_ONCE_ROOT="$work/legs-root" BUILD_ONCE_SRC="$legs_src" \
    BUILD_ONCE_COLD=true LEGS_STATE="$work/legs-state" LEGS_CARGO_MODE="$1" RUNNER_TEMP="$work/legs-state" \
    VERIFICATION_SELECTION="${LEGS_SELECTION:-}" BUILD_ONCE_JOBSERVER_TOKENS=6 \
    "$SCRIPT" build "$work/legs-out" > "$work/legs.log" 2>&1
}
LEGS_SELECTION='|rust|' legs_build ok || fail "a cold build failed: $(cat "$work/legs.log")"
# Every leg runs at once, the archive and the feature graphs here, and both
# take their compilers from the one jobserver.
at() { sed -n "s/^$1 //p" "$work/legs-state/times"; }
[ "$(at archive-start)" -lt "$(at features-end)" ] && [ "$(at features-start)" -lt "$(at archive-end)" ] ||
  fail 'the legs ran one after another'
for leg in archive features; do
  [[ "$(at "$leg-makeflags")" == '-j6 '*'--jobserver-auth='*,* ]] || fail "the $leg leg had no jobserver: $(at "$leg-makeflags")"
done
[ "$(at archive-makeflags)" = "$(at features-makeflags)" ] || fail 'the legs had different jobservers'
grep -q 'build-once: legs archive features at once, 6 compilers in all' "$work/legs.log" || fail 'the build did not report its legs'
for leg in archive features; do
  grep -q "^\[build-once\] leg $leg: finish (status=0 elapsed_seconds=[0-9]*)$" "$work/legs.log" ||
    fail "the $leg leg's finish did not reach the job log"
done
legs_build corrupt || fail "a corrupt archive was not rebuilt: $(cat "$work/legs.log")"
[ -f "$work/legs-out/archive.tar.zst" ] || fail 'the rebuilt leg wrote no archive'
[ "$(wc -l < "$work/legs-state/calls")" -eq 2 ] || fail 'the corrupt leg did not build exactly twice'
grep -q 'it is wiped and the leg runs once more' "$work/legs.log" || fail 'the rebuild gave no reason'
for signature in 'could not load dep-graph' 'required to be available in rlib format' 'No space left on device' 'E046\[0-4\]' 'can.t find crate for'; do
  grep -q "^readonly CORRUPT_OUTPUT=.*$signature" "$SCRIPT" || fail "the corrupt-output rebuild misses: $signature"
done
legs_build missing || fail "a missing crate was not rebuilt: $(cat "$work/legs.log")"
[ "$(wc -l < "$work/legs-state/calls")" -eq 2 ] || fail 'the missing-crate leg did not build exactly twice'
grep -q "read a corrupt output in $work/legs-root/pr/targets/archive; it is wiped" "$work/legs.log" ||
  fail 'a missing crate did not wipe the leg'"'"'s own folder'
if legs_build compile; then fail 'a compile error passed'; fi
[ "$(wc -l < "$work/legs-state/calls")" -eq 1 ] || fail 'a compile error was rebuilt'
[ -e "$work/legs-root/pr/targets/archive/debug/deps/libbroken.rlib" ] || fail 'a compile error wiped the target folder'

# publish uploads every leg output and names its job output after the leg.
mkdir -p "$work/out" "$work/store/v1/archives"
printf 'one' > "$work/out/archive.tar.zst"
printf 'two' > "$work/out/database.tar.zst"
GITHUB_OUTPUT="$work/outputs" ARCHIVE_STORE_URL="file://$work/store" "$SCRIPT" publish "$work/out" >/dev/null
for leg in archive:one database:two; do
  digest="$(printf '%s' "${leg#*:}" | sha256sum | cut -d' ' -f1)"
  grep -qx "${leg%%:*}_sha256=$digest" "$work/outputs" || fail "no ${leg%%:*}_sha256 output"
  [ "$(cat "$work/store/v1/archives/$digest")" = "${leg#*:}" ] || fail "${leg%%:*} was not uploaded"
done
printf 'x' > "$work/out/Bad-Name.tar.zst"
if ARCHIVE_STORE_URL="file://$work/store" "$SCRIPT" publish "$work/out" >/dev/null 2>&1; then
  fail 'publish accepted an invalid leg output name'
fi

echo 'test-build-once: shallow checkouts sync into the persistent clone; the leg table, the per-kind build folder, the archive fetch and its build fallback, interrupted folders and lockfile changes kept warm, the disk bound, the corrupt-output rebuild and publish hold; bad input refused'
