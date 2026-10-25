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
unset VERIFICATION_SELECTION ARCHIVE_STORE_URL GITHUB_EVENT_NAME GITHUB_REF

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
# The leg table: both lanes' legs, in build order.
[ "$("$SCRIPT" legs | tr '\n' ' ')" = 'archive compile ' ] || fail 'unexpected wanted legs'
[ "$("$SCRIPT" legs tests | tr '\n' ' ')" = 'archive ' ] || fail 'unexpected tests lane'
[ "$("$SCRIPT" legs checks | tr '\n' ' ')" = 'compile ' ] || fail 'unexpected checks lane'
[ "$(VERIFICATION_SELECTION='|policy|database|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive compile database ' ] ||
  fail 'a selected database family did not want the database leg'
grep -Eq '^  "[a-z0-9_]+ (tests|checks) (always|selected:[a-z0-9_,-]+|env:[A-Z0-9_]+)"$' "$SCRIPT" ||
  fail 'the leg table is missing'
# A selected leg runs when any of its tokens is selected.
all='|database|service_idp|service_coordinator|service_billing|service_connectcore|service_orchestration|service_nats|'
[ "$(VERIFICATION_SELECTION="$all" "$SCRIPT" legs tests | tr '\n' ' ')" = \
  'archive database services_control services_runtime ' ] || fail 'unexpected tests lane with every family'
[ "$(VERIFICATION_SELECTION='|service_nats|' "$SCRIPT" legs tests | tr '\n' ' ')" = 'archive services_runtime ' ] ||
  fail 'service_nats alone must select the runtime plane leg only'
[ "$(VERIFICATION_SELECTION='|service_billing|service_temporal|' "$SCRIPT" legs tests | tr '\n' ' ')" = 'archive services_control ' ] ||
  fail 'service_billing alone must select the control plane leg only'
[ "$(VERIFICATION_SELECTION='|service_temporal|service_nats_extra|' "$SCRIPT" legs tests | tr '\n' ' ')" = 'archive ' ] ||
  fail 'a selected leg matched a token it does not name'
while read -r name; do
  grep -Eq "^leg_$name\(\) \{" "$SCRIPT" || fail "the $name leg has no function"
done < <(VERIFICATION_SELECTION="$all" "$SCRIPT" legs)

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

# A build that never reached finish (a cancel, or its guest died) leaves the
# unfinished marker, and the next prepare wipes the target folders, which may
# hold truncated outputs; a finished build keeps them; a lockfile change wipes
# them too.
git init -q "$work/lock-origin"
mkdir -p "$work/lock-origin/deployments/docker"
printf 'lock one\n' > "$work/lock-origin/Cargo.lock"
printf '[toolchain]\n' > "$work/lock-origin/rust-toolchain.toml"
printf 'derp\n' > "$work/lock-origin/deployments/docker/derp.Cargo.lock"
git -C "$work/lock-origin" add -A
git -C "$work/lock-origin" -c user.name=t -c user.email=t@example.invalid commit -q -m one
git clone -q --depth 1 "file://$work/lock-origin" "$work/lock-checkout"
targets_prepare() {
  BUILD_ONCE_ROOT="$work/marker-root" BUILD_ONCE_TEST_STOP_AFTER_TARGETS=1 \
    GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
    "$SCRIPT" prepare "$work/lock-checkout" > "$work/prepare.log" 2>&1 || fail "prepare failed: $(cat "$work/prepare.log")"
}
marker_root="$work/marker-root/pr"
targets_prepare
[ -e "$marker_root/unfinished" ] || fail 'prepare did not mark the build folder unfinished'
mkdir -p "$marker_root/targets/archive"
printf 'truncated' > "$marker_root/targets/archive/lib.rlib"
targets_prepare
[ ! -e "$marker_root/targets/archive/lib.rlib" ] || fail 'an unfinished build folder kept its targets'
grep -q 'previous build did not finish' "$work/prepare.log" || fail 'the unfinished wipe gave no reason'
mkdir -p "$marker_root/targets/archive"
printf 'complete' > "$marker_root/targets/archive/lib.rlib"
BUILD_ONCE_ROOT="$work/marker-root" "$SCRIPT" finish || fail 'finish failed'
[ ! -e "$marker_root/unfinished" ] || fail 'finish left the unfinished marker'
targets_prepare
[ -f "$marker_root/targets/archive/lib.rlib" ] || fail 'a finished build folder lost its targets'
BUILD_ONCE_ROOT="$work/marker-root" "$SCRIPT" finish
printf 'lock two\n' > "$work/lock-origin/Cargo.lock"
git -C "$work/lock-origin" -c user.name=t -c user.email=t@example.invalid commit -q -am two
rm -rf "$work/lock-checkout"
git clone -q --depth 1 "file://$work/lock-origin" "$work/lock-checkout"
targets_prepare
[ ! -e "$marker_root/targets/archive/lib.rlib" ] || fail 'a lockfile change kept the targets'
grep -q 'layout changed; the target folders are wiped' "$work/prepare.log" || fail 'the lockfile wipe gave no reason'
grep -q "echo 'build-once layout 2'" "$SCRIPT" || fail 'the folder layout version is missing from the stamp'
if "$SCRIPT" finish extra >/dev/null 2>&1; then fail 'finish accepted an argument'; fi

# A leg that reads a corrupt output from its warm target folder wipes the
# folder its error names and builds once more in the same job; any other
# failure fails at once, with no rebuild.
legs_src="$work/legs-src"
git init -q "$legs_src"
mkdir -p "$legs_src/scripts/ci/verify" "$work/legs-bin" "$work/legs-out"
printf '#!/bin/sh\nexit 0\n' > "$legs_src/scripts/ci/verify/compile-all-targets.sh"
chmod +x "$legs_src/scripts/ci/verify/compile-all-targets.sh"
cat > "$work/legs-bin/cargo" <<'CARGO'
#!/usr/bin/env bash
# The archive leg's cargo: fails as LEGS_CARGO_MODE says while its marker
# file exists, then writes the archive.
calls="$LEGS_STATE/calls"; echo x >> "$calls"
if [ -e "$CARGO_TARGET_DIR/debug/deps/libbroken.rlib" ]; then
  case "$LEGS_CARGO_MODE" in
    corrupt) echo "rust-lld: error: $CARGO_TARGET_DIR/debug/deps/libbroken.rlib: Archive::children failed: truncated or malformed archive"; exit 101 ;;
    compile) echo "error[E0308]: mismatched types"; exit 101 ;;
  esac
fi
while [ "$#" -gt 0 ]; do [ "$1" = --archive-file ] && { shift; printf 'archive' > "$1"; }; shift; done
CARGO
chmod +x "$work/legs-bin/cargo"
legs_build() {
  rm -rf "$work/legs-out" "$work/legs-state"; mkdir -p "$work/legs-out" "$work/legs-state"
  mkdir -p "$work/legs-root/pr/targets/archive/debug/deps"
  printf 'half' > "$work/legs-root/pr/targets/archive/debug/deps/libbroken.rlib"
  PATH="$work/legs-bin:$PATH" BUILD_ONCE_ROOT="$work/legs-root" BUILD_ONCE_SRC="$legs_src" \
    BUILD_ONCE_COLD=true LEGS_STATE="$work/legs-state" LEGS_CARGO_MODE="$1" RUNNER_TEMP="$work/legs-state" \
    "$SCRIPT" build "$work/legs-out" > "$work/legs.log" 2>&1
}
legs_build corrupt || fail "a corrupt archive was not rebuilt: $(cat "$work/legs.log")"
[ -f "$work/legs-out/archive.tar.zst" ] || fail 'the rebuilt leg wrote no archive'
[ "$(wc -l < "$work/legs-state/calls")" -eq 2 ] || fail 'the corrupt leg did not build exactly twice'
grep -q 'it is wiped and the leg runs once more' "$work/legs.log" || fail 'the rebuild gave no reason'
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

echo 'test-build-once: shallow checkouts sync into the persistent clone; the leg table, the per-kind build folder, the archive fetch and its build fallback, the unfinished-build wipe, the corrupt-output rebuild and publish hold; bad input refused'
