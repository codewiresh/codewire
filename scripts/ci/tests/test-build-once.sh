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
# event (main or pr build folder), and the Rust checks their CPU share
# (CARGO_BUILD_JOBS, set in every CI job), and the use marks their run
# (GITHUB_RUN_ID), and the compiler cache its runner's switch
# (CODEWIRE_BUILD_ONCE_SCCACHE); a CI job running this test may have its own
# in the environment, so each case states its own.
unset VERIFICATION_SELECTION ARCHIVE_STORE_URL GITHUB_EVENT_NAME GITHUB_REF BUILD_ONCE_LOCAL_VMM CARGO_BUILD_JOBS GITHUB_RUN_ID
unset CODEWIRE_BUILD_ONCE_SCCACHE

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
  local checkout="$1" src="$work/root/build/src"
  local git_src=(git -c core.hooksPath=/dev/null -C "$src")
  [ -d "$src/.git" ] || git init -q "$src"
  eval "$(sed -nE 's/^ +"\$\{git_src\[@\]\}" (fetch .*)$/"${git_src[@]}" \1/p' "$SCRIPT")"
  "${git_src[@]}" checkout -q --force --detach FETCH_HEAD
  "${git_src[@]}" rev-parse HEAD
}
mkdir -p "$work/root/build"
[ "$(sync_clone "$work/checkout1")" = "$first" ] || fail 'the first fetch into an empty clone did not land on the commit'
[ "$(sync_clone "$work/checkout2")" = "$second" ] || fail 'a later fetch did not land on the newer commit'
grep -Fq -- '--update-shallow "$checkout" HEAD' "$SCRIPT" || fail 'the fetch must update the shallow boundary'

# A pull request builds its head merged onto its base tip (#5146): the clone
# fetches both from the job's full checkout (no credential), merges with
# merge-identity.sh's identity, and must give the tree selection checked; the
# same inputs give the same commit.
mrepo="$work/merge-origin"
git init -q -b main "$mrepo"
git -C "$mrepo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m base
base_c="$(git -C "$mrepo" rev-parse HEAD)"
git -C "$mrepo" checkout -q -b feature
echo pr > "$mrepo/pr.txt"; git -C "$mrepo" add pr.txt
git -C "$mrepo" -c user.name=t -c user.email=t@t commit -q -m pr
pr_head="$(git -C "$mrepo" rev-parse HEAD)"
git -C "$mrepo" checkout -q main
echo main > "$mrepo/main.txt"; git -C "$mrepo" add main.txt
git -C "$mrepo" -c user.name=t -c user.email=t@t commit -q -m main
main_tip="$(git -C "$mrepo" rev-parse HEAD)"
merged_tree="$(git -C "$mrepo" merge-tree --write-tree "$main_tip" "$pr_head" | head -n 1)"
mcheckout="$work/merge-checkout"
git clone -q "file://$mrepo" "$mcheckout"
git -C "$mcheckout" checkout -q --detach "$pr_head"
eval "$(awk '/^merge_onto_base\(\) \{/,/^\}/' "$SCRIPT")"
# As the script's die: merge_onto_base runs in a subshell here, so this ends it.
die() { echo "die: $*" >&2; exit 1; }
merge_clone() {
  local src="$1" checkout="${3:-$mcheckout}"
  local git_src=(git -c core.hooksPath=/dev/null -c advice.detachedHead=false -C "$src")
  git init -q "$src"
  if ( BUILD_ONCE_MERGE_ONTO="$main_tip" BUILD_ONCE_MERGED_TREE="$2" BUILD_ONCE_BASE_REF=main \
      ROOT="$ROOT" merge_onto_base "$pr_head" "$checkout" ) >/dev/null; then
    git -C "$src" rev-parse HEAD
  else
    return 1
  fi
}
one="$(merge_clone "$work/merge-a" "$merged_tree")" || fail 'a clean merge onto the base tip failed'
two="$(merge_clone "$work/merge-b" "$merged_tree")" || fail 'the second clean merge failed'
[ "$one" = "$two" ] || fail 'the same head and tip gave two different merge commits'
[ "$(git -C "$work/merge-a" rev-parse "$one^{tree}")" = "$merged_tree" ] || fail 'the merge built another tree'
[ "$(git -C "$work/merge-a" rev-parse "$one^1")" = "$main_tip" ] || fail 'the merge is not onto the base tip'
! merge_clone "$work/merge-c" "$base_c$base_c" >/dev/null 2>&1 || fail 'a malformed tree was accepted'
! merge_clone "$work/merge-d" "$(git -C "$mrepo" rev-parse "$base_c^{tree}")" >/dev/null 2>&1 ||
  fail 'a merge giving another tree than selection checked was accepted'
git clone -q --depth 1 "file://$mrepo" "$work/merge-shallow"
! merge_clone "$work/merge-e" "$merged_tree" "$work/merge-shallow" >/dev/null 2>&1 ||
  fail 'a shallow checkout was accepted for a merge build'
# Selection's half: a clean head gives the tree; a conflicting one stops.
sel="$work/merge-sel"
git clone -q "file://$mrepo" "$sel"
git -C "$sel" checkout -q --detach "$pr_head"
: > "$work/merge-out"
( cd "$sel" && GITHUB_OUTPUT="$work/merge-out" "$ROOT/scripts/ci/select/merge-onto-base.sh" main ) >/dev/null ||
  fail 'selection refused a clean merge'
grep -qx "merged_tree=$merged_tree" "$work/merge-out" || fail 'selection gave another tree'
grep -qx "merge_onto=$main_tip" "$work/merge-out" || fail 'selection named another tip'
echo conflict > "$sel/main.txt"; git -C "$sel" add main.txt
git -C "$sel" -c user.name=t -c user.email=t@t commit -q -m clash
if ( cd "$sel" && GITHUB_OUTPUT="$work/merge-out" "$ROOT/scripts/ci/select/merge-onto-base.sh" main ) >/dev/null 2>&1; then
  fail 'selection accepted a head that conflicts with its base'
fi

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
for retired in compile feature_checks local_vmm_checks services_control; do
  if grep -Eq "^leg_$retired\(\) \{" "$SCRIPT"; then fail "the $retired check is still a build-runner leg"; fi
done
if "$SCRIPT" legs tests >/dev/null 2>&1; then fail 'legs accepted a lane'; fi
# A selected leg runs when any of its tokens is selected.
all='|database|service_idp|service_coordinator|service_billing|service_connectcore|service_orchestration|service_nats|'
[ "$(VERIFICATION_SELECTION="$all" "$SCRIPT" legs | tr '\n' ' ')" = \
  'archive database services_runtime ' ] || fail 'unexpected legs with every family'
[ "$(VERIFICATION_SELECTION='|service_orchestration|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive services_runtime ' ] ||
  fail 'service_orchestration alone must select the runtime plane leg only'
[ "$(VERIFICATION_SELECTION='|service_nats|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive ' ] ||
  fail 'service_nats alone runs from the workspace archive without its own leg'
[ "$(VERIFICATION_SELECTION='|service_billing|service_temporal|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive ' ] ||
  fail 'control-plane services run from the workspace archive without their own leg'
[ "$(VERIFICATION_SELECTION='|service_temporal|service_nats_extra|' "$SCRIPT" legs | tr '\n' ' ')" = 'archive ' ] ||
  fail 'a selected leg matched a token it does not name'
while read -r name; do
  grep -Eq "^leg_$name\(\) \{" "$SCRIPT" || fail "the $name leg has no function"
  # Each leg builds in its own target folder.
  grep -A12 -E "^leg_$name\(\) \{" "$SCRIPT" | grep -q "targets/$name\b" ||
    fail "the $name leg does not build in targets/$name"
done < <(VERIFICATION_SELECTION="${all}rust|transport|" BUILD_ONCE_LOCAL_VMM=true "$SCRIPT" legs)

# PR archive scoping: narrow pull requests build only the selected crates plus
# every default-feature consumer crate read from archive.tar.zst; push runs,
# rust_workspace, contracts_proto, desktop-only and incomplete selections fail
# closed to --workspace (infra#1534).
archive_scope_case() {
  local name="$1" event="$2" selection="$3" expected="$4" actual
  actual="$(cd "$ROOT" && GITHUB_EVENT_NAME="$event" VERIFICATION_SELECTION="$selection" \
    "$SCRIPT" archive-scope | tr '\n' ' ')"
  actual="${actual% }"
  [ "$actual" = "$expected" ] || fail "archive-scope $name: got '$actual', expected '$expected'"
}
archive_scope_case pr-narrow pull_request \
  '|valid:v3|rust|rust_pkg_codewire_cli|rust_pkg_codewire_cli_bin|rust_pkg_codewire_desktop|complete|' \
  '-p codewire-cli -p codewire-cli-bin'
archive_scope_case pr-database pull_request \
  '|valid:v3|rust|rust_pkg_codewire_billing|database|complete|' \
  '-p codewire-billing -p codewire-credential-service -p codewire-mesh -p codewire-orchestration -p codewire-platform-credentials -p codewire-server-core'
archive_scope_case pr-services pull_request \
  '|valid:v3|rust|rust_pkg_codewire_idp|service_idp|service_nats|service_orchestration|complete|' \
  '-p codewire-cli-bin -p codewire-coordinator -p codewire-idp -p codewire-mesh -p codewire-server-core'
archive_scope_case pr-workspace pull_request \
  '|valid:v3|rust|rust_workspace|rust_pkg_codewire_cli|complete|' \
  '--workspace'
archive_scope_case pr-contracts-proto pull_request \
  '|valid:v3|contracts|contracts_proto|rust|rust_pkg_codewire_proto|complete|' \
  '--workspace'
archive_scope_case push-narrow push \
  '|valid:v3|rust|rust_pkg_codewire_cli|complete|' \
  '--workspace'
archive_scope_case pr-desktop-only pull_request \
  '|valid:v3|rust|rust_pkg_codewire_desktop|complete|' \
  '--workspace'
archive_scope_case pr-incomplete pull_request \
  '|rust|rust_pkg_codewire_cli|' \
  '--workspace'

# Every run builds in one folder (#5146), so main's and a pull request's
# compiler cache keys, which carry absolute paths, match; the kind follows the
# event, main only for a push to main.
tree() {
  # shellcheck source=scripts/ci/setup/build-once-tree.sh
  ( source "$ROOT/scripts/ci/setup/build-once-tree.sh"; GITHUB_EVENT_NAME="$1" GITHUB_REF="$2"
    printf '%s %s\n' "$(build_once_tree /d)" "$(build_once_kind)" )
}
[ "$(tree push refs/heads/main)" = '/d/build main' ] || fail 'a push to main must build in build as main'
[ "$(tree pull_request refs/pull/1/head)" = '/d/build pr' ] || fail 'a pull request must build in build as pr'
[ "$(tree push refs/heads/other)" = '/d/build pr' ] || fail 'a push to another branch must build as pr'
[ "$(tree workflow_dispatch refs/heads/main)" = '/d/build pr' ] || fail 'a dispatched run must build as pr'

# prepare refuses a disk that holds the other kind's folder, and a workflow
# that names another folder, before it touches anything.
mkdir -p "$work/disk/main/src" "$work/env"
if GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/head BUILD_ONCE_ROOT="$work/disk" \
    GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
    "$SCRIPT" prepare "$work/checkout1" build > "$work/refused.log" 2>&1; then
  fail 'a pull request prepared on a disk holding main'
fi
grep -q 'holds .*/main; a pr run does not build here' "$work/refused.log" || fail 'no reason for the refusal'
[ -d "$work/disk/main/src" ] || fail 'the refused prepare touched the main folder'
# A disk that records the other kind is refused the same way.
mkdir -p "$work/kind-disk/build/src"
printf 'main\n' > "$work/kind-disk/.build-once-kind"
if GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/head BUILD_ONCE_ROOT="$work/kind-disk" \
    GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
    "$SCRIPT" prepare "$work/checkout1" build > "$work/refused.log" 2>&1; then
  fail "a pull request prepared on main's disk"
fi
grep -q "this build disk is the main runner's .*; a pr run does not build here" "$work/refused.log" ||
  fail "no reason for the kind refusal: $(cat "$work/refused.log")"
[ -d "$work/kind-disk/build/src" ] && grep -qx main "$work/kind-disk/.build-once-kind" ||
  fail "the refused prepare touched main's disk"
if GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main BUILD_ONCE_ROOT="$work/disk" BUILD_ONCE_TREE=/ci-cache/pr \
    GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
    "$SCRIPT" prepare "$work/checkout1" build > "$work/refused.log" 2>&1; then
  fail 'prepare accepted a workflow folder that differs from the run kind'
fi
grep -q 'BUILD_ONCE_TREE=/ci-cache/pr, but this run builds in' "$work/refused.log" || fail 'no reason for the folder refusal'
# prepare names the job it prepares for, whose folders the disk bound keeps.
for args in "prepare $work/checkout1" "prepare $work/checkout1 tests"; do
  # shellcheck disable=SC2086 # Word splitting builds each case's arguments.
  if BUILD_ONCE_ROOT="$work/other-disk" GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" \
      RUNNER_TEMP="$work/env" "$SCRIPT" $args > /dev/null 2>&1; then
    fail "prepare accepted: $args"
  fi
done
[ ! -e "$work/other-disk" ] || fail 'a refused prepare touched the build disk'

# A test job's fetch: verified bytes are ready; with --or-build, a missing
# digest, store or archive is a miss the job builds through (ready=false, a
# warning, success) on a guest big enough to build; without it a missing
# archive fails; a corrupt archive always fails. The guest's memory comes from
# a fixture, never this host's.
FETCH="$ROOT/scripts/ci/setup/fetch-test-archive.sh"
mkdir -p "$work/fetch-store/v1/archives"
printf 'archive' > "$work/fetch-src"
good="$(sha256sum "$work/fetch-src" | cut -d' ' -f1)"
cp "$work/fetch-src" "$work/fetch-store/v1/archives/$good"
absent="$(printf 'absent' | sha256sum | cut -d' ' -f1)"
printf 'MemTotal:       70254592 kB\n' > "$work/meminfo-warm"
printf 'MemTotal:        8170496 kB\n' > "$work/meminfo-medium"
fetch() {
  : > "$work/fetch-out"
  GITHUB_OUTPUT="$work/fetch-out" ARCHIVE_STORE_URL="${STORE-file://$work/fetch-store}" \
    CODEWIRE_CI_MEMINFO="${MEMINFO-$work/meminfo-warm}" GITHUB_SHA=0123abcd \
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
# A medium guest (7.8 GiB) never builds in place (infra#2471): an evicted
# archive, as in a single job rerun after its first fetch, or no store, fails
# at once naming the head and the build job, leaves nothing and reports no
# readiness. A stored archive still fetches there, and a guest whose memory
# cannot be read fails the same way.
for case in "medium $absent" "unreadable $absent" "medium-no-store $good"; do
  read -r kind digest <<< "$case"
  meminfo="$work/meminfo-medium" store="file://$work/fetch-store"
  [ "$kind" = unreadable ] && meminfo="$work/no-meminfo"
  [ "$kind" = medium-no-store ] && store=''
  if MEMINFO="$meminfo" STORE="$store" fetch --or-build "$digest" "$work/fetched/g.tar"; then
    fail "a $kind guest built in place"
  fi
  grep -q 'test archive missing for 0123abcd: .*too small to build its tests in place, so rerun Build test archives' \
    "$work/fetch.log" || fail "a $kind guest gave no fail-fast reason"
  grep -q 'ready=' "$work/fetch-out" && fail "a $kind guest reported readiness"
  [ ! -e "$work/fetched/g.tar" ] && [ ! -e "$work/fetched/g.tar.partial" ] || fail "a $kind guest left a file behind"
done
MEMINFO="$work/meminfo-medium" fetch --or-build "$good" "$work/fetched/h.tar" || fail 'a medium guest did not fetch a stored archive'
grep -qx 'ready=true' "$work/fetch-out" || fail 'a medium guest fetch is not ready'
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
# A fake df: a 100 GB build disk, 10 % used, plus FAKE_DF_PER_LEG % for each
# leg folder when it is set.
cat > "$work/fake-df" <<'DF'
#!/usr/bin/env bash
size=97656250
used=10
if [ -n "${FAKE_DF_PER_LEG:-}" ]; then
  legs="$(find "$FAKE_DF_TARGETS" -mindepth 1 -maxdepth 1 -type d ! -name '*_desktop' | wc -l)"
  used=$(( 10 + FAKE_DF_PER_LEG * legs ))
fi
kib=$(( size * used / 100 ))
printf 'Filesystem 1024-blocks Used Available Capacity Mounted\nfake %s %s %s %s%% /x\n' "$size" "$kib" "$(( size - kib ))" "$used"
DF
chmod +x "$work/fake-df"
targets_prepare() {
  BUILD_ONCE_DF="$work/fake-df" FAKE_DF_TARGETS="$work/marker-root/build/targets" \
  BUILD_ONCE_ROOT="$work/marker-root" BUILD_ONCE_TEST_STOP_AFTER_TARGETS=1 \
    GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
    "$SCRIPT" prepare "$work/lock-checkout" "${PREPARE_JOB:-build}" > "$work/prepare.log" 2>&1 ||
    fail "prepare failed: $(cat "$work/prepare.log")"
  # These cases are about the folders; job-running has its own below.
  [ "${KEEP_JOB_RUNNING:-}" = 1 ] || rm -f "$marker_root/job-running"
}
marker_root="$work/marker-root/build"
# The archive leg's epoch, as prepare records it; the cases below keep their
# fixture's archive folder at the current epoch, and the epoch has its own.
archive_epoch() { printf '1\n' > "$marker_root/targets/archive/.build-once-epoch"; }
targets_prepare
mkdir -p "$marker_root/targets/archive"
archive_epoch
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
archive_epoch
printf 'kept' > "$marker_root/targets/archive/lib.rlib"
rm -f "$marker_root/layout"
printf 'old-stamp\n' > "$marker_root/lock-stamp"
targets_prepare
[ -f "$marker_root/targets/archive/lib.rlib" ] || fail 'the move to the layout file wiped the targets'
# Builds are not incremental (their sessions filled the disk, main run 22822),
# and prepare removes the sessions earlier builds left.
grep -q "^    echo 'CARGO_INCREMENTAL=0'$" "$SCRIPT" || fail 'build runner builds are incremental'
# They write no debug information either (infra#1534): nothing in CI reads
# it, and the archive store needs the workspace archive small (infra#2471).
grep -q "^    echo 'CARGO_PROFILE_DEV_DEBUG=0'$" "$SCRIPT" || fail 'build runner builds write debug information'
mkdir -p "$marker_root/targets/archive/debug/incremental/codewire_proto-x/s-1" "$marker_root/targets/archive/debug/deps"
archive_epoch
printf 'x' > "$marker_root/targets/archive/debug/incremental/codewire_proto-x/s-1/dep-graph.bin"
printf 'keep' > "$marker_root/targets/archive/debug/deps/libkeep.rlib"
targets_prepare
[ ! -e "$marker_root/targets/archive/debug/incremental" ] || fail 'prepare kept incremental sessions'
[ -f "$marker_root/targets/archive/debug/deps/libkeep.rlib" ] || fail 'removing incremental sessions removed an artifact'
# The Rust checks' own folders stay beside the legs'; any other folder goes.
readonly CHECK_FOLDERS='clippy clippy_features darwin darwin_cw desktop'
for folder in $CHECK_FOLDERS stray; do mkdir -p "$marker_root/targets/$folder"; done
targets_prepare
for folder in $CHECK_FOLDERS; do
  [ -d "$marker_root/targets/$folder" ] || fail "prepare removed the Rust checks' $folder folder"
done
[ ! -e "$marker_root/targets/stray" ] || fail 'prepare kept an unknown target folder'
grep -q 'removing the unused target folder stray' "$work/prepare.log" || fail 'the stray folder removal gave no reason'
# The folder a kind built in before #5146 becomes the build folder: its clone
# and Cargo home move, its targets, which name the old path, do not, and the
# disk records its kind.
mkdir -p "$work/move-disk/pr/targets/archive" "$work/move-disk/pr/cargo-home/registry"
printf '1\n' > "$work/move-disk/pr/targets/archive/.build-once-epoch"
printf 'warm' > "$work/move-disk/pr/targets/archive/lib.rlib"
printf 'index' > "$work/move-disk/pr/cargo-home/registry/kept"
GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/head BUILD_ONCE_DF="$work/fake-df" \
  FAKE_DF_TARGETS="$work/move-disk/build/targets" BUILD_ONCE_ROOT="$work/move-disk" BUILD_ONCE_TEST_STOP_AFTER_TARGETS=1 \
  GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
  "$SCRIPT" prepare "$work/lock-checkout" build > "$work/move.log" 2>&1 || fail "the move prepare failed: $(cat "$work/move.log")"
[ -f "$work/move-disk/build/cargo-home/registry/kept" ] || fail "the pull request folder's Cargo home did not move to build"
[ ! -e "$work/move-disk/build/targets/archive/lib.rlib" ] || fail 'a moved target, which names the old path, was kept'
[ ! -e "$work/move-disk/pr" ] || fail 'the old pull request folder stayed'
grep -qx pr "$work/move-disk/.build-once-kind" || fail 'the disk did not record its kind'
grep -q "the build folder moved from $work/move-disk/pr to $work/move-disk/build; its targets, which name the old path, are dropped" \
  "$work/move.log" || fail 'the move gave no reason'
# The compiler cache canary (#5146): its folder stays only while the runner
# turns it on, and an unknown setting is refused before anything is touched.
mkdir -p "$marker_root/sccache"
printf 'entry' > "$marker_root/sccache/entry"
CODEWIRE_BUILD_ONCE_SCCACHE=local targets_prepare
[ -f "$marker_root/sccache/entry" ] || fail 'prepare removed the compiler cache while it was on'
targets_prepare
[ ! -e "$marker_root/sccache" ] || fail 'prepare kept the compiler cache while it was off'
mkdir -p "$marker_root/sccache"
if CODEWIRE_BUILD_ONCE_SCCACHE=remote BUILD_ONCE_ROOT="$work/marker-root" BUILD_ONCE_TEST_STOP_AFTER_TARGETS=1 \
    GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
    "$SCRIPT" prepare "$work/lock-checkout" build > "$work/prepare.log" 2>&1; then
  fail 'prepare accepted an unknown compiler cache setting'
fi
grep -q 'CODEWIRE_BUILD_ONCE_SCCACHE is off or local, not remote' "$work/prepare.log" ||
  fail "the unknown cache setting's refusal does not name it: $(cat "$work/prepare.log")"
[ -d "$marker_root/sccache" ] || fail 'a refused cache setting touched the build folder'
rm -rf "$marker_root/sccache"
# With it on, the legs and Rust checks compile through the cache, and a rebuild
# after a corrupt output does not (it may hold the corrupt output).
grep -q '^    export RUSTC_WRAPPER="$sccache_bin"$' "$SCRIPT" || fail 'the legs do not use the compiler cache when it is on'
grep -q '^  BUILD_ONCE_NO_CACHE=1 "$ROOT/scripts/ci/setup/build-once.sh" leg ' "$SCRIPT" ||
  fail 'a rebuild after a corrupt output reads the compiler cache'
sed -n '/^run_checks_beside_legs() {/,/^}/p' "$SCRIPT" | grep -q 'start_sccache_server checks' ||
  fail 'the Rust checks do not start their compiler cache server'
sed -n '/^checks() {/,/^}/p' "$SCRIPT" | grep -q '^    unset RUSTC_WRAPPER$' ||
  fail 'a corrupt-output rebuild of the Rust checks does not disable the compiler cache'

# A leg's epoch: an archive folder from before it (no epoch file, or an older
# number) is wiped once, with the reason, and started again at the epoch;
# the next prepare keeps it, and another leg's folder is never touched.
rm -rf "$marker_root/targets"
mkdir -p "$marker_root/targets/archive/debug" "$marker_root/targets/database"
printf 'old' > "$marker_root/targets/archive/debug/libold.rlib"
printf 'kept' > "$marker_root/targets/database/lib.rlib"
targets_prepare
[ ! -e "$marker_root/targets/archive/debug/libold.rlib" ] || fail 'an archive folder from before its epoch kept its targets'
grep -q "the archive leg's epoch is now 1; its target folder is wiped" "$work/prepare.log" ||
  fail 'the epoch wipe gave no reason'
grep -qx 1 "$marker_root/targets/archive/.build-once-epoch" || fail 'prepare did not record the archive epoch'
[ -f "$marker_root/targets/database/lib.rlib" ] || fail "the archive epoch wiped another leg's folder"
mkdir -p "$marker_root/targets/archive/debug"
printf 'new' > "$marker_root/targets/archive/debug/libnew.rlib"
targets_prepare
[ -f "$marker_root/targets/archive/debug/libnew.rlib" ] || fail 'a folder at its epoch was wiped again'
if grep -q 'epoch is now' "$work/prepare.log"; then fail 'a folder at its epoch was reported wiped'; fi
printf '0\n' > "$marker_root/targets/archive/.build-once-epoch"
targets_prepare
[ ! -e "$marker_root/targets/archive/debug/libnew.rlib" ] || fail 'a folder at an older epoch kept its targets'

# The disk bound: target files no build read for 3 days go; above 65 % of the
# disk, whole idle leg folders go, least recently used first (a folder with no
# use mark first), and a leg's desktop folder with it. A mark that names no
# run (from before marks named their run) is idle.
rm -rf "$marker_root/targets"
mkdir -p "$marker_root/targets/archive/debug/deps" "$marker_root/targets/database" \
  "$marker_root/targets/features" "$marker_root/targets/database_desktop"
archive_epoch
printf 'stale' > "$marker_root/targets/archive/debug/deps/libold.rlib"
printf 'fresh' > "$marker_root/targets/archive/debug/deps/libnew.rlib"
touch -a -d '5 days ago' "$marker_root/targets/archive/debug/deps/libold.rlib"
touch -d '2 hours ago' "$marker_root/targets/database/.build-once-used"
touch "$marker_root/targets/archive/.build-once-used"
FAKE_DF_PER_LEG=20 targets_prepare
[ ! -e "$marker_root/targets/archive/debug/deps/libold.rlib" ] || fail 'a target file unread for 5 days was kept'
[ -f "$marker_root/targets/archive/debug/deps/libnew.rlib" ] || fail 'a fresh target file was swept'
grep -q 'removed 1 target files no build read for 3 days' "$work/prepare.log" || fail 'the sweep gave no count'
[ ! -e "$marker_root/targets/features" ] || fail 'the never-used leg folder was kept over the disk bound'
[ -d "$marker_root/targets/database" ] && [ -d "$marker_root/targets/archive" ] ||
  fail 'the bound removed more than it needed'
grep -q 'disk 70% used (limit 65%); removing the least recently used idle target folder features' "$work/prepare.log" ||
  fail 'the bound gave no reason'
FAKE_DF_PER_LEG=20 BUILD_ONCE_DISK_PERCENT=35 targets_prepare
[ ! -e "$marker_root/targets/database" ] && [ ! -e "$marker_root/targets/database_desktop" ] ||
  fail 'the older leg and its desktop folder were kept'
[ -d "$marker_root/targets/archive" ] || fail 'the most recently used leg was removed'
grep -q '^  mark_used "$work/targets/$name"$' "$SCRIPT" || fail 'a leg does not mark its folder used'

# A build script's directory is one unit (main run 32717): a live unit keeps
# out/ files no build read, an empty out/ stays, a unit no build read goes with
# its fingerprint, and one already left without out/ goes so Cargo reruns it.
# So does one whose out/ Cargo recreated empty after an older per-file sweep
# took its files and invoked.timestamp (#3869).
profile="$marker_root/targets/darwin/aarch64-apple-darwin/debug"
for unit in live-1 empty-2 stale-3 broken-4 nested-5 recreated-6; do
  mkdir -p "$profile/build/$unit" "$profile/.fingerprint/$unit"
  printf 'cargo:rerun-if-changed=build.rs\n' > "$profile/build/$unit/output"
  printf '{}' > "$profile/.fingerprint/$unit/run-build-script-build-script-build.json"
  [ "$unit" = recreated-6 ] || touch -d '5 days ago' "$profile/build/$unit/invoked.timestamp"
done
mkdir -p "$profile/build/live-1/out" "$profile/build/empty-2/out" "$profile/build/stale-3/out" \
  "$profile/build/recreated-6/out"
printf 'generated' > "$profile/build/live-1/out/private.rs"
printf 'generated' > "$profile/build/stale-3/out/private.rs"
# A CMake-style script's own build/ under out/ is part of its unit: one read
# file there keeps the unit, however old its record is.
mkdir -p "$profile/build/nested-5/out/build"
printf 'object' > "$profile/build/nested-5/out/build/fresh.o"
touch -a -d '5 days ago' "$profile/build/live-1/out/private.rs" "$profile/build/stale-3/out/private.rs" \
  "$profile/build/stale-3/output" "$profile/build/nested-5/output"
FAKE_DF_PER_LEG=1 targets_prepare
[ -f "$profile/build/live-1/out/private.rs" ] || fail "a live build script unit lost an out/ file no build read"
[ -d "$profile/build/empty-2/out" ] || fail 'an empty out/ of a live build script unit was removed'
[ -d "$profile/.fingerprint/live-1" ] && [ -d "$profile/.fingerprint/empty-2" ] ||
  fail 'a live build script unit lost its fingerprint'
[ ! -e "$profile/build/stale-3" ] && [ ! -e "$profile/.fingerprint/stale-3" ] ||
  fail 'a build script unit no build read was kept, or kept its fingerprint'
[ -f "$profile/build/nested-5/out/build/fresh.o" ] && [ -d "$profile/.fingerprint/nested-5" ] ||
  fail 'a unit read only under its out/build/ was swept'
[ ! -e "$profile/build/broken-4" ] && [ ! -e "$profile/.fingerprint/broken-4" ] ||
  fail 'a build script unit left without out/ was kept, so Cargo would not rerun it'
[ ! -e "$profile/build/recreated-6" ] && [ ! -e "$profile/.fingerprint/recreated-6" ] ||
  fail 'a build script unit with an empty out/ and no invoked.timestamp was kept, so Cargo would not rerun it'
grep -q 'removed 3 build-script units no build read for 3 days or left without out/ or invoked.timestamp' \
  "$work/prepare.log" ||
  fail 'the unit sweep gave no count'
rm -rf "$marker_root/targets/darwin"

# Live folders stay. A folder is live when this run or the run before it on
# this disk (the latest mark of another run) used it; idle folders go first,
# least recently used first. A folder this job is about to use never goes.
mark() {
  # mark FOLDER RUN TIME: RUN used FOLDER at TIME.
  mkdir -p "$marker_root/targets/$1"
  printf '%s\n' "$2" > "$marker_root/targets/$1/.build-once-used"
  touch -d "$3" "$marker_root/targets/$1/.build-once-used"
}
kept() {
  local folder
  for folder in "$@"; do
    [ -d "$marker_root/targets/$folder" ] || fail "the bound removed $folder: $(cat "$work/prepare.log")"
  done
}
removals() { grep -c 'removing the least recently used' "$work/prepare.log" || true; }
two_hours_ago="$(date -d '2 hours ago' '+%Y-%m-%d %H:%M:%S')"
just_now="$(date -d '1 minute ago' '+%Y-%m-%d %H:%M:%S')"
# Pull request run 24177: the build's prepare at 86 % removed the idle desktop
# folder, then the archive folder its build was about to use, whose mark tied
# with the previous run's other legs. Run 300's build wants archive and
# features: the idle desktop folder of run 250 goes, and at 70 % only live
# folders are left, which stay.
rm -rf "$marker_root/targets"
mark desktop 250 '1 day ago'
for folder in archive database features; do mark "$folder" 299 "$two_hours_ago"; done
mark clippy 299 '1 hour ago'
GITHUB_RUN_ID=300 VERIFICATION_SELECTION='|rust|' FAKE_DF_PER_LEG=15 targets_prepare
[ ! -e "$marker_root/targets/desktop" ] || fail 'the idle folder was kept over the bound'
grep -q 'disk 85% used (limit 65%); removing the least recently used idle target folder desktop' "$work/prepare.log" ||
  fail "the idle folder's removal gave no reason"
kept archive features database clippy
[ "$(removals)" -eq 1 ] || fail 'the bound removed a live folder under the live limit'
grep -q '^::warning::build-once: disk too small: 108 GB needed to keep .* under the 65% bound; the 100 GB disk is 70% used. They stay over the bound up to 80%.$' \
  "$work/prepare.log" || fail "the bound did not say the disk is too small: $(cat "$work/prepare.log")"
# Main run 24440, the first on its disk: the Rust checks' prepare at 71 %
# removed the archive folder the run's build had just filled, and the next
# archive leg built cold. Run 400's legs are live: they stay.
rm -rf "$marker_root/targets"
for folder in archive features database services_control; do mark "$folder" 400 "$just_now"; done
GITHUB_RUN_ID=400 PREPARE_JOB=checks FAKE_DF_PER_LEG=15 targets_prepare
kept archive features database services_control
[ "$(removals)" -eq 0 ] || fail 'the bound removed a folder the run just used'
grep -q '::warning::build-once: disk too small: 108 GB needed' "$work/prepare.log" || fail 'a too-small disk gave no warning'
# Only live folders, over 80 %: the least recently used live folder this job
# does not use goes, until the disk is under 80 %; the Rust checks' folders
# stay, though older.
rm -rf "$marker_root/targets"
mark clippy 499 '1 hour ago'
mark darwin 499 '1 hour ago'
mark features 500 '10 minutes ago'
mark archive 500 '5 minutes ago'
GITHUB_RUN_ID=500 PREPARE_JOB=checks FAKE_DF_PER_LEG=20 targets_prepare
[ ! -e "$marker_root/targets/features" ] || fail 'the least recently used live folder was kept over 80 %'
grep -q 'disk 90% used, over 80%; removing the least recently used live target folder features, which this job does not use' \
  "$work/prepare.log" || fail "the live folder's removal gave no reason"
kept clippy darwin archive
[ "$(removals)" -eq 1 ] || fail 'the bound removed more live folders than it needed'
grep -q '::warning::build-once: disk too small' "$work/prepare.log" || fail 'a too-small disk gave no warning'
# Only the folders this job uses, over 80 %: they all stay, and the bound
# says so.
rm -rf "$marker_root/targets"
for folder in $CHECK_FOLDERS; do mark "$folder" 600 "$just_now"; done
GITHUB_RUN_ID=601 PREPARE_JOB=checks FAKE_DF_PER_LEG=15 targets_prepare
# shellcheck disable=SC2086 # Each check folder is one argument.
kept $CHECK_FOLDERS
[ "$(removals)" -eq 0 ] || fail 'the bound removed a folder this job is about to use'
grep -q 'only this job.s folders left' "$work/prepare.log" && fail 'the bound removed one of this job folders at 85 %'
grep -q 'disk 85% used with no target folder left that this job does not use' "$work/prepare.log" ||
  fail 'the bound did not say every folder left is in use'
# Past 90 % with only this job's folders (pull request run 44254, 91 % before
# its build, then "No space left on device"): its largest folder goes, and
# only as many as bring the disk back to 90 %.
rm -rf "$marker_root/targets"
for folder in $CHECK_FOLDERS; do mark "$folder" 700 "$just_now"; done
head -c 4096 /dev/zero > "$marker_root/targets/darwin/big.rlib"
GITHUB_RUN_ID=701 PREPARE_JOB=checks FAKE_DF_PER_LEG=17 targets_prepare
[ ! -e "$marker_root/targets/darwin" ] || fail "this job's largest folder was kept past 90 %: $(cat "$work/prepare.log")"
grep -q '^::warning::build-once: disk 95% used, over 90%, with only this job.s folders left; removing its largest, darwin, which builds cold$' \
  "$work/prepare.log" || fail "the full-disk removal gave no reason: $(cat "$work/prepare.log")"
[ "$(grep -c 'only this job.s folders left' "$work/prepare.log")" -eq 1 ] || fail 'the bound removed more of this job folders than it needed'
kept clippy clippy_features darwin_cw desktop
# A main push's build runs the Rust checks beside its legs
# (BUILD_ONCE_CHECKS): its prepare keeps their folders as its own, where a
# build without them removes them first, as any live folder it does not use.
# At 88 %: over the live limit, under the full-disk one.
rm -rf "$marker_root/targets"
for folder in $CHECK_FOLDERS archive; do mark "$folder" 690 '1 hour ago'; done
GITHUB_RUN_ID=700 PREPARE_JOB=build BUILD_ONCE_CHECKS=true FAKE_DF_PER_LEG=13 targets_prepare
# shellcheck disable=SC2086 # Each check folder is one argument.
kept $CHECK_FOLDERS archive
[ "$(removals)" -eq 0 ] || fail 'a build with the Rust checks removed their folders'
GITHUB_RUN_ID=700 PREPARE_JOB=build FAKE_DF_PER_LEG=13 targets_prepare
[ "$(removals)" -gt 0 ] || fail 'a build without the Rust checks kept their folders over 80 %'
kept archive

# job-running: a job that never reached finish has what it wrote deleted, and
# nothing else: the folder stays warm (owner, 2026-10-25: "Always warm. No
# whole-folder wipe"). A job that finished leaves everything.
finish_folder() {
  BUILD_ONCE_ROOT="$work/marker-root" "$SCRIPT" finish > "$work/finish.log" 2>&1 ||
    fail "finish failed: $(cat "$work/finish.log")"
}
interrupted='did not finish (cancelled, or its guest died)'
rm -rf "$marker_root/targets" "$marker_root/cargo-home"
mkdir -p "$marker_root/targets/archive/debug/deps" "$marker_root/cargo-home/registry"
archive_epoch
old_bin="$marker_root/targets/archive/debug/deps/old-test"
old_crate="$marker_root/cargo-home/registry/old.crate"
: > "$old_bin"; : > "$old_crate"
touch -d '1 hour ago' "$old_bin" "$old_crate"
KEEP_JOB_RUNNING=1 targets_prepare
[ -f "$marker_root/job-running" ] || fail 'prepare wrote no job-running mark'
# The guest dies here: a zero-filled test binary Cargo would call fresh.
zero_bin="$marker_root/targets/archive/debug/deps/credentials-6c0e981d19666fc8"
zero_crate="$marker_root/cargo-home/registry/new.crate"
head -c 4096 /dev/zero > "$zero_bin"; : > "$zero_crate"
touch -d '+1 minute' "$zero_bin" "$zero_crate"
KEEP_JOB_RUNNING=1 targets_prepare
grep -qF "$interrupted" "$work/prepare.log" || fail 'a kept mark was not logged'
grep -qF 'deleted the 2 files it wrote' "$work/prepare.log" || fail "the deleted count is wrong: $(cat "$work/prepare.log")"
[ ! -e "$zero_bin" ] || fail "the interrupted job's output survived"
[ ! -e "$zero_crate" ] || fail "the interrupted job's download survived"
[ -f "$old_bin" ] || fail "an older output was deleted; the folder must stay warm"
[ -f "$old_crate" ] || fail 'an older download was deleted; the folder must stay warm'
[ -f "$marker_root/job-running" ] || fail 'the next job wrote no mark of its own'
# A job that finished, whether it passed, failed or was cancelled, keeps its work.
finished_bin="$marker_root/targets/archive/debug/deps/finished-test"
: > "$finished_bin"; touch -d '+1 minute' "$finished_bin"
finish_folder
[ ! -e "$marker_root/job-running" ] || fail 'finish left the mark'
grep -qE 'writes are on disk; sync took [0-9]+ s' "$work/finish.log" || fail 'finish did not report the sync time'
KEEP_JOB_RUNNING=1 targets_prepare
if grep -qF "$interrupted" "$work/prepare.log"; then fail 'a finished job was treated as interrupted'; fi
[ -f "$finished_bin" ] || fail "a finished job's output was deleted"
# Finish removes the mark only after the writes are on disk.
fake_sync="$work/fake-sync"; mkdir -p "$fake_sync"
printf '#!/bin/sh\nexit 1\n' > "$fake_sync/sync"; chmod +x "$fake_sync/sync"
if PATH="$fake_sync:$PATH" BUILD_ONCE_ROOT="$work/marker-root" "$SCRIPT" finish > "$work/finish.log" 2>&1; then
  fail 'finish passed although its sync failed'
fi
[ -f "$marker_root/job-running" ] || fail 'finish removed the mark before its writes were on disk'
finish_folder
# No mark: nothing to do (the job inherited its tree, or its prepare never ran).
finish_folder
if "$SCRIPT" nonsense >/dev/null 2>&1; then fail 'an unknown subcommand was accepted'; fi

# A leg that reads a corrupt output from its warm target folder wipes the
# folder its error names and builds once more in the same job; any other
# failure fails at once, with no rebuild.
legs_src="$work/legs-src"
git init -q "$legs_src"
mkdir -p "$legs_src/scripts/ci/verify" "$work/legs-bin" "$work/legs-out"
cat > "$legs_src/scripts/ci/verify/run-product-verification.sh" <<'FEATURES'
#!/bin/sh
# The feature-graph leg's stage: records its time and the jobserver it sees.
# It ends only once the archive leg beside it has started (60 s hang guard),
# so a slow spawn on a loaded host cannot make two legs that run at once look
# one after another.
echo "features-start $(date +%s%N)" >> "$LEGS_STATE/times"
n=0; until grep -q '^archive-start ' "$LEGS_STATE/times" || [ "$n" -ge 6000 ]; do n=$((n + 1)); sleep 0.01; done
echo "features-end $(date +%s%N)" >> "$LEGS_STATE/times"
echo "features-makeflags ${CARGO_MAKEFLAGS:-none}" >> "$LEGS_STATE/times"
FEATURES
chmod +x "$legs_src/scripts/ci/verify/run-product-verification.sh"
cat > "$work/legs-bin/cargo" <<'CARGO'
#!/usr/bin/env bash
# The archive leg's cargo: fails as LEGS_CARGO_MODE says while its marker
# file exists, then writes the archive, the zstd tar beside it.
calls="$LEGS_STATE/calls"; echo x >> "$calls"
echo "wrapper=${RUSTC_WRAPPER:-none} next=${BUILD_ONCE_HEAVY_NEXT_WRAPPER:-none} bucket=${SCCACHE_BUCKET:-none} redis=${SCCACHE_REDIS:-none} aws=${AWS_ACCESS_KEY_ID:-none}" >> "$LEGS_STATE/cargo-env"
if [ -e "$CARGO_TARGET_DIR/debug/deps/libbroken.rlib" ]; then
  case "$LEGS_CARGO_MODE" in
    corrupt) echo "rust-lld: error: $CARGO_TARGET_DIR/debug/deps/libbroken.rlib: Archive::children failed: truncated or malformed archive"; exit 101 ;;
    compile) echo "error[E0308]: mismatched types"; exit 101 ;;
    missing) echo "error[E0463]: can't find crate for \`sqlx\`"; exit 101 ;;
  esac
fi
echo "archive-start $(date +%s%N)" >> "$LEGS_STATE/times"
# With LEGS_BESIDE, it ends only once that leg has started (60 s hang guard).
if [ -n "${LEGS_BESIDE:-}" ]; then
  n=0; until grep -q "^$LEGS_BESIDE-start " "$LEGS_STATE/times" || [ "$n" -ge 6000 ]; do n=$((n + 1)); sleep 0.01; done
else
  sleep 1
fi
echo "archive-end $(date +%s%N)" >> "$LEGS_STATE/times"
echo "archive-makeflags ${CARGO_MAKEFLAGS:-none}" >> "$LEGS_STATE/times"
if [[ "${CARGO_MAKEFLAGS:-}" =~ --jobserver-auth=([0-9]+),([0-9]+) ]]; then
  if [ -e "/proc/$$/fd/${BASH_REMATCH[1]}" ] && [ -e "/proc/$$/fd/${BASH_REMATCH[2]}" ]; then
    echo "archive-jobserver-fds open" >> "$LEGS_STATE/times"
  else
    echo "archive-jobserver-fds closed" >> "$LEGS_STATE/times"
  fi
fi
while [ "$#" -gt 0 ]; do [ "$1" = --archive-file ] && { shift; cp "${0%/*}/archive.tar.zst" "$1"; }; shift; done
CARGO
chmod +x "$work/legs-bin/cargo"
# What it writes: a zstd tar of one test binary that carries a debug section.
mkdir -p "$work/legs-archive/target/debug/deps"
cp "$(type -P true)" "$work/legs-archive/target/debug/deps/tests-0123"
printf 'debug-info-payload' > "$work/legs-archive/payload"
objcopy --add-section .debug_info="$work/legs-archive/payload" "$work/legs-archive/target/debug/deps/tests-0123"
tar -c -C "$work/legs-archive" target | zstd -q -o "$work/legs-bin/archive.tar.zst"
legs_build() {
  rm -rf "$work/legs-out" "$work/legs-state"; mkdir -p "$work/legs-out" "$work/legs-state"
  # The shared cache's credential file, as the selector leaves it in RUNNER_TEMP.
  [ -z "${LEGS_CREDENTIAL:-}" ] || install -m 0600 /dev/null "$work/legs-state/codewire-sccache-r2.aws"
  # A cache socket something already holds, as a leftover or another server.
  [ -z "${LEGS_HELD_SOCKET:-}" ] || : > "$work/legs-state/$LEGS_HELD_SOCKET"
  mkdir -p "$work/legs-root/build/targets/archive/debug/deps"
  printf 'half' > "$work/legs-root/build/targets/archive/debug/deps/libbroken.rlib"
  PATH="$work/legs-bin:$PATH" BUILD_ONCE_ROOT="$work/legs-root" BUILD_ONCE_SRC="$legs_src" \
    BUILD_ONCE_COLD=true LEGS_STATE="$work/legs-state" LEGS_CARGO_MODE="$1" RUNNER_TEMP="$work/legs-state" \
    VERIFICATION_SELECTION="${LEGS_SELECTION:-}" BUILD_ONCE_JOBSERVER_TOKENS=6 \
    "$SCRIPT" build "$work/legs-out" > "$work/legs.log" 2>&1
}
LEGS_SELECTION='|rust|' LEGS_BESIDE=features legs_build ok || fail "a cold build failed: $(cat "$work/legs.log")"
# The archive leg hands on the archive cargo-nextest wrote, byte for byte.
# The builds write no debug information, so nothing unpacks it, strips its
# binaries and packs it again: that took 121-160 s of the leg (infra#1534).
cmp -s "$work/legs-bin/archive.tar.zst" "$work/legs-out/archive.tar.zst" ||
  fail 'the archive leg changed the archive cargo-nextest wrote'
# Every leg runs at once, the archive and the feature graphs here, and both
# take their compilers from the one jobserver.
at() { sed -n "s/^$1 //p" "$work/legs-state/times"; }
[ "$(at archive-start)" -lt "$(at features-end)" ] && [ "$(at features-start)" -lt "$(at archive-end)" ] ||
  fail 'the legs ran one after another'
for leg in archive features; do
  [[ "$(at "$leg-makeflags")" == '-j6 '*'--jobserver-auth='*,* ]] || fail "the $leg leg had no jobserver: $(at "$leg-makeflags")"
done
[ "$(at archive-makeflags)" = "$(at features-makeflags)" ] || fail 'the legs had different jobservers'
[ "$(at archive-jobserver-fds)" = open ] ||
  fail "peak-rss.py closed the archive leg's jobserver descriptors: $(at archive-jobserver-fds)"
# Direct unit check: peak-rss.py passes the jobserver pipe descriptors through
# so a child can acquire and return a real token, while keeping unrelated
# inherited descriptors closed.
python3 - "$ROOT/scripts/ci/setup/jobserver.py" "$ROOT/scripts/ci/setup/peak-rss.py" "$work/jobserver-rss.out" "$work/unrelated.lock" <<'PY' ||
import os
import re
import subprocess
import sys

jobserver_py, peak_rss_py, rss_out, lock_path = sys.argv[1:5]
with open(lock_path, "w") as lock_file:
    lock_fd = lock_file.fileno()
    os.set_inheritable(lock_fd, True)
    probe = (
        "import os, re, sys\n"
        "m = re.search(r'--jobserver-auth=(\\d+),(\\d+)', os.environ.get('CARGO_MAKEFLAGS', ''))\n"
        "assert m, f'missing jobserver flag: {os.environ.get(\"CARGO_MAKEFLAGS\")}'\n"
        "r, w = int(m.group(1)), int(m.group(2))\n"
        "tok = os.read(r, 1)\n"
        "assert tok == b'+', f'unexpected token: {tok!r}'\n"
        "os.write(w, tok)\n"
        "lock_fd = int(sys.argv[1])\n"
        "try:\n"
        "    os.fstat(lock_fd)\n"
        "except OSError:\n"
        "    pass\n"
        "else:\n"
        "    raise AssertionError(f'unrelated fd {lock_fd} leaked through peak-rss.py')\n"
    )
    res = subprocess.run(
        [sys.executable, jobserver_py, "4", "--", sys.executable, peak_rss_py, rss_out, "--",
         sys.executable, "-c", probe, str(lock_fd)],
        pass_fds=(lock_fd,),
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        sys.stderr.write(res.stdout + res.stderr)
        sys.exit(res.returncode)
PY
  fail 'peak-rss.py did not preserve jobserver descriptors or leaked an unrelated descriptor'
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
grep -q "read a corrupt output in $work/legs-root/build/targets/archive; it is wiped" "$work/legs.log" ||
  fail 'a missing crate did not wipe the leg'"'"'s own folder'
# A leg whose builds run in batches (the database leg) keeps each batch but
# its first in batch-NAME inside its folder: a corrupt output there wipes
# that batch's folder alone, never the leg's own or another batch's.
cat > "$legs_src/scripts/ci/verify/run-integration-verification.sh" <<'DATABASE'
#!/bin/sh
echo x >> "$LEGS_STATE/database-calls"
broken="$CARGO_TARGET_DIR/batch-orchestration/debug/deps/libbroken.rlib"
if [ -e "$broken" ]; then echo "error: $broken: failed to mmap file"; exit 101; fi
DATABASE
chmod +x "$legs_src/scripts/ci/verify/run-integration-verification.sh"
batch_root="$work/legs-root/build/targets/database"
mkdir -p "$batch_root/batch-orchestration/debug/deps" "$batch_root/batch-billing" "$batch_root/debug"
printf 'half' > "$batch_root/batch-orchestration/debug/deps/libbroken.rlib"
: > "$batch_root/batch-billing/kept"
: > "$batch_root/debug/kept"
LEGS_SELECTION='|database|' legs_build ok || fail "a corrupt batch output was not rebuilt: $(cat "$work/legs.log")"
[ "$(wc -l < "$work/legs-state/database-calls")" -eq 2 ] || fail 'the corrupt batch did not build exactly twice'
grep -q "read a corrupt output in $batch_root/batch-orchestration; it is wiped" "$work/legs.log" ||
  fail "the corrupt batch's folder was not the one wiped: $(cat "$work/legs.log")"
[ -e "$batch_root/batch-billing/kept" ] && [ -e "$batch_root/debug/kept" ] ||
  fail "a corrupt batch output wiped the leg's or another batch's folder"
if legs_build compile; then fail 'a compile error passed'; fi
[ "$(wc -l < "$work/legs-state/calls")" -eq 1 ] || fail 'a compile error was rebuilt'
[ -e "$work/legs-root/build/targets/archive/debug/deps/libbroken.rlib" ] || fail 'a compile error wiped the target folder'

# checks runs the Rust checks from src, each in its own target folder, all
# under one jobserver; marks the folders used; and reruns once after a
# corrupt output in a folder it names, wiping only that folder (darwin_cw is
# not darwin); a plain check failure fails at once.
mkdir -p "$legs_src/scripts/ci/verify"
cat > "$legs_src/scripts/ci/verify/run-rust-checks.sh" <<'CHECKS'
#!/bin/sh
echo "checks-start $(date +%s%N)" >> "$LEGS_STATE/times"
# With CHECKS_BESIDE, they end only once that leg has started (60 s hang guard).
if [ -n "${CHECKS_BESIDE:-}" ]; then
  n=0; until grep -q "^$CHECKS_BESIDE-start " "$LEGS_STATE/times" || [ "$n" -ge 6000 ]; do n=$((n + 1)); sleep 0.01; done
fi
echo "checks-end $(date +%s%N)" >> "$LEGS_STATE/times"
echo "checks $PWD $CARGO_TARGET_DIR $RUST_CHECKS_FEATURES_TARGET_DIR $RUST_CHECKS_DARWIN_TARGET_DIR $RUST_CHECKS_CW_DARWIN_TARGET_DIR $CODEWIRE_DESKTOP_CHECK_TARGET_DIR" >> "$LEGS_STATE/checks"
echo "jobs ${CARGO_BUILD_JOBS:-} ${CARGO_MAKEFLAGS:-none}" >> "$LEGS_STATE/jobserver"
case "$CHECKS_MODE" in
  corrupt) broken="$CARGO_TARGET_DIR/broken" ;;
  corrupt-cw) broken="$RUST_CHECKS_CW_DARWIN_TARGET_DIR/broken" ;;
  *) broken="$CARGO_TARGET_DIR/broken" ;;
esac
if [ -e "$broken" ]; then
  case "$CHECKS_MODE" in
    corrupt*) echo "error: $broken: failed to mmap file"; exit 101 ;;
    lint) echo 'error: this could be written more simply'; exit 101 ;;
  esac
fi
CHECKS
chmod +x "$legs_src/scripts/ci/verify/run-rust-checks.sh"
checks_root="$work/legs-root/build/targets"
checks_run() {
  rm -rf "$work/legs-state"; mkdir -p "$work/legs-state" "$checks_root/clippy" "$checks_root/darwin_cw" "$checks_root/darwin"
  : > "$checks_root/clippy/broken"
  : > "$checks_root/darwin_cw/broken"
  : > "$checks_root/darwin/kept"
  BUILD_ONCE_ROOT="$work/legs-root" BUILD_ONCE_SRC="$legs_src" LEGS_STATE="$work/legs-state" \
    BUILD_ONCE_JOBSERVER_TOKENS=5 RUNNER_TEMP="$work/legs-state" CHECKS_MODE="$1" GITHUB_RUN_ID=77 \
    "$SCRIPT" checks > "$work/checks.log" 2>&1
}
checks_run corrupt || fail "a corrupt check output was not rerun: $(cat "$work/checks.log")"
[ "$(wc -l < "$work/legs-state/checks")" -eq 2 ] || fail 'the corrupt checks did not run exactly twice'
grep -qx "checks $legs_src $checks_root/clippy $checks_root/clippy_features $checks_root/darwin $checks_root/darwin_cw $checks_root/desktop" \
  "$work/legs-state/checks" || fail "the checks ran outside src or their folders: $(cat "$work/legs-state/checks")"
grep -q "the Rust checks read a corrupt output in $checks_root/clippy; it is wiped" "$work/checks.log" ||
  fail 'the checks rerun gave no reason'
for folder in $CHECK_FOLDERS; do
  [ "$(cat "$checks_root/$folder/.build-once-used" 2>/dev/null)" = 77 ] ||
    fail "the checks did not mark their $folder folder used by their run"
done
# One jobserver of the runner's compilers for every check; a Cargo that
# cannot reach it falls back to a few jobs.
while read -r _ jobs makeflags; do
  [ "$jobs" = 4 ] && [[ "$makeflags" == '-j5 '*'--jobserver-auth='*,* ]] ||
    fail "the checks ran without the jobserver: $jobs $makeflags"
done < "$work/legs-state/jobserver"
grep -q '^build-once: the Rust checks at once, 5 compilers in all$' "$work/checks.log" ||
  fail 'the checks did not report their jobserver'
# The job's CPU share (CARGO_BUILD_JOBS) caps the jobserver.
rm -rf "$work/legs-state"; mkdir -p "$work/legs-state"
BUILD_ONCE_ROOT="$work/legs-root" BUILD_ONCE_SRC="$legs_src" LEGS_STATE="$work/legs-state" \
  BUILD_ONCE_JOBSERVER_TOKENS=5 CARGO_BUILD_JOBS=3 RUNNER_TEMP="$work/legs-state" CHECKS_MODE=ok \
  "$SCRIPT" checks > "$work/checks.log" 2>&1 || fail "the capped checks failed: $(cat "$work/checks.log")"
grep -q '^build-once: the Rust checks at once, 3 compilers in all$' "$work/checks.log" ||
  fail "the CPU share did not cap the jobserver: $(cat "$work/checks.log")"
[[ "$(cut -d' ' -f3 "$work/legs-state/jobserver")" == -j3 ]] || fail 'the capped jobserver was not the one the checks saw'
checks_run corrupt-cw || fail "a corrupt cw Darwin output was not rerun: $(cat "$work/checks.log")"
grep -q "the Rust checks read a corrupt output in $checks_root/darwin_cw; it is wiped" "$work/checks.log" ||
  fail 'the cw Darwin folder was not wiped'
[ -e "$checks_root/darwin/kept" ] && [ -e "$checks_root/clippy/broken" ] ||
  fail 'a corrupt cw Darwin output wiped another check folder'
[ "$(grep -c 'corrupt output in' "$work/checks.log")" -eq 1 ] || fail 'the rerun wiped more than the named folder'
if checks_run lint; then fail 'a failed check passed'; fi
[ "$(wc -l < "$work/legs-state/checks")" -eq 1 ] || fail 'a failed check was rerun'
[ -e "$checks_root/clippy/broken" ] || fail 'a failed check wiped its folder'

# On a main push the Rust checks run beside the legs (BUILD_ONCE_CHECKS): at
# the same time, from the legs' one jobserver, with their own log; a failed
# check fails the build, and the legs still finish.
legs_checks_build() {
  rm -rf "$work/legs-out" "$work/legs-state"; mkdir -p "$work/legs-out" "$work/legs-state"
  mkdir -p "$checks_root/clippy"; rm -f "$checks_root/clippy/broken" "$checks_root/darwin_cw/broken"
  [ "$1" != lint ] || : > "$checks_root/clippy/broken"
  PATH="$work/legs-bin:$PATH" BUILD_ONCE_ROOT="$work/legs-root" BUILD_ONCE_SRC="$legs_src" \
    LEGS_STATE="$work/legs-state" LEGS_CARGO_MODE=ok RUNNER_TEMP="$work/legs-state" VERIFICATION_SELECTION='' \
    BUILD_ONCE_JOBSERVER_TOKENS=6 BUILD_ONCE_CHECKS=true CHECKS_MODE="$1" CHECKS_BESIDE=archive LEGS_BESIDE=checks GITHUB_RUN_ID=78 \
    "$SCRIPT" build "$work/legs-out" > "$work/legs-checks.log" 2>&1
}
legs_checks_build ok || fail "the build with the Rust checks failed: $(cat "$work/legs-checks.log")"
[ "$(at archive-start)" -lt "$(at checks-end)" ] && [ "$(at checks-start)" -lt "$(at archive-end)" ] ||
  fail 'the Rust checks did not run beside the legs'
read -r _ jobs makeflags < "$work/legs-state/jobserver"
[ "$jobs" = 4 ] && [ "$makeflags" = "$(at archive-makeflags)" ] && [[ "$makeflags" == '-j6 '* ]] ||
  fail "the Rust checks did not take the legs' jobserver: $jobs $makeflags, legs $(at archive-makeflags)"
grep -qx "checks $legs_src $checks_root/clippy $checks_root/clippy_features $checks_root/darwin $checks_root/darwin_cw $checks_root/desktop" \
  "$work/legs-state/checks" || fail "the Rust checks ran outside src or their folders: $(cat "$work/legs-state/checks")"
grep -q '^build-once: legs archive and the Rust checks at once, 6 compilers in all$' "$work/legs-checks.log" ||
  fail "the build did not report the Rust checks beside its legs: $(cat "$work/legs-checks.log")"
grep -q '^build-once: the Rust checks at once, beside the legs, from their 6 compilers$' "$work/legs-checks.log" &&
  grep -q '^\[build-once\] checks: finish (status=0 elapsed_seconds=[0-9]*)$' "$work/legs-checks.log" ||
  fail "the Rust checks' log or time did not reach the job log"
[ "$(cat "$checks_root/clippy/.build-once-used")" = 78 ] || fail 'the Rust checks beside the legs did not mark their folders'
if legs_checks_build lint; then fail 'a failed Rust check passed the build'; fi
grep -q '^::error::the Rust checks failed$' "$work/legs-checks.log" || fail 'the failed Rust checks were not reported'
[ -f "$work/legs-out/archive.tar.zst" ] || fail 'a failed Rust check stopped the legs'
# Without BUILD_ONCE_CHECKS (every run but a main push) the build runs no
# check: Rust checks does, after it.
legs_build ok || fail "a build without the Rust checks failed: $(cat "$work/legs.log")"
[ ! -s "$work/legs-state/checks" ] || fail 'a build without BUILD_ONCE_CHECKS ran the Rust checks'

# With an archive store, each leg uploads its outputs as it finishes and
# records them, so the publish step has nothing left to upload.
rm -rf "$work/store3"; mkdir -p "$work/store3/v1/archives"
ARCHIVE_STORE_URL="file://$work/store3" LEGS_SELECTION='|rust|' LEGS_BESIDE=features legs_build ok ||
  fail "a build with an archive store failed: $(cat "$work/legs.log")"
early_digest="$(sha256sum "$work/legs-out/archive.tar.zst" | cut -d' ' -f1)"
grep -q "^archive.tar.zst $early_digest " "$work/legs-out/.published" || fail 'the archive leg did not record its upload'
cmp -s "$work/legs-out/archive.tar.zst" "$work/store3/v1/archives/$early_digest" ||
  fail 'the archive leg did not upload its output as it finished'
grep -q "^build-once: published archive $early_digest " "$work/legs.log" || fail 'the early upload was not reported'

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
# An output its leg uploaded as it finished is reported, not uploaded again;
# one rewritten since is uploaded again, even at the same size (codewire#5311,
# cw-security on #5329).
rm -rf "$work/store2" "$work/out2"; mkdir -p "$work/out2" "$work/store2/v1/archives"
printf 'three' > "$work/out2/features.tar.zst"
printf 'four' > "$work/out2/services_runtime.tar.zst"
printf 'sixx' > "$work/out2/database.tar.zst"
early="$(printf 'three' | sha256sum | cut -d' ' -f1)"
stale="$(printf 'five' | sha256sum | cut -d' ' -f1)"
printf 'features.tar.zst %s 5\n' "$early" > "$work/out2/.published"
printf 'services_runtime.tar.zst %s 99\n' "$early" >> "$work/out2/.published"
printf 'database.tar.zst %s 4\n' "$stale" >> "$work/out2/.published"
: > "$work/outputs2"
GITHUB_OUTPUT="$work/outputs2" ARCHIVE_STORE_URL="file://$work/store2" "$SCRIPT" publish "$work/out2" > "$work/publish2.log"
grep -qx "features_sha256=$early" "$work/outputs2" || fail 'an early-published output lost its job output'
[ ! -e "$work/store2/v1/archives/$early" ] || fail 'an early-published output was uploaded again'
four="$(printf 'four' | sha256sum | cut -d' ' -f1)"
grep -qx "services_runtime_sha256=$four" "$work/outputs2" || fail 'a changed output kept its stale digest'
[ "$(cat "$work/store2/v1/archives/$four")" = four ] || fail 'a changed output was not uploaded again'
sixx="$(printf 'sixx' | sha256sum | cut -d' ' -f1)"
grep -qx "database_sha256=$sixx" "$work/outputs2" || fail 'a same-size rewrite kept its stale digest'
[ "$(cat "$work/store2/v1/archives/$sixx")" = sixx ] || fail 'a same-size rewrite was not uploaded again'
! grep -q "database_sha256=$stale" "$work/outputs2" || fail 'publish reported a stale digest'
printf 'x' > "$work/out/Bad-Name.tar.zst"
if ARCHIVE_STORE_URL="file://$work/store" "$SCRIPT" publish "$work/out" >/dev/null 2>&1; then
  fail 'publish accepted an invalid leg output name'
fi

# The compiler cache canary (#5146) stays local (cw-security, #5231): a stray
# remote setting in the job's environment reaches neither a leg's server nor
# its compilers, each leg logs its hit rate, and a server that reports any
# other cache leaves its leg uncached.
cat > "$work/legs-bin/fake-sccache" <<'SCCACHE'
#!/usr/bin/env bash
case "$1" in
  --start-server) env > "$LEGS_STATE/sccache-server-env" ;;
  --show-stats)
    # sccache 0.17's own formats: a multi-level server's JSON names no level;
    # its text report lists them under "Cache location".
    python3 -c '
import json, os, sys
levels = os.environ.get("FAKE_SCCACHE_LEVELS")
location = os.environ.get("FAKE_SCCACHE_LOCATION") or "Local disk: \"" + os.environ["SCCACHE_DIR"] + "\""
if levels:
    location = "Multi-level (%d levels)" % len(levels.split("|"))
if sys.argv[1:] == ["--stats-format", "json"]:
    print(json.dumps({"cache_location": location, "cache_size": 7,
                      "stats": {"cache_hits": {"counts": {"Rust": 3}}, "cache_misses": {"counts": {"Rust": 1}}}}))
else:
    print("Cache hits                            3")
    print("Cache location                  " + location)
    # A pull request read-only server lists no level (the build of #5281).
    for index, level in enumerate((levels or "").split("|") if levels and not os.environ.get("FAKE_SCCACHE_HIDE_LEVELS") else []):
        kind, where = level.split("=", 1)
        print("  L%d (%s)                     %s" % (index, kind, where))
    print("Version (client)                0.17.0")
' "${@:2}"
    ;;
esac
SCCACHE
chmod +x "$work/legs-bin/fake-sccache"
cache_legs_build() {
  CODEWIRE_BUILD_ONCE_SCCACHE=local BUILD_ONCE_SCCACHE_BIN="$work/legs-bin/fake-sccache" \
    SCCACHE_DIR="$work/legs-root/build/sccache" SCCACHE_BUCKET=stray-bucket SCCACHE_REDIS=redis://stray \
    AWS_ACCESS_KEY_ID=stray-id LEGS_SELECTION='|valid:v3|complete|' legs_build ok
}
cache_legs_build || fail "a build with the compiler cache failed: $(cat "$work/legs.log")"
for stray in SCCACHE_BUCKET SCCACHE_REDIS AWS_ACCESS_KEY_ID; do
  ! grep -q "^$stray=" "$work/legs-state/sccache-server-env" || fail "the leg's cache server saw $stray"
done
grep -qx 'SCCACHE_CONF=/dev/null' "$work/legs-state/sccache-server-env" || fail 'the cache server could read a configuration file'
# The heavy-unit wrapper stands in front of the cache (heavy-unit-rustc.sh).
grep -Eqx "wrapper=/.*/scripts/ci/setup/heavy-unit-rustc\.sh next=$work/legs-bin/fake-sccache bucket=none redis=none aws=none" "$work/legs-state/cargo-env" ||
  fail "the leg's compilers did not use only the local cache: $(cat "$work/legs-state/cargo-env")"
grep -q '^\[build-once\] leg archive: sccache hits=3 misses=1 hit_rate=75.0 ' "$work/legs.log" ||
  fail "the leg logged no hit rate: $(cat "$work/legs.log")"
FAKE_SCCACHE_LOCATION='S3, name: stray-bucket' cache_legs_build || fail "a build with a remote cache server failed: $(cat "$work/legs.log")"
grep -q "the archive leg's compiler cache is not this build folder's, or the shared one the job selected; it compiles without it" "$work/legs.log" ||
  fail 'a remote cache server was not refused'
grep -Eqx 'wrapper=/.*/scripts/ci/setup/heavy-unit-rustc\.sh next=none bucket=none redis=none aws=none' "$work/legs-state/cargo-env" ||
  fail "a leg compiled through a remote cache: $(cat "$work/legs-state/cargo-env")"
# The shared level the job selected (#5146): exactly the selector's settings
# reach a pull request leg's server, read-only, with its own configuration;
# a stray setting still does not.
# A level that names another bucket, or a pull request's without read-only,
# is dropped and the leg keeps only the local cache.
shared_legs_build() {
  CODEWIRE_BUILD_ONCE_SCCACHE=local BUILD_ONCE_SCCACHE_BIN="$work/legs-bin/fake-sccache" \
    SCCACHE_DIR="$work/legs-state/selector-cache" CODEWIRE_SCCACHE_MODE=r2 \
    CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED=protected-bucket CODEWIRE_R2_CACHE_ENDPOINT=https://r2.example.invalid \
    SCCACHE_BUCKET="${SHARED_BUCKET:-protected-bucket}" SCCACHE_ENDPOINT=https://r2.example.invalid \
    SCCACHE_REGION=auto SCCACHE_S3_KEY_PREFIX=protected/codewire/v1 SCCACHE_MULTILEVEL_CHAIN=disk,s3 \
    SCCACHE_S3_RW_MODE="${SHARED_MODE-READ_ONLY}" CODEWIRE_R2_CACHE_TRUST=protected-read \
    AWS_SHARED_CREDENTIALS_FILE="$work/legs-state/codewire-sccache-r2.aws" AWS_PROFILE=default \
    SCCACHE_REDIS=redis://stray AWS_ACCESS_KEY_ID=stray-id GITHUB_EVENT_NAME=pull_request \
    GITHUB_REF=refs/pull/1/head LEGS_CREDENTIAL=1 LEGS_SELECTION='|valid:v3|complete|' legs_build ok
}
shared_levels="disk=Local disk: \"$work/legs-root/build/sccache\"|s3=s3, name: protected-bucket, prefix: /protected/codewire/v1/"
FAKE_SCCACHE_LEVELS="$shared_levels" \
  shared_legs_build || fail "a build with the shared cache failed: $(cat "$work/legs.log")"
! grep -q "compiler cache is not this build folder's" "$work/legs.log" ||
  fail "a leg refused the shared cache it selected: $(cat "$work/legs.log")"
server_env="$work/legs-state/sccache-server-env"
for kept in SCCACHE_BUCKET=protected-bucket SCCACHE_S3_RW_MODE=READ_ONLY SCCACHE_MULTILEVEL_CHAIN=disk,s3 \
    "SCCACHE_DIR=$work/legs-root/build/sccache" \
    "SCCACHE_CONF=$work/legs-state/build-once-sccache.conf" \
    "AWS_SHARED_CREDENTIALS_FILE=$work/legs-state/codewire-sccache-r2.aws"; do
  grep -qxF "$kept" "$server_env" || fail "the leg's cache server lacked $kept"
done
for stray in SCCACHE_REDIS AWS_ACCESS_KEY_ID; do
  ! grep -q "^$stray=" "$server_env" || fail "the leg's shared cache server saw $stray"
done
grep -q '^\[build-once\] leg archive: sccache hits=3 misses=1 hit_rate=75.0 .* location=Multi-level (2 levels)' "$work/legs.log" ||
  fail "the leg did not log its cache's location: $(cat "$work/legs.log")"
# A server that lists no level, as a pull request's read-only one does, keeps
# its two levels when the settings were the job's own; three are refused.
FAKE_SCCACHE_HIDE_LEVELS=1 FAKE_SCCACHE_LEVELS="$shared_levels" shared_legs_build ||
  fail "a build with an unlisted two-level cache failed: $(cat "$work/legs.log")"
! grep -q "compiler cache is not this build folder's" "$work/legs.log" ||
  fail "a leg refused a two-level cache whose server lists no level: $(cat "$work/legs.log")"
FAKE_SCCACHE_HIDE_LEVELS=1 FAKE_SCCACHE_LEVELS="$shared_levels|redis=Redis" shared_legs_build ||
  fail "a build with an unlisted three-level cache failed: $(cat "$work/legs.log")"
grep -q "the archive leg's compiler cache is not this build folder's.*Multi-level (3 levels)" "$work/legs.log" ||
  fail "an unlisted three-level cache was not refused with its reason: $(cat "$work/legs.log")"
# A socket something already holds is refused before any server starts.
LEGS_HELD_SOCKET=build-once-sccache-archive.sock FAKE_SCCACHE_LEVELS="$shared_levels" shared_legs_build ||
  fail "a build with a held socket failed: $(cat "$work/legs.log")"
grep -q "the archive leg's compiler cache is not this build folder's.*(a server already held $work/legs-state/build-once-sccache-archive.sock)" "$work/legs.log" ||
  fail "a socket something already held was not refused: $(cat "$work/legs.log")"
# A server whose levels are not exactly this folder's disk and the job's
# bucket leaves its leg uncached.
for levels in "disk=Local disk: \"/elsewhere\"|s3=s3, name: protected-bucket, prefix: /protected/codewire/v1/" \
    "disk=Local disk: \"$work/legs-root/build/sccache\"|s3=s3, name: other-bucket, prefix: /protected/codewire/v1/" \
    "$shared_levels|redis=Redis"; do
  FAKE_SCCACHE_LEVELS="$levels" shared_legs_build || fail "a build with a wrong level failed: $(cat "$work/legs.log")"
  grep -q "the archive leg's compiler cache is not this build folder's, or the shared one the job selected; it compiles without it" "$work/legs.log" ||
    fail "a server with levels $levels was not refused"
done
SHARED_BUCKET=other-bucket shared_legs_build || fail "a build with another bucket failed: $(cat "$work/legs.log")"
grep -q "the job's shared compiler cache does not name its own bucket, prefix and trust" "$work/legs.log" ||
  fail 'a shared cache with another bucket was not refused'
! grep -q '^SCCACHE_BUCKET=' "$server_env" || fail 'a shared cache with another bucket reached the leg'
grep -qx 'SCCACHE_CONF=/dev/null' "$server_env" || fail 'a refused shared cache left a configuration file'
SHARED_MODE='' shared_legs_build || fail "a read-write pull request build failed: $(cat "$work/legs.log")"
grep -q "the job's shared compiler cache does not name its own bucket, prefix and trust" "$work/legs.log" ||
  fail "a pull request's shared cache without read-only was not refused"
! grep -q '^SCCACHE_BUCKET=' "$server_env" || fail "a pull request's read-write shared cache reached the leg"

# Why one folder (#5146): sccache's Rust keys carry absolute paths, which
# SCCACHE_BASEDIRS does not remove. A crate compiled in main's build folder
# on one disk is a hit for a pull request's on another disk at the same path,
# sharing one cache; at another path it never is.
real_cache_build() {
  # real_cache_build DISK_ROOT NAME: build the probe crate in build_once_tree
  # DISK_ROOT through the shared cache; print the server's hits.
  local tree crate
  tree="$( source "$ROOT/scripts/ci/setup/build-once-tree.sh"; build_once_tree "$1" )"
  crate="$tree/src/probe"
  mkdir -p "$crate/src"
  printf '[package]\nname = "build_once_probe"\nversion = "0.1.0"\nedition = "2021"\n' > "$crate/Cargo.toml"
  printf 'pub fn probe() -> u32 { 42 }\n' > "$crate/src/lib.rs"
  (
    export SCCACHE_DIR="$work/real-cache" SCCACHE_SERVER_UDS="$work/real-$2.sock" SCCACHE_CONF=/dev/null
    RUSTC_WRAPPER="$(command -v sccache)"
    export RUSTC_WRAPPER CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
    unset SCCACHE_BASEDIRS
    sccache --start-server >/dev/null 2>&1 || exit 1
    (cd "$crate" && CARGO_TARGET_DIR="$tree/targets/probe" cargo build -q --offline >/dev/null 2>&1) || exit 1
    sccache --show-stats --stats-format json |
      python3 -c 'import json, sys; print(sum(json.load(sys.stdin)["stats"]["cache_hits"]["counts"].values()))'
    sccache --stop-server >/dev/null 2>&1 || true
  )
}
command -v cargo >/dev/null && [ "$(sccache --version 2>/dev/null)" = 'sccache 0.17.0' ] ||
  fail 'the CI image has no cargo or no pinned sccache 0.17.0 for the shared-path case'
mkdir -p "$work/real-cache"
[ "$(real_cache_build "$work/real-disk" main)" = 0 ] || fail 'the first build read a cache nothing had written'
rm -rf -- "$work/real-disk"
hits="$(real_cache_build "$work/real-disk" pr)"
[[ "$hits" =~ ^[0-9]+$ ]] && [ "$hits" -gt 0 ] || fail "a pull request at main's path got no cache hit: ${hits:-none}"
[ "$(real_cache_build "$work/real-other-disk" other)" = 0 ] || fail 'a build at another path hit the cache'

# Why the move drops the targets: Cargo calls a moved target fresh, but a
# compiled env!("CARGO_MANIFEST_DIR") keeps the old path. A crate built in
# the old folder, moved by prepare, then built again names the new one.
probe_dir() {
  # probe_dir TREE: build and run the probe in TREE; print the path compiled in.
  (cd "$1/tools/dir-probe" && CARGO_HOME="$1/cargo-home" CARGO_TARGET_DIR="$1/targets/archive" CARGO_INCREMENTAL=0 \
    cargo run -q --offline 2>/dev/null)
}
# The probe lives in tools/, which prepare keeps; it syncs and cleans src/.
mkdir -p "$work/dir-disk/pr/tools/dir-probe/src" "$work/dir-disk/pr/cargo-home"
printf '[package]\nname = "dir_probe"\nversion = "0.1.0"\nedition = "2021"\n' > "$work/dir-disk/pr/tools/dir-probe/Cargo.toml"
printf 'fn main() { println!("{}", env!("CARGO_MANIFEST_DIR")); }\n' > "$work/dir-disk/pr/tools/dir-probe/src/main.rs"
[ "$(probe_dir "$work/dir-disk/pr")" = "$work/dir-disk/pr/tools/dir-probe" ] || fail 'the probe did not build in the old folder'
# A warm folder at the archive leg's epoch, so only the move can drop it.
printf '1\n' > "$work/dir-disk/pr/targets/archive/.build-once-epoch"
GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/1/head BUILD_ONCE_DF="$work/fake-df" \
  FAKE_DF_TARGETS="$work/dir-disk/build/targets" BUILD_ONCE_ROOT="$work/dir-disk" BUILD_ONCE_TEST_STOP_AFTER_TARGETS=1 \
  GITHUB_ENV="$work/env/env" GITHUB_PATH="$work/env/path" RUNNER_TEMP="$work/env" \
  "$SCRIPT" prepare "$work/lock-checkout" build > "$work/dir.log" 2>&1 || fail "the move prepare failed: $(cat "$work/dir.log")"
[ "$(probe_dir "$work/dir-disk/build")" = "$work/dir-disk/build/tools/dir-probe" ] ||
  fail "a target built before the move still names the old path: $(probe_dir "$work/dir-disk/build")"

echo 'test-build-once: shallow checkouts sync into the persistent clone; the leg table, the one build folder and its kind, the archive fetch and its build fallback, interrupted folders and lockfile changes kept warm, the disk bound (idle folders first, live ones kept, the folders a job uses never removed), the corrupt-output rebuild and publish hold, the local compiler cache stays local and reads only the shared level its job selected, and main and pull request builds share one path; bad input refused'
