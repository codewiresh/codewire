#!/usr/bin/env bash
# The metal guest's warm Rust cache: used only by a main push or a pull request
# on a guest that mounts it, wiped weekly or on an operator epoch,
# kept under its caps by whole least recently used profile directories.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly SELECT="$ROOT/scripts/ci/setup/select-warm-rust-cache.sh"
readonly FINISH="$ROOT/scripts/ci/setup/finish-warm-rust-cache.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  printf '[test-warm-rust-cache] FAIL: %s\n' "$*" >&2
  exit 1
}

# A fake df for the cache filesystem: FAKE_DF_SIZE_KIB in all, of which
# FAKE_DF_OTHER_KIB is used by something else and the rest by what is really
# under the cache, so removing a directory frees exactly its size.
mkdir -p "$work/fake"
cat > "$work/fake/df" <<'DF'
#!/bin/sh
used=$(du -sk "$FAKE_DF_ROOT" | awk '{print $1}')
used=$((used + FAKE_DF_OTHER_KIB))
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
echo "/dev/loop1 $FAKE_DF_SIZE_KIB $used $((FAKE_DF_SIZE_KIB - used)) 0% /ci-cache"
DF
chmod +x "$work/fake/df"

run() {
  local job="$1" event="$2" ref="$3"
  shift 3
  rm -rf "$work/workspace"
  mkdir -p "$work/workspace/target/ci-cache"
  env -i PATH="$PATH" HOME="$work" WARM_CACHE_ROOT="$work/cache" GITHUB_WORKSPACE="$work/workspace" \
    WARM_CACHE_DF="$work/fake/df" FAKE_DF_ROOT="$work/cache" \
    FAKE_DF_SIZE_KIB="${FAKE_DF_SIZE_KIB:-1000000000}" FAKE_DF_OTHER_KIB="${FAKE_DF_OTHER_KIB:-0}" \
    GITHUB_JOB="$job" GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" "$@" "$SELECT"
}

# Other refs and other events never touch the cache.
out="$(run rust-compile push refs/heads/feature)"; grep -qF 'not a push to main or a pull request' <<<"$out" || fail 'another ref used the cache'
out="$(run rust-compile schedule refs/heads/main)"; grep -qF 'not a push to main or a pull request' <<<"$out" || fail 'a scheduled run used the cache'
[[ ! -e "$work/cache/v1" && ! -L "$work/workspace/target/ci-cache" ]] || fail 'a skipped job changed the cache'

# A main push links its target and Cargo home into the cache.
out="$(run rust-compile push refs/heads/main)"; grep -qF 'using' <<<"$out" || fail 'a main push did not use the cache'
[[ "$(readlink "$work/workspace/target/ci-cache")" == "$work/cache/v1/ci-cache" ]] || fail 'target is not linked'
[[ "$(readlink "$work/workspace/target/ci-rust-cargo-home")" == "$work/cache/v1/cargo-home" ]] || fail 'Cargo home is not linked'
week="$(date -u +%G-W%V)"
[[ "$(cat "$work/cache/v1/.key")" == "$week/0" ]] || fail 'the cache key is not this week'
# A pull request uses the same cache.
out="$(run rust-compile pull_request refs/pull/1/head)"; grep -qF 'using' <<<"$out" || fail 'a pull request did not use the cache'
[[ "$(readlink "$work/workspace/target/ci-cache")" == "$work/cache/v1/ci-cache" ]] || fail 'a pull request target is not linked'

# A build is kept for the next job; a new epoch (or week) wipes everything.
mkdir -p "$work/cache/v1/ci-cache/host-debug"
echo artifact > "$work/cache/v1/ci-cache/host-debug/lib.rlib"
run database push refs/heads/main >/dev/null
[[ -f "$work/cache/v1/ci-cache/host-debug/lib.rlib" ]] || fail 'a build was not kept'
out="$(run database push refs/heads/main CODEWIRE_WARM_CACHE_EPOCH=2)"; grep -qF 'clean build' <<<"$out" || fail 'a new epoch did not wipe'
[[ ! -e "$work/cache/v1/ci-cache/host-debug" && "$(cat "$work/cache/v1/.key")" == "$week/2" ]] || fail 'the wipe left content'
echo old > "$work/cache/v1/.key"
out="$(run database push refs/heads/main CODEWIRE_WARM_CACHE_EPOCH=2)"; grep -qF 'clean build' <<<"$out" || fail 'a new week did not wipe'

# Over the cap, whole profile directories go, least recently used first.
for dir in host-debug host-ci desktop-release; do
  mkdir -p "$work/cache/v1/ci-cache/$dir"
  head -c 3000000 /dev/zero > "$work/cache/v1/ci-cache/$dir/blob"
done
touch -d '3 days ago' "$work/cache/v1/ci-cache/host-ci/.last-used"
touch -d '2 days ago' "$work/cache/v1/ci-cache/desktop-release/.last-used"
touch -d '1 day ago' "$work/cache/v1/ci-cache/host-debug/.last-used"
run standard push refs/heads/main CODEWIRE_WARM_CACHE_EPOCH=2 WARM_CACHE_TARGET_CAP_KIB=7000 >/dev/null
[[ ! -e "$work/cache/v1/ci-cache/host-ci" && -d "$work/cache/v1/ci-cache/desktop-release" && -d "$work/cache/v1/ci-cache/host-debug" ]] ||
  fail 'the least recently used directory was not the one removed'
head -c 3000000 /dev/zero > "$work/cache/v1/cargo-home/registry.blob"
out="$(run standard push refs/heads/main CODEWIRE_WARM_CACHE_EPOCH=2 WARM_CACHE_CARGO_HOME_CAP_KIB=1000)"; grep -qF 'Cargo home cap' <<<"$out" ||
  fail 'an oversized Cargo home was kept'
[[ ! -e "$work/cache/v1/cargo-home/registry.blob" ]] || fail 'the Cargo home was not wiped'

# Under the free-space floor (a quarter of the filesystem, at least 2 GiB),
# whole profile directories go, least recently used first and logged, until
# the floor holds; the step continues (main run 19967).
cache_used_kib() { du -sk "$work/cache" | awk '{print $1}'; }
fresh_profiles() {
  rm -rf "$work/cache/v1/ci-cache" && mkdir -p "$work/cache/v1/ci-cache"
  for dir in host-debug host-ci desktop-release; do
    mkdir -p "$work/cache/v1/ci-cache/$dir"
    head -c 3000000 /dev/zero > "$work/cache/v1/ci-cache/$dir/blob"
  done
  touch -d '3 days ago' "$work/cache/v1/ci-cache/host-ci/.last-used"
  touch -d '2 days ago' "$work/cache/v1/ci-cache/desktop-release/.last-used"
  touch -d '1 day ago' "$work/cache/v1/ci-cache/host-debug/.last-used"
}
readonly fs_kib=40000000 floor_kib=10000000
fresh_profiles
# 1000 KiB short of the floor: the least recently used directory frees enough.
other=$(( fs_kib - floor_kib + 1000 - $(cache_used_kib) ))
out="$(FAKE_DF_SIZE_KIB=$fs_kib FAKE_DF_OTHER_KIB=$other run standard push refs/heads/main CODEWIRE_WARM_CACHE_EPOCH=2)" ||
  fail "a cache under its floor failed instead of pruning: $out"
grep -qE "^\[warm-rust-cache\] under $floor_kib KiB free: removing host-ci \([0-9]+ KiB\)$" <<<"$out" ||
  fail "the least recently used removal was not logged: $out"
[[ ! -e "$work/cache/v1/ci-cache/host-ci" && -d "$work/cache/v1/ci-cache/desktop-release" && -d "$work/cache/v1/ci-cache/host-debug" ]] ||
  fail 'pruning to the floor removed more or other than the least recently used directory'
grep -qF '[warm-rust-cache] using ' <<<"$out" || fail 'the step did not continue after pruning'
# Far under the floor: every profile directory goes in order, then the Cargo
# home; above the 2 GiB hard minimum the step still continues.
fresh_profiles
head -c 1000000 /dev/zero > "$work/cache/v1/cargo-home/registry.blob"
other=$(( fs_kib - 3000000 - $(cache_used_kib) ))
out="$(FAKE_DF_SIZE_KIB=$fs_kib FAKE_DF_OTHER_KIB=$other run standard push refs/heads/main CODEWIRE_WARM_CACHE_EPOCH=2)" ||
  fail "a cache that pruning can bring over 2 GiB failed: $out"
[[ "$(grep -oE 'removing [a-z-]+' <<<"$out" | tr '\n' ' ')" == 'removing host-ci removing desktop-release removing host-debug ' ]] ||
  fail "profile directories were not removed least recently used first: $out"
grep -qF 'with no target left: wiping the Cargo home' <<<"$out" || fail 'the Cargo home was not wiped under the floor'
[[ ! -e "$work/cache/v1/cargo-home/registry.blob" ]] || fail 'the Cargo home survived the floor'
# Equal last use: the name decides, so pruning is deterministic.
fresh_profiles
touch -d '2 days ago' "$work/cache/v1/ci-cache/host-ci/.last-used" "$work/cache/v1/ci-cache/desktop-release/.last-used"
other=$(( fs_kib - floor_kib + 1000 - $(cache_used_kib) ))
out="$(FAKE_DF_SIZE_KIB=$fs_kib FAKE_DF_OTHER_KIB=$other run standard push refs/heads/main CODEWIRE_WARM_CACHE_EPOCH=2)"
grep -qE 'removing desktop-release ' <<<"$out" && [[ -d "$work/cache/v1/ci-cache/host-ci" ]] ||
  fail "a tie in last use was not broken by name: $out"
# Nothing left to remove and under 2 GiB free: the step fails and says why.
fresh_profiles
other=$(( fs_kib - 1000000 - $(cache_used_kib) ))
if out="$(FAKE_DF_SIZE_KIB=$fs_kib FAKE_DF_OTHER_KIB=$other run standard push refs/heads/main CODEWIRE_WARM_CACHE_EPOCH=2 2>&1)"; then
  fail 'a cache filesystem pruning cannot free was accepted'
fi
grep -qE 'ERROR: the cache filesystem has [0-9]+ KiB free with nothing left to remove; at least 2097152 KiB is required' <<<"$out" ||
  fail "the hard minimum failure did not say why: $out"
# The floor is a quarter of the filesystem but never under 2 GiB.
fresh_profiles
other=$(( 6000000 - 2097152 + 1000 - $(cache_used_kib) ))
out="$(FAKE_DF_SIZE_KIB=6000000 FAKE_DF_OTHER_KIB=$other run standard push refs/heads/main CODEWIRE_WARM_CACHE_EPOCH=2)"
grep -qF 'under 2097152 KiB free: removing host-ci' <<<"$out" || fail "a small filesystem's floor is not the 2 GiB minimum: $out"
# The finish-step cases below start from the LRU case's directories.
fresh_profiles
rm -rf "$work/cache/v1/ci-cache/host-ci"

# The default caps start a job at most 80% into the 110 GB image, whose
# filesystem holds 105149384 KiB (measured on the metal guests, 2026-10-22),
# so the job's own build has room: 70 GB of targets and 12 GB of Cargo home.
default_cap() {
  sed -n "s/^readonly $1=\"\${[A-Z_]*:-\([0-9]*\)}\"\$/\1/p" "$SELECT"
}
target_default="$(default_cap target_cap_kib)"
cargo_home_default="$(default_cap cargo_home_cap_kib)"
[[ "$target_default" == 68359375 && "$cargo_home_default" == 11718750 ]] ||
  fail "default caps are ${target_default:-unset} and ${cargo_home_default:-unset} KiB, not 70 GB and 12 GB"
(( (target_default + cargo_home_default) * 100 <= 105149384 * 80 )) ||
  fail 'the default caps leave a job less than 20% of the cache image'

# The finish step marks what the job built and reports sizes.
echo started-before > "$work/cache/v1/ci-cache/host-debug/older"
date -u -d '1 minute ago' +%s > "$work/cache/v1/.job-started"
touch -d '1 day ago' "$work/cache/v1/ci-cache/host-debug/.last-used" "$work/cache/v1/ci-cache/desktop-release/.last-used"
touch -d '2 minutes ago' "$work/cache/v1/ci-cache/desktop-release/blob"
echo new > "$work/cache/v1/ci-cache/host-debug/new.rlib"
report="$(env -i PATH="$PATH" WARM_CACHE_ROOT="$work/cache" GITHUB_WORKSPACE="$work/workspace" "$FINISH")"
grep -qF '[warm-rust-cache] size host-debug' <<<"$report" || fail 'the finish step did not report sizes'
[[ "$(find "$work/cache/v1/ci-cache/host-debug/.last-used" -mmin -1)" ]] || fail 'a built directory was not marked used'
[[ -z "$(find "$work/cache/v1/ci-cache/desktop-release/.last-used" -mmin -1)" ]] || fail 'an untouched directory was marked used'
grep -qE '^\[warm-rust-cache\] filesystem [0-9]+ KiB used of [0-9]+$' <<<"$report" || fail 'the finish step did not report the cache disk'

# Over 85% full after a job, the finish step warns on the run page; at or
# under 85% it stays quiet. A fake df reports the cache disk's usage.
mkdir -p "$work/bin"
finish_at() {
  printf '#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted on"\necho "/dev/loop1 1000 %s 0 0%% /ci-cache"\n' "$1" > "$work/bin/df"
  chmod +x "$work/bin/df"
  env -i PATH="$work/bin:$PATH" WARM_CACHE_ROOT="$work/cache" GITHUB_WORKSPACE="$work/workspace" "$FINISH"
}
report="$(finish_at 880)"
grep -qxF '::warning::the warm Rust cache disk is 88% full after this job; the next job may run out of space' <<<"$report" ||
  fail "a cache disk 88% full did not warn: $report"
report="$(finish_at 850)"
! grep -qF '::warning::' <<<"$report" || fail 'a cache disk 85% full warned'
rm -f "$work/bin/df"

# The workflow wires exactly the families that build a shared profile target,
# each right after its checkout and under the same condition, and never a job
# that ships an artifact.
python3 -I - "$ROOT/.gitea/workflows/ci.yaml" <<'WIRING'
import sys
import yaml

jobs = yaml.safe_load(open(sys.argv[1]))["jobs"]
expected = {"standard", "rust-compile", "rust-packages", "rust-features", "rust-transport",
            "database", "services-control", "services-runtime"}
wired = set()
for name, job in jobs.items():
    steps = job.get("steps") or []
    names = [step.get("name") for step in steps]
    if "Select the warm Rust cache" not in names:
        assert "Report the warm Rust cache" not in names, name
        continue
    wired.add(name)
    index = names.index("Select the warm Rust cache")
    checkout = steps[index - 1]
    assert str(checkout.get("uses", "")).startswith("noel/actions-checkout@"), name
    # A job that compiles once on the build runner (infra#1632) uses the warm
    # cache only where it still compiles: a main push.
    gate = checkout["if"]
    if "BUILD_ONCE" in (job.get("env") or {}):
        gate = gate[:-len(" }}")] + " && env.BUILD_ONCE != 'true' }}"
    assert steps[index]["if"] == gate, name
    assert steps[index]["run"] == "scripts/ci/setup/select-warm-rust-cache.sh", name
    # The report is the job's last step.
    report = steps[-1]
    assert report["name"] == "Report the warm Rust cache", name
    assert report["if"] == gate.replace("${{ ", "${{ always() && ", 1), name
assert wired == expected, sorted(wired ^ expected)
WIRING

printf '[test-warm-rust-cache] main and pull requests only, weekly and epoch wipes, LRU and Cargo home caps, free-space floor: OK\n'
