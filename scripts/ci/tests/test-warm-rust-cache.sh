#!/usr/bin/env bash
# The metal guest's warm Rust cache: used only by a main push or a pull request
# on a guest that mounts it, never by a job that ships, wiped weekly or on an operator epoch,
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

run() {
  local job="$1" event="$2" ref="$3"
  shift 3
  rm -rf "$work/workspace"
  mkdir -p "$work/workspace/target/ci-cache"
  env -i PATH="$PATH" HOME="$work" WARM_CACHE_ROOT="$work/cache" GITHUB_WORKSPACE="$work/workspace" \
    GITHUB_JOB="$job" GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref" "$@" "$SELECT"
}

# Other refs, other events and shipping jobs never touch the cache.
out="$(run rust-compile push refs/heads/feature)"; grep -qF 'not a push to main or a pull request' <<<"$out" || fail 'another ref used the cache'
out="$(run rust-compile schedule refs/heads/main)"; grep -qF 'not a push to main or a pull request' <<<"$out" || fail 'a scheduled run used the cache'
for job in cw-release-assets workspace-image; do
  out="$(run "$job" push refs/heads/main)"; grep -qF 'ships an artifact' <<<"$out" || fail "$job used the cache on main"
  out="$(run "$job" pull_request refs/pull/1/head)"; grep -qF 'ships an artifact' <<<"$out" || fail "$job used the cache on a pull request"
done
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
    assert str(checkout.get("uses", "")).startswith("https://git.example.invalid/noel/actions-checkout@"), name
    assert steps[index]["if"] == checkout["if"], name
    assert steps[index]["run"] == "scripts/ci/setup/select-warm-rust-cache.sh", name
    # The report is the job's last step.
    report = steps[-1]
    assert report["name"] == "Report the warm Rust cache", name
    assert report["if"] == checkout["if"].replace("${{ ", "${{ always() && ", 1), name
assert wired == expected, sorted(wired ^ expected)
assert not wired & {"cw-release-assets", "workspace-image"}
WIRING

printf '[test-warm-rust-cache] main and pull requests only, shipping excluded, weekly and epoch wipes, LRU and Cargo home caps: OK\n'
