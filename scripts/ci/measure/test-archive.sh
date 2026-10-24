#!/usr/bin/env bash
# Measurement 3 of the compile-once design (infra#1632): build the workspace
# test archive in this job, then run it as a test runner will, from a fresh
# directory with cargo-nextest and no Rust toolchain on PATH, and report what
# the decision needs:
# - the archive's size and its build time and peak memory;
# - per run, the extraction and test times, peak memory and cores, and which
#   tests failed, so a repeated run shows the flake rate.
#
# Variants (owner decisions of 2026-10-24): `full` builds with the dev
# profile's full debug info from the job's warm target; `line-tables` builds
# with CARGO_PROFILE_DEV_DEBUG=line-tables-only in a target of its own. Both
# use the default features: --all-features turns on smoke-only features that
# change cw itself, and each explicit feature lane gets its own archive.
#
# Usage: test-archive.sh NEXTEST_DIR OUT_DIR VARIANTS RUNS
#   NEXTEST_DIR holds cargo-nextest (install-cargo-nextest.sh), VARIANTS is a
#   space-separated list of full and line-tables, RUNS is 1 to 9.
# Writes OUT_DIR/summary.md (also to GITHUB_STEP_SUMMARY when set) and one
# JSON record per build and run. Each run extracts into a fresh directory
# under TEST_ARCHIVE_RUN_ROOT (default OUT_DIR), removed after the run. Exits non-zero when a build fails or a run
# has a failing test.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly SAMPLER="$ROOT/scripts/ci/measure/sample-process-tree.py"

die() {
  echo "test-archive: $*" >&2
  exit 2
}

[ "$#" -eq 4 ] || die 'usage: test-archive.sh NEXTEST_DIR OUT_DIR VARIANTS RUNS'
nextest_dir="$1" out="$2" variants="$3" runs="$4"
[ -x "$nextest_dir/cargo-nextest" ] || die "no cargo-nextest in $nextest_dir"
[[ "$runs" =~ ^[1-9]$ ]] || die "RUNS must be 1 to 9, got: $runs"
[ -n "$variants" ] || die 'name at least one variant'
for variant in $variants; do
  case "$variant" in full|line-tables) ;; *) die "unknown variant: $variant" ;; esac
done
mkdir -p "$out"
out="$(cd "$out" && pwd)"

# A run sees no Rust toolchain: cargo, rustc and rustup first on its PATH
# refuse and record the call, so a test that builds at run time fails and is
# named. System tools stay on the PATH (cargo may share /usr/bin with them).
no_rust="$out/no-rust-toolchain"
mkdir -p "$no_rust"
for tool in cargo rustc rustup; do
  printf '#!/bin/sh\necho "%s $*" >> "%s/toolchain-calls.txt"\necho "test-archive: a test called %s; a test runner has no Rust toolchain" >&2\nexit 127\n' \
    "$tool" "$out" "$tool" > "$no_rust/$tool"
  chmod 0755 "$no_rust/$tool"
done
run_path="$no_rust:$nextest_dir:$PATH"
: > "$out/toolchain-calls.txt"

json() {
  python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

summary="$out/summary.md"
{
  echo '| Variant | Archive | Build | Build peak | Run | Extract | Tests | Passed | Failed | Run peak | Run peak cores |'
  echo '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|'
} > "$summary"
failed_any=0
for variant in $variants; do
  case "$variant" in
    full) debug=true target="${CARGO_TARGET_DIR:-$ROOT/target}" ;;
    line-tables) debug=line-tables-only target="${CARGO_TARGET_DIR:-$ROOT/target}-line-tables" ;;
  esac
  archive="$out/tests-$variant.tar.zst"
  echo "test-archive: building $variant (debug=$debug) in $target"
  set +e
  CARGO_PROFILE_DEV_DEBUG="$debug" CARGO_TARGET_DIR="$target" PATH="$nextest_dir:$PATH" \
    python3 -I "$SAMPLER" "$out/build-$variant.json" -- \
    cargo nextest archive --locked --workspace --archive-file "$archive" 2>&1 | tee "$out/build-$variant.log"
  status="${PIPESTATUS[0]}"
  set -e
  [ "$status" -eq 0 ] || { echo "test-archive: the $variant archive did not build" >&2; exit 1; }
  size_gb="$(python3 -I -c 'import os, sys; print(f"{os.path.getsize(sys.argv[1]) / 1e9:.2f} GB")' "$archive")"
  build="$(json "$out/build-$variant.json" wall_seconds) s"
  build_peak="$(json "$out/build-$variant.json" peak_rss_gib) GiB"
  for run in $(seq 1 "$runs"); do
    dest="${TEST_ARCHIVE_RUN_ROOT:-$out}/test-archive-run-$variant-$run"
    [ ! -e "$dest" ] || die "the run directory already exists: $dest"
    mkdir -m 0700 "$dest"
    echo "test-archive: running $variant, run $run of $runs, from $dest"
    set +e
    python3 -I "$SAMPLER" "$out/run-$variant-$run.json" -- \
      env -u CARGO_TARGET_DIR -u CARGO_HOME -u CARGO -u RUSTC PATH="$run_path" \
      cargo-nextest nextest run --archive-file "$archive" --workspace-remap "$ROOT" \
        --extract-to "$dest" --profile ci --no-fail-fast 2>&1 | tee "$out/run-$variant-$run.log"
    set -e
    log="$out/run-$variant-$run.log"
    # nextest prints "in 30.28s" or, past a minute, "in 1m 18.87s".
    extract="$(sed -nE 's/.*Extracted [0-9]+ files to .* in (([0-9]+)m )?([0-9.]+)s.*/\2 \3/p' "$log" |
      head -n 1 | awk 'NF { printf "%.1f s", ($2 == "" ? $1 : $1 * 60 + $2) }')"
    tests="$(sed -nE 's/^ *Summary \[ *([0-9.]+)s\].*/\1 s/p' "$log" | tail -n 1)"
    passed="$(sed -nE 's/^ *Summary .* ([0-9]+) passed.*/\1/p' "$log" | tail -n 1)"
    failed="$(sed -nE 's/^ *Summary .* ([0-9]+) failed.*/\1/p' "$log" | tail -n 1)"
    failed="${failed:-0}"
    [ "$failed" = 0 ] && [ -n "$passed" ] || failed_any=1
    grep -E '^ +(FAIL|TIMEOUT|SIGSEGV|SIGABRT) ' "$log" | sed -E 's/^ +([A-Z]+) \[[^]]*\] \([^)]*\) /\1 /' \
      > "$out/failed-$variant-$run.txt" || true
    printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s GiB | %s |\n' \
      "$variant" "$size_gb" "$build" "$build_peak" "$run" "${extract:-?}" "${tests:-?}" "${passed:-?}" "$failed" \
      "$(json "$out/run-$variant-$run.json" peak_rss_gib)" "$(json "$out/run-$variant-$run.json" peak_cores)" >> "$summary"
    rm -rf -- "$dest"
  done
done
{
  echo
  if [ -s "$out/toolchain-calls.txt" ]; then
    echo 'Toolchain calls from tests (these fail on a test runner):'
    sort -u "$out/toolchain-calls.txt" | sed 's/^/- /'
  fi
  for list in "$out"/failed-*.txt; do
    [ -s "$list" ] || continue
    echo "Failed in ${list##*/failed-}:"
    sed 's/^/- /' "$list"
  done
} >> "$summary"
cat "$summary"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$summary" >> "$GITHUB_STEP_SUMMARY"
fi
exit "$failed_any"
