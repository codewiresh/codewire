#!/usr/bin/env bash
# run-rust-checks.sh (Rust checks, infra#1534, #3494) starts every selected
# check at once, each in its own target folder, waits for them all, then
# prints each one's log between its start and finish lines in a fixed order.
# A failed check fails the script while the others still run and print, and
# the selection gates each check as before. The checks here are stand-ins
# that record when they start and end. RUST_CHECKS_SCRIPT names another copy
# of the script to test.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="${RUST_CHECKS_SCRIPT:-$ROOT/scripts/ci/verify/run-rust-checks.sh}"
readonly SCRIPT
# A CI job running this test may have its own selection in the environment,
# so each case states its own.
unset VERIFICATION_SELECTION BUILD_ONCE_LOCAL_VMM DESKTOP_PACKAGE_SELECTED CW_PACKAGE_SELECTED \
  RUST_CHECKS_FEATURES_TARGET_DIR RUST_CHECKS_DARWIN_TARGET_DIR RUST_CHECKS_CW_DARWIN_TARGET_DIR \
  CODEWIRE_DESKTOP_CHECK_TARGET_DIR CARGO_ZIGBUILD_CACHE_DIR

fail() {
  echo "test-run-rust-checks: $*" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/test-run-rust-checks.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
src="$work/src"
mkdir -p "$src/scripts/ci/verify" "$work/state"
cp "$SCRIPT" "$src/scripts/ci/verify/run-rust-checks.sh"

# One stand-in for every check: it records its end, its target folders and
# selection, prints a line of its own, sleeps (compile-all-targets longest, so
# the checks end in another order than they print), and fails when FAIL_CHECK
# names it. Its start is recorded by the stub the script runs, as early as the
# test can see it, so the time between start and end is the check's own time
# however slow the machine is.
cat > "$work/check" <<'CHECK'
#!/usr/bin/env bash
set -euo pipefail
name="$1"
echo "$name target=${CARGO_TARGET_DIR:-} desktop=${CODEWIRE_DESKTOP_CARGO_TARGET_DIR:-} zigbuild=${CARGO_ZIGBUILD_CACHE_DIR:-} selection=${VERIFICATION_SELECTION:-}" >> "$CHECK_STATE/env"
echo "output of $name"
if [ "$name" = compile ]; then sleep "${COMPILE_SLEEP:-3}"; else sleep "${CHECK_SLEEP:-1}"; fi
echo "$name end $(date +%s%N)" >> "$CHECK_STATE/times"
if [ "${FAIL_CHECK:-}" = "$name" ]; then echo "error in $name"; exit 101; fi
CHECK
chmod +x "$work/check"
cat > "$src/scripts/ci/verify/compile-all-targets.sh" <<STUB
#!/bin/sh
sleep "\${STUB_DELAY:-0}"
echo "compile start \$(date +%s%N)" >> "\$CHECK_STATE/times"
exec "$work/check" compile
STUB
cat > "$src/scripts/ci/verify/run-product-verification.sh" <<STUB
#!/bin/sh
case "\$1 \$RUST_TRANSPORT_SHARD \$RUST_SHARD_STAGE" in
  'rust-transport features checks') name=features ;;
  'rust-transport local-vmm checks') name=local-vmm ;;
  'rust local-vmm checks') name=desktop ;;
  *) echo "unexpected run-product-verification.sh \$*" >&2; exit 2 ;;
esac
sleep "\${STUB_DELAY:-0}"
echo "\$name start \$(date +%s%N)" >> "\$CHECK_STATE/times"
exec "$work/check" "\$name"
STUB
cat > "$src/scripts/ci/verify/check-darwin-cross.sh" <<STUB
#!/bin/sh
[ "\$*" = --cli ] || { echo "unexpected check-darwin-cross.sh \$*" >&2; exit 2; }
sleep "\${STUB_DELAY:-0}"
echo "cw-darwin start \$(date +%s%N)" >> "\$CHECK_STATE/times"
exec "$work/check" cw-darwin
STUB
chmod +x "$src/scripts/ci/verify/"*.sh

readonly ALL_CHECKS='compile-all-targets|feature-graph checks|local-vmm checks|desktop checks|cw Darwin cross-check'
target="$work/targets"

# checks SELECTION [ENV...]: one run; its output in $work/out, its status in rc.
rc=0
checks() {
  local selection="$1"
  shift
  rm -f "$work/state/times" "$work/state/env"
  rc=0
  env CHECK_STATE="$work/state" RUNNER_TEMP="$work/state" CARGO_TARGET_DIR="$target/clippy" \
    RUST_CHECKS_FEATURES_TARGET_DIR="$target/clippy_features" \
    RUST_CHECKS_DARWIN_TARGET_DIR="$target/darwin" \
    RUST_CHECKS_CW_DARWIN_TARGET_DIR="$target/darwin_cw" \
    CODEWIRE_DESKTOP_CHECK_TARGET_DIR="$target/desktop" \
    VERIFICATION_SELECTION="$selection" "$@" \
    "$src/scripts/ci/verify/run-rust-checks.sh" > "$work/out" 2>&1 < /dev/null || rc=$?
}
at() { sed -n "s/^$1 $2 //p" "$work/state/times"; }
ran() { cut -d' ' -f1 "$work/state/times" | sort -u | tr '\n' ' '; }
printed() { sed -nE "s/^\[rust-checks\] (.*): start$/\1/p" "$work/out" | tr '\n' '|'; }

# Every check selected: all five run, and every one starts before any ends.
checks '|rust|transport|' BUILD_ONCE_LOCAL_VMM=true DESKTOP_PACKAGE_SELECTED=true CW_PACKAGE_SELECTED=true
[ "$rc" -eq 0 ] || fail "every check passed but the script failed: $(cat "$work/out")"
[ "$(ran)" = 'compile cw-darwin desktop features local-vmm ' ] || fail "not every check ran: $(ran)"
last_start=0 first_end=''
for check in compile features local-vmm desktop cw-darwin; do
  started="$(at "$check" start)" ended="$(at "$check" end)"
  [ -n "$started" ] && [ -n "$ended" ] || fail "the $check check did not run to its end"
  (( started > last_start )) && last_start="$started"
  if [ -z "$first_end" ] || (( ended < first_end )); then first_end="$ended"; fi
done
(( last_start < first_end )) || fail 'the checks ran one after another: a check ended before another started'
# Each check in its own target folder, each Darwin check with its own
# cargo-zigbuild wrapper folder.
for expected in \
    "compile target=$target/clippy desktop= zigbuild= selection=|rust|transport|" \
    "features target=$target/clippy_features desktop= zigbuild= selection=|rust|transport|" \
    "local-vmm target=$target/darwin desktop=$target/desktop zigbuild=$target/darwin selection=|rust|transport|" \
    "desktop target=$target/desktop desktop=$target/desktop zigbuild= selection=|valid:v3|rust_pkg_codewire_desktop|complete|" \
    "cw-darwin target=$target/darwin_cw desktop= zigbuild=$target/darwin_cw selection=|rust|transport|"; do
  grep -qxF "$expected" "$work/state/env" || fail "a check ran in the wrong folders; wanted: $expected; got: $(cat "$work/state/env")"
done
# One line names the checks started at once; then each check's log, in the
# fixed order, between its start and its finish line.
grep -qxF '[rust-checks] at once: compile-all-targets, feature-graph checks, local-vmm checks, desktop checks, cw Darwin cross-check' "$work/out" ||
  fail "the checks started at once were not named: $(cat "$work/out")"
[ "$(printed)" = "$ALL_CHECKS|" ] || fail "the logs were not printed in the fixed order: $(printed)"
expected_out="$(
  for pair in 'compile-all-targets:compile' 'feature-graph checks:features' 'local-vmm checks:local-vmm' \
      'desktop checks:desktop' 'cw Darwin cross-check:cw-darwin'; do
    echo "[rust-checks] ${pair%%:*}: start"
    echo "output of ${pair#*:}"
    echo "[rust-checks] ${pair%%:*}: finish (status=0 elapsed_seconds=N)"
  done
)"
[ "$(sed -n '/: start$/,$p' "$work/out" | sed -E 's/elapsed_seconds=[0-9]+\)$/elapsed_seconds=N)/')" = "$expected_out" ] ||
  fail "a log was not printed between its start and finish lines: $(cat "$work/out")"
# Each finish line carries its own check's time. The script counts whole
# seconds from just before a check's stub starts until just after the check
# ends; the stub records its own start and end inside that. A busy runner only
# adds to the script's count: starting and ending those processes took seconds
# (#4048: 7 s reported for a 3 s check). So each report is at least the check's
# own measured time, rounded down, however slow the runner. A time shared by
# the checks (#3876: every check reporting the longest one's end) is caught by
# comparison instead: each 1 s check reports less than the 3 s compile check.
elapsed() { sed -nE "s/^\[rust-checks\] $1: finish \(status=[0-9]+ elapsed_seconds=([0-9]+)\)$/\1/p" "$work/out"; }
assert_own_times() {
  local pair reported took compile
  compile="$(elapsed compile-all-targets)"
  for pair in 'compile-all-targets:compile' 'feature-graph checks:features' 'local-vmm checks:local-vmm' \
      'desktop checks:desktop' 'cw Darwin cross-check:cw-darwin'; do
    reported="$(elapsed "${pair%%:*}")"
    took=$(( $(at "${pair#*:}" end) - $(at "${pair#*:}" start) ))
    if ! { [ -n "$reported" ] && (( reported >= took / 1000000000 )); }; then
      fail "the ${pair%%:*} finish line reported less than its own time (${took} ns): $(grep finish "$work/out")"
    fi
    if [ "${pair#*:}" != compile ] && (( reported >= compile )); then
      fail "the ${pair%%:*} finish line reported the compile check's time, not its own: $(grep finish "$work/out")"
    fi
  done
}
assert_own_times
! grep -q '::error::' "$work/out" || fail 'a passing run reported an error'

# A slow runner, reproduced: every stub starts 3 s after the script starts
# timing it, more than the old 1.5 s upper bound allowed. Each report still
# carries its check's own time.
checks '|rust|transport|' BUILD_ONCE_LOCAL_VMM=true DESKTOP_PACKAGE_SELECTED=true CW_PACKAGE_SELECTED=true \
  STUB_DELAY=3
[ "$rc" -eq 0 ] || fail "a slow runner failed the script: $(cat "$work/out")"
assert_own_times

# A failed check fails the script; every other check still runs to its end
# and prints, and only the failed one reports an error.
checks '|rust|transport|' BUILD_ONCE_LOCAL_VMM=true DESKTOP_PACKAGE_SELECTED=true CW_PACKAGE_SELECTED=true \
  FAIL_CHECK=features
[ "$rc" -ne 0 ] || fail 'a failed check passed the script'
for check in compile features local-vmm desktop cw-darwin; do
  [ -n "$(at "$check" end)" ] || fail "the $check check was stopped by another check's failure"
  grep -qxF "output of $check" "$work/out" || fail "the $check check's log was not printed"
done
[ "$(printed)" = "$ALL_CHECKS|" ] || fail "a failure changed the printed checks: $(printed)"
grep -qxF 'error in features' "$work/out" || fail "the failed check's log was not printed"
grep -qE '^\[rust-checks\] feature-graph checks: finish \(status=101 elapsed_seconds=[0-9]+\)$' "$work/out" ||
  fail "the failed check's finish line lost its status: $(grep finish "$work/out")"
if ! { [ "$(grep -c '::error::' "$work/out")" -eq 1 ] && grep -qxF '::error::the feature-graph checks check failed' "$work/out"; }; then
  fail "the failure was not reported as exactly one error: $(grep '::error::' "$work/out")"
fi
[ "$(grep -c 'finish (status=0 ' "$work/out")" -eq 4 ] || fail 'the other checks did not all finish passing'

# The selection gates each check as it did before they ran at once.
# selection_case SELECTION EXPECTED_CHECKS [ENV...]
selection_case() {
  local selection="$1" expected="$2"
  shift 2
  checks "$selection" COMPILE_SLEEP=0 CHECK_SLEEP=0 "$@"
  [ "$rc" -eq 0 ] || fail "selection '$selection' $*: the script failed: $(cat "$work/out")"
  [ "$(printed)" = "$expected" ] || fail "selection '$selection' $*: ran $(printed), wanted $expected"
}
selection_case '' 'compile-all-targets|'
selection_case '|rust|' 'compile-all-targets|feature-graph checks|'
selection_case '|transport|' 'compile-all-targets|'
selection_case '|transport|' 'compile-all-targets|local-vmm checks|' BUILD_ONCE_LOCAL_VMM=true
selection_case '|rust|' 'compile-all-targets|feature-graph checks|local-vmm checks|' BUILD_ONCE_LOCAL_VMM=true
selection_case '|rust|rust_pkg_codewire_desktop|' 'compile-all-targets|feature-graph checks|local-vmm checks|' \
  BUILD_ONCE_LOCAL_VMM=true DESKTOP_PACKAGE_SELECTED=true
selection_case '' 'compile-all-targets|desktop checks|' BUILD_ONCE_LOCAL_VMM=true DESKTOP_PACKAGE_SELECTED=true
selection_case '|rust|transport|' 'compile-all-targets|feature-graph checks|' DESKTOP_PACKAGE_SELECTED=true
selection_case '' 'compile-all-targets|cw Darwin cross-check|' CW_PACKAGE_SELECTED=true
selection_case '' 'compile-all-targets|' CW_PACKAGE_SELECTED=false BUILD_ONCE_LOCAL_VMM=false

echo 'test-run-rust-checks: the checks start at once in their own folders, print in a fixed order, fail on any failure without stopping the others, and keep their selection'
