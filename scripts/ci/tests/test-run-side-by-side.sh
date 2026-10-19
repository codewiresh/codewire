#!/usr/bin/env bash
# Synthetic proof for run_side_by_side: every listed command runs, output
# keeps list order, a failure fails the family only after all have reported, each
# command keeps errexit, and no more than the limit run at once.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# shellcheck source=scripts/ci/verify/side-by-side.sh
source "$ROOT/scripts/ci/verify/side-by-side.sh"
CASES=0

fail() {
  printf '[test-run-side-by-side] ERROR: %s\n' "$*" >&2
  exit 1
}
pass() { CASES=$((CASES + 1)); }

work="$(mktemp -d "${TMPDIR:-/tmp}/run-side-by-side.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

# Output keeps the given order even when later commands finish first.
output="$(VERIFICATION_TEST_JOBS=3 run_side_by_side <<'STEPS'
  sleep 0.4; echo first

  sleep 0.2; echo second
  echo third
STEPS
)" ||
  fail 'passing commands failed'
[[ "$(grep -v '^==>' <<<"$output")" == $'first\nsecond\nthird' ]] ||
  fail "output is not in the given order: $output"
[[ "$(grep -c '^==> .*: passed in [0-9]*s$' <<<"$output")" -eq 3 ]] ||
  fail 'each command does not report its result'
pass

# A failure fails the family, but every command still runs and reports.
status=0
output="$(VERIFICATION_TEST_JOBS=2 run_side_by_side <<STEPS
  echo before
  echo broken; exit 7
  touch '$work/after'; echo after
STEPS
)" || status=$?
[[ "$status" -eq 1 ]] || fail "a failure returned $status, not 1"
[[ -e "$work/after" ]] || fail 'a command after the failure did not run'
grep -Eq '^::error::echo broken; exit 7 failed \(exit 7\) after [0-9]+s$' <<<"$output" ||
  fail "the failure is not named: $output"
grep -Fxq 'after' <<<"$output" || fail 'output after the failure was dropped'
pass

# Each command keeps errexit: a failing step fails it even when a later
# step succeeds, as when the family ran in order. The call is not a condition,
# which would turn errexit off for everything under it, in order or not.
steps() {
  false
  true
}
set +e
VERIFICATION_TEST_JOBS=1 run_side_by_side <<<steps >/dev/null
status=$?
set -e
[[ "$status" -eq 1 ]] || fail 'a failing step inside a command was not reported'
pass

# Functions and variables of the calling shell are visible to the commands.
greeting=hello
greet() { printf '%s\n' "$greeting"; }
grep -Fxq hello <<<"$(run_side_by_side <<<greet)" || fail 'a calling-shell function did not run'
pass

# No more than the limit run at once, and more than one does.
mkdir "$work/running"
probe() {
  local mine count
  mine="$(mktemp "$work/running/probe.XXXXXX")"
  count="$(find "$work/running" -type f | wc -l)"
  printf '%s\n' "$count" >>"$work/counts"
  sleep 0.3
  rm -f -- "$mine"
}
printf 'probe\n%.0s' 1 2 3 4 5 6 | VERIFICATION_TEST_JOBS=2 run_side_by_side >/dev/null ||
  fail 'the limit probes failed'
[[ "$(sort -n "$work/counts" | tail -1)" -le 2 ]] || fail 'more commands ran at once than the limit'
[[ "$(sort -n "$work/counts" | tail -1)" -ge 2 ]] || fail 'commands did not run side by side'
pass

# The limit must be a positive integer.
for limit in 0 -1 two ''; do
  status=0
  VERIFICATION_TEST_JOBS="$limit" run_side_by_side <<<true >/dev/null 2>&1 || status=$?
  if [[ -z "$limit" ]]; then
    # Empty falls back to the CPU count.
    [[ "$status" -eq 0 ]] || fail 'an empty limit did not fall back to the CPU count'
  else
    [[ "$status" -eq 2 ]] || fail "limit '$limit' was accepted"
  fi
  pass
done

# An empty list is an error, not a silent pass.
status=0
run_side_by_side </dev/null >/dev/null 2>&1 || status=$?
[[ "$status" -eq 2 ]] || fail 'an empty list was accepted'
pass

printf 'test-run-side-by-side: PASS cases=%s\n' "$CASES"
