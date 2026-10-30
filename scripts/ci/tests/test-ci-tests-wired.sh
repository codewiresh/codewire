#!/usr/bin/env bash
# Every test script under scripts/*/tests (test-*) runs somewhere: a runner, a
# workflow, a hook or another test names it. The selector and its own test
# name every path to classify it, and documentation runs nothing, so those
# count only where the selector's test runs a test (defer_check,
# defer_slow_check). A test that nothing else names never runs:
# test-fetch-forgejo-deploy-dev-token.sh sat classified, passing and unrun
# until this check (test-fail-fast-watch.py and test-push-check-shellcheck.sh
# did too, until the selector's test began to run them). A file that merely mentions a test still counts, so this catches a
# test nothing knows of, not every way to leave one out.
#
# Usage: test-ci-tests-wired.sh [--self-test]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

fail() {
  printf '[test-ci-tests-wired] ERROR: %s\n' "$*" >&2
  exit 1
}

# unwired_tests REPO: the test scripts in REPO's tree that no other file names.
unwired_tests() {
  local repo="$1" test
  local selector_test=scripts/ci/tests/test-select-verification.sh name selector_runs=''
  [ -f "$repo/$selector_test" ] &&
    selector_runs="$(grep -E '^[[:space:]]*defer_(slow_)?check ' "$repo/$selector_test" || true)"
  while IFS= read -r test; do
    name="$(basename "$test")"
    git -C "$repo" grep -q -F "$name" -- . ':!*.md' \
      ':!scripts/ci/select/select-verification.sh' \
      ":!$selector_test" \
      ':!scripts/ci/tests/test-ci-tests-wired.sh' ":!$test" && continue
    grep -qF "/$name" <<<"$selector_runs" && continue
    printf '%s\n' "$test"
  done < <(git -C "$repo" ls-files 'scripts/**/tests/test-*')
}

self_test() {
  local work repo found
  mkdir -p "$ROOT/.tmp"
  work="$(mktemp -d "$ROOT/.tmp/ci-tests-wired.XXXXXX")"
  repo="$work/repo"
  mkdir -p "$repo/scripts/ci/tests" "$repo/scripts/ci/verify" "$repo/scripts/ci/select" "$repo/docs"
  git -C "$repo" init -q
  printf '#!/bin/sh\n' > "$repo/scripts/ci/tests/test-run.sh"
  printf '#!/bin/sh\n' > "$repo/scripts/ci/tests/test-unrun.sh"
  printf 'scripts/ci/tests/test-run.sh\nscripts/ci/tests/test-select-verification.sh\n' \
    > "$repo/scripts/ci/verify/runner.sh"
  # Named only where nothing runs it: the selector, a path case of the
  # selector's test, and a document. A test the selector's test runs counts.
  printf '#!/bin/sh\n' > "$repo/scripts/ci/tests/test-run-by-selector-test.sh"
  printf 'scripts/ci/tests/test-unrun.sh) ;;\n' > "$repo/scripts/ci/select/select-verification.sh"
  printf "run_paths_case unrun pr ref false 'policy' scripts/ci/tests/test-unrun.sh\ndefer_slow_check \"\$ROOT/scripts/ci/tests/test-run-by-selector-test.sh\"\n" \
    > "$repo/scripts/ci/tests/test-select-verification.sh"
  printf 'See test-unrun.sh.\n' > "$repo/docs/TESTING.md"
  git -C "$repo" add -A
  found="$(unwired_tests "$repo")"
  [ "$found" = scripts/ci/tests/test-unrun.sh ] ||
    fail "self-test: expected only test-unrun.sh unwired, found: ${found:-none}"
  # Old fail, new pass: a runner that names it wires it.
  printf 'scripts/ci/tests/test-unrun.sh\n' >> "$repo/scripts/ci/verify/runner.sh"
  git -C "$repo" add -A
  found="$(unwired_tests "$repo")"
  [ -z "$found" ] || fail "self-test: a runner named the test, still unwired: $found"
  # A test named early in a run list longer than a pipe holds still counts.
  # Piped into `grep -q`, the list's reader dies of SIGPIPE once the match is
  # found, and pipefail would call the test unwired.
  for filler in $(seq 1 2000); do
    printf 'defer_check scripts/ci/tests/filler-%s-of-a-long-run-list\n' "$filler"
  done >> "$repo/scripts/ci/tests/test-select-verification.sh"
  git -C "$repo" add -A
  found="$(unwired_tests "$repo")"
  [ -z "$found" ] || fail "self-test: a long run list hid a test it runs: $found"
  rm -rf -- "$work"
  printf '[test-ci-tests-wired] self-test: an unrun test fails, a run one passes\n'
}

case "${1:-}" in
  --self-test) self_test ;;
  '')
    self_test
    unwired="$(unwired_tests "$ROOT")"
    [ -z "$unwired" ] || fail "no runner runs these tests; name each in the runner of its family:
$unwired"
    printf '[test-ci-tests-wired] every scripts/*/tests test is run by something\n'
    ;;
  *) fail 'usage: test-ci-tests-wired.sh [--self-test]' ;;
esac
