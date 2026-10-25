#!/usr/bin/env bash
# Sourced by build-once.sh and the test runners (compile once, infra#1632).
#
# build_once_tree [ROOT]: the build folder of this run's kind under ROOT
# (default /ci-cache). A push to main builds in ROOT/main on the main build
# runner; every other run builds in ROOT/pr on the pull request build runner.
# The test binaries carry that folder's paths, so a test job puts its checkout
# and extracted target folder at the same place. The kind comes from the
# event alone, never from a variable a job could set.
build_once_tree() {
  local root="${1:-/ci-cache}"
  case "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}" in
    'push|refs/heads/main') printf '%s/main\n' "$root" ;;
    *) printf '%s/pr\n' "$root" ;;
  esac
}
