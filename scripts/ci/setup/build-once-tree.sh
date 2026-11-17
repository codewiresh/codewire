#!/usr/bin/env bash
# Sourced by build-once.sh and the test runners (compile once, infra#1632).
#
# build_once_tree [ROOT]: the build folder under ROOT (default /ci-cache),
# ROOT/build for every run. A push to main builds there on the main build
# runner and every other run on a pull request build runner, each on its own
# disk. One path for both kinds (#5146): sccache's Rust keys carry absolute
# paths, which SCCACHE_BASEDIRS does not remove, so only a pull request built
# in main's path can read what main compiled. The test binaries carry that
# folder's paths, so a test job puts its checkout and extracted target folder
# at the same place.
build_once_tree() {
  printf '%s/build\n' "${1:-/ci-cache}"
}

# build_once_kind: main for a push to main, pr for every other run. The kind
# comes from the event alone, never from a variable a job could set;
# build-once.sh keeps each disk to the kind that first built on it.
build_once_kind() {
  case "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}" in
    'push|refs/heads/main') printf 'main\n' ;;
    *) printf 'pr\n' ;;
  esac
}
