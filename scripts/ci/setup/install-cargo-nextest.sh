#!/usr/bin/env bash
# Install the pinned cargo-nextest (infra#1632; owner decision 8 of
# 2026-10-23: pin it in rust-base and the runner image). A job that builds or
# runs a test archive installs it here until the runner image carries it.
#
# Pin: 0.9.148, published 2026-10-08, the newest release past the 7-day rule
# when pinned. The tarball's SHA-256 matches the release's published .sha256
# file and GitHub's asset digest, and crates.io names
# https://github.com/nextest-rs/nextest as the crate's repository.
# rust-base.Dockerfile carries the same pin; test-install-cargo-nextest.sh
# keeps the two equal.
#
# Usage: install-cargo-nextest.sh DIR
# Installs DIR/cargo-nextest and checks its version.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly NEXTEST_VERSION='0.9.148'
readonly NEXTEST_URL="https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-${NEXTEST_VERSION}/cargo-nextest-${NEXTEST_VERSION}-x86_64-unknown-linux-musl.tar.gz"
readonly NEXTEST_SHA256='bf92cb81450872d960ffa13857a83084d557ec0cdc141663d263bb23ef756f97'

die() {
  echo "install-cargo-nextest: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || die 'usage: install-cargo-nextest.sh DIR'
dir="$1"
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || die 'the pin is the x86_64 Linux build'
mkdir -p "$dir"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cargo-nextest.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
"$ROOT/scripts/ci/release/fetch-pinned.sh" "$NEXTEST_URL" "$NEXTEST_SHA256" "$work/nextest.tar.gz"
tar -xzf "$work/nextest.tar.gz" -C "$work" cargo-nextest
install -m 0755 "$work/cargo-nextest" "$dir/cargo-nextest"
actual="$("$dir/cargo-nextest" nextest --version | head -n 1)"
[[ "$actual" == "cargo-nextest $NEXTEST_VERSION "* ]] || die "installed '$actual', not $NEXTEST_VERSION"
echo "install-cargo-nextest: $actual at $dir/cargo-nextest"
