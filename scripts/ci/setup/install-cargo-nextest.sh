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
# Installs DIR/cargo-nextest and checks its version. With
# CODEWIRE_TOOL_CACHE (a folder of a metal guest's warm cache), the verified
# tarball is kept there by its SHA-256 and checked again on every use, so a
# guest downloads it once instead of in every job (10 s in main run 23329's
# Database job); a kept file that does not match is fetched again.
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
tarball="$work/nextest.tar.gz"
if [ -n "${CODEWIRE_TOOL_CACHE:-}" ]; then
  mkdir -p "$CODEWIRE_TOOL_CACHE"
  tarball="$CODEWIRE_TOOL_CACHE/$NEXTEST_SHA256.tar.gz"
  if [ -f "$tarball" ] && [ "$(sha256sum "$tarball" | cut -d' ' -f1)" = "$NEXTEST_SHA256" ]; then
    echo "install-cargo-nextest: the kept $NEXTEST_VERSION tarball matches its SHA-256"
  else
    rm -f -- "$tarball"
    "$ROOT/scripts/ci/release/fetch-pinned.sh" "$NEXTEST_URL" "$NEXTEST_SHA256" "$work/nextest.tar.gz"
    mv -f -- "$work/nextest.tar.gz" "$tarball"
  fi
else
  "$ROOT/scripts/ci/release/fetch-pinned.sh" "$NEXTEST_URL" "$NEXTEST_SHA256" "$tarball"
fi
tar -xzf "$tarball" -C "$work" cargo-nextest
install -m 0755 "$work/cargo-nextest" "$dir/cargo-nextest"
actual="$("$dir/cargo-nextest" nextest --version | head -n 1)"
[[ "$actual" == "cargo-nextest $NEXTEST_VERSION "* ]] || die "installed '$actual', not $NEXTEST_VERSION"
echo "install-cargo-nextest: $actual at $dir/cargo-nextest"
