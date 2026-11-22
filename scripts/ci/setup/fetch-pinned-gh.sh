#!/usr/bin/env bash
# fetch-pinned-gh.sh DIR: installs DIR/gh, the stock GitHub CLI the workspace
# image ships, from the same pin (images/base/Dockerfile: GH_VERSION and the
# amd64 gh_sha), checked by its SHA-256. The daemon's stock-gh ingress test
# (credential_bridge::tests::stock_gh_rest_and_graphql_use_authenticated_unix_ingress)
# runs against it, so the test and the image cannot name different clients.
# fetch-pinned-gh.sh --pin DOCKERFILE prints that pin, "VERSION SHA", read from
# DOCKERFILE, and installs nothing (scripts/ci/tests/test-fetch-pinned-gh.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly DOCKERFILE="$ROOT/images/base/Dockerfile"

die() {
  printf '[fetch-pinned-gh] ERROR: %s\n' "$*" >&2
  exit 1
}

# Sets version and sha from $1: GH_VERSION, and the gh_sha of the amd64 arm
# (from its `amd64)` line to its `;;`), exactly 64 lower-case hex digits
# wherever it sits on its line.
pin() {
  version="$(sed -nE 's/^ARG GH_VERSION=([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' "$1")"
  sha="$(awk '/^ *amd64\) /{arm=1} arm{print} arm && /;;/{exit}' "$1" |
    grep -m 1 -oE 'gh_sha=[0-9a-f]{64}([^0-9A-Za-z_]|$)' |
    sed -E 's/^gh_sha=([0-9a-f]{64}).*$/\1/' || true)"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "no GH_VERSION in $1"
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "no amd64 gh_sha in $1"
}

if [ "$#" -eq 2 ] && [ "$1" = --pin ]; then
  pin "$2"
  printf '%s %s\n' "$version" "$sha"
  exit 0
fi
[ "$#" -eq 1 ] || die 'usage: fetch-pinned-gh.sh DIR | --pin DOCKERFILE'
dir="$1"
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || die 'the test pin is the amd64 Linux build'
pin "$DOCKERFILE"
mkdir -p "$dir"
work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gh.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
"$ROOT/scripts/ci/release/fetch-pinned.sh" \
  "https://github.com/cli/cli/releases/download/v${version}/gh_${version}_linux_amd64.tar.gz" \
  "$sha" "$work/gh.tgz"
tar -xzf "$work/gh.tgz" -C "$work" "gh_${version}_linux_amd64/bin/gh"
install -m 0755 "$work/gh_${version}_linux_amd64/bin/gh" "$dir/gh"
actual="$("$dir/gh" --version | head -n 1)"
[[ "$actual" == "gh version $version ("* ]] || die "installed '$actual', not $version"
printf '[fetch-pinned-gh] %s at %s\n' "$actual" "$dir/gh"
