#!/usr/bin/env bash
# The macOS local VM journey (docs/journeys/local-vm-mac.md) with a release's
# own arm64 cw and runtime: scripts/dev/test-cli-local-vm-macos.py installs the
# runtime into a private HOME and keychain, creates a VM, runs in it, checks
# that egress fails closed, stalls and resumes the VM, checks the VZ helper's
# posture and removes it, leaving no process behind. The release dry run's Mac
# job runs it with the run's own macOS pair and packed runtime (#4478).
#
# usage: macos-local-vm-journey.sh PAIR_DIR RUNTIME_DIR
#   PAIR_DIR     the macOS pair package-cw-release.sh wrote (cw-VERSION-TARGET)
#   RUNTIME_DIR  the local runtime directory that cw embeds
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

die() {
  printf '[local-vm-journey] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$#" = 2 ] || die "usage: macos-local-vm-journey.sh PAIR_DIR RUNTIME_DIR"
[ "$(uname -s)-$(uname -m)" = Darwin-arm64 ] || die "a local VM is walked on an Apple silicon Mac"
[ -d "$1" ] || die "no macOS pair at $1"
[ -f "$2/local-runtime.json" ] || die "no local runtime at $2"
pair="$(cd "$1" && pwd)"
runtime="$(cd "$2" && pwd)"

shopt -s nullglob
cws=("$pair"/cw-*-aarch64-apple-darwin)
[ "${#cws[@]}" = 1 ] || die "expected exactly one arm64 cw in $pair, found ${#cws[@]}"
chmod 0755 "${cws[0]}"
sw_vers -productVersion
"${cws[0]}" --version
exec /usr/bin/python3 -I "$ROOT/scripts/dev/test-cli-local-vm-macos.py" --cw "${cws[0]}" --runtime "$runtime"
