#!/usr/bin/env bash
# The VZ helper's own tests on a Mac: its swift-testing suites and its static
# boundary contract (crates/codewire-local-vmm/macos-vz-runner/README.md,
# "Tests"). The release dry run's Mac job runs this (#4478). The Command Line
# Tools for Xcode 27.2 do not find swift-testing's macros plugin on their own,
# so the toolchain's plugin directory is passed when it exists.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PACKAGE="$ROOT/crates/codewire-local-vmm/macos-vz-runner"

die() {
  printf '[vz-helper-tests] ERROR: %s\n' "$*" >&2
  exit 1
}

[ "$(uname -s)-$(uname -m)" = Darwin-arm64 ] || die "the VZ helper is tested on an Apple silicon Mac"
xcrun swift --version
plugin=()
testing_plugins="$(dirname "$(xcrun --find swift)")/../lib/swift/host/plugins/testing"
if [ -d "$testing_plugins" ]; then
  plugin=(-Xswiftc -plugin-path -Xswiftc "$(cd "$testing_plugins" && pwd)")
fi
# macOS's bash 3.2 treats an empty array as unbound under set -u.
xcrun swift test --package-path "$PACKAGE" -Xswiftc -warnings-as-errors -Xcc -Werror \
  ${plugin[@]+"${plugin[@]}"}
python3 "$PACKAGE/Tests/test_static_contract.py"
