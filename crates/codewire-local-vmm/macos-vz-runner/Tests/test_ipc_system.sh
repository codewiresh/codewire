#!/usr/bin/env bash
set -euo pipefail

package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
repository=$(cd -- "$package/../../.." && pwd)
mkdir -p "$repository/.tmp"
scratch=$(mktemp -d "$repository/.tmp/cw-vz-ipc.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT

if [[ $(uname -s) == Darwin ]]; then
  compiler=(xcrun clang)
  libraries=(-lproc)
else
  compiler=("${CC:-cc}")
  libraries=()
fi

"${compiler[@]}" -std=c11 -Wall -Wextra -Werror \
  -I "$package/Sources/CVZRunnerIPC/include" \
  -I "$package/Tests/CVZRunnerIPCTestSupport/include" \
  "$package/Sources/CVZRunnerIPC/CVZRunnerIPC.c" \
  "$package/Sources/CVZRunnerIPC/ProductionBridge.c" \
  "$package/Tests/CVZRunnerIPCTestSupport/CVZRunnerIPCTestSupport.c" \
  "$package/Tests/IPCSystemTests/main.c" \
  "${libraries[@]}" -o "$scratch/test-ipc-system"
"$scratch/test-ipc-system"
