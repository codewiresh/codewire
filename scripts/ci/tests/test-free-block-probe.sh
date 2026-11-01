#!/usr/bin/env bash
# scripts/dev/free-block-probe.sh: plant leaves only the control, keeps the
# markers outside the planted directory and refuses to reuse them; scan's
# exit status says token found, clear, or nothing to vouch for, from images
# built here.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
probe="$repo_root/scripts/dev/free-block-probe.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

expect_status() {
  local want=$1
  shift
  local status=0
  "$@" >"$work/out" 2>&1 || status=$?
  [ "$status" -eq "$want" ] || fail "$* exited $status, expected $want: $(cat "$work/out")"
}

mkdir "$work/disk"
sh "$probe" plant "$work/disk" "$work/markers" >/dev/null
[ "$(ls -A "$work/disk")" = free-block-probe-control ] ||
  fail "plant left more than the control: $(ls -A "$work/disk")"
token="$(cat "$work/markers/token")"
control="$(cat "$work/markers/control")"
[[ "$token" =~ ^cw-free-block-probe-token-[0-9a-f]{32}$ ]] || fail "token marker: $token"
[[ "$control" =~ ^cw-free-block-probe-control-[0-9a-f]{32}$ ]] || fail "control marker: $control"
grep -qxF "$control" "$work/disk/free-block-probe-control" || fail "the control file lacks its marker"
[ "$(stat -c %a "$work/markers")" = 700 ] || fail "markers directory mode"

# Markers are never reused, and never inside what the scan reads.
expect_status 64 sh "$probe" plant "$work/disk" "$work/markers"
expect_status 64 sh "$probe" plant "$work/disk" "$work/disk/markers"
expect_status 64 sh "$probe" plant "$work/missing" "$work/other"

# Images: zeros with the control, with a freed token copy straddling a
# 4 KiB boundary, and with neither.
image() {
  local path=$1
  shift
  head -c 1048576 /dev/zero >"$path"
  local text offset
  while [ "$#" -gt 0 ]; do
    text=$1
    offset=$2
    shift 2
    printf '%s' "$text" | dd of="$path" bs=1 seek="$offset" conv=notrunc status=none
  done
}
image "$work/clear.raw" "$control" 8192
image "$work/leaked.raw" "$control" 8192 "$token" $((4096 * 3 - 10)) "$token" 600000
image "$work/blind.raw" "$token" 600000
image "$work/empty.raw"

expect_status 0 sh "$probe" scan "$work/clear.raw" "$work/markers"
if ! grep -qx 'token 0' "$work/out" || ! grep -qx 'control 1' "$work/out"; then
  fail "clear: $(cat "$work/out")"
fi
expect_status 1 sh "$probe" scan "$work/leaked.raw" "$work/markers"
grep -qx 'token 2' "$work/out" || fail "leaked: $(cat "$work/out")"
expect_status 2 sh "$probe" scan "$work/blind.raw" "$work/markers"
expect_status 2 sh "$probe" scan "$work/empty.raw" "$work/markers"

# The planted directory's own files, read as a disk, hold the control.
expect_status 0 sh "$probe" scan "$work/disk/free-block-probe-control" "$work/markers"

expect_status 64 sh "$probe" scan "$work/missing.raw" "$work/markers"
expect_status 64 sh "$probe" scan "$work/clear.raw" "$work/disk"
expect_status 64 sh "$probe" scan "$work/clear.raw"
expect_status 64 sh "$probe" plant-and-scan a b

echo "free-block probe: OK"
