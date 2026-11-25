#!/usr/bin/env bash
# Print the path of one SHA-256-pinned download, fetching it only when needed
# (infra#1534). On a runner with the persistent build disk (BUILD_ONCE_TREE,
# /ci-cache/build), the download is kept in its tools folder, named by its
# digest, and reused: build-once.sh's tool() keeps its own pinned tools the
# same way. Fetched afresh each job, ziglang.org's tarball took 463-860 s in
# 4 of 7 sampled Build test archives jobs (2026-11-24), all of it before the
# first compile.
#
# A pull request's job can write the build disk, so the kept file is never
# used in place. It is copied into this job's RUNNER_TEMP, and the copy is
# checked against the digest; the printed path is the copy's, so what the
# caller extracts is exactly what was checked. A kept file that is a link, or
# whose copy does not match, is removed and fetched again, and a tools folder
# that is a link is refused. Without the build disk, the download goes to
# RUNNER_TEMP for this job alone.
#
# Usage: pinned-tool.sh URL SHA256
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
[ "$#" -eq 2 ] || { echo 'usage: pinned-tool.sh URL SHA256' >&2; exit 2; }
url="$1" digest="$2"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo 'pinned-tool: SHA256 must be 64 lowercase hex digits' >&2; exit 2; }

temp="${RUNNER_TEMP:?RUNNER_TEMP must be set}/pinned-tools"
mkdir -p "$temp"
[ ! -L "$temp" ] || { echo 'pinned-tool: the job-local folder is a link' >&2; exit 1; }
fetch() {
  # PINNED_TOOL_FETCH is for this script's test, which fetches nothing.
  "${PINNED_TOOL_FETCH:-$ROOT/scripts/ci/release/fetch-pinned.sh}" "$url" "$digest" "$1" >&2
}
copy="$temp/$digest"
rm -f -- "$copy"

if [ -n "${BUILD_ONCE_TREE:-}" ] && [ -d "$BUILD_ONCE_TREE" ]; then
  dir="$BUILD_ONCE_TREE/tools"
  [ ! -L "$BUILD_ONCE_TREE" ] && [ ! -L "$dir" ] || { echo 'pinned-tool: the build disk tools folder is a link' >&2; exit 1; }
  mkdir -p "$dir"
  kept="$dir/$digest"
  if [ -f "$kept" ] && [ ! -L "$kept" ] && cp -- "$kept" "$copy" &&
      [ "$(sha256sum "$copy" | cut -c1-64)" = "$digest" ]; then
    echo "pinned-tool: reusing the kept $digest" >&2
  else
    if [ -e "$kept" ] || [ -L "$kept" ]; then
      echo "pinned-tool: the kept $digest does not match its digest; fetching it again" >&2
      # Whatever is there, a directory included, so a later run never fails on it.
      rm -rf -- "$kept"
    fi
    rm -f -- "$copy"
    fetch "$copy"
    # Keep it for the next job: a copy, so this job's verified file is never shared.
    cp -- "$copy" "$kept.partial.$$" && mv -f -- "$kept.partial.$$" "$kept" || rm -f -- "$kept.partial.$$"
  fi
else
  fetch "$copy"
fi
[ "$(sha256sum "$copy" | cut -c1-64)" = "$digest" ] || { echo "pinned-tool: $digest does not match" >&2; exit 1; }
printf '%s\n' "$copy"
