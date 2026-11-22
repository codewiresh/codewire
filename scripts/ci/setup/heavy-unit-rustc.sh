#!/usr/bin/env bash
# RUSTC_WRAPPER for build-once's legs and Rust checks: one compile of a heavy
# unit at a time across every target folder of the build.
#
# On a change to codewire-proto, every leg and check compiles that 17 MB
# generated crate cold in its own target folder, all at once. Each compile
# takes several GiB, and together they ran the pull request build VMs out of
# memory at any compiler count that keeps the build quick: at 16 compilers
# the guest killed codewire-proto's rustc and clippy-driver four times in one
# job (codewire run 70654). The jobserver counts compilers, not memory.
#
# Cargo runs RUSTC_WRAPPER outermost, before clippy-driver and rustc, so a
# heavy unit takes BUILD_ONCE_HEAVY_LOCK until its compile exits, and every
# other unit runs at once. BUILD_ONCE_HEAVY_NEXT_WRAPPER, when set, is the
# wrapper this one stands in front of (the legs' sccache).
set -euo pipefail

readonly HEAVY_UNITS=" codewire_proto "

heavy=false
prev=''
for arg in "$@"; do
  case "$prev|$arg" in
    --crate-name\|*) [[ "$HEAVY_UNITS" == *" $arg "* ]] && heavy=true ;;
  esac
  case "$arg" in
    --crate-name=*) [[ "$HEAVY_UNITS" == *" ${arg#--crate-name=} "* ]] && heavy=true ;;
  esac
  prev="$arg"
done

command=("$@")
[[ -z "${BUILD_ONCE_HEAVY_NEXT_WRAPPER:-}" ]] || command=("$BUILD_ONCE_HEAVY_NEXT_WRAPPER" "$@")

if [[ "$heavy" == true && -n "${BUILD_ONCE_HEAVY_LOCK:-}" ]]; then
  # flock holds the lock itself and closes it in the compile it runs (-o), so
  # nothing the compile leaves behind keeps it: an sccache client that starts
  # its server would otherwise hand that server the lock for good, and every
  # later heavy compile would wait to the job's timeout.
  exec flock -o "$BUILD_ONCE_HEAVY_LOCK" "${command[@]}"
fi
exec "${command[@]}"
