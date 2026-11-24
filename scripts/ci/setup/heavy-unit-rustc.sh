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
# heavy unit takes one of BUILD_ONCE_HEAVY_SLOTS slots (default 6), the lock
# files BUILD_ONCE_HEAVY_LOCK.0 to .N-1, until its compile exits, and every
# other unit runs at once. One slot made a cold six-leg build safe (40 GiB
# peak, against about 70 that ran the guest out of memory) but serial: its
# legs took 30-36 min (codewire run 71453). A codewire-proto compile peaks at
# about 5 GiB resident (4.8 GiB measured alone, 2026-11-24). On a six-leg
# codewire-proto change the build VM's resident memory peaked at 20 GiB of
# 63 with three slots (run 73890) and 35.7 GiB with six (run 76417), and six
# cut Build test archives from 1146 s to 732 s: three slots queued the 14
# compiles about five deep (infra#1534). BUILD_ONCE_HEAVY_NEXT_WRAPPER, when
# set, is the wrapper this one stands in front of (the legs' sccache).
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
  slots="${BUILD_ONCE_HEAVY_SLOTS:-6}"
  [[ "$slots" =~ ^[1-9]$ ]] || slots=6
  # Take the first free slot; with none free, look again each second. flock
  # holds the slot itself and closes it in the compile it runs (-o), so
  # nothing the compile leaves behind keeps it: an sccache client that starts
  # its server would otherwise hand that server the slot for good. -E 75
  # marks a busy slot; no compiler exits 75.
  while :; do
    for ((slot = 0; slot < slots; slot++)); do
      status=0
      flock -n -E 75 -o "$BUILD_ONCE_HEAVY_LOCK.$slot" "${command[@]}" || status=$?
      [[ "$status" -eq 75 ]] || exit "$status"
    done
    sleep 1
  done
fi
exec "${command[@]}"
