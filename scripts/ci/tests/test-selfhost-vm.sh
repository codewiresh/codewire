#!/usr/bin/env bash
# scripts/dev/selfhost-vm.sh, without booting a VM: create refuses an existing
# directory and one under /tmp; ssh and destroy refuse a directory create did
# not make; destroy stops the recorded QEMU only while its command line names
# this directory's disk, and otherwise leaves both the process and the
# directory alone.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
vm="$repo_root/scripts/dev/selfhost-vm.sh"
work="$(mktemp -d)"
work="$(cd "$work" && pwd -P)"
pids=()
cleanup() {
  local pid
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

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

# A state directory as create leaves it, without a VM.
marked_state() {
  mkdir "$1"
  printf 'selfhost-vm test\n' >"$1/selfhost-vm.state"
}

# Start a stand-in for QEMU whose command line carries ARG, and set stand_in_pid
# to its PID. Its parent never reaps it, so once stopped it lingers as a
# zombie, as an orphan does in a container without an init; destroy must count
# that as stopped. Both PIDs go to pids for cleanup.
stand_in() {
  local i=0 parent
  rm -f "$work/stand-in.pids"
  (bash -c 'python3 -c "import time; time.sleep(60)" "$1" >/dev/null 2>&1 &
    echo "$! $$" >"$2"; exec sleep 60' bash "$1" "$work/stand-in.pids" &)
  until [ -s "$work/stand-in.pids" ]; do
    [ "$i" -lt 100 ] || fail "the stand-in did not start"
    sleep 0.1
    i=$((i + 1))
  done
  read -r stand_in_pid parent <"$work/stand-in.pids"
  pids+=("$stand_in_pid" "$parent")
}

# Whether PID has not exited; a zombie has.
alive() {
  local state
  state="$(sed -n 's/^.*) \(.\).*$/\1/p' "/proc/$1/stat" 2>/dev/null)" || return 1
  [ -n "$state" ] && [ "$state" != Z ]
}

# Wait at most ten seconds for PID to exit.
gone() {
  local i=0
  while alive "$1"; do
    [ "$i" -lt 100 ] || return 1
    sleep 0.1
    i=$((i + 1))
  done
}

expect_status 64 bash "$vm"
expect_status 64 bash "$vm" start "$work/vm"
expect_status 64 bash "$vm" create "$work/vm" extra

# create refuses a directory that exists, and anything under /tmp, before
# making or booting anything.
expect_status 64 bash "$vm" create "$work"
grep -q 'already exists' "$work/out" || fail "create of an existing directory: $(cat "$work/out")"
tmp_target="/tmp/selfhost-vm-test-$$-absent"
expect_status 64 bash "$vm" create "$tmp_target"
grep -q 'under /tmp' "$work/out" || fail "create under /tmp: $(cat "$work/out")"
[ ! -e "$tmp_target" ] || fail "create made $tmp_target before refusing it"

# ssh and destroy refuse a directory without create's marker, and keep it.
mkdir "$work/unmarked"
expect_status 64 bash "$vm" ssh "$work/unmarked" true
expect_status 64 bash "$vm" destroy "$work/unmarked"
[ -d "$work/unmarked" ] || fail "destroy removed a directory create did not make"

# A recorded PID that is now another process is refused: nothing stopped,
# nothing removed.
marked_state "$work/other"
stand_in "something-else"
other_pid="$stand_in_pid"
printf '%s\n' "$other_pid" >"$work/other/qemu.pid"
expect_status 64 bash "$vm" destroy "$work/other"
grep -q 'is not this VM' "$work/out" || fail "destroy of a reused PID: $(cat "$work/out")"
alive "$other_pid" || fail "destroy stopped PID $other_pid, which is not this VM"
[ -d "$work/other" ] || fail "destroy removed the directory of a VM it did not stop"

# The VM's own QEMU is stopped and the directory removed.
marked_state "$work/own"
stand_in "if=virtio,format=qcow2,file=$work/own/disk.qcow2"
own_pid="$stand_in_pid"
printf '%s\n' "$own_pid" >"$work/own/qemu.pid"
expect_status 0 bash "$vm" destroy "$work/own"
gone "$own_pid" || fail "destroy left this VM's QEMU (PID $own_pid) running"
[ ! -e "$work/own" ] || fail "destroy left $work/own"

# A VM that already exited leaves only its directory to remove.
marked_state "$work/exited"
stand_in "if=virtio,format=qcow2,file=$work/exited/disk.qcow2"
exited_pid="$stand_in_pid"
kill "$exited_pid"
gone "$exited_pid" || fail "the stand-in PID $exited_pid did not exit"
printf '%s\n' "$exited_pid" >"$work/exited/qemu.pid"
expect_status 0 bash "$vm" destroy "$work/exited"
[ ! -e "$work/exited" ] || fail "destroy left $work/exited"

echo "selfhost-vm: OK"
