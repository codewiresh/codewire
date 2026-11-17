#!/usr/bin/env bash
# A bounded wait on a Kind host lock that says why it gave up. Source this file.

# kind_lock_wait FD FILE NAME: lock FILE, open on FD, within
# KIND_HOST_LOCK_TIMEOUT_SECONDS. A timeout once ended kind-up with no word
# (#5154); it now names the lock, the wait and the processes /proc/locks says
# hold it.
kind_lock_wait() {
  local descriptor="$1" file="$2" name="$3" status=0 identity pid
  local -a holders=()
  flock -w "$KIND_HOST_LOCK_TIMEOUT_SECONDS" "$descriptor" || status=$?
  [ "$status" -ne 0 ] || return 0
  # /proc/locks names a lock's file by device and inode, but its device can
  # differ from stat's (a btrfs subvolume), so match the inode and keep a
  # process that has this very file open. A waiter's line has "->".
  identity="$(stat -Lc '%d:%i' "$file" 2>/dev/null)" || identity=""
  if [ -n "$identity" ]; then
    while read -r pid; do
      kind_lock_holds_file "$pid" "$identity" || continue
      holders+=("$(kind_lock_holder "$pid")")
    done < <(awk -v inode="${identity#*:}" '
      $2 == "FLOCK" { split($6, id, ":"); if (id[3] == inode) print $5 }' /proc/locks 2>/dev/null | sort -u)
  fi
  local held="an unknown process"
  [ "${#holders[@]}" -eq 0 ] || held="$(IFS=';'; printf '%s' "${holders[*]}")"
  echo "::error::timed out after ${KIND_HOST_LOCK_TIMEOUT_SECONDS} s waiting for the ${name} lock (${file}); held by ${held}" >&2
  return "$status"
}

# kind_lock_holds_file PID DEVICE:INODE: whether PID has that file open.
kind_lock_holds_file() {
  local pid="$1" identity="$2" descriptor
  for descriptor in /proc/"$pid"/fd/*; do
    [ "$(stat -Lc '%d:%i' "$descriptor" 2>/dev/null)" != "$identity" ] || return 0
  done
  return 1
}

# kind_lock_holder PID: the process, how long it has run and its directory.
kind_lock_holder() {
  local pid="$1" command elapsed directory
  command="$(cat "/proc/$pid/comm" 2>/dev/null)" || {
    printf 'pid %s (exited)' "$pid"
    return 0
  }
  elapsed="$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')" || elapsed=""
  directory="$(readlink "/proc/$pid/cwd" 2>/dev/null)" || directory="unknown"
  printf 'pid %s (%s, running %s, in %s)' "$pid" "$command" "${elapsed:-?}" "$directory"
}
