#!/usr/bin/env bash
# close_inherited_lock_fds closes every descriptor above stderr that this shell
# inherited on a *.lock file.
#
# The shared sccache server is started by whichever compile finds it down and
# then outlives that build, keeping every descriptor it inherited. A Kind
# profile, host or publication lock held by the build that ran the compile
# would stay held after the build exits, and the next kind-status, kind-down
# or purge of that profile waits for it (#3323). Closing this shell's copy
# never releases the caller's lock: a flock lasts while any copy is open.
# Only regular *.lock files are closed; Cargo's jobserver pipes and fifos stay.
close_inherited_lock_fds() {
  local dir="/proc/${BASHPID:-$$}/fd" entry fd path
  [[ -d "$dir" ]] || return 0
  for entry in "$dir"/*; do
    fd="${entry##*/}"
    [[ "$fd" =~ ^[0-9]+$ ]] || continue
    ((fd > 2)) || continue
    path="$(readlink -- "$entry" 2>/dev/null)" || continue
    [[ "$path" == *.lock && -f "$path" ]] || continue
    exec {fd}>&-
  done
}
