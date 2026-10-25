#!/usr/bin/env bash
# Sourced by run-product-verification.sh: run a family's independent test
# commands side by side instead of one after another.

# The process IDs of each PID given and every process under it, one per line.
side_by_side_tree() {
  local pid ppid root
  local -A side_by_side_children=()
  while read -r pid ppid; do
    side_by_side_children[$ppid]+=" $pid"
  done < <(ps -A -o pid= -o ppid=)
  for root in "$@"; do
    side_by_side_descend "$root"
  done
}

side_by_side_descend() {
  local child
  printf '%s\n' "$1"
  # Reads the caller's side_by_side_children.
  for child in ${side_by_side_children[$1]:-}; do
    side_by_side_descend "$child"
  done
}

# Stop commands started side by side and every process under them, found
# from the process IDs recorded when they started. The trees are frozen first,
# so no process forks a child the stop would miss, then sent TERM, so their
# EXIT traps clean up; whatever is still running five seconds later is killed.
stop_side_by_side() {
  local tries pid state alive=0
  local -a tree=()
  [ "$#" -gt 0 ] || return 0
  for _ in 1 2 3; do
    mapfile -t tree < <(side_by_side_tree "$@")
    kill -STOP "${tree[@]}" 2>/dev/null || true
  done
  kill -TERM "${tree[@]}" 2>/dev/null || true
  kill -CONT "${tree[@]}" 2>/dev/null || true
  for ((tries = 0; tries < 50; tries++)); do
    alive=0
    # A zombie has exited; only its parent's wait remains.
    while read -r pid state; do
      [[ "$state" == Z* ]] || alive=1
    done < <(ps -o pid= -o stat= -p "$(IFS=,; printf '%s' "${tree[*]}")" 2>/dev/null || true)
    [ "$alive" -eq 1 ] || break
    sleep 0.1
  done
  [ "$alive" -eq 0 ] || kill -KILL "${tree[@]}" 2>/dev/null || true
  wait "$@" 2>/dev/null || true
}

# Run the commands on standard input, one per line (blank lines are skipped),
# side by side: at most VERIFICATION_TEST_JOBS (default: the CPU count) at a
# time. Each command runs in a subshell of this one, so the caller's functions
# and environment apply, and must keep no state outside its own scratch
# directory. Its output is printed whole, in list order, with its exit status
# and time.
#
# The first failure stops the family (owner, 2026-10-25, #3013): the commands
# still running are stopped, the ones not yet started never start, and the
# failed command's output is printed last. VERIFICATION_KEEP_GOING=1 runs
# every command to the end instead and fails after all have reported.
run_side_by_side() {
  local limit="${VERIFICATION_TEST_JOBS:-$(nproc)}" keep_going="${VERIFICATION_KEEP_GOING:-0}"
  local logs line command index next=0 running=0 failed=0 first_failure='' status seconds ended
  local -a commands=() pids=() starts=()
  [[ "$limit" =~ ^[1-9][0-9]*$ ]] || {
    echo '::error::VERIFICATION_TEST_JOBS must be a positive integer' >&2
    return 2
  }
  [[ "$keep_going" == 0 || "$keep_going" == 1 ]] || {
    echo '::error::VERIFICATION_KEEP_GOING must be 0 or 1' >&2
    return 2
  }
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [ -z "$line" ] || commands+=("$line")
  done
  [ "${#commands[@]}" -gt 0 ] || {
    echo '::error::no commands to run side by side' >&2
    return 2
  }
  logs="$(mktemp -d)"
  # Each command reports its end on this queue, so the family learns of a
  # failure the moment it happens. The family holds both ends open, so neither
  # a report nor the wait for one blocks on the other end.
  mkfifo "$logs/ended"
  exec {ended}<>"$logs/ended"
  while :; do
    if [ "$next" -lt "${#commands[@]}" ] && [ "$running" -lt "$limit" ]; then
      command="${commands[$next]}"
      (
        exec {ended}>&-
        started=$SECONDS
        # Not a condition: the command keeps errexit, as when run in order.
        set +e
        (set -e; eval "$command") >"$logs/$next.log" 2>&1 </dev/null
        printf '%s %s\n' "$?" "$((SECONDS - started))" >"$logs/$next.status"
        printf '%s\n' "$next" >"$logs/ended"
      ) &
      pids[next]=$!
      starts[next]=$SECONDS
      next=$((next + 1))
      running=$((running + 1))
      continue
    fi
    [ "$running" -gt 0 ] || break
    read -r index <&"$ended"
    running=$((running - 1))
    read -r status seconds <"$logs/$index.status"
    if [ "$status" -ne 0 ] && [ "$keep_going" -eq 0 ]; then
      first_failure="$index"
      break
    fi
  done
  if [ -n "$first_failure" ]; then
    local -a stopping=()
    for ((index = 0; index < next; index++)); do
      [ "$index" = "$first_failure" ] || [ -s "$logs/$index.status" ] ||
        stopping+=("${pids[$index]}")
    done
    stop_side_by_side "${stopping[@]}"
  fi
  # A command that ended while the others stopped still reports on the queue,
  # so the queue stays open until every command has been waited for.
  wait "${pids[@]}" 2>/dev/null || true
  exec {ended}>&-
  for index in "${!commands[@]}"; do
    command="${commands[$index]}"
    [ "$index" != "$first_failure" ] || continue
    if [ -s "$logs/$index.status" ]; then
      read -r status seconds <"$logs/$index.status"
      cat "$logs/$index.log"
      if [ "$status" -eq 0 ]; then
        printf '==> %s: passed in %ss\n' "$command" "$seconds"
      else
        printf '::error::%s failed (exit %s) after %ss\n' "$command" "$status" "$seconds"
        failed=1
      fi
    elif [ "$index" -lt "$next" ]; then
      printf '==> %s: stopped after %ss, when %s failed\n' \
        "$command" "$((SECONDS - starts[index]))" "${commands[$first_failure]}"
    else
      printf '==> %s: not started, because %s failed\n' "$command" "${commands[$first_failure]}"
    fi
  done
  if [ -n "$first_failure" ]; then
    read -r status seconds <"$logs/$first_failure.status"
    printf '==> first failure: %s\n' "${commands[$first_failure]}"
    cat "$logs/$first_failure.log"
    printf '::error::%s failed (exit %s) after %ss; the family stopped there\n' \
      "${commands[$first_failure]}" "$status" "$seconds"
    failed=1
  fi
  rm -rf -- "$logs"
  return "$failed"
}
