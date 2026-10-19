#!/usr/bin/env bash
# Sourced by run-product-verification.sh: run a family's independent test
# commands side by side instead of one after another.

# Run the commands on standard input, one per line (blank lines are skipped),
# side by side: at most VERIFICATION_TEST_JOBS (default: the CPU count) at a
# time. Each command runs in a subshell of this one, so the caller's functions
# and environment apply, and must keep no state outside its own scratch
# directory. Every command runs to the end; its output is printed whole, in
# list order, with its exit status and time, and any failure fails the caller
# after all have reported.
run_side_by_side() {
  local limit="${VERIFICATION_TEST_JOBS:-$(nproc)}" logs line command index=0 failed=0 status seconds
  local -a commands=()
  [[ "$limit" =~ ^[1-9][0-9]*$ ]] || {
    echo '::error::VERIFICATION_TEST_JOBS must be a positive integer' >&2
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
  for command in "${commands[@]}"; do
    while [ "$(jobs -rp | wc -l)" -ge "$limit" ]; do
      wait -n || true
    done
    (
      started=$SECONDS
      # Not a condition: the command keeps errexit, as when run in order.
      set +e
      (set -e; eval "$command") >"$logs/$index.log" 2>&1 </dev/null
      printf '%s %s\n' "$?" "$((SECONDS - started))" >"$logs/$index.status"
    ) &
    index=$((index + 1))
  done
  wait
  index=0
  for command in "${commands[@]}"; do
    read -r status seconds <"$logs/$index.status"
    cat "$logs/$index.log"
    if [ "$status" -eq 0 ]; then
      printf '==> %s: passed in %ss\n' "$command" "$seconds"
    else
      printf '::error::%s failed (exit %s) after %ss\n' "$command" "$status" "$seconds"
      failed=1
    fi
    index=$((index + 1))
  done
  rm -rf -- "$logs"
  return "$failed"
}
