#!/usr/bin/env bash
# Decide whether a running Dev delivery should stop because canonical main has
# moved past it, so the queued run for the newer commit starts sooner.
#
#   delivery-superseded.sh check
#       Write stop=true or stop=false to GITHUB_OUTPUT.
#   delivery-superseded.sh run -- COMMAND [ARGUMENT...]
#       Run COMMAND. While it runs, re-check every
#       CODEWIRE_SUPERSEDED_POLL_SECONDS (default 60). When the delivery should
#       stop, terminate COMMAND's whole process group, write stop=true and
#       exit 0. Otherwise write stop=false and exit with COMMAND's status.
#
# A delivery stops only when all of these hold:
#   - canonical main reads as a commit other than GITHUB_SHA, and GITHUB_SHA is
#     an ancestor of it on freshly fetched history: the newer run delivers
#     this commit's changes, and Dev never moves backwards;
#   - Dev's running commit is younger than 45 minutes, read from
#     CODEWIRE_DEPLOYED_SOURCE_COMMITTED_AT (Unix seconds). Under steady merges
#     every delivery would otherwise be superseded and Dev would never update.
# Anything unknown (unreadable main, missing history, unknown Dev age) keeps
# delivering: stopping is an optimization, never a gate. Callers check only
# before signing starts, so a stop never leaves a partially signed set.
set -euo pipefail

readonly DEV_STALE_SECONDS=2700

usage() {
  echo 'Usage: delivery-superseded.sh check | run -- COMMAND [ARGUMENT...]' >&2
  exit 2
}

: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'Delivery supersession requires an exact Git object ID' >&2
  exit 2
}
poll_seconds="${CODEWIRE_SUPERSEDED_POLL_SECONDS:-60}"
[[ "$poll_seconds" =~ ^[1-9][0-9]{0,3}$ ]] || {
  echo 'CODEWIRE_SUPERSEDED_POLL_SECONDS must be 1-9999' >&2
  exit 2
}

unshallowed=0
last_reason=''

# Print a reason once per change, so a long poll does not flood the log.
note() {
  if [[ "$1" != "$last_reason" ]]; then
    printf 'delivery-superseded: %s\n' "$1"
    last_reason="$1"
  fi
}

# Succeeds only when this delivery should stop now.
should_stop() {
  local committed_at age remote_main fetched_main
  committed_at="${CODEWIRE_DEPLOYED_SOURCE_COMMITTED_AT:-}"
  if [[ ! "$committed_at" =~ ^[1-9][0-9]{0,11}$ ]]; then
    note "Dev's running commit age is unknown; delivering $GITHUB_SHA"
    return 1
  fi
  age=$(($(date +%s) - committed_at))
  if ((age >= DEV_STALE_SECONDS)); then
    note "Dev runs a commit at least $((DEV_STALE_SECONDS / 60)) minutes old; delivering $GITHUB_SHA"
    return 1
  fi
  if ! remote_main="$(git ls-remote origin refs/heads/main 2>/dev/null |
      awk '$2 == "refs/heads/main" { print $1 }')" \
      || [[ ! "$remote_main" =~ ^[0-9a-f]{40}$ ]]; then
    note "canonical main is unreadable; delivering $GITHUB_SHA"
    return 1
  fi
  if [[ "$remote_main" == "$GITHUB_SHA" ]]; then
    note "$GITHUB_SHA is canonical main; delivering it"
    return 1
  fi
  # Judge ancestry on the history actually fetched, not on the earlier
  # reading, so a further merge in between cannot be misjudged.
  local -a fetch_args=(--quiet --no-tags)
  if [[ "$unshallowed" == 0 && "$(git rev-parse --is-shallow-repository 2>/dev/null)" == true ]]; then
    fetch_args+=(--unshallow)
  fi
  if ! git fetch "${fetch_args[@]}" origin '+refs/heads/main:refs/remotes/origin/main' 2>/dev/null \
      || ! fetched_main="$(git rev-parse --verify -q 'refs/remotes/origin/main^{commit}')"; then
    note "canonical main history is unreadable; delivering $GITHUB_SHA"
    return 1
  fi
  unshallowed=1
  if [[ "$fetched_main" == "$GITHUB_SHA" ]] \
      || ! git merge-base --is-ancestor "$GITHUB_SHA" "$fetched_main" 2>/dev/null; then
    note "canonical main $fetched_main does not supersede $GITHUB_SHA; delivering it"
    return 1
  fi
  note "main is now $fetched_main and Dev runs a commit $((age / 60)) minutes old; stopping so the newer delivery starts"
  return 0
}

case "${1:-}" in
  check)
    [[ $# -eq 1 ]] || usage
    if should_stop; then
      echo 'stop=true' >>"$GITHUB_OUTPUT"
    else
      echo 'stop=false' >>"$GITHUB_OUTPUT"
    fi
    ;;
  run)
    [[ $# -ge 3 && "$2" == -- ]] || usage
    shift 2
    # A new session makes the command the leader of its own process group, so
    # a stop reaches every process it started, and their EXIT traps run.
    setsid "$@" &
    command_pid=$!
    # A step deadline or cancellation that ends this wrapper ends the command.
    trap 'kill -TERM -- "-$command_pid" 2>/dev/null || true; exit 143' TERM INT
    stopped=0
    waited=0
    while kill -0 "$command_pid" 2>/dev/null; do
      sleep 1
      waited=$((waited + 1))
      ((waited >= poll_seconds)) || continue
      waited=0
      kill -0 "$command_pid" 2>/dev/null || break
      if should_stop; then
        stopped=1
        kill -TERM -- "-$command_pid" 2>/dev/null || true
        for _ in $(seq 1 120); do
          kill -0 "$command_pid" 2>/dev/null || break
          sleep 1
        done
        kill -KILL -- "-$command_pid" 2>/dev/null || true
        break
      fi
    done
    status=0
    wait "$command_pid" || status=$?
    if [[ "$stopped" == 1 ]]; then
      echo 'stop=true' >>"$GITHUB_OUTPUT"
      echo "delivery-superseded: stopped the build of $GITHUB_SHA; nothing from it is signed or dispatched"
      exit 0
    fi
    echo 'stop=false' >>"$GITHUB_OUTPUT"
    exit "$status"
    ;;
  *)
    usage
    ;;
esac
