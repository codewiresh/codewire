# shellcheck shell=bash
# One heavy preflight at a time on a workstation (#4215).
#
# Many sessions push at once, and overlapping compiles and test runs made each
# push fail a different timing test. preflight_lock_acquire takes a
# workstation-wide lock before the heavy work (compiles, test runs) and holds
# it until the process exits; a second preflight queues behind it and says
# whom it waits for. Light checks never take it. In CI, and where flock is
# missing (macOS), it does nothing.

# The lock, and beside it who holds it; tests point it elsewhere.
PREFLIGHT_LOCK_FILE="${PREFLIGHT_LOCK_FILE:-$HOME/.cache/codewire-preflight.lock}"
PREFLIGHT_LOCK_HELD=false
# Set once a wait ran out: the rest of this preflight runs without the lock
# rather than waiting again before each heavy step.
PREFLIGHT_LOCK_SKIPPED=false

# preflight_lock_acquire LABEL: take the lock, waiting at most
# PREFLIGHT_LOCK_WAIT_SECONDS (default 600) for the preflight that holds it,
# and naming the holder and the time waited every PREFLIGHT_LOCK_REPORT_SECONDS
# (default 60). When the wait runs out, it warns and runs without the lock: a
# holder that is stuck must not fail every other push (2026-11-12, #4215,
# where one cold build held it 30 minutes and a waiting push gave up).
preflight_lock_acquire() {
  [ "$PREFLIGHT_LOCK_HELD" = false ] && [ "$PREFLIGHT_LOCK_SKIPPED" = false ] || return 0
  [ -z "${CI:-}${GITHUB_ACTIONS:-}" ] || return 0
  command -v flock >/dev/null 2>&1 || return 0
  local label="$1" wait="${PREFLIGHT_LOCK_WAIT_SECONDS:-600}" report="${PREFLIGHT_LOCK_REPORT_SECONDS:-60}"
  local waited=0 step holder
  mkdir -p "$(dirname "$PREFLIGHT_LOCK_FILE")"
  exec {PREFLIGHT_LOCK_FD}>>"$PREFLIGHT_LOCK_FILE"
  if ! flock -n "$PREFLIGHT_LOCK_FD"; then
    holder="$(cat "$PREFLIGHT_LOCK_FILE.holder" 2>/dev/null || true)"
    printf 'preflight: %s is waiting for %s (at most %ss)\n' "$label" "${holder:-another preflight}" "$wait" >&2
    while :; do
      step=$((wait - waited < report ? wait - waited : report))
      if [ "$step" -le 0 ]; then
        printf 'preflight: %s waited %ss for %s; running without the lock\n' \
          "$label" "$waited" "${holder:-another preflight}" >&2
        exec {PREFLIGHT_LOCK_FD}>&-
        PREFLIGHT_LOCK_SKIPPED=true
        return 0
      fi
      flock -w "$step" "$PREFLIGHT_LOCK_FD" && break
      waited=$((waited + step))
      holder="$(cat "$PREFLIGHT_LOCK_FILE.holder" 2>/dev/null || true)"
      printf 'preflight: %s still waiting after %ss for %s\n' "$label" "$waited" "${holder:-another preflight}" >&2
    done
  fi
  printf '%s in %s (pid %s, since %s)\n' "$label" "$(pwd -P)" "$$" "$(date -u +%H:%M:%SZ)" \
    >"$PREFLIGHT_LOCK_FILE.holder"
  PREFLIGHT_LOCK_HELD=true
}
