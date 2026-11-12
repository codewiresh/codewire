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

# preflight_lock_acquire LABEL: take the lock, waiting at most
# PREFLIGHT_LOCK_WAIT_SECONDS (default 1800) for the preflight that holds it.
# Fails, naming the holder, when the wait runs out.
preflight_lock_acquire() {
  [ "$PREFLIGHT_LOCK_HELD" = false ] || return 0
  [ -z "${CI:-}${GITHUB_ACTIONS:-}" ] || return 0
  command -v flock >/dev/null 2>&1 || return 0
  local label="$1" wait="${PREFLIGHT_LOCK_WAIT_SECONDS:-1800}" holder
  mkdir -p "$(dirname "$PREFLIGHT_LOCK_FILE")"
  exec {PREFLIGHT_LOCK_FD}>>"$PREFLIGHT_LOCK_FILE"
  if ! flock -n "$PREFLIGHT_LOCK_FD"; then
    holder="$(cat "$PREFLIGHT_LOCK_FILE.holder" 2>/dev/null || true)"
    printf 'preflight: %s is waiting for %s (at most %ss)\n' "$label" "${holder:-another preflight}" "$wait" >&2
    if ! flock -w "$wait" "$PREFLIGHT_LOCK_FD"; then
      printf 'preflight: %s gave up after %ss waiting for %s\n' "$label" "$wait" "${holder:-another preflight}" >&2
      return 1
    fi
  fi
  printf '%s in %s (pid %s, since %s)\n' "$label" "$(pwd -P)" "$$" "$(date -u +%H:%M:%SZ)" \
    >"$PREFLIGHT_LOCK_FILE.holder"
  PREFLIGHT_LOCK_HELD=true
}
