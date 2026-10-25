#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/dev/kind/kind-forwards.sh"
mkdir -p "$ROOT/.tmp"
FIXTURE="$(mktemp -d "$ROOT/.tmp/kind-forwards.XXXXXX")"
BIN="$FIXTURE/bin"
STATE="$FIXTURE/state"
CALLS="$FIXTURE/kubectl-calls"

cleanup() {
  local pid
  if [ -f "$STATE/postgres.pid" ]; then
    read -r pid _ <"$STATE/postgres.pid" || true
    if [[ "${pid:-}" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  fi
  if [ -n "${UNOWNED_PID:-}" ] && kill -0 "$UNOWNED_PID" 2>/dev/null; then
    kill "$UNOWNED_PID" 2>/dev/null || true
    wait "$UNOWNED_PID" 2>/dev/null || true
  fi
  rm -rf "$FIXTURE"
}
trap cleanup EXIT

fail() {
  printf '[test-kind-forwards] ERROR: %s\n' "$*" >&2
  exit 1
}

process_is_live() {
  local pid="$1" state
  kill -0 "$pid" 2>/dev/null || return 1
  state="$(ps -p "$pid" -o stat= 2>/dev/null | tr -d '[:space:]')"
  [ -n "$state" ] && [[ "$state" != Z* ]]
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$FIXTURE/${label}.out" 2>&1; then
    fail "$label unexpectedly succeeded"
  fi
}

mkdir -p "$BIN" "$STATE"
cat >"$BIN/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"$FAKE_KUBECTL_CALLS"
case "${FAKE_KUBECTL_MODE:-ipv4}" in
  ipv4)
    printf 'Forwarding from 127.0.0.1:25432 -> 5432\n'
    ;;
  ipv6)
    printf 'Forwarding from [::1]:25432 -> 5432\n'
    ;;
  occupied)
    printf 'Unable to listen on any of the requested ports: [{25432 5432}]\n' >&2
    # Keep the fake process alive so the helper reaches its readiness timeout
    # after the diagnostic is committed to its redirected log.
    ;;
  *)
    printf 'unknown fake kubectl mode: %s\n' "$FAKE_KUBECTL_MODE" >&2
    exit 2
    ;;
esac

child=''
stop() {
  if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
    kill "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  exit 0
}
trap stop TERM INT
while :; do
  sleep 30 &
  child=$!
  wait "$child" || true
done
EOF
chmod +x "$BIN/kubectl"
# A loaded host can run the forked forward for a while before nohup execs
# kubectl, and until then its command line is not kubectl's. FAKE_NOHUP_DELAY
# holds the fork in a shell whose command line names no kubectl argument, as
# the helper's forked shell's does, before the real nohup runs.
real_nohup="$(command -v nohup)"
cat >"$BIN/nohup" <<EOF
#!/usr/bin/env bash
FAKE_NOHUP_COMMAND="\$(printf '%q ' "\$@")" exec bash -c \
  'sleep "\${FAKE_NOHUP_DELAY:-0}"; eval "exec $real_nohup \$FAKE_NOHUP_COMMAND"'
EOF
chmod +x "$BIN/nohup"

run_helper() {
  PATH="$BIN:$PATH" \
    STATE_DIR="$STATE" \
    KUBE_CONTEXT=kind-forwards-fixture \
    KIND_FORWARD_READY_ATTEMPTS=2 \
    FAKE_KUBECTL_CALLS="$CALLS" \
    "$SCRIPT" "$@"
}

bash -n "$SCRIPT" "$0"

# A helper-owned forward must use the exact IPv4 bind in both invocation and
# readiness, then stop cleanly through the matching state record.
: >"$CALLS"
FAKE_KUBECTL_MODE=ipv4 run_helper start postgres >"$FIXTURE/ipv4.out"
grep -Fxq -- '--context kind-forwards-fixture -n default port-forward --address 127.0.0.1 service/postgres 25432:5432' "$CALLS" ||
  fail 'helper did not start postgres with the exact IPv4 bind'
read -r managed_pid managed_start <"$STATE/postgres.pid"
[[ "$managed_pid" =~ ^[0-9]+$ && "$managed_start" =~ ^[0-9]+$ ]] ||
  fail 'helper did not record PID plus process-start ownership token'
process_is_live "$managed_pid" || fail 'managed forward is not live'
run_helper stop postgres >"$FIXTURE/stop.out"
for _ in $(seq 1 20); do
  process_is_live "$managed_pid" || break
  sleep 0.1
done
process_is_live "$managed_pid" && fail 'helper-owned forward remained live after stop'
[ ! -e "$STATE/postgres.pid" ] || fail 'stop retained managed state'

# A stopped helper-owned child may remain a zombie until the runner's PID 1
# reaps it. That is not a live forward and must not block a restart.
FAKE_KUBECTL_MODE=ipv4 run_helper start postgres >"$FIXTURE/restart-after-stop.out"
run_helper stop postgres >"$FIXTURE/restart-after-stop-stop.out"

# A forward still starting is the helper's own forward, not one that exited:
# start waits for its command line, becomes ready and stops cleanly.
FAKE_NOHUP_DELAY=1 FAKE_KUBECTL_MODE=ipv4 run_helper start postgres >"$FIXTURE/slow-exec.out" 2>&1 ||
  fail "a forward that execs kubectl late was refused: $(cat "$FIXTURE/slow-exec.out")"
read -r slow_pid _ <"$STATE/postgres.pid"
run_helper stop postgres >"$FIXTURE/slow-exec-stop.out"
# The stopped forward exits on its TERM; give a loaded host a moment.
for _ in $(seq 1 50); do
  process_is_live "$slow_pid" || break
  sleep 0.1
done
process_is_live "$slow_pid" && fail 'a late-exec forward remained live after stop'

# IPv6-only readiness is not equivalent to the advertised IPv4 endpoint.
FAKE_KUBECTL_MODE=ipv6 expect_failure ipv6 run_helper start postgres
grep -Fq 'did not become ready at 127.0.0.1:25432' "$FIXTURE/ipv6.out" ||
  fail 'IPv6-only readiness did not report the required IPv4 endpoint'
[ ! -e "$STATE/postgres.pid" ] || fail 'failed IPv6 forward retained state'

# A port conflict must surface the forward diagnostic and cannot be treated as
# a usable ambient endpoint.
FAKE_KUBECTL_MODE=occupied expect_failure occupied run_helper start postgres
grep -Fq 'Unable to listen on any of the requested ports' "$FIXTURE/occupied.out" ||
  fail 'occupied endpoint diagnostic was not preserved'
[ ! -e "$STATE/postgres.pid" ] || fail 'failed occupied forward retained state'

# A live legacy PID without the helper's process-start token is never
# helper-owned. The helper must neither stop it nor erase its record.
sleep 300 &
UNOWNED_PID=$!
printf '%s\n' "$UNOWNED_PID" >"$STATE/postgres.pid"
expect_failure unowned-stop run_helper stop postgres
grep -Fq 'refusing to remove live legacy state' "$FIXTURE/unowned-stop.out" ||
  fail 'live legacy state rejection was not decisive'
kill -0 "$UNOWNED_PID" 2>/dev/null || fail 'unowned process was terminated'
[ -e "$STATE/postgres.pid" ] || fail 'unowned state was erased'

# Even a complete PID/start record is not ownership unless the live process is
# the helper's exact kubectl invocation.
printf '%s %s\n' "$UNOWNED_PID" "$(awk '{print $22}' "/proc/$UNOWNED_PID/stat")" >"$STATE/postgres.pid"
expect_failure unowned-command run_helper stop postgres
grep -Fq 'refusing to stop live pid' "$FIXTURE/unowned-command.out" ||
  fail 'unowned command rejection was not decisive'
kill -0 "$UNOWNED_PID" 2>/dev/null || fail 'unowned process was terminated by command match'
[ -e "$STATE/postgres.pid" ] || fail 'unowned command state was erased'

# A dead pre-token state file is safe to discard: it cannot identify a live
# process, and the helper must still record a full ownership tuple for the
# replacement forward.
kill "$UNOWNED_PID" 2>/dev/null || true
wait "$UNOWNED_PID" 2>/dev/null || true
UNOWNED_PID=""
printf '999999\n' >"$STATE/postgres.pid"
FAKE_KUBECTL_MODE=ipv4 run_helper start postgres >"$FIXTURE/dead-legacy.out" 2>&1
grep -Fq 'removed dead legacy managed-forward state' "$FIXTURE/dead-legacy.out" ||
  fail 'dead legacy state was not discarded safely'
read -r managed_pid managed_start <"$STATE/postgres.pid"
[[ "$managed_pid" =~ ^[0-9]+$ && "$managed_start" =~ ^[0-9]+$ ]] ||
  fail 'replacement forward did not receive a complete ownership tuple'
run_helper stop postgres >"$FIXTURE/dead-legacy-stop.out"

printf '[test-kind-forwards] exact IPv4 readiness and process ownership passed\n'
