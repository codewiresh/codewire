#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HELPER="$ROOT/images/base/apt-get-with-retry"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "${TMPDIR:-$ROOT/.tmp}/apt-get-with-retry.XXXXXX")"
readonly TEST_TMP
trap 'rm -rf "$TEST_TMP"' EXIT

fail() {
  printf '[test-apt-get-with-retry] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$TEST_TMP/bin"
ln -s /usr/bin/bash "$TEST_TMP/bin/bash"
cat >"$TEST_TMP/bin/apt-get" <<'SH'
#!/usr/bin/bash
set -euo pipefail
count="$(<"$FAKE_APT_STATE")"
count="$((count + 1))"
printf '%s\n' "$count" >"$FAKE_APT_STATE"
printf '%s\0' "$@" >"$FAKE_APT_ARGV.$count"
IFS=, read -r -a results <<<"$FAKE_APT_RESULTS"
result="${results[$((count - 1))]:-unexpected}"
case "$result" in
  partial)
    # Model APT's native transient-index behavior: warning/0 by default,
    # error/100 with the last effective update error-mode set to any.
    error_mode=persistent
    for arg in "$@"; do
      case "$arg" in APT::Update::Error-Mode=*) error_mode="${arg#*=}" ;; esac
    done
    printf 'Some index files failed to download\n' >&2
    [[ "$error_mode" != any ]] || exit 100
    exit 0 ;;
  hang)
    child_pid=''
    terminate() {
      if [[ -n "$child_pid" ]]; then
        kill -TERM "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
      fi
      printf 'TERM\n' >"$FAKE_APT_ARGV.$count.terminated"
      exit 143
    }
    trap terminate TERM
    /usr/bin/sleep 10 &
    child_pid=$!
    printf '%s\n' "$$" >"$FAKE_APT_ARGV.$count.apt-pid"
    printf '%s\n' "$child_pid" >"$FAKE_APT_ARGV.$count.child-pid"
    wait "$child_pid"
    exit 96 ;;
  ''|*[!0-9]*) exit 97 ;;
  *) exit "$result" ;;
esac
SH
chmod 0755 "$TEST_TMP/bin/apt-get"

cat >"$TEST_TMP/bin/sleep" <<'SH'
#!/usr/bin/bash
set -euo pipefail
[[ $# == 1 && "$1" == 30 ]] || exit 98
printf '%s\n' "$1" >>"$FAKE_SLEEP_LOG"
SH
chmod 0755 "$TEST_TMP/bin/sleep"

cat >"$TEST_TMP/bin/timeout" <<'SH'
#!/usr/bin/bash
set -euo pipefail
[[ $# -ge 4 && "$1" == --signal=TERM && "$2" == --kill-after=3s \
  && "$3" == 300s && "$4" == apt-get ]] || exit 99
count="$(<"$FAKE_TIMEOUT_STATE")"
count="$((count + 1))"
printf '%s\n' "$count" >"$FAKE_TIMEOUT_STATE"
printf '%s\0' "$@" >"$FAKE_TIMEOUT_ARGV.$count"
shift 3
# Validate the production bound above, then shorten only the fixture deadline.
# The real GNU timeout still delivers TERM and owns its ordinary process group.
exec /usr/bin/timeout --signal=TERM --kill-after=3s 1s "$@"
SH
chmod 0755 "$TEST_TMP/bin/timeout"

cat >"$TEST_TMP/update-and-install" <<'SH'
#!/usr/bin/bash
set -euo pipefail
"$APT_HELPER_UNDER_TEST" "$@" && "$APT_HELPER_UNDER_TEST" install -y package-one
SH

helper_args=(-o Acquire::https::Verify-Peer=false -o 'Acquire::https::User-Agent=codewire fixture' install -y package-one)
cases=0 timed_out_transactions=0 bounded_acquisitions=0 total_apt_calls=0

run_case() {
  local name="$1" results="$2" expected_status="$3" kinds="$4" expected_waits="$5"
  local mode="${6:-single}" expected_calls expected_timeouts=0 timeout_index=0
  local case_dir="$TEST_TMP/$name" status attempt kind pid pid_file state
  local -a expected_results expected_kinds invocation=("$HELPER") expected_args install_args
  if [[ "$mode" == chain ]]; then
    invocation=(/usr/bin/bash "$TEST_TMP/update-and-install")
  fi
  IFS=, read -r -a expected_results <<<"$results"
  IFS=, read -r -a expected_kinds <<<"$kinds"
  expected_calls="${#expected_kinds[@]}"
  [[ "${#expected_results[@]}" == "$expected_calls" ]] || fail "$name has inconsistent fixture calls"
  for kind in "${expected_kinds[@]}"; do
    [[ "$kind" == apply ]] || expected_timeouts=$((expected_timeouts + 1))
  done
  mkdir "$case_dir"
  printf '0\n' >"$case_dir/apt.state"
  printf '0\n' >"$case_dir/timeout.state"
  : >"$case_dir/sleep.log"
  set +e
  # A closed PATH cannot fall through to real apt-get if any fake is missing.
  PATH="$TEST_TMP/bin" \
    FAKE_APT_STATE="$case_dir/apt.state" FAKE_APT_ARGV="$case_dir/apt.argv" FAKE_APT_RESULTS="$results" \
    FAKE_TIMEOUT_STATE="$case_dir/timeout.state" FAKE_TIMEOUT_ARGV="$case_dir/timeout.argv" \
    FAKE_SLEEP_LOG="$case_dir/sleep.log" \
    APT_HELPER_UNDER_TEST="$HELPER" \
    "${invocation[@]}" "${helper_args[@]}" >"$case_dir/output.log" 2>&1
  status=$?
  set -e
  [[ "$status" == "$expected_status" ]] || fail "$name returned $status, expected $expected_status"
  [[ "$(<"$case_dir/apt.state")" == "$expected_calls" ]] || fail "$name changed the APT invocation count"
  [[ "$(<"$case_dir/timeout.state")" == "$expected_timeouts" ]] || fail "$name changed bounded acquisition count"
  [[ "$(wc -l <"$case_dir/sleep.log")" == "$expected_waits" ]] || fail "$name changed the fixed inter-attempt waits"
  [[ "$(grep -c '^APT acquisition failed; retrying the exact command ' "$case_dir/output.log" || true)" == "$expected_waits" ]] \
    || fail "$name changed the retry reports"
  for ((attempt = 1; attempt <= expected_calls; attempt++)); do
    kind="${expected_kinds[$((attempt - 1))]}"
    install_args=("${helper_args[@]}")
    [[ "$mode" != chain ]] || install_args=(install -y package-one)
    case "$kind" in
      update) expected_args=("${helper_args[@]}") ;;
      download) expected_args=("${install_args[@]}" --download-only) ;;
      apply) expected_args=("${install_args[@]}" --no-download) ;;
      *) fail "$name has unknown expected invocation kind $kind" ;;
    esac
    expected_args+=(-o APT::Update::Error-Mode=any)
    printf '%s\0' "${expected_args[@]}" >"$TEST_TMP/expected-apt-argv"
    cmp "$TEST_TMP/expected-apt-argv" "$case_dir/apt.argv.$attempt" || fail "$name changed APT argument boundaries"
    if [[ "$kind" != apply ]]; then
      timeout_index=$((timeout_index + 1))
      printf '%s\0' --signal=TERM --kill-after=3s 300s apt-get "${expected_args[@]}" >"$TEST_TMP/expected-timeout-argv"
      cmp "$TEST_TMP/expected-timeout-argv" "$case_dir/timeout.argv.$timeout_index" \
        || fail "$name changed the 300s/TERM/3s acquisition deadline"
    fi
    if [[ "${expected_results[$((attempt - 1))]}" == hang ]]; then
      [[ "$kind" != apply ]] || fail "$name attempted to retry a mutating package apply"
      grep -Fxq TERM "$case_dir/apt.argv.$attempt.terminated" || fail "$name did not terminate the timed-out fake APT"
      for pid_file in "$case_dir/apt.argv.$attempt.apt-pid" "$case_dir/apt.argv.$attempt.child-pid"; do
        pid="$(<"$pid_file")"
        state="$(ps -o stat= -p "$pid" || true)"
        [[ -z "$state" ]] || fail "$name left its TERM-responsive fixture process $pid ($state)"
      done
      timed_out_transactions=$((timed_out_transactions + 1))
    fi
  done
  cases=$((cases + 1))
  total_apt_calls=$((total_apt_calls + expected_calls))
  bounded_acquisitions=$((bounded_acquisitions + expected_timeouts))
}

helper_args=(-o Acquire::https::Verify-Peer=false -o 'Acquire::https::User-Agent=codewire fixture' update)
run_case partial-update-recovery partial,0,0,0 0 update,update,download,apply 1 chain
run_case partial-update-exhaustion partial,partial,partial,partial 100 update,update,update,update 3 chain
helper_args+=(-o APT::Update::Error-Mode=persistent)
run_case caller-cannot-weaken-update partial,0,0,0 0 update,update,download,apply 1 chain

helper_args=(-o Acquire::https::Verify-Peer=false -o 'Acquire::https::User-Agent=codewire fixture' install -y package-one)
run_case immediate-success 0,0 0 download,apply 0
run_case ordinary-recovery 42,43,0,0 0 download,download,download,apply 2
run_case ordinary-exhaustion 41,42,43,44 44 download,download,download,download 3
run_case timeout-recovery hang,0,0 0 download,download,apply 1
run_case timeout-exhaustion hang,hang,hang,hang 124 download,download,download,download 3
run_case apply-failure-is-not-retried 0,67 67 download,apply 0

# This proves ordinary TERM-responsive children, not arbitrary detached process
# cleanup. The enclosing BuildKit namespace owns the broader lifecycle.
printf '[test-apt-get-with-retry] %s cases, %s APT calls, %s bounded acquisitions, %s real timeouts: safe acquisition/apply contract passed\n' \
  "$cases" "$total_apt_calls" "$bounded_acquisitions" "$timed_out_transactions"
