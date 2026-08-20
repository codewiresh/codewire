#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HELPER="$ROOT/images/base/apt-get-with-retry"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/apt-get-with-retry.XXXXXX")"
readonly TEST_TMP
trap 'rm -rf "$TEST_TMP"' EXIT

fail() {
  printf '[test-apt-get-with-retry] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$TEST_TMP/bin"
cat >"$TEST_TMP/bin/apt-get" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
count="$(cat "$FAKE_APT_STATE")"
count="$((count + 1))"
printf '%s\n' "$count" >"$FAKE_APT_STATE"
printf '%s\n' "$*" >>"$FAKE_APT_LOG"
if [ "$count" -le "$FAKE_APT_FAILURES" ]; then
  exit 42
fi
SH
chmod 0755 "$TEST_TMP/bin/apt-get"

cat >"$TEST_TMP/bin/sleep" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_SLEEP_LOG"
SH
chmod 0755 "$TEST_TMP/bin/sleep"

run_helper() {
  PATH="$TEST_TMP/bin:$PATH" \
    FAKE_APT_STATE="$1" \
    FAKE_APT_LOG="$2" \
    FAKE_SLEEP_LOG="$3" \
    FAKE_APT_FAILURES="$4" \
    "$HELPER" -o Acquire::https::Verify-Peer=false install -y package-one
}

success_state="$TEST_TMP/success.state"
success_apt_log="$TEST_TMP/success.apt.log"
success_sleep_log="$TEST_TMP/success.sleep.log"
printf '0\n' >"$success_state"
: >"$success_apt_log"
: >"$success_sleep_log"
run_helper "$success_state" "$success_apt_log" "$success_sleep_log" 2
[[ "$(cat "$success_state")" -eq 3 ]] || fail 'transient failure did not recover on attempt three'
[[ "$(grep -c '^30$' "$success_sleep_log")" -eq 2 ]] || fail 'transient failure did not use two fixed waits'
[[ "$(sort -u "$success_apt_log" | wc -l | tr -d ' ')" -eq 1 ]] || fail 'retry changed the original APT arguments'

exhausted_state="$TEST_TMP/exhausted.state"
exhausted_apt_log="$TEST_TMP/exhausted.apt.log"
exhausted_sleep_log="$TEST_TMP/exhausted.sleep.log"
printf '0\n' >"$exhausted_state"
: >"$exhausted_apt_log"
: >"$exhausted_sleep_log"
if run_helper "$exhausted_state" "$exhausted_apt_log" "$exhausted_sleep_log" 4; then
  fail 'four failed transactions were accepted'
fi
[[ "$(cat "$exhausted_state")" -eq 4 ]] || fail 'retry boundary did not stop after four attempts'
[[ "$(grep -c '^30$' "$exhausted_sleep_log")" -eq 3 ]] || fail 'retry boundary did not use exactly three waits'

printf '[test-apt-get-with-retry] bounded transaction contract passed\n'
