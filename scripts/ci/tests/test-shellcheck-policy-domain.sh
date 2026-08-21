#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUNNER="$ROOT/scripts/ci/verify/run-product-verification.sh"
CHECKER="$ROOT/scripts/ci/verify/check-shell-scripts.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/shellcheck-policy-domain.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf 'ShellCheck policy-domain test: %s\n' "$*" >&2
  exit 1
}

policy_dispatch="$TMP/run-policy.sh"
awk '
  /^run_policy\(\) \{/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "$RUNNER" > "$policy_dispatch"
grep -Fq 'selected policy_shell || ! selected policy_shell_omittable' \
  "$policy_dispatch" || fail 'policy runner omits the legacy-safe routing guard'
grep -Fq 'policy-core) run_policy_core' "$RUNNER" \
  || fail 'hosted policy core has no independent entrypoint'
grep -Fq 'policy-shell) run_shell_policy' "$RUNNER" \
  || fail 'hosted ShellCheck has no independent heavy entrypoint'

run_dispatch_fixture() {
  local selection="$1"
  SELECTION="$selection" bash -c '
    set -euo pipefail
    selected() { [[ "$SELECTION" == *"|$1|"* ]]; }
    run_shell_policy() { printf "shell\n"; }
    run_policy_core() { printf "core\n"; }
    source "$1"
    run_policy
  ' bash "$policy_dispatch"
}

legacy_output="$(run_dispatch_fixture '|valid:v3|policy|complete|')"
[[ "$legacy_output" == $'shell\ncore' ]] \
  || fail 'legacy trusted selection skipped ShellCheck'
selected_output="$(run_dispatch_fixture \
  '|valid:v3|policy|policy_shell|policy_shell_omittable|complete|')"
[[ "$selected_output" == $'shell\ncore' ]] \
  || fail 'selected shell policy did not execute ShellCheck'
omitted_output="$(run_dispatch_fixture \
  '|valid:v3|policy|policy_shell_omittable|complete|')"
[[ "$omitted_output" == core ]] \
  || fail 'authoritative shell-policy omission still executed ShellCheck'

fake_shellcheck="$TMP/shellcheck"
fake_log="$TMP/shellcheck.log"
cat > "$fake_shellcheck" <<'FAKE_SHELLCHECK'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == --version ]]; then
  printf 'ShellCheck - shell script analysis tool\nversion: 0.11.0\n'
  exit 0
fi

{
  printf 'analysis'
  printf '\t%s' "$@"
  printf '\n'
} >> "${FAKE_SHELLCHECK_LOG:?}"

case "${FAKE_SHELLCHECK_MODE:-baseline}" in
  baseline)
    jq -cn '
      def findings($count; $file; $code):
        [range(0; $count) | {file: $file, code: $code}];
      {comments: (
        findings(2; "scripts/ci/select/select-verification.sh"; 2221) +
        findings(2; "scripts/ci/select/select-verification.sh"; 2222) +
        findings(2; "scripts/runtime/dev/smoke-dev-commodity.sh"; 2034) +
        findings(9; "scripts/runtime/tests/test-smoke-dev-commodity.sh"; 1090) +
        findings(14; "scripts/runtime/tests/test-smoke-dev-commodity.sh"; 2034)
      )}
    '
    exit 1
    ;;
  error)
    exit "${FAKE_SHELLCHECK_STATUS:-7}"
    ;;
  timeout)
    sleep "${FAKE_SHELLCHECK_SLEEP_SECONDS:-5}"
    exit 0
    ;;
  *)
    exit 2
    ;;
esac
FAKE_SHELLCHECK
chmod +x "$fake_shellcheck"

run_checker() {
  env \
    FAKE_SHELLCHECK_LOG="$fake_log" \
    SHELLCHECK_BIN="$fake_shellcheck" \
    "$@" \
    "$CHECKER"
}

: > "$fake_log"
baseline_output="$(run_checker 2>&1)" \
  || fail 'matching fake ShellCheck baseline was rejected'
grep -Fq 'ShellCheck analysis: start (' <<<"$baseline_output" \
  || fail 'ShellCheck start timing is absent'
grep -Eq 'ShellCheck analysis: finish \(status=1 elapsed_seconds=[0-9]+\)' \
  <<<"$baseline_output" || fail 'ShellCheck finish timing is absent'
grep -Fq 'ShellCheck warning ratchet: OK' <<<"$baseline_output" \
  || fail 'matching warning baseline did not pass'

mapfile -t tracked_shell_files < <(cd "$ROOT" && git ls-files -- '*.sh')
expected_invocation='analysis'
expected_invocation+=$'\t--severity=warning\t--format=json1'
for tracked_shell_file in "${tracked_shell_files[@]}"; do
  expected_invocation+=$'\t'"$tracked_shell_file"
done
[[ "$(cat "$fake_log")" == "$expected_invocation" ]] \
  || fail 'ShellCheck arguments or tracked file order changed'

: > "$fake_log"
set +e
error_output="$(FAKE_SHELLCHECK_MODE=error FAKE_SHELLCHECK_STATUS=7 \
  run_checker 2>&1)"
error_status=$?
set -e
[[ "$error_status" -eq 7 ]] || fail 'ShellCheck execution status was not propagated'
grep -Fq 'ShellCheck failed with status 7' <<<"$error_output" \
  || fail 'ShellCheck execution failure was not diagnosed'

: > "$fake_log"
set +e
timeout_output="$(FAKE_SHELLCHECK_MODE=timeout FAKE_SHELLCHECK_SLEEP_SECONDS=5 \
  run_checker SHELLCHECK_TIMEOUT_SECONDS=1 2>&1)"
timeout_status=$?
set -e
[[ "$timeout_status" -eq 124 ]] || fail 'ShellCheck timeout status was not propagated'
grep -Fq 'ShellCheck timed out after 1 seconds' <<<"$timeout_output" \
  || fail 'ShellCheck timeout was not diagnosed'
grep -Eq 'ShellCheck analysis: finish \(status=124 elapsed_seconds=[0-9]+\)' \
  <<<"$timeout_output" || fail 'ShellCheck timeout timing is absent'

set +e
invalid_output="$(run_checker SHELLCHECK_TIMEOUT_SECONDS=invalid 2>&1)"
invalid_status=$?
set -e
[[ "$invalid_status" -eq 2 ]] || fail 'invalid timeout was accepted'
grep -Fq 'SHELLCHECK_TIMEOUT_SECONDS must be an integer from 1 through 900' \
  <<<"$invalid_output" || fail 'invalid timeout was not diagnosed'

printf 'ShellCheck policy-domain routing and timeout tests: OK\n'
