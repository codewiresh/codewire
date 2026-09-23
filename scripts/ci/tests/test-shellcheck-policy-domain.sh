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
  local selection="$1" failure="${2:-}"
  SELECTION="$selection" POLICY_FIXTURE_FAILURE="$failure" bash -c '
    set -euo pipefail
    selected() { [[ "$SELECTION" == *"|$1|"* ]]; }
    run_shell_policy() {
      printf "shell\n"
      if [ "$POLICY_FIXTURE_FAILURE" = shell ]; then return 41; fi
    }
    run_policy_core() {
      printf "core\n"
      if [ "$POLICY_FIXTURE_FAILURE" = core ]; then return 42; fi
    }
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

# Exercise the actual shared dispatcher in a fresh shell so a failure cannot
# be hidden by an outer conditional or followed by another policy phase.
if shell_failure_output="$(run_dispatch_fixture \
  '|valid:v3|policy|policy_shell|policy_shell_omittable|complete|' shell)"; then
  fail 'shared policy accepted a failing shell phase'
else
  shell_failure_status=$?
fi
[[ "$shell_failure_status" -eq 41 ]] \
  || fail 'shared policy changed the shell failure status'
[[ "$shell_failure_output" == shell ]] \
  || fail 'shared policy ran core after a shell failure'
if core_failure_output="$(run_dispatch_fixture \
  '|valid:v3|policy|policy_shell|policy_shell_omittable|complete|' core)"; then
  fail 'shared policy accepted a failing core phase'
else
  core_failure_status=$?
fi
[[ "$core_failure_status" -eq 42 ]] \
  || fail 'shared policy changed the core failure status'
[[ "$core_failure_output" == $'shell\ncore' ]] \
  || fail 'shared policy repeated a phase before the core failure'
if omitted_failure_output="$(run_dispatch_fixture \
  '|valid:v3|policy|policy_shell_omittable|complete|' core)"; then
  fail 'shell-omitted policy accepted a failing core phase'
else
  omitted_failure_status=$?
fi
[[ "$omitted_failure_status" -eq 42 && "$omitted_failure_output" == core ]] \
  || fail 'shell-omitted policy did not preserve the core failure'

# Validate the shared syntax owner, including a second fixed-list file and a
# runtime path containing spaces. No product runner or heavy policy is invoked.
syntax_dispatch="$TMP/run-verification-shell-syntax.sh"
awk '
  /^run_verification_shell_syntax\(\) \{/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "$RUNNER" > "$syntax_dispatch"
grep -Fq 'run_verification_shell_syntax() {' "$syntax_dispatch" \
  || fail 'shared policy has no verification syntax owner'
syntax_tree="$TMP/syntax-tree"
mkdir -p "$syntax_tree/.githooks" "$syntax_tree/scripts/dev" \
  "$syntax_tree/scripts/runtime"
printf '#!/usr/bin/env bash\n:\n' > "$syntax_tree/.githooks/pre-push"
printf '#!/usr/bin/env bash\n:\n' > "$syntax_tree/scripts/dev/preflight.sh"
printf '#!/usr/bin/env bash\n:\n' > "$syntax_tree/scripts/runtime/space name.sh"
run_syntax_fixture() {
  bash -c '
    set -euo pipefail
    cd "$1"
    source "$2"
    run_verification_shell_syntax
  ' bash "$syntax_tree" "$syntax_dispatch"
}
run_syntax_fixture || fail 'shared syntax owner rejected valid fixture files'
printf '#!/usr/bin/env bash\nif then\n' > "$syntax_tree/scripts/dev/preflight.sh"
if fixed_syntax_output="$(run_syntax_fixture 2>&1)"; then
  fail 'shared syntax owner ignored an invalid second fixed-list file'
fi
grep -Fq 'scripts/dev/preflight.sh' <<<"$fixed_syntax_output" \
  || fail 'second-file syntax failure did not identify its source'
printf '#!/usr/bin/env bash\n:\n' > "$syntax_tree/scripts/dev/preflight.sh"
printf '#!/usr/bin/env bash\nif then\n' > "$syntax_tree/scripts/runtime/space name.sh"
if runtime_syntax_output="$(run_syntax_fixture 2>&1)"; then
  fail 'shared syntax owner ignored an invalid runtime script'
fi
grep -Fq 'scripts/runtime/space name.sh' <<<"$runtime_syntax_output" \
  || fail 'runtime syntax failure did not identify its source'

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
    # Report the reviewed findings only for files this batch analyzes.
    printf '%s\n' "$@" | jq -Rn '
      def findings($count; $file; $code):
        [range(0; $count) | {file: $file, code: $code}];
      [inputs] as $files
      | {comments: ([
          findings(2; "scripts/ci/select/select-verification.sh"; 2221),
          findings(2; "scripts/ci/select/select-verification.sh"; 2222),
          findings(9; "scripts/runtime/tests/test-smoke-dev-commodity.sh"; 1090),
          findings(12; "scripts/runtime/tests/test-smoke-dev-commodity.sh"; 2034)
        ] | add | map(select(.file as $file | $files | index($file))))}
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
  env -u SHELLCHECK_TIMEOUT_SECONDS -u SHELLCHECK_JOBS \
    FAKE_SHELLCHECK_LOG="$fake_log" \
    SHELLCHECK_BIN="$fake_shellcheck" \
    "$@" \
    "$CHECKER"
}

: > "$fake_log"
baseline_output="$(run_checker SHELLCHECK_JOBS=1 2>&1)" \
  || fail 'matching fake ShellCheck baseline was rejected'
grep -Fq 'ShellCheck analysis: start (' <<<"$baseline_output" \
  || fail 'ShellCheck start timing is absent'
grep -Fq 'timeout_seconds=300)' <<<"$baseline_output" \
  || fail 'ShellCheck default deadline does not allow bounded full-analysis headroom'
grep -Eq 'ShellCheck analysis: finish \(status=1 elapsed_seconds=[0-9]+\)' \
  <<<"$baseline_output" || fail 'ShellCheck finish timing is absent'
grep -Fq 'ShellCheck warning ratchet: OK' <<<"$baseline_output" \
  || fail 'matching warning baseline did not pass'

mapfile -t tracked_shell_files < <(cd "$ROOT" && git ls-files -- '*.sh')
expected_invocation='analysis'
expected_invocation+=$'\t--external-sources\t--severity=warning\t--format=json1'
for tracked_shell_file in "${tracked_shell_files[@]}"; do
  expected_invocation+=$'\t'"$tracked_shell_file"
done
[[ "$(cat "$fake_log")" == "$expected_invocation" ]] \
  || fail 'ShellCheck arguments or tracked file order changed'

# Parallel batches analyze every tracked file exactly once, with the same
# arguments, and their merged findings meet the same reviewed baseline.
: > "$fake_log"
parallel_output="$(run_checker SHELLCHECK_JOBS=3 2>&1)" \
  || fail 'parallel ShellCheck batches did not meet the reviewed baseline'
grep -Fq 'jobs=3 ' <<<"$parallel_output" \
  || fail 'ShellCheck start did not report its batch count'
[[ "$(wc -l < "$fake_log")" -eq 3 ]] \
  || fail 'ShellCheck did not run exactly three batches'
if grep -v $'^analysis\t--external-sources\t--severity=warning\t--format=json1\t' "$fake_log"; then
  fail 'a ShellCheck batch changed its analysis arguments'
fi
[[ "$(cut -f5- "$fake_log" | tr '\t' '\n' | LC_ALL=C sort)" \
    == "$(printf '%s\n' "${tracked_shell_files[@]}" | LC_ALL=C sort)" ]] \
  || fail 'ShellCheck batches did not analyze each tracked file exactly once'

set +e
invalid_jobs_output="$(run_checker SHELLCHECK_JOBS=0 2>&1)"
invalid_jobs_status=$?
set -e
[[ "$invalid_jobs_status" -eq 2 ]] || fail 'invalid ShellCheck job count was accepted'
grep -Fq 'SHELLCHECK_JOBS must be an integer from 1 through 64' \
  <<<"$invalid_jobs_output" || fail 'invalid ShellCheck job count was not diagnosed'

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
