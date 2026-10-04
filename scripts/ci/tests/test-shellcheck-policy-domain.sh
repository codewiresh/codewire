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


# The fake ShellCheck reproduces the behaviour the policy depends on. It reports
# json1 findings only for the scripts named on its command line, and it applies
# ShellCheck's sourcing rule: without --external-sources, a sourced tracked
# script (a directive, a literal path, or "$dir/name" read as "./name") is
# followed only when it is named in the same invocation. A missing closure
# member surfaces as an SC2154 finding that no baseline reviews, as an
# unassigned variable from the unread file would. A fixture script marks each
# warning with a whole `# fixture-finding SC<code>` line.
fake_shellcheck="$TMP/shellcheck"
fake_log="$TMP/shellcheck.log"
cat > "$fake_shellcheck" <<'FAKE_SHELLCHECK'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == --version ]]; then
  printf 'ShellCheck - shell script analysis tool\nversion: 0.11.0\n'
  exit 0
fi

# Shards run concurrently: record each invocation as one locked write, or
# their partial writes interleave and the parser sees changed flags.
line=analysis
for arg in "$@"; do line+=$'\t'"$arg"; done
{
  flock 9
  printf '%s\n' "$line" >&9
} 9>> "${FAKE_SHELLCHECK_LOG:?}"

[[ "${1:-}" == --severity=warning && "${2:-}" == --format=json1 ]] || exit 4
shift 2
files=("$@")
named() {
  local file
  for file in "${files[@]}"; do
    [[ "$file" == "$1" ]] && return 0
  done
  return 1
}

if [[ -n "${FAKE_SHELLCHECK_FAIL_FILE:-}" ]] && named "$FAKE_SHELLCHECK_FAIL_FILE"; then
  exit "${FAKE_SHELLCHECK_STATUS:-7}"
fi
if [[ -n "${FAKE_SHELLCHECK_KILL_FILE:-}" ]] && named "$FAKE_SHELLCHECK_KILL_FILE"; then
  kill -KILL "$$"
fi
if [[ -n "${FAKE_SHELLCHECK_SLEEP_FILE:-}" ]] && named "$FAKE_SHELLCHECK_SLEEP_FILE"; then
  exec sleep "${FAKE_SHELLCHECK_SLEEP_SECONDS:-5}"
fi
if [[ -n "${FAKE_SHELLCHECK_GARBAGE_FILE:-}" ]] && named "$FAKE_SHELLCHECK_GARBAGE_FILE"; then
  printf 'not json1\n'
  exit 1
fi

lists="$(mktemp -d)"
trap 'rm -rf -- "$lists"' EXIT
printf '%s\n' "${files[@]}" > "$lists/named"
git ls-files -- '*.sh' > "$lists/tracked"
awk '
  FILENAME == ARGV[1] { named[$0] = 1; next }
  FILENAME == ARGV[2] { tracked[$0] = 1; next }
  FNR == 1 {
    directory = FILENAME
    if (!sub(/\/[^\/]*$/, "", directory)) directory = "."
  }
  /^# fixture-finding SC[0-9]+$/ {
    code = $0
    sub(/.*fixture-finding SC/, "", code)
    sub(/[^0-9].*/, "", code)
    print FILENAME "\t" FNR "\t" code
  }
  {
    target = ""
    if (match($0, /# shellcheck source=[^ ]+/)) {
      target = substr($0, RSTART + 20, RLENGTH - 20)
      if (substr(target, 1, 10) == "SCRIPTDIR/") {
        target = directory "/" substr(target, 11)
      }
    } else if ($0 ~ /^[[:space:]]*(source|\.)[[:space:]]+[^[:space:]]+[[:space:]]*$/) {
      target = $0
      sub(/^[[:space:]]*(source|\.)[[:space:]]+/, "", target)
      sub(/[[:space:]]+$/, "", target)
      gsub(/"/, "", target)
      # "$dir/name" is read as "./name"; any other expansion is not followed.
      if (target ~ /^\$[A-Za-z_][A-Za-z0-9_]*\//) sub(/^\$[A-Za-z_][A-Za-z0-9_]*\//, "", target)
      if (target ~ /^\$\{[^}]*\}\//) sub(/^\$\{[^}]*\}\//, "", target)
      if (target ~ /[$`]/) target = ""
    }
    if (target in tracked && !(target in named)) {
      print FILENAME "\t" FNR "\t2154"
    }
  }
' "$lists/named" "$lists/tracked" "${files[@]}" > "$lists/findings"

repository_findings='[]'
if [[ "${FAKE_SHELLCHECK_REPOSITORY_BASELINE:-0}" == 1 ]]; then
  select_named=false
  smoke_named=false
  named scripts/ci/select/select-verification.sh && select_named=true
  named scripts/runtime/tests/test-smoke-dev-commodity.sh && smoke_named=true
  repository_findings="$(jq -cn \
    --argjson select "$select_named" --argjson smoke "$smoke_named" '
      def findings($count; $file; $code):
        [range(0; $count) | {file: $file, line: 1, code: $code, level: "warning"}];
      (if $select then
        findings(2; "scripts/ci/select/select-verification.sh"; 2221) +
        findings(2; "scripts/ci/select/select-verification.sh"; 2222)
      else [] end) +
      (if $smoke then
        findings(9; "scripts/runtime/tests/test-smoke-dev-commodity.sh"; 1090) +
        findings(12; "scripts/runtime/tests/test-smoke-dev-commodity.sh"; 2034)
      else [] end)
    ')"
fi
jq -Rn --argjson repository "$repository_findings" '
  {comments: ($repository + [inputs | split("\t")
    | {file: .[0], line: (.[1] | tonumber), code: (.[2] | tonumber), level: "warning"}])}
' < "$lists/findings" > "$lists/report"
cat "$lists/report"
if [[ "$(jq '.comments | length' "$lists/report")" -gt 0 ]]; then
  exit 1
fi
FAKE_SHELLCHECK
chmod +x "$fake_shellcheck"

# Print each invocation's script arguments, one invocation per line.
invocation_scripts() {
  awk -F '\t' '
    $1 != "analysis" || $2 != "--severity=warning" || $3 != "--format=json1" {
      print "unexpected invocation: " $0
      next
    }
    { line = ""; for (i = 4; i <= NF; i++) line = line (i > 4 ? "\t" : "") $i; print line }
  ' "$fake_log"
}

# Require every tracked script in exactly one invocation and every named group
# of scripts in a shared invocation.
assert_partition() {
  local repository="$1" context="$2"
  shift 2
  local tracked invoked group
  grep -q '^unexpected invocation: ' < <(invocation_scripts) \
    && fail "$context: ShellCheck flags changed"
  tracked="$(env "${git_unset[@]}" git -C "$repository" ls-files -- '*.sh' | LC_ALL=C sort)"
  invoked="$(invocation_scripts | tr '\t' '\n' | LC_ALL=C sort)"
  [[ "$invoked" == "$tracked" ]] \
    || fail "$context: shards did not analyze each tracked script exactly once"
  for group in "$@"; do
    awk -F '\t' -v group="$group" '
      BEGIN { wanted = split(group, names, " ") }
      {
        found = 0
        for (i = 1; i <= NF; i++) for (j = 1; j <= wanted; j++) if ($i == names[j]) found++
        if (found == wanted) shared = 1
      }
      END { exit shared ? 0 : 1 }
    ' < <(invocation_scripts) || fail "$context: source closure split across shards: $group"
  done
}

# Hook environments can carry another repository's Git paths.
git_unset=(-u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_COMMON_DIR
  -u GIT_OBJECT_DIRECTORY -u GIT_ALTERNATE_OBJECT_DIRECTORIES)
run_checker() {
  local checker="$1"
  shift
  env "${git_unset[@]}" -u SHELLCHECK_TIMEOUT_SECONDS -u SHELLCHECK_SHARDS \
    FAKE_SHELLCHECK_LOG="$fake_log" \
    SHELLCHECK_BIN="$fake_shellcheck" \
    "$@" \
    "$checker"
}

# --- Fixture repository: sourced closures, ratchet changes and shard failures.
fixture="$TMP/fixture-repository"
mkdir -p "$fixture/scripts/ci/verify" "$fixture/scripts/ci/setup" \
  "$fixture/z-lib" "$fixture/tools"
cp "$CHECKER" "$fixture/scripts/ci/verify/check-shell-scripts.sh"
cp "$ROOT/scripts/ci/setup/setup-shellcheck.sh" "$fixture/scripts/ci/setup/setup-shellcheck.sh"
cat > "$fixture/scripts/ci/verify/shellcheck-baseline.sh" <<'BASELINE'
#!/usr/bin/env bash
readonly SHELLCHECK_BASELINE_TSV=$'# path\tcode\tcount\treason\n'\
$'m-03.sh\tSC2034\t2\tfixture-reviewed'
BASELINE
# The consumer sorts first and its library last, and padding makes their
# component the heaviest, so a split by path order or by size would separate
# them. The library sources a deeper file in turn.
{
  printf '#!/usr/bin/env bash\n'
  printf '# shellcheck source=z-lib/common.sh\nsource "$LIBRARY"\n'
  printf 'printf "%%s\\n" "$common_value"\n'
  for ((line = 0; line < 1000; line++)); do
    printf '# consumer padding line %s\n' "$line"
  done
} > "$fixture/a-consumer.sh"
printf '#!/usr/bin/env bash\n# shellcheck source=z-lib/deep.sh\nsource "$DEEP"\ncommon_value="$deep_value"\n' \
  > "$fixture/z-lib/common.sh"
printf '#!/usr/bin/env bash\ndeep_value=1\n' > "$fixture/z-lib/deep.sh"
printf '#!/usr/bin/env bash\n# shellcheck source=SCRIPTDIR/helper.sh\nsource "$HELPER"\n' \
  > "$fixture/tools/scriptdir.sh"
printf '#!/usr/bin/env bash\nhelper_value=1\n' > "$fixture/tools/helper.sh"
printf '#!/usr/bin/env bash\nsource tools/literal-lib.sh\n' > "$fixture/tools/literal.sh"
printf '#!/usr/bin/env bash\nliteral_value=1\n' > "$fixture/tools/literal-lib.sh"
printf '#!/usr/bin/env bash\nsource "$FIXTURE_ROOT/tools/dynamic-lib.sh"\n' > "$fixture/tools/dynamic.sh"
printf '#!/usr/bin/env bash\ndynamic_value=1\n' > "$fixture/tools/dynamic-lib.sh"
for member in 01 02 03 04 05 06 07 08; do
  printf '#!/usr/bin/env bash\nprintf "%%s\\n" %s\n' "$member" > "$fixture/m-$member.sh"
done
printf '# fixture-finding SC2034\n# fixture-finding SC2034\n' >> "$fixture/m-03.sh"
env "${git_unset[@]}" git -C "$fixture" init -q
env "${git_unset[@]}" git -C "$fixture" add -A
fixture_checker="$fixture/scripts/ci/verify/check-shell-scripts.sh"
fixture_closures=(
  'a-consumer.sh z-lib/common.sh z-lib/deep.sh'
  'tools/scriptdir.sh tools/helper.sh'
  'tools/literal.sh tools/literal-lib.sh'
  'tools/dynamic.sh tools/dynamic-lib.sh'
  'scripts/ci/verify/check-shell-scripts.sh scripts/ci/verify/shellcheck-baseline.sh'
)

# Control: the fake reports an unread closure, so a split closure cannot pass.
split_output="$(cd "$fixture" && env "${git_unset[@]}" FAKE_SHELLCHECK_LOG="$TMP/control.log" \
  "$fake_shellcheck" --severity=warning --format=json1 a-consumer.sh z-lib/common.sh)" \
  && fail 'fake ShellCheck accepted a consumer without its whole closure'
[[ "$(jq -c '[.comments[] | [.file, .code]]' <<<"$split_output")" \
    == '[["z-lib/common.sh",2154]]' ]] \
  || fail 'fake ShellCheck did not report the unread deeper source'

: > "$fake_log"
fixture_output="$(run_checker "$fixture_checker" 2>&1)" \
  || fail "sharded fixture analysis failed: $fixture_output"
grep -Fq 'ShellCheck analysis: start (scripts=20 shards=4 timeout_seconds=600)' \
  <<<"$fixture_output" || fail 'fixture analysis did not start four shards'
grep -Fq 'ShellCheck shard 1/4 (scripts=3 heaviest=a-consumer.sh): start' \
  <<<"$fixture_output" || fail 'heaviest closure did not lead its own shard'
grep -Fq 'ShellCheck warning ratchet: OK (20 scripts, 4 shards, 1 reviewed groups)' \
  <<<"$fixture_output" || fail 'reviewed fixture findings did not pass'
[[ "$(wc -l < "$fake_log")" -eq 4 ]] || fail 'fixture analysis did not run four shards'
assert_partition "$fixture" 'four shards' "${fixture_closures[@]}"

: > "$fake_log"
single_output="$(run_checker "$fixture_checker" SHELLCHECK_SHARDS=1 2>&1)" \
  || fail "single-shard fixture analysis failed: $single_output"
grep -Fq 'ShellCheck warning ratchet: OK (20 scripts, 1 shards, 1 reviewed groups)' \
  <<<"$single_output" || fail 'single-shard analysis did not pass'
[[ "$(wc -l < "$fake_log")" -eq 1 ]] || fail 'SHELLCHECK_SHARDS=1 ran more than one process'
assert_partition "$fixture" 'one shard' "${fixture_closures[@]}"

# A new warning fails the ratchet even though it appears in one shard only.
cp "$fixture/m-05.sh" "$TMP/m-05.sh"
printf '# fixture-finding SC2086\n' >> "$fixture/m-05.sh"
if new_output="$(run_checker "$fixture_checker" 2>&1)"; then
  fail 'sharded analysis accepted a new warning'
fi
grep -Fq 'ShellCheck warning set differs from the reviewed baseline' <<<"$new_output" \
  || fail 'new warning was not diagnosed'
grep -Fxq -e $'+m-05.sh\tSC2086\t1' <<<"$new_output" \
  || fail 'new warning was not reported in the ratchet diff'
cp "$TMP/m-05.sh" "$fixture/m-05.sh"

# A fixed warning is reported as a changed reviewed count, which also fails
# until the baseline is ratcheted down.
cp "$fixture/m-03.sh" "$TMP/m-03.sh"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" 03\n# fixture-finding SC2034\n' > "$fixture/m-03.sh"
if fixed_output="$(run_checker "$fixture_checker" 2>&1)"; then
  fail 'sharded analysis accepted a stale reviewed count'
fi
grep -Fxq -e $'-m-03.sh\tSC2034\t2' <<<"$fixed_output" \
  && grep -Fxq -e $'+m-03.sh\tSC2034\t1' <<<"$fixed_output" \
  || fail 'fixed warning was not reported against the reviewed count'
cp "$TMP/m-03.sh" "$fixture/m-03.sh"

# Any failing shard fails the analysis; the other shards' findings never pass.
: > "$fake_log"
set +e
failure_output="$(run_checker "$fixture_checker" \
  FAKE_SHELLCHECK_FAIL_FILE=m-07.sh FAKE_SHELLCHECK_STATUS=7 2>&1)"
failure_status=$?
set -e
[[ "$failure_status" -eq 7 ]] || fail 'shard failure status was not propagated'
grep -Eq '^ShellCheck shard [1-4]/4 \(scripts=[0-9]+ heaviest=[^)]+\) failed with status 7$' \
  <<<"$failure_output" || fail 'shard failure did not name its shard'
grep -Fq 'ratchet: OK' <<<"$failure_output" && fail 'a failed shard still passed the ratchet'
[[ "$(wc -l < "$fake_log")" -eq 4 ]] || fail 'a failed shard stopped the other shards'

set +e
killed_output="$(run_checker "$fixture_checker" FAKE_SHELLCHECK_KILL_FILE=m-02.sh 2>&1)"
killed_status=$?
set -e
[[ "$killed_status" -eq 137 ]] || fail 'killed shard status was not propagated'
grep -Eq '^ShellCheck shard [1-4]/4 \(.*\) was killed after [0-9]+ seconds, before its deadline' \
  <<<"$killed_output" || fail 'killed shard was not diagnosed'
grep -Fq 'ratchet: OK' <<<"$killed_output" && fail 'a killed shard still passed the ratchet'

set +e
garbage_output="$(run_checker "$fixture_checker" FAKE_SHELLCHECK_GARBAGE_FILE=m-04.sh 2>&1)"
garbage_status=$?
set -e
[[ "$garbage_status" -eq 1 ]] || fail 'invalid shard report did not fail'
grep -Eq '^ShellCheck shard [1-4]/4 \(.*\) wrote no valid json1 report$' \
  <<<"$garbage_output" || fail 'invalid shard report was not diagnosed'

# One deadline bounds every shard and the whole analysis, and the timeout
# names the shard holding the script that did not finish.
set +e
timeout_output="$(run_checker "$fixture_checker" SHELLCHECK_TIMEOUT_SECONDS=1 \
  FAKE_SHELLCHECK_SLEEP_FILE=z-lib/deep.sh FAKE_SHELLCHECK_SLEEP_SECONDS=5 2>&1)"
timeout_status=$?
set -e
[[ "$timeout_status" -eq 124 ]] || fail 'shard timeout status was not propagated'
grep -Fxq 'ShellCheck shard 1/4 (scripts=3 heaviest=a-consumer.sh) timed out after 1 seconds' \
  <<<"$timeout_output" || fail 'shard timeout did not name its shard'
grep -Eq 'ShellCheck analysis: finish \(status=124 elapsed_seconds=[0-3]\)' \
  <<<"$timeout_output" || fail 'the deadline did not bound the whole analysis'
grep -Fq 'ratchet: OK' <<<"$timeout_output" && fail 'a timed-out shard still passed the ratchet'

for invalid_shards in 0 17 two; do
  set +e
  invalid_shards_output="$(run_checker "$fixture_checker" \
    SHELLCHECK_SHARDS="$invalid_shards" 2>&1)"
  invalid_shards_status=$?
  set -e
  [[ "$invalid_shards_status" -eq 2 ]] || fail "invalid shard count $invalid_shards was accepted"
  grep -Fq 'SHELLCHECK_SHARDS must be an integer from 1 through 16' \
    <<<"$invalid_shards_output" || fail 'invalid shard count was not diagnosed'
done

# --- The repository itself: every tracked script, the reviewed baseline, and
# every sourced tracked script analyzed beside the scripts that source it.
: > "$fake_log"
baseline_output="$(run_checker "$CHECKER" FAKE_SHELLCHECK_REPOSITORY_BASELINE=1 2>&1)" \
  || fail "matching fake ShellCheck baseline was rejected: $baseline_output"
grep -Fq 'ShellCheck analysis: start (' <<<"$baseline_output" \
  || fail 'ShellCheck start timing is absent'
grep -Fq 'shards=4 timeout_seconds=600)' <<<"$baseline_output" \
  || fail 'ShellCheck default shards or deadline changed'
grep -Eq 'ShellCheck analysis: finish \(status=1 elapsed_seconds=[0-9]+\)' \
  <<<"$baseline_output" || fail 'ShellCheck finish timing is absent'
grep -Fq 'ShellCheck warning ratchet: OK' <<<"$baseline_output" \
  || fail 'matching warning baseline did not pass'
assert_partition "$ROOT" 'repository' \
  'scripts/ci/verify/check-shell-scripts.sh scripts/ci/verify/shellcheck-baseline.sh'

set +e
error_output="$(run_checker "$CHECKER" FAKE_SHELLCHECK_REPOSITORY_BASELINE=1 \
  FAKE_SHELLCHECK_FAIL_FILE=scripts/ci/verify/check-shell-scripts.sh \
  FAKE_SHELLCHECK_STATUS=7 2>&1)"
error_status=$?
set -e
[[ "$error_status" -eq 7 ]] || fail 'ShellCheck execution status was not propagated'
grep -Fq 'failed with status 7' <<<"$error_output" \
  || fail 'ShellCheck execution failure was not diagnosed'

set +e
invalid_output="$(run_checker "$CHECKER" SHELLCHECK_TIMEOUT_SECONDS=invalid 2>&1)"
invalid_status=$?
set -e
[[ "$invalid_status" -eq 2 ]] || fail 'invalid timeout was accepted'
grep -Fq 'SHELLCHECK_TIMEOUT_SECONDS must be an integer from 1 through 900' \
  <<<"$invalid_output" || fail 'invalid timeout was not diagnosed'

printf 'ShellCheck policy-domain routing, shard and timeout tests: OK\n'
