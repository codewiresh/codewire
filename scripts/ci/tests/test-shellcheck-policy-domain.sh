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

# The policy family is the parts the runner lists for the selection, run in
# order. Extract the list, the part dispatcher and the family together.
policy_dispatch="$TMP/run-policy.sh"
for policy_function in policy_parts run_policy_part run_policy; do
  awk -v name="$policy_function" '
    $0 == name "() {" { capture = 1 }
    capture { print }
    capture && /^}$/ { exit }
  ' "$RUNNER"
done > "$policy_dispatch"
grep -Fq 'selected policy_shell || ! selected policy_shell_omittable' \
  "$policy_dispatch" || fail 'policy runner omits the legacy-safe routing guard'
grep -Fq 'selected ci_script_tests || ! selected ci_script_tests_omittable' \
  "$policy_dispatch" || fail 'policy runner omits the legacy-safe CI-script test guard'
grep -Fq 'policy-core) run_policy_core' "$RUNNER" \
  || fail 'hosted policy core has no independent entrypoint'
grep -Fq 'policy-repo-rules|policy-ci-script-tests|policy-planner-tests) run_policy_part "$FAMILY"' "$RUNNER" \
  || fail 'policy core parts have no independent entrypoints'
grep -Fq 'policy-parts) policy_parts' "$RUNNER" \
  || fail 'the policy part list has no entrypoint'
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
    run_repo_rules() {
      printf "rules\n"
      if [ "$POLICY_FIXTURE_FAILURE" = rules ]; then return 42; fi
    }
    run_ci_script_tests() {
      printf "ci-tests\n"
      if [ "$POLICY_FIXTURE_FAILURE" = ci-tests ]; then return 43; fi
    }
    source "$1"
    run_policy
  ' bash "$policy_dispatch"
}

legacy_output="$(run_dispatch_fixture '|valid:v3|policy|complete|')"
[[ "$legacy_output" == $'shell\nrules\nci-tests' ]] \
  || fail 'legacy trusted selection skipped ShellCheck or the CI-script tests'
selected_output="$(run_dispatch_fixture \
  '|valid:v3|policy|policy_shell|policy_shell_omittable|complete|')"
[[ "$selected_output" == $'shell\nrules\nci-tests' ]] \
  || fail 'selected shell policy did not execute ShellCheck'
omitted_output="$(run_dispatch_fixture \
  '|valid:v3|policy|policy_shell_omittable|complete|')"
[[ "$omitted_output" == $'rules\nci-tests' ]] \
  || fail 'authoritative shell-policy omission still executed ShellCheck'
ci_omitted_output="$(run_dispatch_fixture \
  '|valid:v3|ci_script_tests_omittable|policy|policy_shell_omittable|complete|')"
[[ "$ci_omitted_output" == rules ]] \
  || fail 'authoritative CI-script test omission still executed the CI-script tests'
ci_selected_output="$(run_dispatch_fixture \
  '|valid:v3|ci_script_tests|ci_script_tests_omittable|policy|policy_shell_omittable|complete|')"
[[ "$ci_selected_output" == $'rules\nci-tests' ]] \
  || fail 'selected CI-script tests did not execute'

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
  '|valid:v3|policy|policy_shell|policy_shell_omittable|complete|' rules)"; then
  fail 'shared policy accepted failing repository rules'
else
  core_failure_status=$?
fi
[[ "$core_failure_status" -eq 42 ]] \
  || fail 'shared policy changed the repository rules failure status'
[[ "$core_failure_output" == $'shell\nrules' ]] \
  || fail 'shared policy repeated a phase or ran on after the repository rules failed'
if second_core_failure_output="$(run_dispatch_fixture \
  '|valid:v3|policy|policy_shell|policy_shell_omittable|complete|' ci-tests)"; then
  fail 'shared policy accepted failing CI-script tests'
else
  second_core_failure_status=$?
fi
[[ "$second_core_failure_status" -eq 43 \
    && "$second_core_failure_output" == $'shell\nrules\nci-tests' ]] \
  || fail 'shared policy did not preserve the CI-script test failure'
if omitted_failure_output="$(run_dispatch_fixture \
  '|valid:v3|ci_script_tests_omittable|policy|policy_shell_omittable|complete|' rules)"; then
  fail 'shell-omitted policy accepted failing repository rules'
else
  omitted_failure_status=$?
fi
[[ "$omitted_failure_status" -eq 42 && "$omitted_failure_output" == rules ]] \
  || fail 'shell-omitted policy did not preserve the repository rules failure'

# A pull request names its base, so ShellCheck covers only its changed
# scripts; without a base every script is checked. Run the runner's own
# function against a stub checker that records its arguments.
shell_policy="$TMP/run-shell-policy.sh"
awk '
  /^run_shell_policy\(\) \{/ { capture = 1 }
  capture { print }
  capture && /^}$/ { exit }
' "$RUNNER" > "$shell_policy"
stub_tree="$TMP/shell-policy-tree"
mkdir -p "$stub_tree/scripts/ci/verify"
printf '#!/usr/bin/env bash\nprintf "[%%s]\\n" "$*" >> "$SHELL_POLICY_LOG"\n' \
  > "$stub_tree/scripts/ci/verify/check-shell-scripts.sh"
chmod +x "$stub_tree/scripts/ci/verify/check-shell-scripts.sh"
run_shell_policy_fixture() {
  : > "$TMP/shell-policy.log"
  (cd "$stub_tree" && SHELL_POLICY_LOG="$TMP/shell-policy.log" CODEWIRE_SHELL_POLICY_BASE="$1" \
    bash -c 'set -euo pipefail; source "$1"; run_shell_policy' bash "$shell_policy")
  cat "$TMP/shell-policy.log"
}
pull_request_base="$(printf '%040d' 7)"
[[ "$(run_shell_policy_fixture "$pull_request_base")" == $'[--self-test]\n[--changed-since '"$pull_request_base]" ]] \
  || fail 'a pull request did not ShellCheck only its changed scripts'
[[ "$(run_shell_policy_fixture '')" == $'[--self-test]\n[]' ]] \
  || fail 'a run without a pull-request base did not ShellCheck every script'

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


# The fake ShellCheck reproduces the behaviour the policy depends on. Every
# analysis must pass --external-sources, so it follows each tracked script a
# named script sources (a directive, a literal path, or "$dir/name" read as
# "./name"), through any depth. It reports json1 findings for each named script
# and also, as a report may, for each followed script the invocation does not
# name; the checker must count only the named scripts' comments. A fixture
# script marks each warning with a whole `# fixture-finding SC<code>` line.
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

[[ "${1:-}" == --external-sources && "${2:-}" == --severity=warning \
  && "${3:-}" == --format=json1 ]] || exit 4
shift 3
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
mapfile -t tracked < "$lists/tracked"
awk '
  function follow(file, root,    position) {
    if (file in seen) return
    seen[file] = 1
    if (file == root || !(file in is_named)) {
      for (position = 1; position <= findings[file]; position++) {
        print file "\t" finding[file, position]
      }
    }
    for (position = 1; position <= edges[file]; position++) {
      follow(edge[file, position], root)
    }
  }
  FILENAME == ARGV[1] { named[++named_count] = $0; is_named[$0] = 1; next }
  FILENAME == ARGV[2] { tracked[$0] = 1; next }
  FNR == 1 {
    directory = FILENAME
    if (!sub(/\/[^\/]*$/, "", directory)) directory = "."
  }
  /^# fixture-finding SC[0-9]+$/ {
    code = $0
    sub(/.*fixture-finding SC/, "", code)
    sub(/[^0-9].*/, "", code)
    finding[FILENAME, ++findings[FILENAME]] = FNR "\t" code
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
    if (target in tracked && target != FILENAME) {
      edge[FILENAME, ++edges[FILENAME]] = target
    }
  }
  END {
    for (position = 1; position <= named_count; position++) {
      split("", seen)
      follow(named[position], named[position])
    }
  }
' "$lists/named" "$lists/tracked" "${tracked[@]}" > "$lists/findings"

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
        findings(11; "scripts/runtime/tests/test-smoke-dev-commodity.sh"; 2034)
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
    $1 != "analysis" || $2 != "--external-sources" || $3 != "--severity=warning" \
        || $4 != "--format=json1" {
      print "unexpected invocation: " $0
      next
    }
    { line = ""; for (i = 5; i <= NF; i++) line = line (i > 5 ? "\t" : "") $i; print line }
  ' "$fake_log"
}

# Require every invocation to pass --external-sources and every tracked script
# to be named in exactly one invocation.
assert_partition() {
  local repository="$1" context="$2"
  local tracked invoked invocations
  invocations="$(invocation_scripts)"
  grep -q '^unexpected invocation: ' <<<"$invocations" \
    && fail "$context: ShellCheck flags changed"
  tracked="$(env "${git_unset[@]}" git -C "$repository" ls-files -- '*.sh' | LC_ALL=C sort)"
  invoked="$(printf '%s\n' "$invocations" | tr '\t' '\n' | LC_ALL=C sort)"
  [[ "$invoked" == "$tracked" ]] \
    || fail "$context: shards did not analyze each tracked script exactly once"
}

# Require two scripts to be named in different invocations.
assert_split() {
  local context="$1" left="$2" right="$3"
  invocation_scripts | awk -F '\t' -v left="$left" -v right="$right" '
    {
      found = 0
      for (i = 1; i <= NF; i++) if ($i == left || $i == right) found++
      if (found == 2) shared = 1
    }
    END { exit shared ? 1 : 0 }
  ' || fail "$context: $left and $right shared an invocation"
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

# --- Fixture repository: sourced scripts, ratchet changes and shard failures.
# The fixture runs SHELLCHECK_SHARDS=4 so that its placement does not follow
# the repository default.
fixture="$TMP/fixture-repository"
mkdir -p "$fixture/scripts/ci/verify" "$fixture/scripts/ci/setup" \
  "$fixture/z-lib" "$fixture/tools"
cp "$CHECKER" "$fixture/scripts/ci/verify/check-shell-scripts.sh"
cp "$ROOT/scripts/ci/setup/setup-shellcheck.sh" "$fixture/scripts/ci/setup/setup-shellcheck.sh"
cat > "$fixture/scripts/ci/verify/shellcheck-baseline.sh" <<'BASELINE'
#!/usr/bin/env bash
readonly SHELLCHECK_BASELINE_TSV=$'# path\tcode\tcount\treason\n'\
$'m-03.sh\tSC2034\t2\tfixture-reviewed\n'\
$'z-lib/deep.sh\tSC2034\t1\tfixture-reviewed-sourced'
BASELINE
# The consumer sorts first and its library last, and padding makes the
# consumer the costliest script, so it starts the first shard alone and its
# library lands elsewhere. The library sources a deeper file, which holds a
# reviewed finding that each analysis following it may report again.
{
  printf '#!/usr/bin/env bash\n'
  printf '# shellcheck source=z-lib/common.sh\nsource "$LIBRARY"\n'
  printf 'printf "%%s\\n" "$common_value"\n'
  for ((line = 0; line < 4000; line++)); do
    printf '# consumer padding line %s\n' "$line"
  done
} > "$fixture/a-consumer.sh"
printf '#!/usr/bin/env bash\n# shellcheck source=z-lib/deep.sh\nsource "$DEEP"\ncommon_value="$deep_value"\n' \
  > "$fixture/z-lib/common.sh"
printf '#!/usr/bin/env bash\ndeep_value=1\n# fixture-finding SC2034\n' > "$fixture/z-lib/deep.sh"
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

# Control: the fake requires --external-sources, and it reports a finding in a
# followed script the invocation does not name, as each consumer's analysis
# would. A followed script that is also named is reported once.
(cd "$fixture" && env "${git_unset[@]}" FAKE_SHELLCHECK_LOG="$TMP/control.log" \
  "$fake_shellcheck" --severity=warning --format=json1 a-consumer.sh >/dev/null) \
  && fail 'fake ShellCheck accepted an analysis without --external-sources'
followed_output="$(cd "$fixture" && env "${git_unset[@]}" FAKE_SHELLCHECK_LOG="$TMP/control.log" \
  "$fake_shellcheck" --external-sources --severity=warning --format=json1 a-consumer.sh)" \
  && fail 'fake ShellCheck reported no finding in a followed script'
[[ "$(jq -c '[.comments[] | [.file, .code]]' <<<"$followed_output")" \
    == '[["z-lib/deep.sh",2034]]' ]] \
  || fail 'fake ShellCheck did not report the followed deeper source'
named_output="$(cd "$fixture" && env "${git_unset[@]}" FAKE_SHELLCHECK_LOG="$TMP/control.log" \
  "$fake_shellcheck" --external-sources --severity=warning --format=json1 \
  a-consumer.sh z-lib/common.sh z-lib/deep.sh)" \
  && fail 'fake ShellCheck reported no finding in a named script'
[[ "$(jq -c '[.comments[] | [.file, .code]]' <<<"$named_output")" \
    == '[["z-lib/deep.sh",2034]]' ]] \
  || fail 'fake ShellCheck reported a named, followed script more than once'

# Four shards: the costliest script leads a shard of its own, its sourced
# library is analyzed in another shard, and the finding inside the deeper
# sourced file is counted exactly once.
: > "$fake_log"
fixture_output="$(run_checker "$fixture_checker" SHELLCHECK_SHARDS=4 2>&1)" \
  || fail "sharded fixture analysis failed: $fixture_output"
grep -Fq 'ShellCheck analysis: start (scripts=20 shards=4 timeout_seconds=600)' \
  <<<"$fixture_output" || fail 'fixture analysis did not start four shards'
grep -Fq 'ShellCheck shard 1/4 (scripts=1 heaviest=a-consumer.sh): start' \
  <<<"$fixture_output" || fail 'costliest script did not lead its own shard'
grep -Fq 'ShellCheck warning ratchet: OK (20 scripts, 4 shards, 2 reviewed groups)' \
  <<<"$fixture_output" || fail 'reviewed fixture findings did not pass'
[[ "$(wc -l < "$fake_log")" -eq 4 ]] || fail 'fixture analysis did not run four shards'
assert_partition "$fixture" 'four shards'
assert_split 'four shards' a-consumer.sh z-lib/common.sh
assert_split 'four shards' a-consumer.sh z-lib/deep.sh

: > "$fake_log"
single_output="$(run_checker "$fixture_checker" SHELLCHECK_SHARDS=1 2>&1)" \
  || fail "single-shard fixture analysis failed: $single_output"
grep -Fq 'ShellCheck warning ratchet: OK (20 scripts, 1 shards, 2 reviewed groups)' \
  <<<"$single_output" || fail 'single-shard analysis did not pass'
[[ "$(wc -l < "$fake_log")" -eq 1 ]] || fail 'SHELLCHECK_SHARDS=1 ran more than one process'
assert_partition "$fixture" 'one shard'

# Old and new behaviour: the same checker without its own-comments filter
# counts the deeper file's finding again in each shard that only followed it,
# and the ratchet fails. With the filter (above) the same shards pass.
unfiltered="$TMP/unfiltered-repository"
cp -R "$fixture" "$unfiltered"
unfiltered_checker="$unfiltered/scripts/ci/verify/check-shell-scripts.sh"
awk '
  $0 == "own_comments() {" { print; print "  jq -c .comments"; skip = 1; replaced++; next }
  skip && $0 == "}" { skip = 0 }
  !skip { print }
  END { exit replaced == 1 ? 0 : 1 }
' "$fixture_checker" > "$unfiltered_checker" \
  || fail 'the checker has no own_comments filter to remove'
if unfiltered_output="$(run_checker "$unfiltered_checker" SHELLCHECK_SHARDS=4 2>&1)"; then
  fail 'unfiltered sharded analysis accepted duplicated findings'
fi
grep -Fq 'ShellCheck warning set differs from the reviewed baseline' <<<"$unfiltered_output" \
  || fail 'unfiltered duplicates were not diagnosed'
grep -Fxq -e $'-z-lib/deep.sh\tSC2034\t1' <<<"$unfiltered_output" \
  && grep -Eq $'^\\+z-lib/deep\\.sh\tSC2034\t[2-9]$' <<<"$unfiltered_output" \
  || fail 'unfiltered duplicates did not change the sourced finding count'

# A new warning fails the ratchet even though it appears in one shard only.
cp "$fixture/m-05.sh" "$TMP/m-05.sh"
printf '# fixture-finding SC2086\n' >> "$fixture/m-05.sh"
if new_output="$(run_checker "$fixture_checker" SHELLCHECK_SHARDS=4 2>&1)"; then
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
if fixed_output="$(run_checker "$fixture_checker" SHELLCHECK_SHARDS=4 2>&1)"; then
  fail 'sharded analysis accepted a stale reviewed count'
fi
grep -Fxq -e $'-m-03.sh\tSC2034\t2' <<<"$fixed_output" \
  && grep -Fxq -e $'+m-03.sh\tSC2034\t1' <<<"$fixed_output" \
  || fail 'fixed warning was not reported against the reviewed count'
cp "$TMP/m-03.sh" "$fixture/m-03.sh"

# Any failing shard fails the analysis; the other shards' findings never pass.
: > "$fake_log"
set +e
failure_output="$(run_checker "$fixture_checker" SHELLCHECK_SHARDS=4 \
  FAKE_SHELLCHECK_FAIL_FILE=m-07.sh FAKE_SHELLCHECK_STATUS=7 2>&1)"
failure_status=$?
set -e
[[ "$failure_status" -eq 7 ]] || fail 'shard failure status was not propagated'
grep -Eq '^ShellCheck shard [1-4]/4 \(scripts=[0-9]+ heaviest=[^)]+\) failed with status 7$' \
  <<<"$failure_output" || fail 'shard failure did not name its shard'
grep -Fq 'ratchet: OK' <<<"$failure_output" && fail 'a failed shard still passed the ratchet'
[[ "$(wc -l < "$fake_log")" -eq 4 ]] || fail 'a failed shard stopped the other shards'

set +e
killed_output="$(run_checker "$fixture_checker" SHELLCHECK_SHARDS=4 FAKE_SHELLCHECK_KILL_FILE=m-02.sh 2>&1)"
killed_status=$?
set -e
[[ "$killed_status" -eq 137 ]] || fail 'killed shard status was not propagated'
grep -Eq '^ShellCheck shard [1-4]/4 \(.*\) was killed after [0-9]+ seconds, before its deadline' \
  <<<"$killed_output" || fail 'killed shard was not diagnosed'
grep -Fq 'ratchet: OK' <<<"$killed_output" && fail 'a killed shard still passed the ratchet'

set +e
garbage_output="$(run_checker "$fixture_checker" SHELLCHECK_SHARDS=4 FAKE_SHELLCHECK_GARBAGE_FILE=m-04.sh 2>&1)"
garbage_status=$?
set -e
[[ "$garbage_status" -eq 1 ]] || fail 'invalid shard report did not fail'
grep -Eq '^ShellCheck shard [1-4]/4 \(.*\) wrote no valid json1 report$' \
  <<<"$garbage_output" || fail 'invalid shard report was not diagnosed'

# One deadline bounds every shard and the whole analysis, and the timeout
# names the shard holding the script that did not finish. The stalled shard
# would sleep two minutes; the analysis must end well before, though the
# other shards may take a few seconds on a loaded CI guest (main run 22943
# missed a three-second bound with a five-second stall).
set +e
timeout_output="$(run_checker "$fixture_checker" SHELLCHECK_SHARDS=4 SHELLCHECK_TIMEOUT_SECONDS=1 \
  FAKE_SHELLCHECK_SLEEP_FILE=a-consumer.sh FAKE_SHELLCHECK_SLEEP_SECONDS=120 2>&1)"
timeout_status=$?
set -e
[[ "$timeout_status" -eq 124 ]] || fail 'shard timeout status was not propagated'
grep -Fxq 'ShellCheck shard 1/4 (scripts=1 heaviest=a-consumer.sh) timed out after 1 seconds' \
  <<<"$timeout_output" || fail 'shard timeout did not name its shard'
timeout_elapsed="$(sed -nE 's/^ShellCheck analysis: finish \(status=124 elapsed_seconds=([0-9]+)\)$/\1/p' \
  <<<"$timeout_output")"
[[ -n "$timeout_elapsed" && "$timeout_elapsed" -lt 30 ]] ||
  fail "the deadline did not bound the whole analysis: $timeout_output"
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

# --- The repository itself: every tracked script named once, with
# --external-sources, the measured costliest script leading the first shard,
# and the reviewed baseline.
: > "$fake_log"
baseline_output="$(run_checker "$CHECKER" FAKE_SHELLCHECK_REPOSITORY_BASELINE=1 2>&1)" \
  || fail "matching fake ShellCheck baseline was rejected: $baseline_output"
grep -Fq 'ShellCheck analysis: start (' <<<"$baseline_output" \
  || fail 'ShellCheck start timing is absent'
grep -Fq 'shards=3 timeout_seconds=600)' <<<"$baseline_output" \
  || fail 'ShellCheck default shards or deadline changed'
# The costliest script is whichever the checker's own cost table measures as
# costliest; this test names none.
measured_costliest="$(sed -n "/^readonly SHELLCHECK_MEASURED_COST_MS='$/,/^'$/p" "$CHECKER" |
  awk 'NF == 2' | sort -rn | head -n 1 | cut -d' ' -f2)"
[[ -n "$measured_costliest" ]] || fail 'the checker has no measured cost table'
grep -Eq "^ShellCheck shard 1/3 \(scripts=[0-9]+ heaviest=${measured_costliest//./\\.}\): start$" \
  <<<"$baseline_output" || fail 'the costliest repository script did not lead the first shard'
grep -Eq 'ShellCheck analysis: finish \(status=1 elapsed_seconds=[0-9]+\)' \
  <<<"$baseline_output" || fail 'ShellCheck finish timing is absent'
grep -Fq 'ShellCheck warning ratchet: OK' <<<"$baseline_output" \
  || fail 'matching warning baseline did not pass'
assert_partition "$ROOT" 'repository'

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
