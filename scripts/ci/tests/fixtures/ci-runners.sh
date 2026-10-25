# shellcheck shell=bash disable=SC2034 # The tests that source this file read every value.
# The exact `runs-on` values the workflows use. Runner labels are repository
# Actions variables (docs/dev/CI-CONFIGURATION.md). A missing one leaves the
# job queued on an `unset-<variable>` label that no runner advertises; a main
# push never falls through to the untrusted runner. Keep in step with
# scripts/ci/tests/ci_runner_fixtures.py.

ci_runner_one() {
  # shellcheck disable=SC2016 # The workflow expression is literal text.
  printf '${{ vars.%s || '"'"'unset-%s'"'"' }}' "$1" "$1"
}

ci_runner_by_trust() {
  # shellcheck disable=SC2016 # The workflow expression is literal text.
  printf '${{ github.event_name == '"'"'push'"'"' && github.ref == '"'"'refs/heads/main'"'"' && (vars.%s || '"'"'unset-%s'"'"') || (vars.%s || '"'"'unset-%s'"'"') }}' \
    "$1" "$1" "$2" "$2"
}

RUNS_ON_UNTRUSTED_LIGHT="$(ci_runner_one CODEWIRE_CI_RUNNER_UNTRUSTED_LIGHT)"
RUNS_ON_TRUSTED_LIGHT="$(ci_runner_one CODEWIRE_CI_RUNNER_TRUSTED_LIGHT)"
RUNS_ON_MACOS="$(ci_runner_one CODEWIRE_CI_RUNNER_MACOS)"
RUNS_ON_UNTRUSTED_BUILD="$(ci_runner_one CODEWIRE_CI_RUNNER_UNTRUSTED_BUILD)"
RUNS_ON_HEAVY="$(ci_runner_by_trust CODEWIRE_CI_RUNNER_TRUSTED_HEAVY CODEWIRE_CI_RUNNER_UNTRUSTED_HEAVY)"
# The medium metal class (infra#1534): every verification group that needs a
# metal guest but not the heavy one's memory.
RUNS_ON_MEDIUM="$(ci_runner_by_trust CODEWIRE_CI_RUNNER_TRUSTED_MEDIUM CODEWIRE_CI_RUNNER_UNTRUSTED_MEDIUM)"
RUNS_ON_KIND="$(ci_runner_by_trust CODEWIRE_CI_RUNNER_TRUSTED_KIND CODEWIRE_CI_RUNNER_UNTRUSTED_KIND)"
# Compile once (infra#1632): a main push compiles on trusted Heavy, every
# other run on the pull request build runner.
RUNS_ON_BUILD="$(ci_runner_by_trust CODEWIRE_CI_RUNNER_TRUSTED_BUILD CODEWIRE_CI_RUNNER_UNTRUSTED_BUILD)"
readonly RUNS_ON_UNTRUSTED_LIGHT RUNS_ON_TRUSTED_LIGHT RUNS_ON_MACOS RUNS_ON_UNTRUSTED_BUILD RUNS_ON_HEAVY RUNS_ON_MEDIUM RUNS_ON_KIND RUNS_ON_BUILD
