#!/usr/bin/env bash
# The build runner measurement (compile-once step 1, infra#1632) runs only on
# the pull request build runner, reaches no credential, and builds with the
# same protoc pin as ci.yaml; its script refuses bad input before touching
# the build disk.
# shellcheck disable=SC2016 # The checks match literal workflow text.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly WORKFLOW="$ROOT/.gitea/workflows/build-runner-measure.yaml"
readonly SCRIPT="$ROOT/scripts/ci/measure/build-runner.sh"
# shellcheck source=scripts/ci/tests/fixtures/ci-runners.sh
source "$ROOT/scripts/ci/tests/fixtures/ci-runners.sh"

fail() {
  echo "test-build-runner-measure: $*" >&2
  exit 1
}

[[ "$(grep -Fxc "    runs-on: $RUNS_ON_UNTRUSTED_BUILD" "$WORKFLOW")" == 2 ]] ||
  fail 'both jobs must run on the untrusted build runner'
[[ "$(grep -c '^    runs-on:' "$WORKFLOW")" == 2 ]] || fail 'a job runs elsewhere'
if grep -Eq 'enable-openid-connect|secrets\.|vars\.CODEWIRE_CI_RUNNER_(TRUSTED|MACOS|UNTRUSTED_HEAVY|UNTRUSTED_LIGHT)' "$WORKFLOW"; then
  fail 'the measurement reaches a credential or another runner'
fi
grep -Fq '          WIPE: '"'"'false'"'"'' "$WORKFLOW" || fail 'the second build must start warm'

pin() { sed -nE "s/^readonly $1='([^']*)'$/\\1/p" "$SCRIPT"; }
url="$(pin PROTOC_URL)"
digest="$(pin PROTOC_SHA256)"
grep -Fq "$url" "$ROOT/.gitea/workflows/ci.yaml" || fail 'protoc differs from the ci.yaml pin'
grep -Fq "$digest" "$ROOT/.gitea/workflows/ci.yaml" || fail 'the protoc digest differs from the ci.yaml pin'
grep -Fq '"$ROOT/scripts/ci/release/fetch-pinned.sh" "$url" "$digest" "$file"' "$SCRIPT" ||
  fail 'pinned tools must download through fetch-pinned.sh'

work="$(mktemp -d "${TMPDIR:-/tmp}/test-build-runner.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/root/keep"
expect_refusal() {
  local name="$1"
  shift
  if env BUILD_RUNNER_ROOT="$work/root" "$@" "$SCRIPT" "$ROOT" "$work/out" >/dev/null 2>&1; then
    fail "$name was accepted"
  fi
}
expect_refusal 'an unknown clippy mode' CLIPPY=sometimes
expect_refusal 'a bad job count' JOBS=0
expect_refusal 'a bad wipe value' WIPE=yes
if "$SCRIPT" "$ROOT" >/dev/null 2>&1; then
  fail 'the script ran without an output directory'
fi
[ -d "$work/root/keep" ] || fail 'a refused run touched the build disk'
echo 'test-build-runner-measure: build runner only, no credential, pinned tools, bad input refused'
