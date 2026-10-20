#!/usr/bin/env bash
# Execute scripts/ci/release/dry-run-deferral.sh against a real synthetic
# main history, with the checked-in switch and with it flipped.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

fail() {
  printf '[test-dry-run-deferral] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=fixture \
  GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_COMMITTER_NAME=fixture \
  GIT_COMMITTER_EMAIL=fixture@example.invalid PYTHONDONTWRITEBYTECODE=1

repo="$work/repo"
git init --quiet --initial-branch=main "$repo"
mkdir -p "$repo/scripts/ci/release" "$repo/scripts/ci/select" "$repo/.gitea/workflows"
cp "$ROOT/scripts/ci/release/dry-run-deferral.sh" "$repo/scripts/ci/release/"
cp "$ROOT/scripts/ci/select/main-push-switch.sh" "$repo/scripts/ci/select/"
cp "$ROOT/.gitea/workflows/cw-release-dry-run.yaml" "$repo/.gitea/workflows/"
printf 'base\n' >"$repo/Cargo.lock"
git -C "$repo" add -A
git -C "$repo" commit --quiet -m base
base="$(git -C "$repo" rev-parse HEAD)"

change() {
  mkdir -p "$repo/$(dirname "$1")"
  printf '%s\n' "$2" >>"$repo/$1"
  git -C "$repo" add -A
  git -C "$repo" commit --quiet -m "$1"
  git -C "$repo" rev-parse HEAD
}

docs_only="$(change docs/notes.md 'no dry run')"
server_only="$(change crates/codewire-dashboard-web/src/s.rs 'pub fn s() {}')"
cw_change="$(change crates/codewire-cli/src/a.rs 'pub fn a() {}')"
after_cw="$(change docs/more.md 'still no dry run')"
git -C "$repo" checkout --quiet -b side "$base"
side="$(change docs/side.md 'off main')"
git -C "$repo" checkout --quiet main

script="$repo/scripts/ci/release/dry-run-deferral.sh"
# run NAME EVENT SHA BASELINE -> build=..., or "failed"
run() {
  local name="$1" event="$2" sha="$3" baseline="$4" output="$work/$1.out"
  : >"$output"
  : >"$work/$name.summary"
  if (cd "$repo" && env GITHUB_OUTPUT="$output" GITHUB_STEP_SUMMARY="$work/$name.summary" \
      GITHUB_EVENT_NAME="$event" SCHEDULE_BASELINE_SHA="$baseline" \
      "$script" "$sha") >"$work/$name.log" 2>&1; then
    cat "$output"
  else
    echo failed
  fi
}

expect() {
  local name="$1" want="$2" got
  shift 2
  got="$(run "$name" "$@")"
  [[ "$got" == "$want" ]] || {
    sed 's/^/  /' "$work/$name.log" >&2
    fail "$name: want $want, got $got"
  }
}

# The one switch. The checked-in file must set it to true or false; each case
# below sets the value it describes, so it holds whichever is checked in.
switch_file="$repo/scripts/ci/select/main-push-switch.sh"
grep -Eq '^MAIN_PUSH_RUNS_KIND_AND_DRY_RUN=(true|false)$' "$switch_file" \
  || fail 'main-push-switch.sh does not set MAIN_PUSH_RUNS_KIND_AND_DRY_RUN to true or false'
set_switch() {
  sed -i "s/^MAIN_PUSH_RUNS_KIND_AND_DRY_RUN=.*/MAIN_PUSH_RUNS_KIND_AND_DRY_RUN=$1/" "$switch_file"
}

# False (owner decision 2026-10-20): a push to main defers the dry run and
# says so in one line, in the log and the step summary.
set_switch false
deferred='main push: release dry run deferred to the scheduled or dispatched dry run (owner decision 2026-10-20)'
expect push-deferred build=false push "$cw_change" ''
grep -Fxq "$deferred" "$work/push-deferred.log" || fail 'a deferred push did not say so in its log'
grep -Fxq "$deferred" "$work/push-deferred.summary" || fail 'a deferred push did not say so in its summary'
expect dispatched build=true workflow_dispatch "$cw_change" ''

# A schedule builds when a push path changed since the last successful
# scheduled run's commit, or when that commit is unknown.
expect schedule-unknown build=true schedule "$cw_change" ''
grep -Fq 'no successful scheduled dry run on this history' "$work/schedule-unknown.log" \
  || fail 'an unknown schedule baseline did not say why it builds'
expect schedule-not-a-commit build=true schedule "$cw_change" "$(printf '%040d' 7)"
expect schedule-malformed build=true schedule "$cw_change" not-a-commit
expect schedule-off-history build=true schedule "$cw_change" "$side"
expect schedule-same-commit build=false schedule "$cw_change" "$cw_change"
grep -Fq "no release input changed since $cw_change" "$work/schedule-same-commit.log" \
  || fail 'an unchanged schedule did not say why it builds nothing'
expect schedule-docs-and-server build=false schedule "$server_only" "$base"
expect schedule-cw-change build=true schedule "$cw_change" "$base"
grep -Fq "a release input changed since $base" "$work/schedule-cw-change.log" \
  || fail 'a changed schedule did not say why it builds'
expect schedule-after-cw build=false schedule "$after_cw" "$cw_change"
expect schedule-across-cw build=true schedule "$after_cw" "$docs_only"
expect malformed-sha failed push not-a-commit ''

# True restores the dry run on every push to main, and the schedule then has
# nothing to build, changed inputs or not.
set_switch true
expect push-restored build=true push "$cw_change" ''
! grep -Fq 'deferred' "$work/push-restored.log" || fail 'a push that builds said it was deferred'
expect schedule-restored-changed build=false schedule "$cw_change" "$base"
expect schedule-restored-unknown build=false schedule "$cw_change" ''
grep -Fxq 'schedule: a push to main runs the dry run (main-push-switch.sh); the schedule builds nothing' \
  "$work/schedule-restored-unknown.log" || fail 'an idle schedule did not say why it builds nothing'
expect dispatched-restored build=true workflow_dispatch "$cw_change" ''

# Any other value fails the step rather than guessing.
set_switch maybe
expect push-invalid-switch failed push "$cw_change" ''
expect schedule-invalid-switch failed schedule "$cw_change" "$base"

echo 'test-dry-run-deferral: PASS cases=18'
