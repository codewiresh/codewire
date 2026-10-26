#!/usr/bin/env bash
# Execute scripts/ci/select/dispatch-source.sh against a real synthetic main
# history: a run verifies its own commit, or the earlier first-parent main
# commit a dispatch of main names while that workflow file is unchanged.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT

fail() {
  printf '[test-dispatch-source] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=fixture \
  GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_COMMITTER_NAME=fixture \
  GIT_COMMITTER_EMAIL=fixture@example.invalid

repo="$work/repo"
workflow=.gitea/workflows/ci.yaml
git init --quiet --initial-branch=main "$repo"
mkdir -p "$repo/scripts/ci/select" "$repo/.gitea/workflows"
cp "$ROOT/scripts/ci/select/dispatch-source.sh" "$repo/scripts/ci/select/"
printf 'name: CI\n' >"$repo/$workflow"
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

# main: base <- the workflow's current definition <- candidate <- merge of a
# branch <- later <- head. Only base has another definition.
change "$workflow" '# the current definition' >/dev/null
candidate="$(change crates/a.rs 'pub fn a() {}')"
git -C "$repo" checkout --quiet -b branch
branch_commit="$(change crates/b.rs 'pub fn b() {}')"
git -C "$repo" checkout --quiet main
git -C "$repo" merge --quiet --no-ff -m 'merge branch' branch
later="$(change scripts/ci/later.sh 'echo later')"
head="$(change docs/notes.md 'main moved on')"
git -C "$repo" merge-base --is-ancestor "$branch_commit" "$head" ||
  fail 'the fixture branch commit is not an ancestor of main'

shallow="$work/shallow"
git clone --quiet --depth 1 --branch main "file://$repo" "$shallow"

script="$repo/scripts/ci/select/dispatch-source.sh"
# run NAME CHECKOUT EVENT REF SOURCE -> the output, or "failed"
run() {
  local name="$1" checkout="$2" event="$3" ref="$4" source="$5" output="$work/$1.out"
  : >"$output"
  if (cd "$checkout" && env GITHUB_OUTPUT="$output" GITHUB_SHA="$head" GITHUB_EVENT_NAME="$event" \
      GITHUB_REF="$ref" DISPATCH_SOURCE_SHA="$source" "$script" "${MODE:-$workflow}") >"$work/$name.log" 2>&1; then
    cat "$output"
  else
    echo failed
  fi
}
cases=0
expect() { # NAME EXPECTED CHECKOUT EVENT REF SOURCE
  local name="$1" expected="$2" actual
  shift 2
  actual="$(run "$name" "$@")"
  [ "$actual" = "$expected" ] || fail "$name: expected '$expected', got '$actual' ($(cat "$work/$name.log"))"
  cases=$((cases + 1))
}

# Without a source every run verifies its own commit, and logs no source line.
for event in push pull_request schedule workflow_dispatch; do
  expect "own-$event" "source_sha=$head" "$repo" "$event" refs/heads/main ''
  ! grep -q 'dispatch source:' "$work/own-$event.log" || fail "own-$event logged a source line"
done
expect own-branch-ref "source_sha=$head" "$repo" push refs/heads/feature ''

# A dispatch of main verifies an earlier first-parent commit whose workflow
# file is main's, and logs the line the release tag receipt binds to.
expect candidate "source_sha=$candidate" "$repo" workflow_dispatch refs/heads/main "$candidate"
grep -Fxq "dispatch source: $candidate on main $head" "$work/candidate.log" ||
  fail 'the candidate dispatch did not log its source line'
expect later "source_sha=$later" "$repo" workflow_dispatch refs/heads/main "$later"
expect head "source_sha=$head" "$repo" workflow_dispatch refs/heads/main "$head"

# Everything else is refused before a source is chosen.
expect push-with-source failed "$repo" push refs/heads/main "$candidate"
expect schedule-with-source failed "$repo" schedule refs/heads/main "$candidate"
expect branch-dispatch failed "$repo" workflow_dispatch refs/heads/feature "$candidate"
expect short-sha failed "$repo" workflow_dispatch refs/heads/main "${candidate:0:12}"
expect upper-sha failed "$repo" workflow_dispatch refs/heads/main "$(tr a-f A-F <<<"$candidate")"
expect unknown-sha failed "$repo" workflow_dispatch refs/heads/main "$(printf '%040d' 7)"
# A merged branch's commit is an ancestor of main but was never main itself.
expect second-parent failed "$repo" workflow_dispatch refs/heads/main "$branch_commit"
grep -Fq 'not a commit of main' "$work/second-parent.log" || fail 'second-parent was refused for another reason'
# Main's steps would drive scripts written for another definition.
expect workflow-changed failed "$repo" workflow_dispatch refs/heads/main "$base"
grep -Fq 'changed between' "$work/workflow-changed.log" || fail 'workflow-changed was refused for another reason'
expect shallow failed "$shallow" workflow_dispatch refs/heads/main "$head"
git -C "$repo" checkout --quiet "$later"
expect not-dispatched-checkout failed "$repo" workflow_dispatch refs/heads/main "$candidate"
git -C "$repo" checkout --quiet main
for name in push-with-source branch-dispatch second-parent workflow-changed; do
  ! grep -q 'dispatch source:' "$work/$name.log" || fail "$name logged a source line"
done

# --main-history (support-images.yaml) keeps every history rule but the
# workflow-file one, and runs only on main, with or without a source.
export MODE=--main-history
expect history-candidate "source_sha=$candidate" "$repo" workflow_dispatch refs/heads/main "$candidate"
grep -Fxq "dispatch source: $candidate on main $head" "$work/history-candidate.log" ||
  fail 'the main-history dispatch did not log its source line'
expect history-workflow-changed "source_sha=$base" "$repo" workflow_dispatch refs/heads/main "$base"
expect history-own-push "source_sha=$head" "$repo" push refs/heads/main ''
expect history-own-dispatch "source_sha=$head" "$repo" workflow_dispatch refs/heads/main ''
expect history-branch-dispatch failed "$repo" workflow_dispatch refs/heads/feature ''
grep -Fq 'runs only on main' "$work/history-branch-dispatch.log" ||
  fail 'history-branch-dispatch was refused for another reason'
expect history-branch-source failed "$repo" workflow_dispatch refs/heads/feature "$candidate"
expect history-push-with-source failed "$repo" push refs/heads/main "$candidate"
expect history-second-parent failed "$repo" workflow_dispatch refs/heads/main "$branch_commit"
grep -Fq 'not a commit of main' "$work/history-second-parent.log" ||
  fail 'history-second-parent was refused for another reason'
expect history-unknown-sha failed "$repo" workflow_dispatch refs/heads/main "$(printf '%040d' 7)"
expect history-shallow failed "$shallow" workflow_dispatch refs/heads/main "$head"
unset MODE

echo "test-dispatch-source: PASS cases=$cases"
