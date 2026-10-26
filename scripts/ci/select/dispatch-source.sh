#!/usr/bin/env bash
# dispatch-source.sh WORKFLOW_FILE: the commit this run verifies, as
# GITHUB_OUTPUT source_sha. A run verifies its own commit, unless a dispatch of
# main names an earlier main commit in DISPATCH_SOURCE_SHA: a release candidate
# is verified where it stands while main moves on, because main is never
# frozen for a cut (owner, 2026-10-13; #2892). The workflow definition and the
# protected runners still come from main, and only the source under test
# moves, when
#   - the run is a dispatch of refs/heads/main;
#   - the source is a full commit ID on the first-parent history of the
#     dispatched commit, so it was main itself, never a merged branch's
#     unreviewed commit;
#   - WORKFLOW_FILE is byte-identical at the source and the dispatched commit,
#     so main's steps drive exactly the scripts they were written for, as the
#     source's own dispatch would have.
# It then prints "dispatch source: SOURCE on main HEAD", the line the release
# tag receipt binds the run to (verify-release-tag-receipt.sh). Run it from a
# full checkout of the dispatched commit, before anything else is checked out.
#
# dispatch-source.sh --main-history drops the workflow-file rule, for a
# workflow whose steps never run the source's own scripts: support-images.yaml
# plans with main's planner and, for an earlier commit, only tags a published
# pair. Every run in this mode must be of main, with or without a source,
# because it publishes for the commit it names.
set -euo pipefail

fail() {
  printf '[dispatch-source] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  echo 'usage: dispatch-source.sh WORKFLOW_FILE|--main-history' >&2
  exit 2
}
workflow="$1"
main_history_only=false
if [[ "$workflow" == --main-history ]]; then
  main_history_only=true
  workflow=''
  [[ "${GITHUB_REF:-}" == refs/heads/main ]] || fail 'this workflow runs only on main'
fi
readonly workflow main_history_only
readonly head="${GITHUB_SHA:-}"
[[ "$head" =~ ^[0-9a-f]{40}$ ]] || fail 'GITHUB_SHA is not a full commit ID'
output="${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
readonly source="${DISPATCH_SOURCE_SHA:-}"

if [[ -z "$source" ]]; then
  printf 'source_sha=%s\n' "$head" >>"$output"
  exit 0
fi

[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || fail 'only a dispatch may name a source commit'
[[ "${GITHUB_REF:-}" == refs/heads/main ]] || fail 'only a dispatch of main may name a source commit'
[[ "$source" =~ ^[0-9a-f]{40}$ ]] || fail "source_sha '$source' is not a full lowercase commit ID"
[[ "$(git rev-parse --is-shallow-repository 2>/dev/null)" == false ]] ||
  fail "the checkout is shallow or unreadable, so main's history is unknown"
[[ "$(git rev-parse --verify --quiet HEAD)" == "$head" ]] || fail 'run from a checkout of the dispatched commit'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git rev-list --first-parent "$head" >"$tmp/main" || fail "main's history at $head is unreadable"
grep -Fxq "$source" "$tmp/main" || fail "source $source is not a commit of main's first-parent history at $head"

if [[ "$main_history_only" == false ]]; then
  git cat-file -e "$head:$workflow" 2>/dev/null || fail "$workflow is not in the dispatched commit"
  status=0
  git diff --quiet "$source" "$head" -- "$workflow" || status=$?
  case "$status" in
    0) ;;
    1) fail "$workflow changed between $source and $head; dispatch a later candidate" ;;
    *) fail "cannot compare $workflow between $source and $head" ;;
  esac
fi

printf 'dispatch source: %s on main %s\n' "$source" "$head"
printf 'source_sha=%s\n' "$source" >>"$output"
