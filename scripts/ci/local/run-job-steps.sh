#!/usr/bin/env bash
# run-job-steps.sh PHASE: run-family.sh's side inside the CI runner image.
# It runs as the image's own user (root), as Forgejo Runner's job container
# does, with these mounts:
#   /run/run-family/source.git  the repository's git directory, read-only;
#   /run/run-family/plan        ci-job-plan.py's output for this run;
#   /workspace                  a fresh volume for the run's checkouts.
#
# PHASE select: check out the commit and run what the selection job runs
#   to decide this job: select-verification.sh, with the select step's
#   inputs (unless plan/selection is already set), then
#   emit-verification-matrices.sh; on a pull request, the base's own copies.
#   Writes plan/selection and plan/dispatch (the dispatch outputs).
# PHASE steps: check out the commit at the job's workspace, as the job's
#   checkout step does (full history, origin's branches and tags, detached
#   at the commit), then run each planned step as Forgejo Runner does: in
#   `bash --noprofile --norc -e -o pipefail`, with the job environment, what
#   earlier steps wrote to GITHUB_ENV and GITHUB_PATH, and the step's env. A
#   step runs while the job is green unless its `if` says otherwise. It
#   prints `[run-family] step STEP: passed|failed in Ns` per step and
#   exits 1 when any step failed.
set -uo pipefail

readonly SOURCE=/run/run-family/source.git
readonly PLAN=/run/run-family/plan
readonly WORKSPACE=/workspace/codewire/codewire
readonly ACT=/var/run/act/workflow

# checkout DIR COMMIT: what noel/actions-checkout does with fetch-depth 0,
# from the local repository instead of the forge. Objects come from the
# source by alternates, so nothing is copied.
checkout() {
  local dir="$1" commit="$2"
  rm -rf "$dir"
  mkdir -p "$dir"
  git -c init.defaultBranch=master init -q "$dir"
  printf '%s/objects\n' "$SOURCE" >"$dir/.git/objects/info/alternates"
  git -C "$dir" config gc.auto 0
  git -C "$dir" -c safe.directory='*' fetch -q --no-tags "$SOURCE" \
    '+refs/remotes/origin/*:refs/remotes/origin/*' '+refs/tags/*:refs/tags/*'
  git -C "$dir" remote add origin "$(cat "$PLAN/origin-url")"
  git -C "$dir" checkout -q --detach "$commit"
}

phase_select() {
  local commit base placement root output
  commit="$(cat "$PLAN/commit")"
  base="$(cat "$PLAN/base")"
  placement="$(cat "$PLAN/placement")"
  checkout /workspace/selection "$commit" || return 1
  cd /workspace/selection || return 1
  root=.
  if [ "$placement" = pr ]; then
    # A pull request selects and dispatches with its base's scripts
    # (.trusted-ci-policy).
    checkout /workspace/selection/.trusted-ci-policy "$base" || return 1
    root=.trusted-ci-policy
  fi
  output="$(mktemp)"
  if [ -s "$PLAN/selection" ]; then
    : # run-family.sh --selection
  elif [ "$placement" = pr ]; then
    CI=true GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request GITHUB_REF=refs/pull/0/head \
      GITHUB_BASE_REF=main GITHUB_SHA="$commit" PR_BASE_SHA="$base" \
      VERIFICATION_SOURCE_SHA="$commit" GITHUB_OUTPUT="$output" \
      "$root/scripts/ci/select/select-verification.sh" || return 1
    sed -n 's/^selection=//p' "$output" >"$PLAN/selection"
  else
    # A push to main selects from the newest main commit main CI verified.
    # A local run cannot read verdicts (that needs the job token), so without
    # --base it takes the selector's own unverified-base path: everything.
    local unverified=false
    [ -n "$base" ] || unverified=true
    CI=true GITHUB_ACTIONS=true GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main \
      GITHUB_SHA="$commit" PUSH_BEFORE_SHA="$base" PUSH_AFTER_SHA="$commit" \
      PUSH_BASE_UNVERIFIED="$unverified" VERIFICATION_SOURCE_SHA="$commit" \
      GITHUB_OUTPUT="$output" "$root/scripts/ci/select/select-verification.sh" || return 1
    sed -n 's/^selection=//p' "$output" >"$PLAN/selection"
  fi
  [ -s "$PLAN/selection" ] || { echo 'run-job-steps: the selector printed no selection' >&2; return 1; }
  # Which jobs the selection starts, as the dispatch step decides it. A
  # local run never reuses a tested-tree receipt, and keeps every artifact.
  : >"$output"
  VERIFICATION_SELECTION="$(cat "$PLAN/selection")" VERIFICATION_TESTED_TREE_RECEIPT=fallback \
    CW_PACKAGE_SELECTED=true DESKTOP_PACKAGE_SELECTED=true VERIFICATION_SUPERSEDED=false \
    GITHUB_OUTPUT="$output" "$root/scripts/ci/select/emit-verification-matrices.sh" >/dev/null || return 1
  cp "$output" "$PLAN/dispatch"
}

# load_github_env FILE: export what steps wrote to GITHUB_ENV (NAME=VALUE and
# NAME<<DELIMITER blocks), in order.
load_github_env() {
  local file="$1" line name delimiter value
  [ -s "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)\<\<(.+)$ ]]; then
      name="${BASH_REMATCH[1]}" delimiter="${BASH_REMATCH[2]}" value=''
      local first=true
      while IFS= read -r line && [ "$line" != "$delimiter" ]; do
        if $first; then value="$line"; first=false; else value+=$'\n'"$line"; fi
      done
      export "$name=$value"
    elif [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      export "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
    fi
  done <"$file"
}

phase_steps() {
  local commit
  commit="$(cat "$PLAN/commit")"
  checkout "$WORKSPACE" "$commit" || { echo '::error::run-family checkout failed'; return 1; }
  mkdir -p "$ACT"
  cp "$PLAN/event.json" "$ACT/event.json"
  : >"$ACT/envs.txt"
  : >"$ACT/pathcmd.txt"
  local status=success number on_success on_failure name start rc elapsed failed=0
  while IFS=$'\t' read -r number on_success on_failure name; do
    [ -n "$number" ] || continue
    if { [ "$status" = success ] && [ "$on_success" = 1 ]; } \
      || { [ "$status" = failure ] && [ "$on_failure" = 1 ]; }; then
      :
    else
      printf '[run-family] step %s: skipped\n' "$name"
      continue
    fi
    printf '[run-family] step %s\n' "$name"
    : >"$ACT/outputcmd.txt"
    start=$SECONDS
    (
      # shellcheck source=/dev/null
      source "$PLAN/job.env"
      load_github_env "$ACT/envs.txt"
      # shellcheck source=/dev/null
      source "$PLAN/$number.env"
      while IFS= read -r entry; do
        [ -n "$entry" ] && PATH="$entry:$PATH"
      done < <(tac "$ACT/pathcmd.txt")
      export PATH GITHUB_ENV="$ACT/envs.txt" GITHUB_PATH="$ACT/pathcmd.txt" \
        GITHUB_OUTPUT="$ACT/outputcmd.txt" GITHUB_STATE="$ACT/statecmd.txt" \
        GITHUB_STEP_SUMMARY="$ACT/SUMMARY.md"
      cd "$WORKSPACE" || exit 1
      exec bash --noprofile --norc -e -o pipefail "$PLAN/$number.sh"
    ) </dev/null
    rc=$?
    elapsed=$((SECONDS - start))
    if [ "$rc" -eq 0 ]; then
      printf '[run-family] step %s: passed in %ss\n' "$name" "$elapsed"
    else
      printf '[run-family] step %s: failed (exit %s) in %ss\n' "$name" "$rc" "$elapsed"
      status=failure failed=1
    fi
  done <"$PLAN/steps.tsv"
  return "$failed"
}

case "${1:-}" in
  select) phase_select ;;
  steps) phase_steps ;;
  *) echo 'usage: run-job-steps.sh select|steps' >&2; exit 2 ;;
esac
