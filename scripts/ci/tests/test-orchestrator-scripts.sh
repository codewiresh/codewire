#!/usr/bin/env bash
# Run the orchestrator helpers in scripts/dev/orchestrator against local bare
# repositories and a fake fj that serves canned Forgejo answers: each merges,
# waits or refuses only on the evidence it is meant to read.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SCRIPTS="$ROOT/scripts/dev/orchestrator"

fail() {
  printf '[test-orchestrator-scripts] ERROR: %s\n' "$*" >&2
  exit 1
}

# Under the checkout, not the system temporary directory: the fakes must be
# executable, and /tmp may be mounted noexec.
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/orchestrator-scripts.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_AUTHOR_NAME=fixture \
  GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_COMMITTER_NAME=fixture \
  GIT_COMMITTER_EMAIL=fixture@example.invalid ORCHESTRATOR_POLL_SECONDS=0 \
  TMPDIR="$work"
export FAKE="$work/fake"
mkdir -p "$work/bin" "$FAKE"

# The fake fj: every answer is a file under $FAKE; every call is logged.
cat >"$work/bin/fj" <<'FJ'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE/calls"
while [[ "${1:-}" == -C || "${1:-}" == -R ]]; do shift 2; done
args=()
for arg in "$@"; do [[ "$arg" == -R ]] && skip=1 && continue; [[ -n "${skip:-}" ]] && skip='' && continue; args+=("$arg"); done
set -- "${args[@]}"
answer() { [[ -f "$FAKE/$1" ]] && cat "$FAKE/$1" || exit 1; }
case "$1 ${2:-}" in
  'probe ') printf 'fake fj\n' ;;
  'pr status') answer "status-$3" ;;
  'pr view') [[ -f "$FAKE/merged-$3" ]] && answer "merged-$3" || answer "view-$3" ;;
  'pr merge')
    printf '%s\n' "$*" >>"$FAKE/merges"
    [[ -x "$FAKE/on-merge" ]] && "$FAKE/on-merge" "$@"
    ;;
  'actions runs')
    case "$3" in
      list)
        workflow='' head=''
        while [[ $# -gt 0 ]]; do
          case "$1" in --workflow) workflow="$2" ;; --head) head="$2" ;; esac
          shift
        done
        if [[ -n "$head" ]]; then answer "runs-$workflow-$head.json"; else answer "runs-$workflow.json"; fi
        ;;
      view) answer "run-$4.json" ;;
      logs) answer "log-$4" ;;
      watch) answer "watch-$4" ;;
      rerun) printf '%s\n' "$4" >>"$FAKE/reruns" ;;
      *) exit 1 ;;
    esac
    ;;
  'actions tasks')
    page=1
    [[ "${3:-}" == -p ]] && page="$4"
    answer "tasks-$page"
    ;;
  *) exit 1 ;;
esac
FJ
chmod +x "$work/bin/fj"
export PATH="$work/bin:$PATH"
[[ "$(fj probe 2>/dev/null)" == 'fake fj' ]] || fail 'the fake fj does not run'

reset_fake() { rm -rf "$FAKE"; mkdir -p "$FAKE"; }
iso() { printf '\xe2\x81\xa8%s\xe2\x81\xa9' "$1"; } # fj wraps values in direction isolates
dash=$'\xe2\x80\x94' # and separates them with an em dash

# A codewire origin with main and one pull request ref, and a clone carrying
# the real merge helper.
origin="$work/codewire.git"
git init -q --bare --initial-branch=main "$origin"
codewire="$work/codewire"
git init -q --initial-branch=main "$codewire"
mkdir -p "$codewire/scripts/dev"
cp "$ROOT/scripts/dev/merge-pr.sh" "$codewire/scripts/dev/"
git -C "$codewire" add -A
git -C "$codewire" commit -q -m base
git -C "$codewire" remote add origin "$origin"
git -C "$codewire" push -q origin main
git -C "$codewire" checkout -q -b topic
git -C "$codewire" commit -q --allow-empty -m topic
pr_head="$(git -C "$codewire" rev-parse HEAD)"
git -C "$codewire" push -q origin "HEAD:refs/pull/7/head"
git -C "$codewire" checkout -q main

pr_status() { # STATE CI SCAN
  {
    printf '%s %s %s\n' "$(iso Open)" "$dash" "$(iso "$1")"
    printf -- "- %s $dash %s\n" "$(iso "$2")" "$(iso 'CI / Required verification (pull_request)')"
    printf -- "- %s $dash %s\n" "$(iso "$3")" "$(iso 'Supply-chain scan / Supply-chain scan (pull_request_target)')"
  } >"$FAKE/status-7"
}
pr_view() {
  printf "%s %s\nBy fixture $dash %s\n" "$(iso 'feat: a change')" "#$(iso 7)" "$(iso Open)" >"$FAKE/view-7"
  printf "%s %s\nBy fixture $dash %s\n" "$(iso 'feat: a change')" "#$(iso 7)" "$(iso Merged)" >"$FAKE/merged-7"
}
# The fake merge lands a squash commit with the requested title on main.
merge_lands() {
  cat >"$FAKE/on-merge" <<EOF
#!/usr/bin/env bash
title=''
while [[ \$# -gt 0 ]]; do [[ "\$1" == -t ]] && title="\$2"; shift; done
git -C "$codewire" commit -q --allow-empty -m "\$title"
git -C "$codewire" push -q origin main
touch "$FAKE/landed"
EOF
  chmod +x "$FAKE/on-merge"
}
queue() { (cd "$codewire" && "$SCRIPTS/merge-queue.sh" "$@") >"$work/out" 2>&1; }

# A red required status stops the queue before any merge.
reset_fake; pr_view; pr_status 'Can be merged' Success Failure
queue 7 && fail 'merge-queue passed a red supply-chain scan'
grep -q '^STOP$' "$work/out" || fail 'merge-queue did not print STOP'
[[ ! -f "$FAKE/merges" ]] || fail 'merge-queue merged a red pull request'

# A conflicting pull request stops it too.
reset_fake; pr_view; pr_status 'Merge conflicts' Success Success
queue 7 && fail 'merge-queue passed a conflicting pull request'
[[ ! -f "$FAKE/merges" ]] || fail 'merge-queue merged a conflicting pull request'

# A dry run of a green one merges nothing and names the exact head and title.
reset_fake; pr_view; pr_status 'Can be merged' Success Success
queue --dry-run 7 || fail "merge-queue --dry-run failed: $(cat "$work/out")"
grep -qF "#7: would merge $pr_head as \"feat: a change (#7)\"" "$work/out" ||
  fail "merge-queue --dry-run named the wrong head or title: $(cat "$work/out")"
[[ ! -f "$FAKE/merges" ]] || fail 'merge-queue --dry-run merged'

# A green one merges through merge-pr.sh, then waits for main's run on the
# merged commit, found by its head rather than by being newest.
green_merge() { # OUTCOME
  reset_fake; pr_view; pr_status 'Can be merged' Success Success; merge_lands
  cat >>"$FAKE/on-merge" <<EOF
landed="\$(git -C "$codewire" rev-parse HEAD)"
printf '{"runs":[{"id":99,"head_sha":"%s"}]}' "\$landed" >"$FAKE/runs-ci.yaml-\$landed.json"
printf '{"type":"summary","outcome":"$1"}\n' >"$FAKE/watch-99"
EOF
}
green_merge success
queue 7 || fail "merge-queue failed a green merge: $(cat "$work/out")"
grep -qxF 'pr merge 7 -M squash -t feat: a change (#7) -m Reviewed-on: #7' "$FAKE/merges" ||
  fail "merge-queue did not merge through merge-pr.sh: $(cat "$FAKE/merges")"
landed="$(git -C "$codewire" rev-parse HEAD)"
grep -q -- "--expect-head $landed" "$FAKE/calls" || fail 'merge-queue did not watch the run bound to the merged commit'
grep -q '^QUEUE-DONE$' "$work/out" || fail 'merge-queue did not print QUEUE-DONE'

# A red main run stops the queue before the next pull request.
green_merge failure
queue 7 8 && fail 'merge-queue continued past a red main run'
grep -q '^STOP$' "$work/out" || fail 'merge-queue did not stop on a red main run'
grep -q 'pr status 8' "$FAKE/calls" && fail 'merge-queue read the next pull request after a red main run'

# watch-release: the run that delivers the tag is the one whose finder named
# it; a run for another tag and a run that delivered nothing are not.
release_runs() { # DEPLOY_PROD_STATUS CLI_RELEASE_STATUS
  local finder='"name":"Find the release to deliver"'
  printf '{"runs":[{"id":13},{"id":12},{"id":11}]}' >"$FAKE/runs-deploy-prod.yaml.json"
  printf '{"run":{"id":13,"head_sha":"%s","status":"success"},"jobs":[{"id":131,%s,"status":"success"},{"id":132,"name":"Publish","status":"skipped"}]}' \
    "$pr_head" "$finder" >"$FAKE/run-13.json"
  printf '{"run":{"id":12,"head_sha":"%s","status":"success"},"jobs":[{"id":121,%s,"status":"success"},{"id":122,"name":"Publish","status":"success"}]}' \
    "$pr_head" "$finder" >"$FAKE/run-12.json"
  printf 'T ::set-output:: release_tag=v1.2.30\n' >"$FAKE/log-12"
  printf '{"run":{"id":11,"head_sha":"%s","status":"%s"},"jobs":[{"id":111,%s,"status":"success"},{"id":112,"name":"Publish","status":"%s"}]}' \
    "$pr_head" "$1" "$finder" "$1" >"$FAKE/run-11.json"
  # The real log goes on long after the tag: a reader that stops at the match
  # must not turn the writer's SIGPIPE into a miss.
  { printf 'T ::set-output:: release_tag=v1.2.3\r\n'; seq 1 200000; } >"$FAKE/log-11"
  printf '{"runs":[{"id":21}]}' >"$FAKE/runs-cli-release.yaml.json"
  printf '{"run":{"id":21,"head_sha":"%s","status":"%s"},"jobs":[{"id":211,%s,"status":"success"},{"id":212,"name":"Sign","status":"%s"}]}' \
    "$pr_head" "$2" "$finder" "$2" >"$FAKE/run-21.json"
  printf 'T ::set-output:: release_tag=v1.2.3\n' >"$FAKE/log-21"
}
reset_fake; release_runs success success
(cd "$codewire" && "$SCRIPTS/watch-release.sh" --timeout 5 v1.2.3) >"$work/out" 2>&1 ||
  fail "watch-release failed a delivered release: $(cat "$work/out")"
grep -q '^deploy-prod: run 11 delivers v1.2.3' "$work/out" || fail "watch-release chose the wrong deploy-prod run: $(cat "$work/out")"
grep -q '^cli-release: run 21 delivers v1.2.3' "$work/out" || fail 'watch-release missed the cli-release run'
grep -q '^RELEASE-DONE v1.2.3$' "$work/out" || fail 'watch-release did not print RELEASE-DONE'
grep -Eq 'logs (-R origin )?13 ' "$FAKE/calls" && fail 'watch-release read the log of a run that delivered nothing'

reset_fake; release_runs failure success
(cd "$codewire" && "$SCRIPTS/watch-release.sh" --timeout 5 v1.2.3) >"$work/out" 2>&1 &&
  fail 'watch-release passed a failed deploy-prod'
grep -q '^RELEASE-FAILED v1.2.3$' "$work/out" || fail 'watch-release did not print RELEASE-FAILED'

reset_fake; release_runs running success
status=0
(cd "$codewire" && "$SCRIPTS/watch-release.sh" --timeout 1 v1.2.3) >"$work/out" 2>&1 || status=$?
[[ "$status" == 3 ]] || fail "watch-release did not time out with exit 3 (got $status)"

# dev-settled: a deploy origin whose latest dev promote names codewire main.
deploy_origin="$work/deploy.git"
deploy="$work/deploy"
git init -q --bare --initial-branch=main "$deploy_origin"
git init -q --initial-branch=main "$deploy"
git -C "$deploy" remote add origin "$deploy_origin"
printf 'base\n' >"$deploy/file"
git -C "$deploy" add -A
git -C "$deploy" commit -q -m base
codewire_main="$(git -C "$codewire" rev-parse origin/main)"
git -C "$deploy" commit -q --allow-empty -m "deploy(dev): promote source $codewire_main"
git -C "$deploy" commit -q --allow-empty -m 'docs: a later deploy change'
git -C "$deploy" push -q origin main
deploy_main="$(git -C "$deploy" rev-parse HEAD)"

settled() { (cd "$codewire" && "$SCRIPTS/dev-settled.sh" "$deploy" "$@") >"$work/out" 2>&1; }
reset_fake
printf '{"runs":[]}' >"$FAKE/runs-promote-dev.yaml.json"
settled || fail "dev-settled refused a settled Dev: $(cat "$work/out")"
printf '{"runs":[{"id":5}]}' >"$FAKE/runs-promote-dev.yaml.json"
settled && fail 'dev-settled passed while promote-dev runs'
printf '{"runs":[]}' >"$FAKE/runs-promote-dev.yaml.json"
cat >"$work/bin/fake-kube" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == kubectl ]] || exit 1
cat "$FAKE/kustomization.json"
EOF
chmod +x "$work/bin/fake-kube"
printf '{"status":{"lastAppliedRevision":"main@sha1:%s","conditions":[{"type":"Ready","status":"True"}]}}' \
  "$deploy_main" >"$FAKE/kustomization.json"
settled --kube fake-kube || fail "dev-settled refused an applied, Ready Dev: $(cat "$work/out")"
printf '{"status":{"lastAppliedRevision":"main@sha1:%s","conditions":[{"type":"Ready","status":"True"}]}}' \
  "$codewire_main" >"$FAKE/kustomization.json"
settled --kube fake-kube && fail 'dev-settled passed while Flux had not applied deploy main'
git -C "$codewire" commit -q --allow-empty -m 'feat: newer than Dev'
git -C "$codewire" push -q origin main
settled && fail 'dev-settled passed while Dev runs an older source'

# deploy-update-merge: main merges into the branch (never a rebase), the merge
# waits for both checks on the pushed head, and the worktree goes every time.
git -C "$deploy" checkout -q -b feature "$(git -C "$deploy" rev-parse HEAD~2)"
printf 'feature\n' >"$deploy/feature"
git -C "$deploy" add -A
git -C "$deploy" commit -q -m feature
feature_before="$(git -C "$deploy" rev-parse HEAD)"
git -C "$deploy" push -q origin feature "HEAD:refs/pull/9/head"
git -C "$deploy" checkout -q main
deploy_status() { # CHECK_STATUS
  {
    printf '%s %s %s\n' "$(iso Open)" "$dash" "$(iso 'Can be merged')"
    printf -- "- %s $dash %s\n" "$(iso "$1")" "$(iso 'Supply-chain scan / Supply-chain scan (pull_request_target)')"
    printf -- "- %s $dash %s\n" "$(iso "$1")" "$(iso 'Validate deploy release / validate (pull_request)')"
  } >"$FAKE/status-9"
  printf "x\nBy fixture $dash %s\n" "$(iso Open)" >"$FAKE/view-9"
  printf "x\nBy fixture $dash %s\n" "$(iso Merged)" >"$FAKE/merged-9"
}
# The fake forge moves the pull request ref when a helper pushes the branch.
cat >"$work/bin/git" <<EOF
#!/usr/bin/env bash
real_git="$(command -v git)"
"\$real_git" "\$@" || exit \$?
if [[ " \$* " == *" push "* ]]; then
  "\$real_git" -C "$deploy_origin" update-ref refs/pull/9/head refs/heads/feature
fi
EOF
chmod +x "$work/bin/git"
update() { "$SCRIPTS/deploy-update-merge.sh" "$@" >"$work/out" 2>&1; }
worktrees() { git -C "$deploy" worktree list | wc -l; }

reset_fake; deploy_status Success
update --dry-run "$deploy" 9 feature || fail "deploy-update-merge --dry-run failed: $(cat "$work/out")"
[[ "$(git -C "$deploy_origin" rev-parse feature)" == "$feature_before" ]] || fail 'deploy-update-merge --dry-run pushed'
[[ "$(worktrees)" == 1 ]] || fail 'deploy-update-merge --dry-run left its worktree'

reset_fake; deploy_status Failure
update --timeout 5 "$deploy" 9 feature && fail 'deploy-update-merge merged over a failed check'
[[ ! -f "$FAKE/merges" ]] || fail 'deploy-update-merge called merge over a failed check'
[[ "$(worktrees)" == 1 ]] || fail 'deploy-update-merge left its worktree after a failed check'

reset_fake; deploy_status Success
update --timeout 5 "$deploy" 9 feature || fail "deploy-update-merge failed: $(cat "$work/out")"
pushed="$(git -C "$deploy_origin" rev-parse feature)"
git -C "$deploy_origin" merge-base --is-ancestor "$feature_before" "$pushed" || fail 'deploy-update-merge rewrote the branch'
git -C "$deploy_origin" merge-base --is-ancestor "$deploy_main" "$pushed" || fail 'deploy-update-merge did not merge main'
grep -qxF 'pr merge 9 -M merge -d -m Reviewed-on: #9' "$FAKE/merges" || fail "deploy-update-merge merged wrongly: $(cat "$FAKE/merges")"
[[ "$(worktrees)" == 1 ]] || fail 'deploy-update-merge left its worktree'

# A conflict stops before any push, and the worktree still goes.
git -C "$deploy" checkout -q main
printf 'main side\n' >"$deploy/feature"
git -C "$deploy" add -A
git -C "$deploy" commit -q -m 'conflicting main'
git -C "$deploy" push -q origin main
git -C "$deploy" checkout -q --detach "$pushed"
printf 'branch side\n' >"$deploy/feature"
git -C "$deploy" commit -q -am 'conflicting branch'
git -C "$deploy" push -q origin HEAD:feature
git -C "$deploy_origin" update-ref refs/pull/9/head refs/heads/feature
git -C "$deploy" checkout -q main
conflicted="$(git -C "$deploy_origin" rev-parse feature)"
reset_fake; deploy_status Success
update --timeout 5 "$deploy" 9 feature && fail 'deploy-update-merge passed a conflict'
grep -q 'conflicts' "$work/out" || fail "deploy-update-merge did not report the conflict: $(cat "$work/out")"
[[ "$(git -C "$deploy_origin" rev-parse feature)" == "$conflicted" ]] || fail 'deploy-update-merge pushed a conflict'
[[ "$(worktrees)" == 1 ]] || fail 'deploy-update-merge left its worktree after a conflict'

# rerun-run: a whole-run rerun only once nothing of the run is alive (#4141).
# Run 42471 read cancelled while its archive job's previous task still ran, so
# a task list that names a live task refuses even when every job has ended.
rerun_run() { "$SCRIPTS/rerun-run.sh" "$@" >"$work/out" 2>&1; }
task_page() { # PAGE LINE...: one page of `fj actions tasks`, 20 lines when full
  local page="$1"
  shift
  { printf '64504 tasks\n'; printf '%s\n' "$@"; } >"$FAKE/tasks-$page"
}
filler() { # N tasks of other runs
  local i
  for ((i = 0; i < $1; i++)); do printf '#9%03d (1111111111) success Policy verification 1m (push): other\n' "$i"; done
}
reset_fake
jq -n '{run: {id: 42471, number: 27221, status: "cancelled"},
  jobs: [{id: 1, name: "Build test archives", status: "running"}, {id: 2, name: "Rust / transport packages", status: "cancelled"}]}' \
  >"$FAKE/run-42471.json"
task_page 1 '#27221 (a054388b61) success Verification selection 36s (pull_request): t'
rerun_run 42471 && fail 'rerun-run reran a run with a running job'
grep -q '^job 1 is running: Build test archives$' "$work/out" || fail "rerun-run did not name the running job: $(cat "$work/out")"
[[ ! -e "$FAKE/reruns" ]] || fail 'rerun-run reran a live run'
jq '.jobs[0].status = "success"' "$FAKE/run-42471.json" >"$FAKE/run.tmp" && mv "$FAKE/run.tmp" "$FAKE/run-42471.json"
# Every job has ended, but the second page holds the archive job's task, alive.
mapfile -t others < <(filler 19)
task_page 1 '#27221 (a054388b61) cancelled Policy verification 4m (pull_request): t' "${others[@]}"
task_page 2 '#27221 (a054388b61) running Build test archives 13m (pull_request): t'
rerun_run 42471 && fail 'rerun-run reran a run whose task was still running'
grep -q '^task is running Build test archives 13m$' "$work/out" || fail "rerun-run did not name the live task: $(cat "$work/out")"
[[ ! -e "$FAKE/reruns" ]] || fail 'rerun-run reran a run with a live task'
task_page 2 '#27221 (a054388b61) success Build test archives 18m42s (pull_request): t'
rerun_run 42471 || fail "rerun-run refused a run with nothing alive: $(cat "$work/out")"
[[ "$(cat "$FAKE/reruns")" == 42471 ]] || fail 'rerun-run did not rerun the run by its ID'
grep -q '^reran run 42471 (#27221)' "$work/out" || fail 'rerun-run did not report the rerun'
rm -f "$FAKE/run-42471.json" "$FAKE/reruns"
status=0
rerun_run 42471 || status=$?
[[ "$status" -eq 2 ]] || fail "rerun-run did not say it cannot tell when the run cannot be read (exit $status)"
grep -q '^unknown: cannot read run 42471' "$work/out" || fail 'rerun-run gave no reason for an unreadable run'
[[ ! -e "$FAKE/reruns" ]] || fail 'rerun-run reran a run it could not read'

printf '[test-orchestrator-scripts] merge queue, release watch, Dev settle, deploy update and rerun all decide on their evidence\n'
