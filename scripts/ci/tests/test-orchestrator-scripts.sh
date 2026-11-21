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
        workflow='' head='' page=''
        while [[ $# -gt 0 ]]; do
          case "$1" in --workflow) workflow="$2" ;; --head) head="$2" ;; -p) page="$2" ;; esac
          shift
        done
        if [[ -n "$head" ]]; then answer "runs-$workflow-$head.json"
        elif [[ -n "$page" && -f "$FAKE/runs-$workflow-p$page.json" ]]; then answer "runs-$workflow-p$page.json"
        else answer "runs-$workflow.json"; fi
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
no_deliveries() {
  reset_fake
  local workflow
  for workflow in promote-dev deploy-dev ci; do printf '{"runs":[]}' >"$FAKE/runs-$workflow.yaml.json"; done
}
# A codewire deploy-dev run's jobs, each given as "STATUS" in workflow order.
delivery_run() { # ID SELECTION TURN SERVICES DAEMON PUBLISH DEFERRED HAND_ON
  local names=('Deploy selection' 'Dev delivery turn' 'Build and push the service runtime images'
    'Build and push the daemon runtime image' 'Publish the exact runtime image set'
    'Deferred to the delivery in flight' 'Hand the Dev delivery turn on')
  local id="$1" jobs='' i=0
  shift
  for status in "$@"; do
    jobs+="${jobs:+,}{\"name\":\"${names[$i]}\",\"status\":\"$status\"}"
    i=$((i + 1))
  done
  printf '{"run":{"id":%s},"jobs":[%s]}' "$id" "$jobs" >"$FAKE/run-$id.json"
}
active() { # WORKFLOW ID [SHA] [REF]
  printf '{"runs":[{"id":%s,"head_sha":"%s","ref":"%s"}]}' "$2" "${3:-$codewire_main}" "${4:-main}" \
    >"$FAKE/runs-$1.yaml.json"
}
reasons() { grep -c '^not settled: ' "$work/out"; }

no_deliveries
settled || fail "dev-settled refused a settled Dev: $(cat "$work/out")"
grep -q '^settled: ' "$work/out" || fail 'dev-settled did not say settled'
active promote-dev 5
settled && fail 'dev-settled passed while promote-dev runs'
grep -q '^not settled: promote-dev run 5 is running$' "$work/out" || fail "dev-settled did not name the promote-dev run: $(cat "$work/out")"

# deploy-dev: a run waiting for its turn, building or publishing is in flight;
# one that builds nothing, or that only hands the turn on, is not.
no_deliveries; active deploy-dev 60
delivery_run 60 success running blocked blocked blocked blocked blocked
settled && fail 'dev-settled passed while a deploy-dev run waits for its turn'
grep -q '^not settled: deploy-dev run 60 (.*) is running at "Dev delivery turn"$' "$work/out" ||
  fail "dev-settled did not name where deploy-dev waits: $(cat "$work/out")"
delivery_run 60 success success success success running skipped blocked
settled && fail 'dev-settled passed while a deploy-dev run publishes'
grep -q 'at "Publish the exact runtime image set"' "$work/out" || fail 'dev-settled did not name the publish job'
delivery_run 60 success success skipped skipped skipped running blocked
settled || fail "dev-settled counted a deferred deploy-dev run as in flight: $(cat "$work/out")"
delivery_run 60 success success skipped skipped skipped skipped skipped
settled || fail "dev-settled counted a deploy-dev run that delivers nothing as in flight: $(cat "$work/out")"
delivery_run 60 success success success success success skipped waiting
settled || fail "dev-settled counted a delivery that only hands the turn on as in flight: $(cat "$work/out")"
active deploy-dev 60 "$codewire_main" topic
delivery_run 60 success running blocked blocked blocked blocked blocked
settled || fail "dev-settled counted a deploy-dev run off main: $(cat "$work/out")"

# Main CI: in flight when its commit's delivery built, or is building, and its
# publish waits on this verdict; not when that delivery builds nothing, or the
# commit has none.
no_deliveries; active ci 70
printf '{"runs":[{"id":61,"ref":"main"}]}' >"$FAKE/runs-deploy-dev.yaml-$codewire_main.json"
delivery_run 61 success success success success success skipped success
settled && fail 'dev-settled passed while main CI decides a built delivery'
grep -q '^not settled: main CI run 70 (.*) is running, and deploy-dev run 61 waits on its verdict$' "$work/out" ||
  fail "dev-settled did not name the main CI run a delivery waits on: $(cat "$work/out")"
delivery_run 61 success success skipped skipped skipped success skipped
settled || fail "dev-settled counted main CI for a deferred delivery: $(cat "$work/out")"
printf '{"runs":[]}' >"$FAKE/runs-deploy-dev.yaml-$codewire_main.json"
settled || fail "dev-settled counted main CI for a commit with no delivery: $(cat "$work/out")"

# Every reason is its own line, and an unreadable run cannot tell.
no_deliveries; active promote-dev 5; active deploy-dev 60
delivery_run 60 success running blocked blocked blocked blocked blocked
settled && fail 'dev-settled passed with two deliveries in flight'
[[ "$(reasons)" == 2 ]] || fail "dev-settled did not give one line per reason: $(cat "$work/out")"
rm "$FAKE/run-60.json"
status=0; settled || status=$?
[[ "$status" == 2 ]] || fail "dev-settled did not say it cannot tell when a deploy-dev run is unreadable (exit $status)"
grep -q '^unknown: cannot read deploy-dev run 60' "$work/out" || fail 'dev-settled gave no reason for an unreadable run'

# Main CI is listed by push event, so pull-request runs never crowd a main run
# off the page; a full page of any list cannot tell.
no_deliveries
settled || fail "dev-settled refused a settled Dev: $(cat "$work/out")"
grep -Eq 'actions runs list -R origin -L [0-9]+ --workflow ci.yaml --event push ' "$FAKE/calls" ||
  fail 'dev-settled listed main CI without --event push'
page="$(jq -cn '{runs: [range(50) | {id: (100 + .), head_sha: "x", ref: "pull/1/head"}]}')"
for workflow in promote-dev deploy-dev ci; do
  no_deliveries
  printf '%s' "$page" >"$FAKE/runs-$workflow.yaml.json"
  status=0; settled || status=$?
  [[ "$status" == 2 ]] || fail "dev-settled did not say it cannot tell with a full page of $workflow runs (exit $status)"
  grep -q "^unknown: 50 or more running $workflow.yaml runs, more than one page" "$work/out" ||
    fail "dev-settled gave no reason for a full page of $workflow runs: $(cat "$work/out")"
done
no_deliveries; active ci 70
printf '%s' "$page" >"$FAKE/runs-deploy-dev.yaml-$codewire_main.json"
status=0; settled || status=$?
[[ "$status" == 2 ]] || fail "dev-settled did not say it cannot tell with a full page of one commit's deploy-dev runs (exit $status)"

# The job names it reads are deploy-dev.yaml's.
for job in 'Deploy selection' 'Dev delivery turn' \
    'Build and push the service runtime images' 'Build and push the daemon runtime image' \
    'Publish the exact runtime image set' 'Hand the Dev delivery turn on'; do
  grep -Fq "    name: $job" "$ROOT/.gitea/workflows/deploy-dev.yaml" || fail "deploy-dev.yaml has no job named $job"
  grep -Fq "$job" "$SCRIPTS/dev-settled.sh" || fail "dev-settled does not read the job $job"
done

no_deliveries
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

# Dev's source may lag main by commits that need no Dev delivery: settled only
# while every commit ahead has a deploy-dev run whose selection skipped the
# delivery turn. A deferred delivery skips its builds too, but still delivers.
git -C "$codewire" commit -q --allow-empty -m 'docs: newer than Dev'
git -C "$codewire" push -q origin main
docs_commit="$(git -C "$codewire" rev-parse HEAD)"
no_deliveries
printf '{"runs":[{"id":80,"ref":"main"}]}' >"$FAKE/runs-deploy-dev.yaml-$docs_commit.json"
delivery_run 80 success skipped skipped skipped skipped skipped skipped
settled || fail "dev-settled refused a Dev that lags main only by a commit needing no delivery: $(cat "$work/out")"
grep -q "^settled: Dev source $codewire_main (main $docs_commit needs no Dev delivery since)" "$work/out" ||
  fail "dev-settled did not say why the lag is settled: $(cat "$work/out")"
behind="^not settled: Dev's source is $codewire_main, codewire main is $docs_commit\$"
delivery_run 80 success success skipped skipped skipped success skipped
status=0; settled || status=$?
{ [[ "$status" == 1 ]] && grep -q "$behind" "$work/out"; } ||
  fail "dev-settled passed while the commit ahead of Dev deferred its delivery: $(cat "$work/out")"
printf '{"runs":[]}' >"$FAKE/runs-deploy-dev.yaml-$docs_commit.json"
status=0; settled || status=$?
{ [[ "$status" == 1 ]] && grep -q "$behind" "$work/out"; } ||
  fail "dev-settled passed while a commit ahead of Dev had no deploy-dev run: $(cat "$work/out")"

# A source that is not on main's history, or more commits ahead than it reads
# one by one, is not settled, and the second reads none of them.
git -C "$deploy" commit -q --allow-empty -m "deploy(dev): promote source $(printf 'f%.0s' {1..40})"
git -C "$deploy" push -q origin main
no_deliveries
status=0; settled || status=$?
[[ "$status" == 1 ]] || fail "dev-settled passed while Dev's source is not on main's history (exit $status)"
git -C "$deploy" reset -q --hard HEAD~1
git -C "$deploy" push -q -f origin main
for i in $(seq 1 20); do git -C "$codewire" commit -q --allow-empty -m "docs: ahead $i"; done
git -C "$codewire" push -q origin main
no_deliveries
status=0; settled || status=$?
[[ "$status" == 1 ]] || fail "dev-settled passed with Dev 21 commits behind main (exit $status)"
! grep -q -- '--head' "$FAKE/calls" || fail 'dev-settled read the commits ahead one by one past its limit'

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
# With $FAKE/ref-lag holding N, it moves it only after N more reads, as
# Forgejo does a little after a push; with $FAKE/ref-other, it moves it to
# that commit instead, as another person's push would.
cat >"$work/bin/git" <<EOF
#!/usr/bin/env bash
real_git="$(command -v git)"
"\$real_git" "\$@" || exit \$?
if [[ " \$* " == *" push "* && ! -f "$FAKE/ref-lag" ]]; then
  "\$real_git" -C "$deploy_origin" update-ref refs/pull/9/head "\$(cat "$FAKE/ref-other" 2>/dev/null || echo refs/heads/feature)"
fi
if [[ " \$* " == *" ls-remote "*" refs/pull/9/head "* && -f "$FAKE/ref-lag" ]]; then
  lag="\$(cat "$FAKE/ref-lag")"
  if (( lag <= 1 )); then
    rm "$FAKE/ref-lag"
    "\$real_git" -C "$deploy_origin" update-ref refs/pull/9/head refs/heads/feature
  else
    echo \$((lag - 1)) >"$FAKE/ref-lag"
  fi
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

# Forgejo moves refs/pull/9/head a little after the push: the old head read
# meanwhile is waited out, not taken for someone else's push (deploy#336). A
# head that never moves stops within the timeout, and a head another push
# moved still stops.
branch_back() {
  git -C "$deploy_origin" update-ref refs/heads/feature "$feature_before"
  git -C "$deploy_origin" update-ref refs/pull/9/head "$feature_before"
}
branch_back; reset_fake; deploy_status Success; echo 3 >"$FAKE/ref-lag"
update --timeout 5 "$deploy" 9 feature || fail "deploy-update-merge stopped on a pull request ref that lagged its push: $(cat "$work/out")"
grep -qxF 'pr merge 9 -M merge -d -m Reviewed-on: #9' "$FAKE/merges" || fail 'deploy-update-merge did not merge after the ref caught up'
branch_back; reset_fake; deploy_status Success; echo 1000000 >"$FAKE/ref-lag"
update --timeout 2 "$deploy" 9 feature && fail 'deploy-update-merge merged while the pull request ref never moved'
grep -q "still names $feature_before" "$work/out" || fail "deploy-update-merge did not say the ref never moved: $(cat "$work/out")"
[[ ! -f "$FAKE/merges" ]] || fail 'deploy-update-merge called merge while the ref never moved'
branch_back; reset_fake; deploy_status Success; git -C "$deploy_origin" rev-parse main >"$FAKE/ref-other"
update --timeout 5 "$deploy" 9 feature && fail 'deploy-update-merge merged over someone else'"'"'s push'
grep -q 'someone else pushed' "$work/out" || fail "deploy-update-merge did not report the other push: $(cat "$work/out")"
[[ "$(worktrees)" == 1 ]] || fail 'deploy-update-merge left its worktree'
reset_fake
git -C "$deploy_origin" update-ref refs/heads/feature "$pushed"
git -C "$deploy_origin" update-ref refs/pull/9/head "$pushed"

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
jq -n '{run: {id: 42471, number: 27221, status: "cancelled", stopped_at: "2026-10-25T10:00:00Z"},
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
# A run cancelled under 60 s ago waits: its task may still run on a warm VM
# until the cancel reaper stops it, and a rerun would attach to it.
rm -f "$FAKE/reruns"
jq --arg at "$(date -u -d '-10 seconds' +%Y-%m-%dT%H:%M:%SZ)" '.run.stopped_at = $at' "$FAKE/run-42471.json" \
  >"$FAKE/run.tmp" && mv "$FAKE/run.tmp" "$FAKE/run-42471.json"
rerun_run 42471 && fail 'rerun-run reran a run cancelled 10 s ago'
grep -q '^run was cancelled [0-9]*s ago (at .*); .*cancel reaper .*rerun after [0-9]*s$' "$work/out" ||
  fail "rerun-run did not name the recent cancel: $(cat "$work/out")"
[[ ! -e "$FAKE/reruns" ]] || fail 'rerun-run reran a run inside the cancel window'
# A cancelled run without a readable stop time can't be judged.
jq 'del(.run.stopped_at)' "$FAKE/run-42471.json" >"$FAKE/run.tmp" && mv "$FAKE/run.tmp" "$FAKE/run-42471.json"
status=0
rerun_run 42471 || status=$?
[[ "$status" -eq 2 ]] || fail "rerun-run judged a cancelled run with no stop time (exit $status)"
grep -q '^unknown: cancelled run 42471 has no stop time' "$work/out" || fail 'rerun-run gave no reason for a missing stop time'
[[ ! -e "$FAKE/reruns" ]] || fail 'rerun-run reran a run with no stop time'
rm -f "$FAKE/run-42471.json" "$FAKE/reruns"
status=0
rerun_run 42471 || status=$?
[[ "$status" -eq 2 ]] || fail "rerun-run did not say it cannot tell when the run cannot be read (exit $status)"
grep -q '^unknown: cannot read run 42471' "$work/out" || fail 'rerun-run gave no reason for an unreadable run'
[[ ! -e "$FAKE/reruns" ]] || fail 'rerun-run reran a run it could not read'

# rerun-recycle-cuts: after a warm VM's recycle, the runs it cut (a job ended
# with the runner's "context canceled") are rerun through rerun-run.sh; a run
# that failed any other way, or outside the window, is left alone (infra#1534).
recycle_cuts() { "$SCRIPTS/rerun-recycle-cuts.sh" "$@" >"$work/out" 2>&1; }
reset_fake
jq -n '{runs: [
  {id: 68336, number: 47048, status: "failure", created_at: "2026-11-21T17:00:00Z", stopped_at: "2026-11-21T17:45:22Z"},
  {id: 68337, number: 47049, status: "failure", created_at: "2026-11-21T17:01:00Z", stopped_at: "2026-11-21T17:46:00Z"},
  {id: 68300, number: 47010, status: "failure", created_at: "2026-11-21T16:00:00Z", stopped_at: "2026-11-21T16:30:00Z"},
  {id: 68338, number: 47050, status: "success", created_at: "2026-11-21T17:02:00Z", stopped_at: "2026-11-21T17:45:30Z"}]}' \
  >"$FAKE/runs-.json"
for run in 68336:47048 68337:47049; do
  jq -n --argjson id "${run%%:*}" --argjson number "${run#*:}" '{run: {id: $id, number: $number, status: "failure"},
    jobs: [{id: 1, name: "Verification selection", status: "failure"}, {id: 2, name: "Required verification", status: "failure"}]}' \
    >"$FAKE/run-${run%%:*}.json"
done
printf '%s\n' 'PR admission: 2 pull request runs admitted and 1 waiting ahead; 2 at once; waiting' \
  '⚙️ [runner]: context canceled' '🏁  Job failed' >"$FAKE/log-68336"
printf '%s\n' '::error::scripts/ci/tests/test-x.sh failed (exit 1) after 5s' '🏁  Job failed' >"$FAKE/log-68337"
task_page 1 '#47048 (b31b213495) failure Verification selection 45m (pull_request): t'
recycle_cuts 2026-11-21T17:40:00Z 2026-11-21T17:50:00Z || fail "rerun-recycle-cuts failed: $(cat "$work/out")"
[[ "$(cat "$FAKE/reruns")" == 68336 ]] || fail "rerun-recycle-cuts did not rerun exactly the cut run: $(cat "$FAKE/reruns" 2>/dev/null)"
grep -q '^cut by the recycle (job 1): reran run 68336 (#47048)' "$work/out" || fail "rerun-recycle-cuts did not report the rerun: $(cat "$work/out")"
grep -q "^not cut: run 68337 failed without the runner's context canceled$" "$work/out" ||
  fail "rerun-recycle-cuts did not name the real failure it left alone: $(cat "$work/out")"
grep -q '68300' "$FAKE/calls" && fail 'rerun-recycle-cuts read a run that stopped before the window'
grep -q '^1 cut run(s) between' "$work/out" || fail 'rerun-recycle-cuts did not count the cut runs'
# A cut run with a task still alive is named for later and exits 1.
rm -f "$FAKE/reruns"
task_page 1 '#47048 (b31b213495) running Verification selection 2m (pull_request): t'
status=0
recycle_cuts 2026-11-21T17:40:00Z 2026-11-21T17:50:00Z || status=$?
[[ "$status" -eq 1 ]] || fail "rerun-recycle-cuts did not say a cut run is still alive (exit $status): $(cat "$work/out")"
grep -q '^cut by the recycle (job 1), still alive, rerun once it ends: .*task is running Verification selection 2m' "$work/out" ||
  fail "rerun-recycle-cuts did not name the live task: $(cat "$work/out")"
[[ ! -e "$FAKE/reruns" ]] || fail 'rerun-recycle-cuts reran a run with a live task'
# A list it cannot read is no evidence: exit 2, rerun nothing.
rm -f "$FAKE/runs-.json"
status=0
recycle_cuts 2026-11-21T17:40:00Z 2026-11-21T17:50:00Z || status=$?
[[ "$status" -eq 2 && ! -e "$FAKE/reruns" ]] || fail "rerun-recycle-cuts did not refuse an unreadable run list (exit $status)"
recycle_cuts 2026-11-21T17:50:00Z 2026-11-21T17:40:00Z && fail 'rerun-recycle-cuts accepted a window that ends before it starts'
# A cut run started before the cut, so newer runs can push it to a later page:
# here 100 runs started after it, and it is on page 3. A cancelled run with the
# same runner line was a deliberate cancel, never a cut, and is not rerun.
reset_fake
newer() { # PAGE: 50 successful runs started after the cut runs but before SINCE
  jq -n --argjson page "$1" '{runs: [range(50) | {id: (70000 + ($page * 100) + .), status: "success",
    created_at: "2026-11-21T17:20:00Z", stopped_at: "2026-11-21T17:30:00Z"}]}'
}
newer 1 >"$FAKE/runs--p1.json"
newer 2 >"$FAKE/runs--p2.json"
jq -n '{runs: [
  {id: 68336, status: "failure", created_at: "2026-11-21T17:00:00Z", stopped_at: "2026-11-21T17:45:22Z"},
  {id: 68340, status: "cancelled", created_at: "2026-11-21T17:01:00Z", stopped_at: "2026-11-21T17:45:30Z"}]}' \
  >"$FAKE/runs--p3.json"
jq -n '{run: {id: 68336, number: 47048, status: "failure"}, jobs: [{id: 1, name: "Verification selection", status: "failure"}]}' \
  >"$FAKE/run-68336.json"
jq -n '{run: {id: 68340, number: 47052, status: "cancelled"}, jobs: [{id: 3, name: "Verification selection", status: "cancelled"}]}' \
  >"$FAKE/run-68340.json"
printf '%s\n' '⚙️ [runner]: context canceled' >"$FAKE/log-68336"
printf '%s\n' '⚙️ [runner]: context canceled' >"$FAKE/log-68340"
task_page 1 '#47048 (b31b213495) failure Verification selection 45m (pull_request): t'
recycle_cuts 2026-11-21T17:40:00Z 2026-11-21T17:50:00Z || fail "rerun-recycle-cuts failed across pages: $(cat "$work/out")"
[[ "$(cat "$FAKE/reruns" 2>/dev/null)" == 68336 ]] ||
  fail "rerun-recycle-cuts did not find the cut run on page 3, or reran the cancel: $(cat "$FAKE/reruns" 2>/dev/null)"
grep -q 'view -R origin 68340' "$FAKE/calls" && fail 'rerun-recycle-cuts read a cancelled run as a candidate'

# The public GitHub repositories' protection (#5407), against a fake gh.
python3 -I -B "$ROOT/scripts/ci/tests/test-github-repository-protection.py" >"$work/ruleset.out" 2>&1 ||
  fail "the GitHub repository protection helper failed its tests: $(tail -20 "$work/ruleset.out")"

printf '[test-orchestrator-scripts] merge queue, release watch, Dev settle, deploy update, rerun, recycle-cut reruns and the GitHub repository protection all decide on their evidence\n'
