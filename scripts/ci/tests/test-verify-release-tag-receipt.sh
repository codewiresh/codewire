#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/receipts/verify-release-tag-receipt.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/release-tag-receipt.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-verify-release-tag-receipt] ERROR: %s\n' "$*" >&2
  exit 1
}

repo="$TMP/repo"
mock_bin="$TMP/bin"
mkdir -p "$repo" "$mock_bin"
git init -q -b main "$repo"
git -C "$repo" config user.name 'Release Receipt Test'
git -C "$repo" config user.email receipt@test.invalid
# This fixture verifies tag provenance paths; it does not exercise a local
# signing agent, so make its disposable annotated tag hermetic.
git -C "$repo" config tag.gpgSign false
commit() {
  printf '%s\n' "$1" >"$repo/product.txt"
  git -C "$repo" add product.txt
  git -C "$repo" -c commit.gpgsign=false commit -q -m "$1"
  git -C "$repo" rev-parse HEAD
}
# main: ancestor_sha <- main_sha. A side commit off the ancestor is never on main.
commit ancestor >/dev/null
git -C "$repo" tag -a -m v1.2.2 v1.2.2
git -C "$repo" switch -q -c side
commit side >/dev/null
git -C "$repo" tag -a -m v1.2.4 v1.2.4
git -C "$repo" switch -q main
main_sha="$(commit release)"
git -C "$repo" tag -a -m v1.2.3 v1.2.3
git -C "$repo" remote add origin https://git.example.invalid/codewire/codewire.git

real_git="$(command -v git)"
cat >"$mock_bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'verify-tag '* )
    [ "${FIXTURE_MODE:?}" != bad_signature ]
    ;;
  'remote get-url origin')
    if [ "$FIXTURE_MODE" = wrong_remote ]; then
      printf 'https://github.com/codewiresh/codewire.git\n'
    else
      printf 'https://git.example.invalid/codewire/codewire.git\n'
    fi
    ;;
  'fetch --quiet --no-tags origin refs/heads/main')
    # The fixture has no network: canonical main is either local already or
    # unavailable.
    exit 1
    ;;
  'ls-remote origin refs/heads/main')
    if [ "$FIXTURE_MODE" = api_unavailable ]; then
      printf '%s\trefs/heads/main\n' "$FIXTURE_MAIN_SHA"
    elif [ "$FIXTURE_MODE" = stale_main ]; then
      printf '%040d\trefs/heads/main\n' 0
    else
      printf '%s\trefs/heads/main\n' "$FIXTURE_MAIN_SHA"
    fi
    ;;
  *) exec "$REAL_GIT" "$@" ;;
esac
EOF

cat >"$mock_bin/fj" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${FIXTURE_MODE:?}" != api_unavailable ] || exit 1
[ "$1 $2" = 'actions runs' ] || { echo "unexpected fj command: $*" >&2; exit 2; }
verb="$3"; shift 3
repo=codewire; target=''; job=''; output=text; workflow=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -R) [ "$2" = origin ] || exit 2; shift 2 ;;
    -r) [ "$2" = codewire/deploy ] || exit 2; repo=deploy; shift 2 ;;
    -H) [ "$2" = git.example.invalid ] || exit 2; shift 2 ;;
    --workflow) workflow="$2"; shift 2 ;;
    --head|--event|--status|-L) shift 2 ;;
    --job) job="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    [0-9]*) target="$1"; shift ;;
    *) echo "unexpected fj argument: $1" >&2; exit 2 ;;
  esac
done
head="$FIXTURE_TAG_COMMIT"
ci_status=success
case "$FIXTURE_MODE" in failed_ci|scheduled_masks_failed_push) ci_status=failure ;; esac
required_status=success
[ "$FIXTURE_MODE" != failed_required ] || required_status=failure
dev_status=success
[ "$FIXTURE_MODE" != failed_dev ] || dev_status=failure
dev_source="$FIXTURE_TAG_COMMIT"
[ "$FIXTURE_MODE" != wrong_dev_source ] || dev_source="$(printf '%040d' 7)"
# A superseded run, or one that reused a tested tree, dispatches no group.
group_status=success
case "$FIXTURE_MODE" in superseded|dispatched_nothing|tested_tree) group_status=skipped ;; esac

# ci.yaml on the tagged commit: the push run 701, whose Kind a push to main
# deferred, and a later Kind run: scheduled 711 (which Forgejo lists with
# event push) or dispatched 721.
run() { # ID EVENT STATUS
  printf '{"id":%s,"head_sha":"%s","workflow":"ci.yaml","status":"%s","event":"%s","ref":"main"}' \
    "$1" "$head" "$3" "$2"
}
job() { # ID RUN NAME STATUS
  printf '{"id":%s,"run_id":%s,"name":"%s","status":"%s","attempt":1}' "$1" "$2" "$3" "$4"
}
kind_run=711; kind_event=push
[ "$FIXTURE_MODE" != kind_from_dispatch ] || { kind_run=721; kind_event=workflow_dispatch; }
kind_status=success; shard_status=success; other_shard=success
case "$FIXTURE_MODE" in
  kind_shard_failed) other_shard=failure ;;
  kind_run_failed) kind_status=failure; other_shard=failure ;;
  kind_shards_skipped) shard_status=skipped; other_shard=skipped ;;
esac
dry_assemble=success
case "$repo:$verb:$target" in
  codewire:list:)
    [ "$output" = json ]
    case "$workflow" in
      ci.yaml)
        runs="$(run 701 push "$ci_status")"
        [ "$FIXTURE_MODE" = no_kind_run ] || runs="$runs,$(run "$kind_run" "$kind_event" "$kind_status")"
        ;;
      cw-release-dry-run.yaml)
        [ "$FIXTURE_MODE" != dry_runs_unavailable ] || exit 1
        # 901: a deferred push run, which built nothing; 902: a dispatch.
        runs="$(run 901 push success | sed 's/"ci.yaml"/"cw-release-dry-run.yaml"/')"
        [ "$FIXTURE_MODE" = no_dry_run ] \
          || runs="$runs,$(run 902 workflow_dispatch success | sed 's/"ci.yaml"/"cw-release-dry-run.yaml"/')"
        ;;
      *) exit 2 ;;
    esac
    printf '{"schema_version":1,"total_count":2,"runs":[%s]}' "$runs"
    ;;
  codewire:view:701)
    printf '{"schema_version":1,"run":%s,"jobs":[%s,%s,%s,%s,%s,%s]}' \
      "$(run 701 push "$ci_status")" \
      "$(job 703 701 'Verification selection' success)" \
      "$(job 704 701 'Policy verification' "$group_status")" \
      "$(job 705 701 'Workspace cache experiment (cold)' success)" \
      "$(job 706 701 'Edge / Kind verification (environment)' skipped)" \
      "$(job 707 701 'Edge / Kind verification (dashboard)' skipped)" \
      "$(job 702 701 'Required verification' "$required_status")"
    ;;
  codewire:view:711|codewire:view:721)
    printf '{"schema_version":1,"run":%s,"jobs":[%s,%s,%s,%s,%s]}' \
      "$(run "$target" "$kind_event" "$kind_status")" \
      "$(job "${target%1}3" "$target" 'Verification selection' success)" \
      "$(job "${target%1}4" "$target" 'Policy verification' skipped)" \
      "$(job "${target%1}6" "$target" 'Edge / Kind verification (environment)' "$shard_status")" \
      "$(job "${target%1}7" "$target" 'Edge / Kind verification (dashboard)' "$other_shard")" \
      "$(job "${target%1}2" "$target" 'Required verification' "$kind_status")"
    ;;
  codewire:view:901|codewire:view:902)
    if [ "$target" = 901 ]; then assemble=skipped; else assemble="$dry_assemble"; fi
    printf '{"schema_version":1,"run":%s,"jobs":[%s,%s,%s]}' \
      "$(run "$target" "$([ "$target" = 901 ] && echo push || echo workflow_dispatch)" success \
        | sed 's/"ci.yaml"/"cw-release-dry-run.yaml"/')" \
      "$(job "${target}0" "$target" 'Refuse anything but protected main' success)" \
      "$(job "${target}1" "$target" 'Skip a superseded commit' success)" \
      "$(job "${target}2" "$target" 'Assemble and verify the unsigned four-target delivery' "$assemble")"
    ;;
  codewire:logs:701|codewire:logs:711|codewire:logs:721)
    case "$job" in
      703|713|723)
        [ "$FIXTURE_MODE" != selection_log_unavailable ] || exit 1
        printf '== job %s Verification selection (success) ==\r\n' "$job"
        if [ "$target" = 701 ]; then
          printf '2026-10-20T12:53:12.0000000Z classification=changed\r\n'
          printf '2026-10-20T12:53:12.0000000Z selection=|valid:v3|edge_kind|policy|complete|\r\n'
          printf '2026-10-20T12:53:12.1000000Z main push: Kind deferred to the scheduled or dispatched Kind run (owner decision 2026-10-20)\r\n'
        elif [ "$target" = 711 ]; then
          printf '2026-10-20T16:15:03.0000000Z classification=scheduled\r\n'
          printf '2026-10-20T16:15:03.0000000Z selection=|valid:v3|kind|scheduled|complete|\r\n'
        else
          printf '2026-10-20T13:40:00.0000000Z classification=requested\r\n'
          printf '2026-10-20T13:40:00.0000000Z selection=|valid:v3|edge_kind|kind|complete|\r\n'
        fi
        if [ "$FIXTURE_MODE" = superseded ] && [ "$target" = 701 ]; then
          printf "2026-10-13T12:53:14.6412715Z superseded by %s: main's queued run verifies this commit's changes\r\n" "$FIXTURE_MAIN_SHA"
          printf '2026-10-13T12:53:14.6527220Z superseded main commit: no capability group is dispatched\r\n'
        fi
        ;;
      702)
        printf '== job 702 Required verification (success) ==\r\n'
        if [ "$FIXTURE_MODE" = tested_tree ]; then
          printf '2026-10-13T12:59:00.0000000Z required verification: exact tested tree from PR #2703 run 13233 accepted\r\n'
        else
          printf '2026-10-13T12:59:00.0000000Z required verification: every selected capability group succeeded\r\n'
        fi
        ;;
      *) exit 2 ;;
    esac
    ;;
  codewire:logs:902)
    [ "$job" = 9022 ] || exit 2
    printf '== job 9022 Assemble and verify the unsigned four-target delivery (success) ==\r\n'
    if [ "$FIXTURE_MODE" = dry_run_superseded ]; then
      printf "2026-10-20T14:01:00.0000000Z main is now %s; the queued dry run of %s builds this commit's changes\r\n" \
        "$FIXTURE_MAIN_SHA" "$FIXTURE_MAIN_SHA"
    else
      printf '2026-10-20T14:01:00.0000000Z only a push to main can be superseded; this run builds\r\n'
      printf '2026-10-20T14:20:00.0000000Z cw-release: verified targets=4 version=v0.0.0 runtime_equal=true signed=false\r\n'
    fi
    ;;
  deploy:list:)
    run_status=success
    [ "$FIXTURE_MODE" != failed_dev ] || run_status=failure
    printf '{"schema_version":1,"total_count":1,"runs":[{"id":801,"head_sha":"%040d","workflow":"promote-dev.yaml","status":"%s","event":"","ref":"main"}]}' \
      9 "$run_status"
    ;;
  deploy:view:801)
    printf '{"schema_version":1,"run":{"id":801,"workflow":"promote-dev.yaml","status":"%s","event":"","ref":"main"},"jobs":[{"id":811,"name":"Commit one complete dev release","status":"success","attempt":1},{"id":812,"name":"Verify the exact promoted dev commit","status":"success","attempt":1},{"id":813,"name":"Run exact-source Dev acceptance smokes","status":"%s","attempt":1}]}' \
      "$dev_status" "$dev_status"
    ;;
  deploy:logs:801)
    case "$job" in 811|813) ;; *) exit 2 ;; esac
    printf '== job %s ==\r\n2026-09-27T16:51:42.6844462Z Checked out exact Codewire source %s\r\n' "$job" "$dev_source"
    # Real job logs are far larger than a pipe buffer after the matched
    # line; an early-exiting matcher must not turn that into a failure.
    awk 'BEGIN { for (i = 0; i < 100000; i++) print "2026-09-27T16:51:43.0000000Z filler line that keeps the job log larger than a pipe buffer\r" }'
    ;;
  *) echo "unexpected fj request: $repo $verb $target" >&2; exit 2 ;;
esac
EOF

# The receipt must not depend on the legacy tea CLI.
cat >"$mock_bin/tea" <<'EOF'
#!/usr/bin/env bash
echo "tea must not be used" >&2
exit 99
EOF

chmod +x "$mock_bin/git" "$mock_bin/fj" "$mock_bin/tea"

# run_case NAME MODE TAG EXPECTED_RECEIPT EXPECTED_REASON
run_case() {
  local name="$1" mode="$2" tag="$3" expected="$4" reason="$5"
  local output tag_object tag_commit
  tag_object="$(git -C "$repo" rev-parse "refs/tags/$tag")"
  tag_commit="$(git -C "$repo" rev-parse "refs/tags/$tag^{commit}")"
  output="$(cd "$repo" && env \
    PATH="$mock_bin:$PATH" \
    REAL_GIT="$real_git" \
    FIXTURE_MODE="$mode" \
    FIXTURE_MAIN_SHA="$main_sha" \
    FIXTURE_TAG_COMMIT="$tag_commit" \
    PREFLIGHT_RELEASE_TAG_REF="refs/tags/$tag" \
    PREFLIGHT_RELEASE_TAG_OBJECT_SHA="$tag_object" \
    PREFLIGHT_PUSH_REMOTE_NAME=origin \
    GITHUB_SERVER_URL="${CASE_SERVER_URL-https://git.example.invalid/}" \
    "$CHECK" 2>&1)" || fail "$name checker returned failure"
  case_output="$output"
  if grep -Fq 'tea must not be used' <<<"$output"; then
    printf '%s\n' "$output" >&2
    fail "$name invoked the legacy tea CLI"
  fi
  if ! grep -Fxq "release_tag_receipt=$expected" <<<"$output" \
      || ! grep -Fxq "release_tag_reason=$reason" <<<"$output"; then
    printf '%s\n' "$output" >&2
    fail "$name expected $expected ($reason)"
  fi
}

# The tag at canonical main, as before.
run_case accepted success v1.2.3 accepted signed-tag-at-exact-green-deployed-main
run_case bad_signature bad_signature v1.2.3 fallback release-tag-signature-invalid
run_case wrong_remote wrong_remote v1.2.3 fallback push-remote-not-canonical-gitea
CASE_SERVER_URL='' run_case no_server_url success v1.2.3 fallback GITHUB_SERVER_URL-unset-or-invalid
CASE_SERVER_URL='https://other.example.invalid' \
  run_case other_server success v1.2.3 fallback push-remote-not-canonical-gitea
run_case api_unavailable api_unavailable v1.2.3 fallback exact-main-runs-unavailable
run_case failed_ci failed_ci v1.2.3 fallback exact-main-ci-not-successful
run_case failed_required failed_required v1.2.3 fallback required-verification-not-successful
run_case failed_dev failed_dev v1.2.3 fallback exact-source-dev-acceptance-not-successful
run_case wrong_dev_source wrong_dev_source v1.2.3 fallback exact-source-dev-acceptance-not-successful
# Main moved on: the tag names an ancestor of canonical main with its own
# exact, verified CI and Dev acceptance.
run_case ancestor_full success v1.2.2 accepted signed-tag-on-main-at-exact-green-deployed-commit
run_case ancestor_tested_tree tested_tree v1.2.2 accepted signed-tag-on-main-at-exact-green-deployed-commit
run_case ancestor_superseded superseded v1.2.2 fallback exact-main-ci-superseded
run_case ancestor_dispatched_nothing dispatched_nothing v1.2.2 fallback exact-main-ci-verified-nothing
run_case ancestor_selection_unreadable selection_log_unavailable v1.2.2 fallback exact-main-selection-unavailable
run_case ancestor_wrong_dev_source wrong_dev_source v1.2.2 fallback exact-source-dev-acceptance-not-successful
# The tip's superseded run is refused too, and a commit main never contained
# is refused before any CI is read.
run_case main_superseded superseded v1.2.3 fallback exact-main-ci-superseded
run_case not_on_main success v1.2.4 fallback release-tag-not-on-canonical-main
# Canonical main this checkout does not have (and cannot fetch) is unproven.
run_case stale_main stale_main v1.2.2 fallback canonical-main-commit-unavailable

# Kind and the release dry run of the exact commit (owner decision
# 2026-10-20). A push to main defers both, so a scheduled or dispatched run
# must have run them green. The accepted cases above took Kind from scheduled
# run 711 and the dry run from dispatched run 902, and name both runs.
run_case accepted_names_runs success v1.2.3 accepted signed-tag-at-exact-green-deployed-main
for expected in release_tag_run=701 release_tag_kind_run=711 release_tag_dry_run=902 \
    release_tag_dev_acceptance_run=801; do
  grep -Fxq "$expected" <<<"$case_output" || fail "accepted receipt does not report $expected"
done
grep -Fq '(CI run 701; Kind run 711; dry run 902; Dev acceptance run 801)' <<<"$case_output" \
  || fail 'accepted receipt message does not name the Kind and dry runs'
run_case kind_from_dispatch kind_from_dispatch v1.2.3 accepted signed-tag-at-exact-green-deployed-main
grep -Fxq release_tag_kind_run=721 <<<"$case_output" || fail 'dispatched Kind run was not reported'
run_case no_kind_run no_kind_run v1.2.3 fallback exact-commit-kind-not-verified
run_case kind_shard_failed kind_shard_failed v1.2.3 fallback exact-commit-kind-not-verified
run_case kind_run_failed kind_run_failed v1.2.3 fallback exact-commit-kind-not-verified
run_case kind_shards_skipped kind_shards_skipped v1.2.3 fallback exact-commit-kind-not-verified
run_case ancestor_no_kind_run no_kind_run v1.2.2 fallback exact-commit-kind-not-verified
run_case no_dry_run no_dry_run v1.2.3 fallback exact-commit-dry-run-not-verified
run_case dry_run_superseded dry_run_superseded v1.2.3 fallback exact-commit-dry-run-not-verified
run_case dry_runs_unavailable dry_runs_unavailable v1.2.3 fallback exact-commit-dry-runs-unavailable
# A scheduled run, which Forgejo lists with event push, is never taken for
# the push run: a failed push run stays failed behind a green schedule.
run_case scheduled_masks_failed_push scheduled_masks_failed_push v1.2.3 fallback exact-main-ci-not-successful

if grep -qF "tags: ['v*']" "$ROOT/.gitea/workflows/ci.yaml"; then
  fail 'generic CI still runs redundantly for release tags'
fi

echo 'release tag tested-tree receipt fixtures: green'
