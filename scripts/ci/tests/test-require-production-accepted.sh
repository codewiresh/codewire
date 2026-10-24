#!/usr/bin/env bash
# Fixtures for require-production-accepted.sh: a CLI release waits for a
# successful deploy-prod run that verified the same tag and commit and saw
# Production accept it (#2892).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHECK="$ROOT/scripts/ci/release/require-production-accepted.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/production-accepted.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-require-production-accepted] ERROR: %s\n' "$*" >&2
  exit 1
}

readonly TAG=v1.2.3
readonly SHA=1111111111111111111111111111111111111111
readonly OBJECT=3333333333333333333333333333333333333333
readonly OTHER_OBJECT=4444444444444444444444444444444444444444
readonly OTHER_SHA=2222222222222222222222222222222222222222
readonly TOKEN=forgejo-production-token-canary-81f2
mkdir -p "$TMP/bin"

# Forgejo's API for codewire/codewire. The tag was signed at 09:00, so runs
# are read back to 08:00 (an hour's slack for the tagger's clock). Run 500
# (10:00) is the release's deploy-prod run; FIXTURE_MODE changes one fact
# about it. Run 450 (09:30) is a scheduled tick that delivered nothing, and
# run 400 (the day before) an older release, read only if the reading does
# not stop at that time.
cat >"$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FIXTURE_ARGV_LOG"
[ "${1:-}" = --disable ] || exit 95
config='' output='' url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --proto|--connect-timeout|--max-time|--write-out) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
# The token arrives on stdin, never in a file.
[ "$config" = - ] || exit 94
grep -Fqx "header = \"Authorization: token ${FIXTURE_TOKEN:?}\"" || exit 99
prefix='https://git.example.invalid/api/v1/repos/codewire/codewire/'
[[ "$url" == "$prefix"* ]] || exit 98
path="${url#"$prefix"}"
mode="${FIXTURE_MODE:?}"
printf '%s\n' "$path" >>"$FIXTURE_PATHS_LOG"
run() { # ID EVENT CREATED [REF [TRIGGER_EVENT]]
  printf '{"id":%s,"workflow_id":"deploy-prod.yaml","status":"success","event":"%s","created":"%s","prettyref":"%s","trigger_event":"%s","commit_sha":"%s"}' \
    "$1" "$2" "$3" "${4:-main}" "${5:-$2}" "$FIXTURE_MAIN_SHA"
}
release_created=2026-10-23T10:00:00Z
[ "$mode" != stale_run ] || release_created=2026-10-23T07:30:00Z
tagger_date=2026-10-23T11:00:00+02:00
# A tagger clock half an hour ahead of Forgejo's.
[ "$mode" != clock_ahead ] || tagger_date=2026-10-23T12:30:00+02:00
case "$path" in
  "git/tags/$FIXTURE_OBJECT")
    jq -n --arg date "$tagger_date" '{tagger: {date: $date}}' >"$output"
    ;;
  'actions/runs?workflow_id=deploy-prod.yaml&status=success&page=1&limit=50')
    [ "$mode" != runs_unavailable ] || { printf 500; exit 0; }
    runs="$(run 450 push 2026-10-23T09:30:00Z main schedule),$(run 400 workflow_dispatch 2026-10-22T10:00:00Z)"
    if [ "$mode" = second_page ]; then
      # Fifty later scheduled ticks fill the first page.
      runs="$(for id in $(seq 600 649); do
        [ "$id" = 600 ] || printf ,
        run "$id" push 2026-10-23T12:00:00Z main schedule
      done)"
    elif [ "$mode" = branch_run ]; then
      runs="$runs,$(run 500 workflow_dispatch "$release_created" feature)"
    elif [ "$mode" = scheduled_run ]; then
      # Forgejo lists a scheduled run with its registering push's event.
      runs="$runs,$(run 500 push "$release_created" main schedule)"
    elif [ "$mode" = push_run ]; then
      runs="$runs,$(run 500 push "$release_created" main push)"
    elif [ "$mode" != no_release_run ]; then
      runs="$runs,$(run 500 workflow_dispatch "$release_created")"
    fi
    printf '{"total_count":3,"workflow_runs":[%s]}' "$runs" >"$output"
    ;;
  'actions/runs?workflow_id=deploy-prod.yaml&status=success&page=2&limit=50')
    [ "$mode" = second_page ] || exit 96
    # A full page that reaches back before the tag: the reading stops here,
    # and a third page is never requested.
    printf '{"total_count":150,"workflow_runs":[%s,%s,%s]}' \
      "$(run 500 push "$release_created" main schedule)" "$(run 400 workflow_dispatch 2026-10-22T10:00:00Z)" \
      "$(for id in $(seq 300 347); do
        [ "$id" = 300 ] || printf ,
        run "$id" workflow_dispatch 2026-10-22T09:00:00Z
      done)" >"$output"
    ;;
  actions/runs/6[0-9][0-9]/jobs|actions/runs/450/jobs)
    id="${path#actions/runs/}" id="${id%/jobs}"
    printf '[{"id":%s1,"run_id":%s,"name":"Verify canonical release tag","status":"skipped","attempt":1}]' "$id" "$id" >"$output"
    ;;
  actions/runs/400/jobs|actions/runs/500/jobs)
    id="${path#actions/runs/}" id="${id%/jobs}"
    dispatch=success
    [ "$id:$mode" != 500:dispatch_failed ] || dispatch=failure
    delivering='Publish the release and deliver it to Production'
    [ "$id:$mode" != 500:built_pair ] ||
      delivering='Publish the built support pair and deliver the release to Production'
    [ "$id:$mode" != 500:before_collapse ] || delivering='Dispatch Signed Tag to Deploy'
    printf '[{"id":%s1,"run_id":%s,"name":"Verify canonical release tag","status":"success","attempt":1},{"id":%s2,"run_id":%s,"name":"'"$delivering"'","status":"%s","attempt":%s}]' \
      "$id" "$id" "$id" "$id" "$dispatch" "$([ "$mode" = rerun_dispatch ] && echo 2 || echo 1)" >"$output"
    ;;
  actions/jobs/*/logs\?attempt=*)
    job="${path#actions/jobs/}" job="${job%/logs*}" attempt="${path##*=}"
    run_id="${job%?}"
    tag="$FIXTURE_TAG" sha="$FIXTURE_SHA" object="$FIXTURE_OBJECT"
    [ "$run_id:$mode" != 500:other_object ] || object="$FIXTURE_OTHER_OBJECT"
    [ "$run_id" != 400 ] || tag=v1.2.2
    [ "$run_id:$mode" != 500:other_commit ] || sha="$FIXTURE_OTHER_SHA"
    [ "$run_id:$mode" != 500:other_tag ] || tag=v1.2.30
    case "$job" in
      *1)
        printf '2026-10-23T10:00:00.0000000Z release tag verified: tag=%s object=%s commit=%s forgejo_signer=noel\r\n' \
          "$tag" "$object" "$sha" >"$output"
        ;;
      *2)
        [ "$attempt" = "$([ "$mode" = rerun_dispatch ] && echo 2 || echo 1)" ] || exit 97
        if [ "$run_id:$mode" = 500:not_accepted ]; then
          printf '2026-10-23T10:05:00.0000000Z [dispatch-deploy-prod] accepted signed source tag %s as deploy run 9 / #9\r\n' "$tag" >"$output"
        else
          printf '2026-10-23T10:09:00.0000000Z [dispatch-deploy-prod] deploy run 9 succeeded: Production accepted %s\r\n' "$tag" >"$output"
        fi
        [ "$run_id:$mode" != 500:log_error ] || { printf 500; exit 0; }
        ;;
    esac
    ;;
  *) exit 98 ;;
esac
printf 200
EOF
chmod +x "$TMP/bin/curl"

argv_log="$TMP/argv.log"
# check_case NAME MODE EXPECT(accepted|refused) [MESSAGE]
check_case() {
  local name="$1" mode="$2" expect="$3" message="${4:-}" output status=0
  output="$(env PATH="$TMP/bin:$PATH" GITHUB_SERVER_URL=https://git.example.invalid/ \
    GITEA_TOKEN="$TOKEN" RUNNER_TEMP="$TMP" FIXTURE_TOKEN="$TOKEN" FIXTURE_MODE="$mode" \
    FIXTURE_ARGV_LOG="$argv_log" FIXTURE_TAG="$TAG" FIXTURE_SHA="$SHA" \
    FIXTURE_OTHER_SHA="$OTHER_SHA" FIXTURE_MAIN_SHA="$SHA" \
    FIXTURE_OBJECT="$OBJECT" FIXTURE_OTHER_OBJECT="$OTHER_OBJECT" FIXTURE_PATHS_LOG="$TMP/paths.log" \
    "$CHECK" "$TAG" "$OBJECT" "$SHA" 2>&1)" || status=$?
  if grep -Fq "$TOKEN" <<<"$output" || grep -Fq "$TOKEN" "$argv_log"; then
    fail "$name leaked the token"
  fi
  case "$expect" in
    accepted)
      [ "$status" = 0 ] || fail "$name was refused: $output"
      grep -Fq "$message" <<<"$output" || fail "$name: $output"
      ;;
    refused)
      [ "$status" != 0 ] || fail "$name was accepted: $output"
      grep -Fq "${message:-no successful deploy-prod run shows Production accepting $TAG}" <<<"$output" \
        || fail "$name: $output"
      ;;
  esac
}

check_case accepted success accepted "Production accepted $TAG ($SHA) in deploy-prod run 500"
check_case rerun_dispatch rerun_dispatch accepted "in deploy-prod run 500"
check_case built_pair built_pair accepted "in deploy-prod run 500"
# A scheduled release counts; a run of any other push does not.
check_case scheduled_run scheduled_run accepted "in deploy-prod run 500"
check_case push_run push_run refused
# The release run is found past a page of later scheduled ticks; a run from
# before the tag was signed is never its release, and the older release's run
# is never read.
: >"$TMP/paths.log"
check_case second_page second_page accepted "in deploy-prod run 500"
! grep -q 'page=3' "$TMP/paths.log" || fail 'the gate read past a page that reached before the tag'
check_case stale_run stale_run refused
check_case clock_ahead clock_ahead accepted "in deploy-prod run 500"
# A release delivered before the jobs were collapsed is still recognised.
check_case before_collapse before_collapse accepted "in deploy-prod run 500"
# Only the release's own run counts: an older release's run, or a scheduled
# run (listed with event push), does not.
: >"$TMP/paths.log"
check_case no_release_run no_release_run refused
! grep -q 'actions/runs/400/' "$TMP/paths.log" || fail 'the gate read a run from before the tag'
check_case other_commit other_commit refused
check_case other_tag other_tag refused
# A tag deleted and signed again on the same commit is another release.
check_case other_object other_object refused
# A run on any branch but main is not the release's.
check_case branch_run branch_run refused
# The dispatch must have seen Production accept the release, not only
# dispatched it, and must have succeeded.
check_case not_accepted not_accepted refused
check_case dispatch_failed dispatch_failed refused
check_case log_error log_error refused
check_case runs_unavailable runs_unavailable refused 'the deploy-prod runs are unavailable'

for args in "v1.2 $OBJECT $SHA" "$TAG $OBJECT not-a-sha" "$TAG not-an-object $SHA" "$TAG $SHA"; do
  # shellcheck disable=SC2086 # Each case is split into its arguments on purpose.
  if env GITHUB_SERVER_URL=https://git.example.invalid GITEA_TOKEN="$TOKEN" "$CHECK" $args >/dev/null 2>&1; then
    fail "invalid arguments were accepted: $args"
  fi
done
if env -u GITEA_TOKEN GITHUB_SERVER_URL=https://git.example.invalid "$CHECK" "$TAG" "$OBJECT" "$SHA" >/dev/null 2>&1; then
  fail 'the check ran without a token'
fi

# The check reads what deploy-prod writes: its two job names, the verifier's
# selection line and the dispatch's acceptance line.
workflow="$ROOT/.gitea/workflows/deploy-prod.yaml"
grep -Fxq '    name: Verify canonical release tag' "$workflow" || fail 'deploy-prod renamed its selection job'
grep -Fxq '    name: Publish the release and deliver it to Production' "$workflow" ||
  fail 'deploy-prod renamed its publishing job'
grep -Fxq '    name: Publish the built support pair and deliver the release to Production' "$workflow" ||
  fail 'deploy-prod renamed its built-pair finish'
grep -Fq "printf 'release tag verified: tag=%s object=%s commit=%s forgejo_signer=%s\\n'" \
  "$ROOT/scripts/ci/release/verify-release-tag-ref.sh" || fail 'the verifier changed its selection line'
grep -Fq "printf '[dispatch-deploy-prod] deploy run %s succeeded: Production accepted %s\\n'" \
  "$ROOT/scripts/ci/deploy/dispatch-deploy-prod.sh" || fail 'the dispatch changed its acceptance line'

echo 'require-production-accepted fixtures: green'
