#!/usr/bin/env bash
# Fixtures for find-pending-release.sh and require-current-release.sh: the
# release a scheduled deploy-prod or cli-release run delivers, once per tag,
# only a tag the release tagger signed in the last day; a dispatch's tag
# passed through; and the newest-release check before publication (#2892).
# The git repository and its tags are real; Forgejo's API and the Production
# gate are stand-ins.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/find-pending-release.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-find-pending-release] ERROR: %s\n' "$*" >&2
  exit 1
}

readonly TOKEN=forgejo-pending-token-canary-2c71
export GIT_CONFIG_GLOBAL="$TMP/gitconfig" GIT_CONFIG_NOSYSTEM=1
: >"$GIT_CONFIG_GLOBAL"
mkdir -p "$TMP/tree/scripts/ci/release" "$TMP/bin"
cp "$ROOT/scripts/ci/release/find-pending-release.sh" "$ROOT/scripts/ci/release/require-current-release.sh" \
  "$ROOT/scripts/ci/release/release-tags.sh" "$TMP/tree/scripts/ci/release/"
# The Production gate: FIXTURE_PRODUCTION=accepted or not.
cat >"$TMP/tree/scripts/ci/release/require-production-accepted.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FIXTURE_DIR/gate.log"
[ "$GITEA_TOKEN" = "$FIXTURE_TOKEN" ] || exit 9
[ "${FIXTURE_PRODUCTION:-accepted}" = accepted ]
EOF
chmod +x "$TMP/tree/scripts/ci/release/require-production-accepted.sh"

# origin, and the job's checkout of it.
git init -q --bare -b main "$TMP/origin.git"
work="$TMP/checkout"
git init -q -b main "$work"
git -C "$work" config user.name 'Release Tagger'
git -C "$work" config user.email tagger@example.invalid
git -C "$work" config commit.gpgsign false
git -C "$work" config tag.gpgSign false
git -C "$work" remote add origin "$TMP/origin.git"
git -C "$work" commit -q --allow-empty -m release
COMMIT="$(git -C "$work" rev-parse HEAD)"
readonly COMMIT
git -C "$work" push -q origin main
now="$(date +%s)"
# tag NAME AGE_SECONDS: an annotated tag signed AGE_SECONDS ago, on origin.
tag() {
  GIT_COMMITTER_DATE="@$((now - $2)) +0000" git -C "$work" tag -a -m "$1" "$1" "$COMMIT"
  git -C "$work" push -q origin "refs/tags/$1"
}
untag() {
  git -C "$work" push -q origin ":refs/tags/$1"
  git -C "$work" tag -d "$1" >/dev/null
}

# Forgejo's API. git/tags/<object> answers from the real tag object, verified
# as the tagger's own signature unless FIXTURE_UNSIGNED (the commit's
# verification, as Forgejo reports for a tag without a signature) or
# FIXTURE_FOREIGN (another account's key) names it; FIXTURE_UNVERIFIED (a
# signature Forgejo did not verify), FIXTURE_RENAMED (an answer for another
# tag name) and FIXTURE_REOBJECTED (an answer for another tag object) change
# one more fact of the named tag's answer. The commit's statuses are
# FIXTURE_STATUS_PAGES pages of CI statuses, then the pickup markers:
# FIXTURE_MARKERS (a JSON array) or one FIXTURE_MARKER context, pending and
# naming run 4070 unless FIXTURE_MARKER_STATE or FIXTURE_MARKER_DESCRIPTION
# say otherwise. A run's jobs are FIXTURE_RUN_JOBS ("ID:status,status;..."),
# answered with FIXTURE_JOBS_STATUS.
cat >"$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FIXTURE_DIR/curl-argv.log"
[ "$1" = --disable ] || exit 95
method=GET output='' body='' url='' config=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config="$2"; shift 2 ;;
    --request) method="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --data-binary) body="$2"; shift 2 ;;
    --header|--proto|--connect-timeout|--max-time|--write-out) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
[ "$config" = - ] || exit 94
grep -Fqx "header = \"Authorization: token $FIXTURE_TOKEN\"" || exit 99
prefix='https://git.example.invalid/api/v1/repos/codewire/codewire/'
[[ "$url" == "$prefix"* ]] || exit 98
path="${url#"$prefix"}"
case "$method $path" in
  GET\ git/tags/*)
    object="${path#git/tags/}"
    [ "${FIXTURE_VERIFY_STATUS:-200}" = 200 ] || { printf '%s' "$FIXTURE_VERIFY_STATUS"; exit 0; }
    raw="$(git -C "$FIXTURE_ORIGIN" cat-file tag "$object")"
    name="$(awk '$1 == "tag" { print $2; exit }' <<<"$raw")"
    commit="$(awk '$1 == "object" { print $2; exit }' <<<"$raw")"
    seconds="$(awk '$1 == "tagger" { print $(NF - 1); exit }' <<<"$raw")"
    payload="$raw"$'\n' signer=release-tagger
    case " ${FIXTURE_UNSIGNED:-} " in *" $name "*) payload="tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904"$'\n' ;; esac
    case " ${FIXTURE_FOREIGN:-} " in *" $name "*) signer=someone-else ;; esac
    verified=true answer_name="$name" answer_object="$object"
    case " ${FIXTURE_UNVERIFIED:-} " in *" $name "*) verified=false ;; esac
    case " ${FIXTURE_RENAMED:-} " in *" $name "*) answer_name=v0.0.1 ;; esac
    case " ${FIXTURE_REOBJECTED:-} " in *" $name "*) answer_object=5555555555555555555555555555555555555555 ;; esac
    jq -n --arg name "$answer_name" --arg object "$answer_object" --arg commit "$commit" --arg payload "$payload" \
      --arg signer "$signer" --argjson verified "$verified" \
      --arg date "$(date -u -d "@$seconds" +%Y-%m-%dT%H:%M:%SZ)" '
      {tag: $name, sha: $object, object: {type: "commit", sha: $commit}, tagger: {date: $date},
       verification: {verified: $verified, signer: {name: $signer}, payload: $payload}}' >"$output"
    ;;
  GET\ commits/*/statuses\?page=*\&limit=50)
    page="${path#*page=}" page="${page%%&*}"
    pages="${FIXTURE_STATUS_PAGES:-0}"
    if [ "$page" -le "$pages" ]; then
      jq -n --argjson page "$page" '[range(50) | {context: "CI / job \($page)-\(.)", state: "success"}]' >"$output"
    elif [ "$page" -eq "$((pages + 1))" ] && [ -n "${FIXTURE_MARKERS:-}" ]; then
      printf '%s' "$FIXTURE_MARKERS" >"$output"
    elif [ "$page" -eq "$((pages + 1))" ] && [ -n "${FIXTURE_MARKER:-}" ]; then
      jq -n --arg context "$FIXTURE_MARKER" --arg state "${FIXTURE_MARKER_STATE:-pending}" \
        --arg description "${FIXTURE_MARKER_DESCRIPTION:-picked up by run 70 (id 4070)}" \
        '[{id: 9001, context: $context, state: $state, description: $description}]' >"$output"
    else
      printf '[]' >"$output"
    fi
    ;;
  GET\ actions/runs/*/jobs\?page=1\&limit=100)
    run="${path#actions/runs/}" run="${run%%/*}"
    [ "${FIXTURE_JOBS_STATUS:-200}" = 200 ] || { printf '%s' "$FIXTURE_JOBS_STATUS"; exit 0; }
    statuses="$(tr ';' '\n' <<<"${FIXTURE_RUN_JOBS:-}" | awk -F: -v run="$run" '$1 == run { print $2 }')"
    jq -n --arg statuses "$statuses" '($statuses | split(",") | map(select(. != ""))) as $s |
      {total_count: ($s | length), jobs: [$s | to_entries[] | {id: .key, status: .value}]}' >"$output"
    ;;
  POST\ statuses/*)
    printf '%s %s\n' "${path#statuses/}" "$body" >>"$FIXTURE_DIR/marks.log"
    [ "${FIXTURE_MARK_STATUS:-201}" = 201 ] || { printf '%s' "$FIXTURE_MARK_STATUS"; exit 0; }
    printf '{}' >"$output"
    printf 201
    exit 0
    ;;
  *) exit 97 ;;
esac
printf 200
EOF
chmod +x "$TMP/bin/curl"

fixture="$TMP/fixture"
run_env() {
  env PATH="$TMP/bin:$PATH" GITHUB_SERVER_URL=https://git.example.invalid/ GITEA_TOKEN="$TOKEN" \
    CODEWIRE_RELEASE_TAGGER=release-tagger GITHUB_RUN_NUMBER=77 GITHUB_RUN_ID=4077 RUNNER_TEMP="$TMP" \
    FIXTURE_TOKEN="$TOKEN" FIXTURE_DIR="$fixture" FIXTURE_ORIGIN="$TMP/origin.git" "$@"
}
# find_release NAME WORKFLOW EVENT: run the finder in the checkout; its output
# is $fixture/NAME.out and its GITHUB_OUTPUT $fixture/NAME.github.
find_release() {
  local name="$1" workflow="$2" event="$3"
  rm -rf "$fixture"
  mkdir -p "$fixture"
  : >"$fixture/$name.github"
  (cd "$work" && run_env GITHUB_EVENT_NAME="$event" GITHUB_OUTPUT="$fixture/$name.github" \
    "$TMP/tree/scripts/ci/release/find-pending-release.sh" "$workflow") >"$fixture/$name.out" 2>&1
}
output_is() { # NAME EXPECTED...: the run's GITHUB_OUTPUT, exactly
  local name="$1"
  shift
  [ "$(cat "$fixture/$name.github")" = "$(printf '%s\n' "$@")" ] ||
    fail "$name output: $(cat "$fixture/$name.github") ($(cat "$fixture/$name.out"))"
  if grep -rFq "$TOKEN" "$fixture"; then fail "$name leaked the token"; fi
}
marked() { # NAME STATE CONTEXT
  grep -Fq "\"state\":\"$2\",\"context\":\"$3\"" "$fixture/marks.log" ||
    fail "$1 did not mark $3 $2: $(cat "$fixture/marks.log" 2>/dev/null)"
}
unmarked() { [ ! -e "$fixture/marks.log" ] || fail "$1 marked a tag: $(cat "$fixture/marks.log")"; }

# --- dispatch ----------------------------------------------------------------
# A dispatch delivers its tag whether or not it can record itself: here the
# tag is not on origin yet, so nothing is marked.
DISPATCHED_TAG=v0.4.0 find_release dispatch deploy-prod workflow_dispatch || fail "dispatch: $(cat "$fixture/dispatch.out")"
output_is dispatch release_tag=v0.4.0
unmarked dispatch
grep -Fq 'notice: this dispatch was not recorded' "$fixture/dispatch.out" || fail "an unrecorded dispatch was silent: $(cat "$fixture/dispatch.out")"
DISPATCHED_TAG=v0.4.0 DISPATCHED_R2_PUBLICATION=immutable DISPATCHED_R2_PROMOTE_CHANNEL=none \
  find_release dispatch-cli cli-release workflow_dispatch || fail "cli dispatch: $(cat "$fixture/dispatch-cli.out")"
output_is dispatch-cli release_tag=v0.4.0 r2_publication=immutable r2_promote_channel=none
for bad in 'DISPATCHED_TAG=v0.4.0;x' 'DISPATCHED_R2_PUBLICATION=stable' 'DISPATCHED_R2_PROMOTE_CHANNEL=beta'; do
  # shellcheck disable=SC2163 # Each case names one variable to set.
  if (export DISPATCHED_TAG=v0.4.0 "$bad"; find_release dispatch-bad cli-release workflow_dispatch); then
    fail "the dispatch input $bad was accepted"
  fi
  [ ! -s "$fixture/dispatch-bad.github" ] || fail "the dispatch input $bad reached the output"
done

# --- schedule ----------------------------------------------------------------
# No release tag at all is nothing to do.
find_release none deploy-prod schedule || fail "none: $(cat "$fixture/none.out")"
output_is none release_tag=
# An old release (released by dispatch) is never picked up by the schedule.
tag v0.4.0 $((3 * 86400))
find_release old deploy-prod schedule || fail "old: $(cat "$fixture/old.out")"
output_is old release_tag=
unmarked old
grep -Fq 'signed more than 24 hours ago' "$fixture/old.out" || fail 'an old tag was not reported as old'
# A newly signed next release is picked up once, marking its commit.
tag v0.4.1 600
find_release pick deploy-prod schedule || fail "pick: $(cat "$fixture/pick.out")"
output_is pick release_tag=v0.4.1
marked pick pending 'release/deploy-prod v0.4.1'
grep -Fq '"description":"picked up by run 77 (id 4077)"' "$fixture/marks.log" || fail "the pickup did not name its run: $(cat "$fixture/marks.log")"
grep -Fq "\"target_url\":\"https://git.example.invalid/codewire/codewire/actions/runs/77\"" "$fixture/marks.log" ||
  fail 'the pickup does not link its run'
# Once marked, it is not picked up again, wherever the marker is listed.
FIXTURE_MARKER='release/deploy-prod v0.4.1' FIXTURE_STATUS_PAGES=3 find_release picked deploy-prod schedule ||
  fail "picked: $(cat "$fixture/picked.out")"
output_is picked release_tag=
unmarked picked
# The newest marker's run decides: still delivering or delivered is quiet;
# cancelled or failed fails the run loudly, naming the recovery dispatch.
for case in 'running 0 success,running,blocked' 'delivered 0 success,skipped,success' \
    'cancelled 1 success,cancelled,cancelled' 'failed 1 success,failure,skipped'; do
  read -r name code jobs <<<"$case"
  rc=0
  FIXTURE_MARKER='release/deploy-prod v0.4.1' FIXTURE_RUN_JOBS="4070:$jobs" find_release "run-$name" deploy-prod schedule || rc=$?
  [ "$rc" = "$code" ] || fail "run $name exited $rc, not $code: $(cat "$fixture/run-$name.out")"
  output_is "run-$name" release_tag=
  unmarked "run-$name"
done
grep -Fxq '::error::v0.4.1 was picked up by deploy-prod, whose run ended without delivering it (picked up by run 70 (id 4070)); recover it with a dispatch of deploy-prod.yaml on main with release_tag=v0.4.1' \
  "$fixture/run-failed.out" || fail "a stopped delivery did not name its recovery: $(cat "$fixture/run-failed.out")"
# cli-release's recovery also names its public publication.
rc=0
FIXTURE_MARKER='release/cli-release v0.4.1' FIXTURE_RUN_JOBS='4070:success,cancelled' find_release run-cli cli-release schedule || rc=$?
[ "$rc" = 1 ] || fail "a stopped cli-release exited $rc, not 1: $(cat "$fixture/run-cli.out")"
grep -Fq 'recover it with a dispatch of cli-release.yaml on main with release_tag=v0.4.1 r2_publication=immutable r2_promote_channel=stable' \
  "$fixture/run-cli.out" || fail "a stopped cli-release did not name its whole recovery: $(cat "$fixture/run-cli.out")"
# A run whose jobs cannot be read, a marker from before markers named their
# run, and a refusal are quiet; the next tick looks again.
FIXTURE_MARKER='release/deploy-prod v0.4.1' FIXTURE_JOBS_STATUS=500 find_release run-unreadable deploy-prod schedule ||
  fail "unreadable run: $(cat "$fixture/run-unreadable.out")"
output_is run-unreadable release_tag=
FIXTURE_MARKER='release/deploy-prod v0.4.1' FIXTURE_MARKER_DESCRIPTION='picked up by run 70' FIXTURE_RUN_JOBS='4070:cancelled' \
  find_release run-legacy deploy-prod schedule || fail "legacy marker: $(cat "$fixture/run-legacy.out")"
output_is run-legacy release_tag=
FIXTURE_MARKER='release/deploy-prod v0.4.1' FIXTURE_MARKER_STATE=failure FIXTURE_RUN_JOBS='4070:failure' \
  find_release run-refused deploy-prod schedule || fail "refused marker: $(cat "$fixture/run-refused.out")"
output_is run-refused release_tag=
# A newer marker (a recovery dispatch) supersedes the run it recovers, in
# whatever order Forgejo lists them.
markers='[{"id": 9002, "context": "release/deploy-prod v0.4.1", "state": "pending", "description": "delivered by dispatch run 80 (id 4080)"},
  {"id": 9001, "context": "release/deploy-prod v0.4.1", "state": "pending", "description": "picked up by run 70 (id 4070)"}]'
for case in 'recovering 0 4080:running' 'recovered 0 4080:success' 'recovery-failed 1 4080:failure'; do
  read -r name code jobs <<<"$case"
  rc=0
  FIXTURE_MARKERS="$markers" FIXTURE_RUN_JOBS="4070:cancelled;$jobs" find_release "$name" deploy-prod schedule || rc=$?
  [ "$rc" = "$code" ] || fail "$name exited $rc, not $code: $(cat "$fixture/$name.out")"
done
grep -Fq '(delivered by dispatch run 80 (id 4080))' "$fixture/recovery-failed.out" || fail 'a failed recovery was not the run reported'
# A dispatch of a tag on origin records itself, naming its run; a dispatch
# whose record cannot be written still delivers.
DISPATCHED_TAG=v0.4.1 find_release dispatch-marks deploy-prod workflow_dispatch || fail "dispatch marks: $(cat "$fixture/dispatch-marks.out")"
output_is dispatch-marks release_tag=v0.4.1
marked dispatch-marks pending 'release/deploy-prod v0.4.1'
grep -Fq '"description":"delivered by dispatch run 77 (id 4077)"' "$fixture/marks.log" || fail "the dispatch did not name its run: $(cat "$fixture/marks.log")"
FIXTURE_MARK_STATUS=403 DISPATCHED_TAG=v0.4.1 find_release dispatch-unmarked deploy-prod workflow_dispatch ||
  fail "a dispatch failed on its record: $(cat "$fixture/dispatch-unmarked.out")"
output_is dispatch-unmarked release_tag=v0.4.1
# Another workflow's marker does not count.
FIXTURE_MARKER='release/cli-release v0.4.1' find_release other-marker deploy-prod schedule ||
  fail "other marker: $(cat "$fixture/other-marker.out")"
output_is other-marker release_tag=v0.4.1
# Tags the release tagger did not sign are ignored: they neither block nor
# take a release, and are never marked.
tag v9.9.9 60
tag v0.4.2 120
FIXTURE_UNSIGNED='v9.9.9' FIXTURE_FOREIGN='v0.4.2' find_release bogus deploy-prod schedule ||
  fail "bogus: $(cat "$fixture/bogus.out")"
output_is bogus release_tag=v0.4.1
grep -Fq 'ignored: v9.9.9 is not signed by the release tagger' "$fixture/bogus.out" || fail 'an unsigned tag was not ignored'
grep -Fq 'ignored: v0.4.2 is not signed by the release tagger' "$fixture/bogus.out" || fail "another account's tag was not ignored"
grep -q 'v9.9.9\|v0.4.2' "$fixture/marks.log" && fail 'an unsigned tag was marked'
untag v9.9.9
# A signature Forgejo did not verify, or an answer about another tag name or
# tag object, is no signature of this tag.
for fact in FIXTURE_UNVERIFIED FIXTURE_RENAMED FIXTURE_REOBJECTED; do
  # shellcheck disable=SC2163 # Each case names one variable to set.
  (export "$fact=v0.4.2"; find_release "$fact" deploy-prod schedule) || fail "$fact: $(cat "$fixture/$fact.out")"
  output_is "$fact" release_tag=v0.4.1
  grep -Fq 'ignored: v0.4.2 is not signed by the release tagger' "$fixture/$fact.out" ||
    fail "$fact: the tag was not ignored: $(cat "$fixture/$fact.out")"
done
untag v0.4.2
# The window is 24 hours from the tagger's signing: just inside is picked up,
# just outside is left to the owner's dispatch. A tagger clock ahead only
# lengthens it, and only the tagger can sign such a tag.
for case in 'inside 86340 v0.4.2' 'outside 86460 ' 'future -3600 v0.4.2'; do
  read -r name age expected <<<"$case"
  tag v0.4.2 "$age"
  find_release "window-$name" deploy-prod schedule || fail "window $name: $(cat "$fixture/window-$name.out")"
  output_is "window-$name" "release_tag=$expected"
  untag v0.4.2
done
# A signed tag that skips a version is refused once, visibly, and never
# released.
tag v0.4.3 60
find_release skip deploy-prod schedule || fail "skip: $(cat "$fixture/skip.out")"
output_is skip release_tag=
marked skip failure 'release/deploy-prod v0.4.3'
untag v0.4.3
for next in v0.5.0 v1.0.0; do
  tag "$next" 60
  find_release "next-$next" deploy-prod schedule || fail "next $next: $(cat "$fixture/next-$next.out")"
  output_is "next-$next" "release_tag=$next"
  untag "$next"
done
# The pickup marker is written before anything is released; when it cannot
# be, nothing is. Unreadable verification is a failure, not "unsigned".
if FIXTURE_MARK_STATUS=403 find_release unmarked deploy-prod schedule; then
  fail 'a release was picked up without its marker'
fi
grep -Fq 'release_tag=v0.4.1' "$fixture/unmarked.github" && fail 'an unmarked pickup named its release'
if FIXTURE_VERIFY_STATUS=500 find_release no-verify deploy-prod schedule; then
  fail 'unreadable verification was taken as no release'
fi
# cli-release follows Production: it picks up a tag only once Production
# accepted that tag object and commit, and then publishes and moves stable.
FIXTURE_PRODUCTION=not find_release cli-waits cli-release schedule || fail "cli waits: $(cat "$fixture/cli-waits.out")"
output_is cli-waits release_tag= r2_publication=none r2_promote_channel=none
unmarked cli-waits
find_release cli cli-release schedule || fail "cli: $(cat "$fixture/cli.out")"
output_is cli release_tag=v0.4.1 r2_publication=immutable r2_promote_channel=stable
grep -Fxq "v0.4.1 $(git -C "$work" rev-parse v0.4.1) $COMMIT" "$fixture/gate.log" ||
  fail "the Production gate was asked about: $(cat "$fixture/gate.log")"
marked cli pending 'release/cli-release v0.4.1'

# --- require-current-release.sh ---------------------------------------------
current() { # NAME TAG
  (cd "$work" && run_env "$TMP/tree/scripts/ci/release/require-current-release.sh" "$2") >"$fixture/$1.out" 2>&1
}
mkdir -p "$fixture"
current current v0.4.1 || fail "the newest release was refused: $(cat "$fixture/current.out")"
current older v0.4.0 && fail 'an older release passed as current'
grep -Fq 'v0.4.1, a newer release, exists' "$fixture/older.out" || fail "an older release was not named: $(cat "$fixture/older.out")"
tag v0.4.2 60
FIXTURE_UNSIGNED='v0.4.2' current unsigned-newer v0.4.1 || fail "an unsigned newer tag blocked the release: $(cat "$fixture/unsigned-newer.out")"
current signed-newer v0.4.1 && fail 'a release passed as current with a newer signed release on origin'
untag v0.4.2
current missing v0.4.9 && fail 'a tag missing from origin passed as current'

echo 'find-pending-release fixtures: green'
