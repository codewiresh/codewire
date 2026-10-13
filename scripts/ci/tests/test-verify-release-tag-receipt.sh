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
repo=codewire; target=''; job=''; output=text
while [ "$#" -gt 0 ]; do
  case "$1" in
    -R) [ "$2" = origin ] || exit 2; shift 2 ;;
    -r) [ "$2" = codewire/deploy ] || exit 2; repo=deploy; shift 2 ;;
    -H) [ "$2" = git.example.invalid ] || exit 2; shift 2 ;;
    --head|--workflow|--event|--status|-L) shift 2 ;;
    --job) job="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    [0-9]*) target="$1"; shift ;;
    *) echo "unexpected fj argument: $1" >&2; exit 2 ;;
  esac
done
ci_status=success
[ "$FIXTURE_MODE" != failed_ci ] || ci_status=failure
required_status=success
[ "$FIXTURE_MODE" != failed_required ] || required_status=failure
dev_status=success
[ "$FIXTURE_MODE" != failed_dev ] || dev_status=failure
dev_source="$FIXTURE_TAG_COMMIT"
[ "$FIXTURE_MODE" != wrong_dev_source ] || dev_source="$(printf '%040d' 7)"
# A superseded run, or one that reused a tested tree, dispatches no group.
group_status=success
case "$FIXTURE_MODE" in superseded|dispatched_nothing|tested_tree) group_status=skipped ;; esac
case "$repo:$verb:$target" in
  codewire:list:)
    [ "$output" = json ]
    printf '{"schema_version":1,"total_count":1,"runs":[{"id":701,"head_sha":"%s","workflow":"ci.yaml","status":"%s","event":"push","ref":"main"}]}' \
      "$FIXTURE_TAG_COMMIT" "$ci_status"
    ;;
  codewire:view:701)
    printf '{"schema_version":1,"run":{"id":701,"head_sha":"%s","workflow":"ci.yaml","status":"%s","event":"push","ref":"main"},"jobs":[{"id":703,"run_id":701,"name":"Verification selection","status":"success","attempt":1},{"id":704,"run_id":701,"name":"Policy verification","status":"%s","attempt":1},{"id":705,"run_id":701,"name":"Workspace cache experiment (cold)","status":"success","attempt":1},{"id":702,"run_id":701,"name":"Required verification","status":"%s","attempt":1}]}' \
      "$FIXTURE_TAG_COMMIT" "$ci_status" "$group_status" "$required_status"
    ;;
  codewire:logs:701)
    case "$job" in
      703)
        [ "$FIXTURE_MODE" != selection_log_unavailable ] || exit 1
        printf '== job 703 Verification selection (success) ==\r\n'
        printf '2026-10-13T12:53:12.0000000Z selection=|valid:v3|policy|complete|\r\n'
        if [ "$FIXTURE_MODE" = superseded ]; then
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
    "$CHECK" 2>&1)" || fail "$name checker returned failure"
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

if grep -qF "tags: ['v*']" "$ROOT/.gitea/workflows/ci.yaml"; then
  fail 'generic CI still runs redundantly for release tags'
fi

echo 'release tag tested-tree receipt fixtures: green'
