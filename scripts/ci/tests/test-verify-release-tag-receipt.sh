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
printf 'release\n' >"$repo/product.txt"
git -C "$repo" add product.txt
git -C "$repo" -c commit.gpgsign=false commit -q -m release
main_sha="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" tag -a -m v1.2.3 v1.2.3
tag_object="$(git -C "$repo" rev-parse refs/tags/v1.2.3)"
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
dev_source="$FIXTURE_MAIN_SHA"
[ "$FIXTURE_MODE" != wrong_dev_source ] || dev_source="$(printf '%040d' 7)"
case "$repo:$verb:$target" in
  codewire:list:)
    [ "$output" = json ]
    printf '{"schema_version":1,"total_count":1,"runs":[{"id":701,"head_sha":"%s","workflow":"ci.yaml","status":"%s","event":"push","ref":"main"}]}' \
      "$FIXTURE_MAIN_SHA" "$ci_status"
    ;;
  codewire:view:701)
    printf '{"schema_version":1,"run":{"id":701,"head_sha":"%s","workflow":"ci.yaml","status":"%s","event":"push","ref":"main"},"jobs":[{"id":702,"run_id":701,"name":"Required verification","status":"%s","attempt":1}]}' \
      "$FIXTURE_MAIN_SHA" "$ci_status" "$required_status"
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

run_case() {
  local name="$1" mode="$2" expected="$3"
  local output
  output="$(cd "$repo" && env \
    PATH="$mock_bin:$PATH" \
    REAL_GIT="$real_git" \
    FIXTURE_MODE="$mode" \
    FIXTURE_MAIN_SHA="$main_sha" \
    PREFLIGHT_RELEASE_TAG_REF=refs/tags/v1.2.3 \
    PREFLIGHT_RELEASE_TAG_OBJECT_SHA="$tag_object" \
    PREFLIGHT_PUSH_REMOTE_NAME=origin \
    "$CHECK" 2>&1)" || fail "$name checker returned failure"
  if grep -Fq 'tea must not be used' <<<"$output"; then
    printf '%s\n' "$output" >&2
    fail "$name invoked the legacy tea CLI"
  fi
  grep -Fxq "release_tag_receipt=$expected" <<<"$output" || {
    printf '%s\n' "$output" >&2
    fail "$name expected $expected"
  }
}

run_case accepted success accepted
run_case bad_signature bad_signature fallback
run_case wrong_remote wrong_remote fallback
run_case stale_main stale_main fallback
run_case api_unavailable api_unavailable fallback
run_case failed_ci failed_ci fallback
run_case failed_required failed_required fallback
run_case failed_dev failed_dev fallback
run_case wrong_dev_source wrong_dev_source fallback

if grep -qF "tags: ['v*']" "$ROOT/.gitea/workflows/ci.yaml"; then
  fail 'generic CI still runs redundantly for release tags'
fi

echo 'release tag tested-tree receipt fixtures: green'
