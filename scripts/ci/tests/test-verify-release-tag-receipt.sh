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

cat >"$mock_bin/tea" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=''
endpoint=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --login|--remote) shift 2 ;;
    api) shift ;;
    /repos/*) endpoint="$1"; shift ;;
    *) echo "unexpected tea argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$output" ] && [ -n "$endpoint" ]
[ "${FIXTURE_MODE:?}" != api_unavailable ] || exit 1
case "$endpoint" in
  *'/actions/runs?event=push&'*)
    conclusion=success
    [ "$FIXTURE_MODE" != failed_ci ] || conclusion=failure
    printf '{"workflow_runs":[{"id":701,"path":"ci.yaml@refs/heads/main","event":"push","run_attempt":1,"head_sha":"%s","status":"completed","conclusion":"%s"}],"total_count":1}' \
      "$FIXTURE_MAIN_SHA" "$conclusion" >"$output"
    ;;
  *'/actions/runs?event=workflow_dispatch&'*)
    conclusion=success
    [ "$FIXTURE_MODE" != failed_dev ] || conclusion=failure
    printf '{"workflow_runs":[{"id":703,"path":"dev-deployment-smoke-receipt.yaml@refs/heads/main","event":"workflow_dispatch","run_attempt":1,"head_sha":"%s","status":"completed","conclusion":"%s","actor":{"login":"codewire-deploy-smoke"}}],"total_count":1}' \
      "$FIXTURE_MAIN_SHA" "$conclusion" >"$output"
    ;;
  */actions/runs/701/jobs\?*)
    conclusion=success
    [ "$FIXTURE_MODE" != failed_required ] || conclusion=failure
    printf '{"jobs":[{"id":702,"name":"Required verification","run_attempt":1,"head_sha":"%s","status":"completed","conclusion":"%s"}],"total_count":1}' \
      "$FIXTURE_MAIN_SHA" "$conclusion" >"$output"
    ;;
  */actions/runs/703/jobs\?*)
    printf '{"jobs":[{"id":704,"name":"Record deploy-owned dev smoke result","run_attempt":1,"head_sha":"%s","status":"completed","conclusion":"success"}],"total_count":1}' \
      "$FIXTURE_MAIN_SHA" >"$output"
    ;;
  *) echo "unexpected endpoint: $endpoint" >&2; exit 2 ;;
esac
EOF
chmod +x "$mock_bin/git" "$mock_bin/tea"

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

if grep -qF "tags: ['v*']" "$ROOT/.gitea/workflows/ci.yaml"; then
  fail 'generic CI still runs redundantly for release tags'
fi

echo 'release tag tested-tree receipt fixtures: green'
