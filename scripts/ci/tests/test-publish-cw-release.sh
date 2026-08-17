#!/usr/bin/env bash
# shellcheck disable=SC2016 # The injected curl function expands in the fixture process.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PUBLISH_SOURCE="$ROOT/scripts/ci/release/publish-cw-release.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/publish-cw-release.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

expected_object='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
expected_target='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
mkdir "$TMP/assets" "$TMP/bin"
printf 'fixture release asset\n' >"$TMP/assets/cw-v9.9.9-x86_64-unknown-linux-musl"
printf 'fixture-github\n' >"$TMP/github-token"
chmod 0600 "$TMP/github-token"

cat >"$TMP/bin/mirror-canonical-tag" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 3 ]]
[[ "$1" == origin ]]
[[ "$2" == https://github.com/codewiresh/codewire.git ]]
[[ "$3" == refs/tags/v9.9.9 ]]
[[ "${GIT_CONFIG_NOSYSTEM:-}" == 1 ]]
[[ -f "${GIT_CONFIG_GLOBAL:?}" ]]
[[ "$(stat -c '%a' "$GIT_CONFIG_GLOBAL")" == 600 ]]
grep -Fq '[http "https://github.com/"]' "$GIT_CONFIG_GLOBAL"
grep -Fq 'extraHeader = Authorization: Basic ' "$GIT_CONFIG_GLOBAL"
printf '%s\n' "$*" >"${FIXTURE_MIRROR_LOG:?}"
SH
chmod +x "$TMP/bin/mirror-canonical-tag"

cat >"$TMP/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
output=''
url=''
[ -z "${FIXTURE_CURL_ARG_LOG:-}" ] || printf '%q ' "$@" >>"$FIXTURE_CURL_ARG_LOG"
[ -z "${FIXTURE_CURL_ARG_LOG:-}" ] || printf '\n' >>"$FIXTURE_CURL_ARG_LOG"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config)
      [ -f "$2" ]
      [ "$(stat -c '%a' -- "$2")" = 600 ]
      grep -Fq 'header = "Authorization: Bearer fixture-github"' "$2"
      shift 2
      ;;
    -o)
      output="$2"
      shift 2
      ;;
    -w)
      shift 2
      ;;
    -X|-H|-F|--data-binary)
      shift 2
      ;;
    -*)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done
[ -n "$url" ]
[ -z "${FIXTURE_CURL_LOG:-}" ] || printf '%s\n' "$url" >>"$FIXTURE_CURL_LOG"
status=200
case "$url" in
  */api/v1/repos/codewire/codewire/releases/tags/*)
    body='{"id":1}'
    ;;
  */api/v1/repos/codewire/codewire/releases/1/assets)
    body='[]'
    ;;
  */api/v1/repos/codewire/codewire/releases/1/assets?name=*)
    status=201
    body='{}'
    ;;
  https://api.github.com/repos/codewiresh/codewire/git/ref/tags/*)
    body="{\"object\":{\"type\":\"$FIXTURE_REF_TYPE\",\"sha\":\"$FIXTURE_REF_SHA\"}}"
    ;;
  https://api.github.com/repos/codewiresh/codewire/git/tags/*)
    body="{\"object\":{\"type\":\"$FIXTURE_TARGET_TYPE\",\"sha\":\"$FIXTURE_TARGET_SHA\"}}"
    ;;
  https://api.github.com/repos/codewiresh/codewire/releases/tags/*)
    body='{"id":2}'
    ;;
  https://api.github.com/repos/codewiresh/codewire/releases/2/assets)
    body='[]'
    ;;
  https://uploads.github.com/repos/codewiresh/codewire/releases/2/assets?name=*)
    status=201
    body='{}'
    ;;
  *)
    status=500
    body='{"error":"unexpected fixture URL"}'
    ;;
esac
if [ -n "$output" ]; then
  printf '%s' "$body" >"$output"
  printf '%s' "$status"
else
  printf '%s' "$body"
fi
SH

PUBLISH="$TMP/publish-cw-release.sh"
{
  head -n 1 "$PUBLISH_SOURCE"
  printf '%s\n' 'curl() { bash "$FIXTURE_CURL" "$@"; }'
  tail -n +2 "$PUBLISH_SOURCE"
} >"$PUBLISH"

run_publish() {
  FIXTURE_CURL="$TMP/bin/curl" \
    GITEA_TOKEN=fixture-gitea \
    GITHUB_SERVER_URL=https://git.example.invalid \
    GITHUB_REPOSITORY=codewire/codewire \
    GH_MIRROR_TOKEN_FILE="$TMP/github-token" \
    MIRROR_CANONICAL_TAG_BIN="$TMP/bin/mirror-canonical-tag" \
    FIXTURE_MIRROR_LOG="$TMP/mirror.log" \
    CW_REQUIRE_GITHUB_MIRROR=1 \
    CW_RELEASE_SOURCE_SHA="$expected_target" \
    CW_RELEASE_TAG_OBJECT_SHA="$expected_object" \
    bash "$PUBLISH" v9.9.9 "$TMP/assets"
}

expect_failure() {
  local name="$1"
  local pattern="$2"
  local ref_type="$3"
  local ref_sha="$4"
  local target_type="$5"
  local target_sha="$6"
  local output
  if output="$(
    FIXTURE_REF_TYPE="$ref_type" \
      FIXTURE_REF_SHA="$ref_sha" \
      FIXTURE_TARGET_TYPE="$target_type" \
      FIXTURE_TARGET_SHA="$target_sha" \
      run_publish 2>&1
  )"; then
    printf 'publish release test failed: %s unexpectedly passed\n' "$name" >&2
    exit 1
  fi
  grep -Fq "$pattern" <<<"$output" || {
    printf 'publish release test failed: %s lacked expected error\n%s\n' "$name" "$output" >&2
    exit 1
  }
}

direct_log="$TMP/direct-curl.log"
arg_log="$TMP/curl-args.log"
direct_output="$(
  FIXTURE_REF_TYPE=tag \
  FIXTURE_REF_SHA="$expected_object" \
  FIXTURE_TARGET_TYPE=commit \
  FIXTURE_TARGET_SHA="$expected_target" \
  FIXTURE_CURL_LOG="$direct_log" \
  FIXTURE_CURL_ARG_LOG="$arg_log" \
    run_publish
)"
grep -Fq 'publish-cw-release: Gitea release published' <<<"$direct_output"
grep -Fq 'publish-cw-release: mirroring canonical GitHub tag' <<<"$direct_output"
grep -Fq 'publish-cw-release: GitHub release published' <<<"$direct_output"
grep -Fxq 'origin https://github.com/codewiresh/codewire.git refs/tags/v9.9.9' \
  "$TMP/mirror.log"
grep -Fq 'https://git.example.invalid/api/v1/repos/codewire/codewire/releases/tags/v9.9.9' "$direct_log"
grep -Fq 'https://api.github.com/repos/codewiresh/codewire/releases/tags/v9.9.9' "$direct_log"
if grep -Fq 'fixture-github' "$arg_log"; then
  echo 'publish release test failed: GitHub token reached curl arguments' >&2
  exit 1
fi

chmod 0644 "$TMP/github-token"
if mode_output="$(
  FIXTURE_CURL="$TMP/bin/curl" \
    GITEA_TOKEN=fixture-gitea \
    GITHUB_SERVER_URL=https://git.example.invalid \
    GITHUB_REPOSITORY=codewire/codewire \
    GH_MIRROR_TOKEN_FILE="$TMP/github-token" \
    MIRROR_CANONICAL_TAG_BIN="$TMP/bin/mirror-canonical-tag" \
    FIXTURE_MIRROR_LOG="$TMP/mirror.log" \
    CW_REQUIRE_GITHUB_MIRROR=1 \
    CW_RELEASE_SOURCE_SHA="$expected_target" \
    CW_RELEASE_TAG_OBJECT_SHA="$expected_object" \
    bash "$PUBLISH" v9.9.9 "$TMP/assets" 2>&1
)"; then
  echo 'publish release test failed: insecure token file mode unexpectedly passed' >&2
  exit 1
fi
grep -Fq 'GH_MIRROR_TOKEN_FILE must have mode 0400 or 0600' <<<"$mode_output"
chmod 0600 "$TMP/github-token"

ln -s "$TMP/github-token" "$TMP/github-token-link"
if symlink_output="$(
  FIXTURE_CURL="$TMP/bin/curl" \
    GITEA_TOKEN=fixture-gitea \
    GITHUB_SERVER_URL=https://git.example.invalid \
    GITHUB_REPOSITORY=codewire/codewire \
    GH_MIRROR_TOKEN_FILE="$TMP/github-token-link" \
    MIRROR_CANONICAL_TAG_BIN="$TMP/bin/mirror-canonical-tag" \
    FIXTURE_MIRROR_LOG="$TMP/mirror.log" \
    CW_REQUIRE_GITHUB_MIRROR=1 \
    CW_RELEASE_SOURCE_SHA="$expected_target" \
    CW_RELEASE_TAG_OBJECT_SHA="$expected_object" \
    bash "$PUBLISH" v9.9.9 "$TMP/assets" 2>&1
)"; then
  echo 'publish release test failed: symlink token file unexpectedly passed' >&2
  exit 1
fi
grep -Fq 'GH_MIRROR_TOKEN_FILE must be one nonempty regular file' <<<"$symlink_output"

if required_output="$(
  FIXTURE_CURL="$TMP/bin/curl" \
    GITEA_TOKEN=fixture-gitea \
    GITHUB_SERVER_URL=https://git.example.invalid \
    GITHUB_REPOSITORY=codewire/codewire \
    GH_MIRROR_TOKEN=ignored-legacy-input \
    CW_REQUIRE_GITHUB_MIRROR=1 \
    bash "$PUBLISH" v9.9.9 "$TMP/assets" 2>&1
)"; then
  echo 'publish release test failed: required GitHub mirror unexpectedly passed' >&2
  exit 1
fi
grep -Fq 'GitHub mirror publication requires GH_MIRROR_TOKEN_FILE' \
  <<<"$required_output"

expect_failure flattened-tag 'is not an annotated tag object' \
  commit "$expected_target" commit "$expected_target"
expect_failure wrong-tag-object 'does not match canonical tag object' \
  tag cccccccccccccccccccccccccccccccccccccccc commit "$expected_target"
expect_failure wrong-tag-target 'does not peel to exact release source' \
  tag "$expected_object" commit dddddddddddddddddddddddddddddddddddddddd

echo 'publish cw release tests passed'
