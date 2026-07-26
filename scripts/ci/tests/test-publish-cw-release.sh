#!/usr/bin/env bash
# shellcheck disable=SC2016 # The injected curl function expands in the fixture process.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PUBLISH_SOURCE="$ROOT/scripts/ci/release/publish-cw-release.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

expected_object='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
expected_target='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
mkdir "$TMP/assets" "$TMP/bin"
printf 'fixture release asset\n' >"$TMP/assets/cw-v9.9.9-x86_64-unknown-linux-musl"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/mirror-app-key.pem" \
  >/dev/null 2>&1

cat >"$TMP/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
output=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
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
  https://api.github.com/app/installations/123/access_tokens)
    body='{"token":"fixture-github"}'
    ;;
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
    GH_MIRROR_TOKEN=fixture-github \
    CW_RELEASE_SOURCE_SHA="$expected_target" \
    CW_RELEASE_TAG_OBJECT_SHA="$expected_object" \
    bash "$PUBLISH" v9.9.9 "$TMP/assets"
}

run_publish_with_installation_token() {
  FIXTURE_CURL="$TMP/bin/curl" \
    GITEA_TOKEN=fixture-gitea \
    GITHUB_SERVER_URL=https://git.example.invalid \
    GITHUB_REPOSITORY=codewire/codewire \
    MIRROR_GITHUB_APP_ID=fixture-app \
    MIRROR_GITHUB_INSTALLATION_ID=123 \
    MIRROR_GITHUB_PRIVATE_KEY="$(<"$TMP/mirror-app-key.pem")" \
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
direct_output="$(
  FIXTURE_REF_TYPE=tag \
  FIXTURE_REF_SHA="$expected_object" \
  FIXTURE_TARGET_TYPE=commit \
  FIXTURE_TARGET_SHA="$expected_target" \
  FIXTURE_CURL_LOG="$direct_log" \
    run_publish
)"
grep -Fq 'publish-cw-release: Gitea release published' <<<"$direct_output"
grep -Fq 'publish-cw-release: GitHub release published' <<<"$direct_output"
grep -Fq 'https://git.example.invalid/api/v1/repos/codewire/codewire/releases/tags/v9.9.9' "$direct_log"
grep -Fq 'https://api.github.com/repos/codewiresh/codewire/releases/tags/v9.9.9' "$direct_log"

installation_log="$TMP/installation-curl.log"
installation_output="$(
  FIXTURE_REF_TYPE=tag \
  FIXTURE_REF_SHA="$expected_object" \
  FIXTURE_TARGET_TYPE=commit \
  FIXTURE_TARGET_SHA="$expected_target" \
  FIXTURE_CURL_LOG="$installation_log" \
    run_publish_with_installation_token
)"
grep -Fq 'publish-cw-release: minting GitHub App installation token' <<<"$installation_output"
grep -Fq 'publish-cw-release: Gitea release published' <<<"$installation_output"
grep -Fq 'publish-cw-release: GitHub release published' <<<"$installation_output"
grep -Fq 'https://api.github.com/app/installations/123/access_tokens' "$installation_log"
grep -Fq 'https://git.example.invalid/api/v1/repos/codewire/codewire/releases/tags/v9.9.9' "$installation_log"
grep -Fq 'https://api.github.com/repos/codewiresh/codewire/releases/tags/v9.9.9' "$installation_log"

if missing_output="$(
  FIXTURE_CURL="$TMP/bin/curl" \
    GITEA_TOKEN=fixture-gitea \
    GITHUB_SERVER_URL=https://git.example.invalid \
    GITHUB_REPOSITORY=codewire/codewire \
    MIRROR_GITHUB_APP_ID=fixture-app \
    bash "$PUBLISH" v9.9.9 "$TMP/assets" 2>&1
)"; then
  echo 'publish release test failed: incomplete GitHub App inputs unexpectedly passed' >&2
  exit 1
fi
grep -Fq 'MIRROR_GITHUB_APP_ID, MIRROR_GITHUB_INSTALLATION_ID, and MIRROR_GITHUB_PRIVATE_KEY must be provided together' \
  <<<"$missing_output"

if required_output="$(
  FIXTURE_CURL="$TMP/bin/curl" \
    GITEA_TOKEN=fixture-gitea \
    GITHUB_SERVER_URL=https://git.example.invalid \
    GITHUB_REPOSITORY=codewire/codewire \
    CW_REQUIRE_GITHUB_MIRROR=1 \
    bash "$PUBLISH" v9.9.9 "$TMP/assets" 2>&1
)"; then
  echo 'publish release test failed: required GitHub mirror unexpectedly passed' >&2
  exit 1
fi
grep -Fq 'GitHub mirror publication requires GH_MIRROR_TOKEN or complete GitHub App inputs' \
  <<<"$required_output"

expect_failure flattened-tag 'is not an annotated tag object' \
  commit "$expected_target" commit "$expected_target"
expect_failure wrong-tag-object 'does not match canonical tag object' \
  tag cccccccccccccccccccccccccccccccccccccccc commit "$expected_target"
expect_failure wrong-tag-target 'does not peel to exact release source' \
  tag "$expected_object" commit dddddddddddddddddddddddddddddddddddddddd

echo 'publish cw release tests passed'
