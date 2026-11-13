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
printf 'ghs_fixture.github-installation~token+0123\n' >"$TMP/github-token"
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
method=GET
[ -z "${FIXTURE_CURL_ARG_LOG:-}" ] || printf '%q ' "$@" >>"$FIXTURE_CURL_ARG_LOG"
[ -z "${FIXTURE_CURL_ARG_LOG:-}" ] || printf '\n' >>"$FIXTURE_CURL_ARG_LOG"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config)
      [ -f "$2" ]
      [ "$(stat -c '%a' -- "$2")" = 600 ]
      grep -Fq 'header = "Authorization: Bearer ghs_fixture.github-installation~token+0123"' "$2"
      shift 2
      ;;
    -o)
      output="$2"
      shift 2
      ;;
    -w)
      shift 2
      ;;
    -X)
      method="$2"
      shift 2
      ;;
    -H|-F|--data-binary)
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
[ -z "${FIXTURE_CURL_LOG:-}" ] || printf '%s %s\n' "$method" "$url" >>"$FIXTURE_CURL_LOG"
# Assets already published: FIXTURE_GITEA_PUBLISHED and FIXTURE_GITHUB_PUBLISHED
# name directories holding them; a published release never deletes one.
listing() { # DIR URL_PREFIX
  local dir="$1" prefix="$2" first=1 f
  printf '['
  if [ -n "$dir" ]; then
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      [ "$first" -eq 1 ] || printf ','
      first=0
      printf '{"id":"%s","name":"%s","browser_download_url":"%s%s"}' \
        "$(basename "$f")" "$(basename "$f")" "$prefix" "$(basename "$f")"
    done
  fi
  printf ']'
}
status=200
[ "$method" != DELETE ] || { status=500; url=deleted; }
case "$url" in
  */api/v1/repos/codewire/codewire/releases/tags/*)
    if [ -n "${FIXTURE_NO_RELEASE:-}" ]; then
      status=404
      body='{}'
    else
      body='{"id":1}'
    fi
    ;;
  */api/v1/repos/codewire/codewire/releases/1/assets)
    body="$(listing "${FIXTURE_GITEA_PUBLISHED:-}" https://git.example.invalid/attachments/)"
    ;;
  https://git.example.invalid/attachments/*)
    cat "${FIXTURE_GITEA_PUBLISHED:?}/${url##*/}" >"$output"
    printf 200
    exit 0
    ;;
  https://api.github.com/repos/codewiresh/codewire/releases/assets/*)
    cat "${FIXTURE_GITHUB_PUBLISHED:?}/${url##*/}" >"$output"
    printf 200
    exit 0
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
    if [ -n "${FIXTURE_NO_GITHUB_RELEASE:-}" ]; then
      status=404
      body='{}'
    else
      body="{\"id\":2,\"assets\":$(listing "${FIXTURE_GITHUB_PUBLISHED:-}" https://github.com/codewiresh/codewire/releases/download/v9.9.9/)}"
    fi
    ;;
  https://github.com/codewiresh/codewire/releases/download/v9.9.9/*)
    cat "${FIXTURE_GITHUB_PUBLISHED:?}/${url##*/}" >"$output"
    printf 200
    exit 0
    ;;
  https://api.github.com/repos/codewiresh/codewire/releases/2/assets)
    body="$(listing "${FIXTURE_GITHUB_PUBLISHED:-}" '')"
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
if grep -Fq 'ghs_fixture.github-installation~token+0123' "$arg_log"; then
  echo 'publish release test failed: GitHub token reached curl arguments' >&2
  exit 1
fi

# The token only has to be header-safe; a GitHub format change (here a period,
# tilde and plus) must not break publication, but quoting characters must.
for bad in 'ghs_fixture"token0123456789' 'ghs_fixture\\token0123456789' 'ghs_fixture token0123456789' 'short_token'; do
  printf '%s\n' "$bad" >"$TMP/github-token-bad"
  chmod 0600 "$TMP/github-token-bad"
  if bad_output="$(
    FIXTURE_CURL="$TMP/bin/curl" \
      GITEA_TOKEN=fixture-gitea \
      GITHUB_SERVER_URL=https://git.example.invalid \
      GITHUB_REPOSITORY=codewire/codewire \
      GH_MIRROR_TOKEN_FILE="$TMP/github-token-bad" \
      MIRROR_CANONICAL_TAG_BIN="$TMP/bin/mirror-canonical-tag" \
      FIXTURE_MIRROR_LOG="$TMP/mirror.log" \
      CW_REQUIRE_GITHUB_MIRROR=1 \
      CW_RELEASE_SOURCE_SHA="$expected_target" \
      CW_RELEASE_TAG_OBJECT_SHA="$expected_object" \
      bash "$PUBLISH" v9.9.9 "$TMP/assets" 2>&1
  )"; then
    echo 'publish release test failed: a header-unsafe token unexpectedly passed' >&2
    exit 1
  fi
  grep -Fq 'GH_MIRROR_TOKEN_FILE contains a malformed token' <<<"$bad_output"
done

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

# --- a published asset never changes (#4444) -------------------------------
mkdir "$TMP/same" "$TMP/changed"
cp "$TMP/assets/"* "$TMP/same/"
cp "$TMP/assets/"* "$TMP/changed/"
printf 'a different build\n' >"$TMP/changed/cw-v9.9.9-x86_64-unknown-linux-musl"
publish_case() { # NAME [ENV=VALUE...] -- [ARGS...]: publish with these fixtures.
  local name="$1"
  shift
  local envs=()
  while [ "$#" -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
  shift
  : >"$TMP/$name.curl"
  : >"$TMP/$name.args"
  env FIXTURE_CURL="$TMP/bin/curl" GITEA_TOKEN=fixture-gitea \
    GITHUB_SERVER_URL=https://git.example.invalid GITHUB_REPOSITORY=codewire/codewire \
    GH_MIRROR_TOKEN_FILE="$TMP/github-token" MIRROR_CANONICAL_TAG_BIN="$TMP/bin/mirror-canonical-tag" \
    FIXTURE_MIRROR_LOG="$TMP/mirror.log" CW_REQUIRE_GITHUB_MIRROR=1 \
    CW_RELEASE_SOURCE_SHA="$expected_target" CW_RELEASE_TAG_OBJECT_SHA="$expected_object" \
    FIXTURE_REF_TYPE=tag FIXTURE_REF_SHA="$expected_object" \
    FIXTURE_TARGET_TYPE=commit FIXTURE_TARGET_SHA="$expected_target" \
    FIXTURE_CURL_LOG="$TMP/$name.curl" FIXTURE_CURL_ARG_LOG="$TMP/$name.args" "${envs[@]}" \
    bash "$PUBLISH" "$@" >"$TMP/$name.out" 2>&1
}
uploads() { grep -cE '^POST .*assets\?name=' "$TMP/$1.curl" || true; }
# The same bytes already published on both: a retry uploads and deletes nothing.
publish_case retry FIXTURE_GITEA_PUBLISHED="$TMP/same" FIXTURE_GITHUB_PUBLISHED="$TMP/same" -- v9.9.9 "$TMP/assets" ||
  { echo "publish release test failed: an unchanged retry was refused: $(cat "$TMP/retry.out")" >&2; exit 1; }
[ "$(uploads retry)" = 0 ] && ! grep -q '^DELETE' "$TMP/retry.curl" ||
  { echo 'publish release test failed: an unchanged retry replaced an asset' >&2; exit 1; }
grep -Fq 'GitHub asset cw-v9.9.9-x86_64-unknown-linux-musl is already published, unchanged' "$TMP/retry.out"
# Different bytes under a published name stop the run; nothing is replaced.
for host in Gitea GitHub; do
  gitea="$TMP/same" github="$TMP/same"
  [ "$host" = Gitea ] && gitea="$TMP/changed" || github="$TMP/changed"
  if publish_case "changed-$host" FIXTURE_GITEA_PUBLISHED="$gitea" FIXTURE_GITHUB_PUBLISHED="$github" -- v9.9.9 "$TMP/assets"; then
    echo "publish release test failed: a changed $host asset was published" >&2
    exit 1
  fi
  grep -Fq "cw-v9.9.9-x86_64-unknown-linux-musl is already published on the $host release v9.9.9 with different bytes" \
    "$TMP/changed-$host.out" || { echo "publish release test failed: $host change not named: $(cat "$TMP/changed-$host.out")" >&2; exit 1; }
  [ "$(uploads "changed-$host")" = 0 ] && ! grep -q '^DELETE' "$TMP/changed-$host.curl" ||
    { echo "publish release test failed: a changed $host asset was replaced" >&2; exit 1; }
done
# --check-unchanged reads Gitea and the public GitHub release, and publishes nothing.
publish_case check-none FIXTURE_NO_RELEASE=1 FIXTURE_NO_GITHUB_RELEASE=1 -- --check-unchanged v9.9.9 "$TMP/assets" ||
  { echo "publish release test failed: check refused an unpublished release: $(cat "$TMP/check-none.out")" >&2; exit 1; }
publish_case check-same FIXTURE_GITEA_PUBLISHED="$TMP/same" FIXTURE_GITHUB_PUBLISHED="$TMP/same" -- --check-unchanged v9.9.9 "$TMP/assets" ||
  { echo "publish release test failed: check refused an unchanged release: $(cat "$TMP/check-same.out")" >&2; exit 1; }
if publish_case check-changed FIXTURE_GITEA_PUBLISHED="$TMP/changed" -- --check-unchanged v9.9.9 "$TMP/assets"; then
  echo 'publish release test failed: check passed a changed asset' >&2
  exit 1
fi
# A GitHub asset that already differs is caught before anything is written.
if publish_case check-changed-github FIXTURE_GITEA_PUBLISHED="$TMP/same" FIXTURE_GITHUB_PUBLISHED="$TMP/changed" \
    -- --check-unchanged v9.9.9 "$TMP/assets"; then
  echo 'publish release test failed: check passed a changed GitHub asset' >&2
  exit 1
fi
grep -Fq 'is already published on the GitHub release v9.9.9 with different bytes' "$TMP/check-changed-github.out" ||
  { echo "publish release test failed: the GitHub change was not named: $(cat "$TMP/check-changed-github.out")" >&2; exit 1; }
# A release that exists without an asset yet: nothing to compare, nothing uploaded.
mkdir "$TMP/none-yet"
publish_case check-partial FIXTURE_GITEA_PUBLISHED="$TMP/none-yet" FIXTURE_GITHUB_PUBLISHED="$TMP/none-yet" -- --check-unchanged v9.9.9 "$TMP/assets" ||
  { echo "publish release test failed: check refused a release missing an asset: $(cat "$TMP/check-partial.out")" >&2; exit 1; }
for name in check-none check-same check-changed check-changed-github check-partial; do
  ! grep -qE '^(POST|DELETE|PATCH) ' "$TMP/$name.curl" ||
    { echo "publish release test failed: $name wrote: $(cat "$TMP/$name.curl")" >&2; exit 1; }
  ! grep -qE -- '--config|ghs_' "$TMP/$name.args" ||
    { echo "publish release test failed: $name held the GitHub token" >&2; exit 1; }
done
grep -q '^GET https://api.github.com/repos/codewiresh/codewire/releases/tags/v9.9.9$' "$TMP/check-same.curl" ||
  { echo 'publish release test failed: check did not read the public GitHub release' >&2; exit 1; }

expect_failure flattened-tag 'is not an annotated tag object' \
  commit "$expected_target" commit "$expected_target"
expect_failure wrong-tag-object 'does not match canonical tag object' \
  tag cccccccccccccccccccccccccccccccccccccccc commit "$expected_target"
expect_failure wrong-tag-target 'does not peel to exact release source' \
  tag "$expected_object" commit dddddddddddddddddddddddddddddddddddddddd

echo 'publish cw release tests passed'
