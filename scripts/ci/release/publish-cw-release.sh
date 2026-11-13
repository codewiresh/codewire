#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: publish-cw-release.sh <vX.Y.Z> <asset-dir>
       publish-cw-release.sh --check-unchanged <vX.Y.Z> <asset-dir>

Publishes cw release assets to the Gitea source release and, when mirror
publication is configured, to the GitHub public mirror release.

A published asset never changes: one already on a release with the same
name and the same bytes is left as it is, and one with different bytes
stops the run. --check-unchanged only reads, the Gitea release with
GITEA_TOKEN and the public GitHub mirror release with no token, and fails
when any asset on either differs, so a run can stop before it publishes
anywhere (#4444).

Required:
  GITEA_TOKEN
  GITHUB_SERVER_URL
  GITHUB_REPOSITORY

Optional:
  GITHUB_SHA
  CW_RELEASE_SOURCE_SHA
  CW_RELEASE_TAG_OBJECT_SHA
  GITHUB_MIRROR_REPOSITORY (default: codewiresh/codewire)
  GH_MIRROR_TOKEN_FILE (private GitHub App installation-token file)
  CW_REQUIRE_GITHUB_MIRROR=1 (require GitHub mirror publication)
EOF
}

die() {
  echo "publish-cw-release: $*" >&2
  exit 1
}

json_field() {
  local file="$1"
  local field="$2"
  python3 - "$file" "$field" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
value = data
for part in sys.argv[2].split("."):
    value = value[part]
print(value)
PY
}

# asset_lookup ASSETS_JSON NAME FIELD: the FIELD of the asset called NAME, or
# nothing when the release has none.
asset_lookup() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

assets = json.load(open(sys.argv[1], encoding="utf-8"))
for asset in assets:
    if asset.get("name") == sys.argv[2]:
        print(asset[sys.argv[3]])
        break
PY
}

# changed_asset HOST NAME: the stop for an asset already published with
# different bytes.
changed_asset() {
  die "$2 is already published on the $1 release $tag with different bytes; a published release's assets never change, so cut the next patch release instead"
}

json_body() {
  local tag="$1"
  local target="$2"
  local body="$3"
  python3 - "$tag" "$target" "$body" <<'PY'
import json
import sys

tag, target, body = sys.argv[1:]
json.dump(
    {
        "tag_name": tag,
        "target_commitish": target,
        "name": tag,
        "body": body,
        "draft": False,
        "prerelease": "-" in tag,
    },
    sys.stdout,
)
PY
}

api_status() {
  local method="$1"
  local url="$2"
  local token="$3"
  local out="$4"
  shift 4
  curl -sS -o "$out" -w '%{http_code}' \
    -X "$method" \
    -H "Authorization: token $token" \
    -H "Accept: application/json" \
    "$@" \
    "$url"
}

github_status() {
  local method="$1"
  local url="$2"
  local out="$3"
  shift 3
  curl --config "$github_auth_config" -sS -o "$out" -w '%{http_code}' \
    -X "$method" \
    "$@" \
    "$url"
}

validate_mirror_identity() {
  [[ "${CW_RELEASE_SOURCE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
    || die "CW_RELEASE_SOURCE_SHA is required for GitHub mirror publication"
  [[ "${CW_RELEASE_TAG_OBJECT_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
    || die "CW_RELEASE_TAG_OBJECT_SHA is required for GitHub mirror publication"
}

github_auth_work=''
github_auth_config=''
github_git_config=''

cleanup_github_auth() {
  if [ -n "$github_auth_work" ] && [ -d "$github_auth_work" ]; then
    find "$github_auth_work" -type f -exec shred -u {} + 2>/dev/null || true
    rmdir "$github_auth_work" 2>/dev/null || true
  fi
}
trap cleanup_github_auth EXIT

configure_github_mirror() {
  if [ -z "${GH_MIRROR_TOKEN_FILE:-}" ]; then
    if [ "${CW_REQUIRE_GITHUB_MIRROR:-}" = "1" ]; then
      die "GitHub mirror publication requires GH_MIRROR_TOKEN_FILE"
    fi
    return 1
  fi

  [ -f "$GH_MIRROR_TOKEN_FILE" ] && [ ! -L "$GH_MIRROR_TOKEN_FILE" ] \
    && [ -s "$GH_MIRROR_TOKEN_FILE" ] \
    || die "GH_MIRROR_TOKEN_FILE must be one nonempty regular file"
  case "$(stat -c '%a' -- "$GH_MIRROR_TOKEN_FILE")" in
    400|600) ;;
    *) die "GH_MIRROR_TOKEN_FILE must have mode 0400 or 0600" ;;
  esac

  local mirror_token
  mirror_token="$(tr -d '\n' <"$GH_MIRROR_TOKEN_FILE")"
  # GitHub's installation-token format is not a stable contract (release run
  # 11957 refused a real token under an alphanumeric-only check). The token
  # only has to be safe inside the quoted curl header and the base64 git
  # header below: printable ASCII with no space, double quote or backslash.
  [[ ${#mirror_token} -ge 20 && ${#mirror_token} -le 4096 ]] \
    && [ -z "$(printf '%s' "$mirror_token" | LC_ALL=C tr -d '\041\043-\133\135-\176')" ] \
    || die "GH_MIRROR_TOKEN_FILE contains a malformed token"
  [ "$(wc -l <"$GH_MIRROR_TOKEN_FILE")" -le 1 ] \
    || die "GH_MIRROR_TOKEN_FILE must contain one token"

  validate_mirror_identity
  umask 077
  github_auth_work="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-github-release.XXXXXX")"
  github_auth_config="$github_auth_work/curl.conf"
  github_git_config="$github_auth_work/gitconfig"
  {
    printf 'header = "Authorization: Bearer %s"\n' "$mirror_token"
    printf 'header = "Accept: application/vnd.github+json"\n'
    printf 'header = "X-GitHub-Api-Version: 2022-11-28"\n'
  } >"$github_auth_config"
  {
    printf '[http "https://github.com/"]\n'
    printf '\textraHeader = Authorization: Basic '
    { printf 'x-access-token:'; printf '%s' "$mirror_token"; } | base64 -w0
    printf '\n'
  } >"$github_git_config"
  chmod 0600 "$github_auth_config" "$github_git_config"
  unset mirror_token
  return 0
}

mirror_github_tag() {
  local tag="$1"
  local repo="${GITHUB_MIRROR_REPOSITORY:-codewiresh/codewire}"
  local mirror_bin="${MIRROR_CANONICAL_TAG_BIN:-$(dirname "$0")/mirror-canonical-release-tag.sh}"
  [ "$repo" = 'codewiresh/codewire' ] \
    || die "GitHub mirror repository must be codewiresh/codewire"
  [ -x "$mirror_bin" ] || die "canonical tag mirror helper is unavailable"
  GIT_CONFIG_GLOBAL="$github_git_config" GIT_CONFIG_NOSYSTEM=1 \
    "$mirror_bin" \
      origin "https://github.com/codewiresh/codewire.git" "refs/tags/$tag"
}

ensure_gitea_release() {
  local tag="$1"
  local asset_dir="$2"
  local api="${GITHUB_SERVER_URL%/}/api/v1"
  local repo="$GITHUB_REPOSITORY"
  local target="${CW_RELEASE_SOURCE_SHA:-${GITHUB_SHA:-$tag}}"
  local body="Rust cw release ${tag}, built by Gitea from ${target}."
  local tmp
  tmp="$(mktemp -d)"
  local release_json="$tmp/gitea-release.json"
  local status

  status="$(api_status GET "$api/repos/$repo/releases/tags/$tag" "$GITEA_TOKEN" "$release_json")"
  case "$status" in
    200)
      ;;
    404)
      if [ "$check_only" -eq 1 ]; then
        echo "publish-cw-release: no Gitea release $tag yet; nothing published can change"
        rm -rf "$tmp"
        return 0
      fi
      json_body "$tag" "$target" "$body" > "$tmp/create.json"
      status="$(api_status POST "$api/repos/$repo/releases" "$GITEA_TOKEN" "$release_json" \
        -H "Content-Type: application/json" \
        --data-binary "@$tmp/create.json")"
      [ "$status" = "201" ] || die "create Gitea release failed with HTTP $status: $(cat "$release_json")"
      ;;
    *)
      die "lookup Gitea release failed with HTTP $status: $(cat "$release_json")"
      ;;
  esac

  local release_id
  release_id="$(json_field "$release_json" id)"
  local assets_json="$tmp/gitea-assets.json"
  status="$(api_status GET "$api/repos/$repo/releases/$release_id/assets" "$GITEA_TOKEN" "$assets_json")"
  [ "$status" = "200" ] || die "list Gitea assets failed with HTTP $status: $(cat "$assets_json")"

  for path in "$asset_dir"/*; do
    [ -f "$path" ] || continue
    local name
    name="$(basename "$path")"
    local existing
    existing="$(asset_lookup "$assets_json" "$name" browser_download_url)"
    if [ -n "$existing" ]; then
      status="$(api_status GET "$existing" "$GITEA_TOKEN" "$tmp/published" -L)"
      [ "$status" = "200" ] || die "download Gitea asset $name failed with HTTP $status"
      cmp -s "$tmp/published" "$path" || changed_asset Gitea "$name"
      echo "publish-cw-release: Gitea asset $name is already published, unchanged"
      continue
    fi
    # Checking only: an asset not published yet has nothing to compare.
    [ "$check_only" -eq 0 ] || continue
    status="$(api_status POST "$api/repos/$repo/releases/$release_id/assets?name=$name" "$GITEA_TOKEN" "$tmp/upload.json" \
      -F "attachment=@$path")"
    [ "$status" = "201" ] || die "upload Gitea asset $name failed with HTTP $status: $(cat "$tmp/upload.json")"
  done

  rm -rf "$tmp"
}

wait_for_github_tag() {
  local repo="$1"
  local tag="$2"
  local expected_object="$3"
  local expected_target="$4"
  local tmp
  tmp="$(mktemp -d)"
  local ref_json="$tmp/ref.json"
  local tag_json="$tmp/tag.json"
  local status ref_type ref_object target_type target_sha
  for _ in $(seq 1 30); do
    status="$(github_status GET "https://api.github.com/repos/$repo/git/ref/tags/$tag" "$ref_json")"
    if [ "$status" = "200" ]; then
      ref_type="$(json_field "$ref_json" object.type)"
      ref_object="$(json_field "$ref_json" object.sha)"
      [ "$ref_type" = tag ] \
        || die "GitHub mirror ref refs/tags/$tag is not an annotated tag object"
      [ "$ref_object" = "$expected_object" ] \
        || die "GitHub mirror ref refs/tags/$tag does not match canonical tag object $expected_object"

      status="$(github_status GET "https://api.github.com/repos/$repo/git/tags/$ref_object" "$tag_json")"
      [ "$status" = "200" ] \
        || die "lookup GitHub annotated tag object failed with HTTP $status: $(cat "$tag_json")"
      target_type="$(json_field "$tag_json" object.type)"
      target_sha="$(json_field "$tag_json" object.sha)"
      [ "$target_type" = commit ] && [ "$target_sha" = "$expected_target" ] \
        || die "GitHub mirror tag $tag does not peel to exact release source $expected_target"
      rm -rf "$tmp"
      return 0
    fi
    [ "$status" = "404" ] \
      || die "lookup GitHub mirror tag failed with HTTP $status: $(cat "$ref_json")"
    sleep 2
  done
  die "GitHub mirror tag $tag did not appear for $repo"
}

# check_public_github_release TAG ASSET_DIR: every asset of the public GitHub
# mirror release, read without a token, equals the delivery's.
check_public_github_release() {
  local tag="$1"
  local asset_dir="$2"
  local repo="${GITHUB_MIRROR_REPOSITORY:-codewiresh/codewire}"
  local tmp status
  tmp="$(mktemp -d)"
  status="$(curl -sS -o "$tmp/release.json" -w '%{http_code}' \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$repo/releases/tags/$tag")"
  case "$status" in
    200)
      ;;
    404)
      echo "publish-cw-release: no GitHub release $tag yet; nothing published can change"
      rm -rf "$tmp"
      return 0
      ;;
    *)
      die "read the public GitHub release $tag failed with HTTP $status"
      ;;
  esac
  python3 - "$tmp/release.json" >"$tmp/assets.json" <<'PY'
import json
import sys

json.dump(json.load(open(sys.argv[1], encoding="utf-8")).get("assets", []), sys.stdout)
PY
  for path in "$asset_dir"/*; do
    [ -f "$path" ] || continue
    local name existing
    name="$(basename "$path")"
    existing="$(asset_lookup "$tmp/assets.json" "$name" browser_download_url)"
    [ -n "$existing" ] || continue
    status="$(curl -sS -L -o "$tmp/published" -w '%{http_code}' "$existing")"
    [ "$status" = "200" ] || die "download the public GitHub asset $name failed with HTTP $status"
    cmp -s "$tmp/published" "$path" || changed_asset GitHub "$name"
    echo "publish-cw-release: GitHub asset $name is already published, unchanged"
  done
  rm -rf "$tmp"
}

ensure_github_release() {
  local tag="$1"
  local asset_dir="$2"
  local repo="${GITHUB_MIRROR_REPOSITORY:-codewiresh/codewire}"
  local target="${CW_RELEASE_SOURCE_SHA:-${GITHUB_SHA:-$tag}}"
  local tag_object="$CW_RELEASE_TAG_OBJECT_SHA"
  local body="Rust cw release ${tag}, built by Gitea from ${target}."
  local tmp
  tmp="$(mktemp -d)"
  local release_json="$tmp/github-release.json"
  local status

  wait_for_github_tag "$repo" "$tag" "$tag_object" "$target"

  status="$(github_status GET "https://api.github.com/repos/$repo/releases/tags/$tag" "$release_json")"
  case "$status" in
    200)
      ;;
    404)
      json_body "$tag" "$target" "$body" > "$tmp/create.json"
      status="$(github_status POST "https://api.github.com/repos/$repo/releases" "$release_json" \
        -H "Content-Type: application/json" \
        --data-binary "@$tmp/create.json")"
      [ "$status" = "201" ] || die "create GitHub release failed with HTTP $status: $(cat "$release_json")"
      ;;
    *)
      die "lookup GitHub release failed with HTTP $status: $(cat "$release_json")"
      ;;
  esac

  local release_id
  release_id="$(json_field "$release_json" id)"
  local assets_json="$tmp/github-assets.json"
  status="$(github_status GET "https://api.github.com/repos/$repo/releases/$release_id/assets" "$assets_json")"
  [ "$status" = "200" ] || die "list GitHub assets failed with HTTP $status: $(cat "$assets_json")"

  for path in "$asset_dir"/*; do
    [ -f "$path" ] || continue
    local name
    name="$(basename "$path")"
    local existing
    existing="$(asset_lookup "$assets_json" "$name" id)"
    if [ -n "$existing" ]; then
      status="$(github_status GET "https://api.github.com/repos/$repo/releases/assets/$existing" "$tmp/published" \
        -H "Accept: application/octet-stream" -L)"
      [ "$status" = "200" ] || die "download GitHub asset $name failed with HTTP $status"
      cmp -s "$tmp/published" "$path" || changed_asset GitHub "$name"
      echo "publish-cw-release: GitHub asset $name is already published, unchanged"
      continue
    fi
    status="$(github_status POST "https://uploads.github.com/repos/$repo/releases/$release_id/assets?name=$name" "$tmp/upload.json" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@$path")"
    [ "$status" = "201" ] || die "upload GitHub asset $name failed with HTTP $status: $(cat "$tmp/upload.json")"
  done

  rm -rf "$tmp"
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

check_only=0
if [ "${1:-}" = "--check-unchanged" ]; then
  check_only=1
  shift
fi
tag="${1:-}"
asset_dir="${2:-}"
[ -n "$tag" ] || die "tag is required"
[ -d "$asset_dir" ] || die "asset directory is required"
[ -n "${GITEA_TOKEN:-}" ] || die "GITEA_TOKEN is required"
[ -n "${GITHUB_SERVER_URL:-}" ] || die "GITHUB_SERVER_URL is required"
[ -n "${GITHUB_REPOSITORY:-}" ] || die "GITHUB_REPOSITORY is required"

if [ "$check_only" -eq 1 ]; then
  ensure_gitea_release "$tag" "$asset_dir"
  check_public_github_release "$tag" "$asset_dir"
  echo "publish-cw-release: every asset already published for $tag is unchanged"
  exit 0
fi

github_mirror_enabled=0
if configure_github_mirror; then
  github_mirror_enabled=1
fi

echo "publish-cw-release: publishing Gitea release"
ensure_gitea_release "$tag" "$asset_dir"
echo "publish-cw-release: Gitea release published"
if [ "$github_mirror_enabled" -eq 1 ]; then
  echo "publish-cw-release: mirroring canonical GitHub tag"
  mirror_github_tag "$tag"
  echo "publish-cw-release: publishing GitHub release"
  ensure_github_release "$tag" "$asset_dir"
  echo "publish-cw-release: GitHub release published"
else
  echo "publish-cw-release: GitHub mirror publication not configured; skipped" >&2
fi
