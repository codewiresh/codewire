#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: publish-cw-release.sh <vX.Y.Z> <asset-dir>

Publishes cw release assets to the Gitea source release and, when mirror
publication is configured, to the GitHub public mirror release.

Required:
  GITEA_TOKEN
  GITHUB_SERVER_URL
  GITHUB_REPOSITORY

Optional:
  GITHUB_SHA
  CW_RELEASE_SOURCE_SHA
  CW_RELEASE_TAG_OBJECT_SHA
  GITHUB_MIRROR_REPOSITORY (default: codewiresh/codewire)
  GH_MIRROR_TOKEN
  MIRROR_GITHUB_APP_ID
  MIRROR_GITHUB_INSTALLATION_ID
  MIRROR_GITHUB_PRIVATE_KEY
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
  local token="$3"
  local out="$4"
  shift 4
  curl -sS -o "$out" -w '%{http_code}' \
    -X "$method" \
    -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$@" \
    "$url"
}

validate_mirror_identity() {
  [[ "${CW_RELEASE_SOURCE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
    || die "CW_RELEASE_SOURCE_SHA is required for GitHub mirror publication"
  [[ "${CW_RELEASE_TAG_OBJECT_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
    || die "CW_RELEASE_TAG_OBJECT_SHA is required for GitHub mirror publication"
}

mint_github_installation_token() {
  local jwt token_json mirror_token

  jwt="$(
    node <<'NODE'
const crypto = require("crypto");

function b64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

const now = Math.floor(Date.now() / 1000);
const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
const payload = b64url(JSON.stringify({
  iat: now - 60,
  exp: now + 540,
  iss: process.env.MIRROR_GITHUB_APP_ID,
}));
const unsigned = `${header}.${payload}`;
const key = process.env.MIRROR_GITHUB_PRIVATE_KEY.replace(/\\n/g, "\n");
const signature = crypto.createSign("RSA-SHA256").update(unsigned).sign(key);

console.log(`${unsigned}.${b64url(signature)}`);
NODE
  )"

  token_json="$(
    curl -fsS -X POST \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${jwt}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/app/installations/${MIRROR_GITHUB_INSTALLATION_ID}/access_tokens"
  )"
  mirror_token="$(printf '%s' "$token_json" | node -e 'const fs = require("fs"); const body = JSON.parse(fs.readFileSync(0, "utf8")); if (!body.token) process.exit(1); process.stdout.write(body.token);')"
  [ -n "$mirror_token" ] || die "GitHub App installation-token response was empty"
  echo "::add-mask::${mirror_token}"
  GH_MIRROR_TOKEN="$mirror_token"
  export GH_MIRROR_TOKEN
}

configure_github_mirror() {
  local app_input_count=0 name
  for name in \
    MIRROR_GITHUB_APP_ID \
    MIRROR_GITHUB_INSTALLATION_ID \
    MIRROR_GITHUB_PRIVATE_KEY; do
    if [ -n "${!name:-}" ]; then
      app_input_count=$((app_input_count + 1))
    fi
  done

  if [ "$app_input_count" -ne 0 ] && [ "$app_input_count" -ne 3 ]; then
    die "MIRROR_GITHUB_APP_ID, MIRROR_GITHUB_INSTALLATION_ID, and MIRROR_GITHUB_PRIVATE_KEY must be provided together"
  fi

  if [ -n "${GH_MIRROR_TOKEN:-}" ]; then
    validate_mirror_identity
    return 0
  fi

  if [ "$app_input_count" -eq 3 ]; then
    validate_mirror_identity
    echo "publish-cw-release: minting GitHub App installation token"
    mint_github_installation_token
    return 0
  fi

  if [ "${CW_REQUIRE_GITHUB_MIRROR:-}" = "1" ]; then
    die "GitHub mirror publication requires GH_MIRROR_TOKEN or complete GitHub App inputs"
  fi

  return 1
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
    existing="$(python3 - "$assets_json" "$name" <<'PY'
import json
import sys

assets = json.load(open(sys.argv[1], encoding="utf-8"))
for asset in assets:
    if asset.get("name") == sys.argv[2]:
        print(asset["id"])
        break
PY
)"
    if [ -n "$existing" ]; then
      status="$(api_status DELETE "$api/repos/$repo/releases/$release_id/assets/$existing" "$GITEA_TOKEN" "$tmp/delete.json")"
      [ "$status" = "204" ] || die "delete Gitea asset $name failed with HTTP $status: $(cat "$tmp/delete.json")"
    fi
    status="$(api_status POST "$api/repos/$repo/releases/$release_id/assets?name=$name" "$GITEA_TOKEN" "$tmp/upload.json" \
      -F "attachment=@$path")"
    [ "$status" = "201" ] || die "upload Gitea asset $name failed with HTTP $status: $(cat "$tmp/upload.json")"
  done

  rm -rf "$tmp"
}

wait_for_github_tag() {
  local repo="$1"
  local tag="$2"
  local token="$3"
  local expected_object="$4"
  local expected_target="$5"
  local tmp
  tmp="$(mktemp -d)"
  local ref_json="$tmp/ref.json"
  local tag_json="$tmp/tag.json"
  local status ref_type ref_object target_type target_sha
  for _ in $(seq 1 30); do
    status="$(github_status GET "https://api.github.com/repos/$repo/git/ref/tags/$tag" "$token" "$ref_json")"
    if [ "$status" = "200" ]; then
      ref_type="$(json_field "$ref_json" object.type)"
      ref_object="$(json_field "$ref_json" object.sha)"
      [ "$ref_type" = tag ] \
        || die "GitHub mirror ref refs/tags/$tag is not an annotated tag object"
      [ "$ref_object" = "$expected_object" ] \
        || die "GitHub mirror ref refs/tags/$tag does not match canonical tag object $expected_object"

      status="$(github_status GET "https://api.github.com/repos/$repo/git/tags/$ref_object" "$token" "$tag_json")"
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

  wait_for_github_tag "$repo" "$tag" "$GH_MIRROR_TOKEN" "$tag_object" "$target"

  status="$(github_status GET "https://api.github.com/repos/$repo/releases/tags/$tag" "$GH_MIRROR_TOKEN" "$release_json")"
  case "$status" in
    200)
      ;;
    404)
      json_body "$tag" "$target" "$body" > "$tmp/create.json"
      status="$(github_status POST "https://api.github.com/repos/$repo/releases" "$GH_MIRROR_TOKEN" "$release_json" \
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
  status="$(github_status GET "https://api.github.com/repos/$repo/releases/$release_id/assets" "$GH_MIRROR_TOKEN" "$assets_json")"
  [ "$status" = "200" ] || die "list GitHub assets failed with HTTP $status: $(cat "$assets_json")"

  for path in "$asset_dir"/*; do
    [ -f "$path" ] || continue
    local name
    name="$(basename "$path")"
    local existing
    existing="$(python3 - "$assets_json" "$name" <<'PY'
import json
import sys

assets = json.load(open(sys.argv[1], encoding="utf-8"))
for asset in assets:
    if asset.get("name") == sys.argv[2]:
        print(asset["id"])
        break
PY
)"
    if [ -n "$existing" ]; then
      status="$(github_status DELETE "https://api.github.com/repos/$repo/releases/assets/$existing" "$GH_MIRROR_TOKEN" "$tmp/delete.json")"
      [ "$status" = "204" ] || die "delete GitHub asset $name failed with HTTP $status: $(cat "$tmp/delete.json")"
    fi
    status="$(github_status POST "https://uploads.github.com/repos/$repo/releases/$release_id/assets?name=$name" "$GH_MIRROR_TOKEN" "$tmp/upload.json" \
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

tag="${1:-}"
asset_dir="${2:-}"
[ -n "$tag" ] || die "tag is required"
[ -d "$asset_dir" ] || die "asset directory is required"
[ -n "${GITEA_TOKEN:-}" ] || die "GITEA_TOKEN is required"
[ -n "${GITHUB_SERVER_URL:-}" ] || die "GITHUB_SERVER_URL is required"
[ -n "${GITHUB_REPOSITORY:-}" ] || die "GITHUB_REPOSITORY is required"

github_mirror_enabled=0
if configure_github_mirror; then
  github_mirror_enabled=1
fi

echo "publish-cw-release: publishing Gitea release"
ensure_gitea_release "$tag" "$asset_dir"
echo "publish-cw-release: Gitea release published"
if [ "$github_mirror_enabled" -eq 1 ]; then
  echo "publish-cw-release: publishing GitHub release"
  ensure_github_release "$tag" "$asset_dir"
  echo "publish-cw-release: GitHub release published"
else
  echo "publish-cw-release: GitHub mirror publication not configured; skipped" >&2
fi
