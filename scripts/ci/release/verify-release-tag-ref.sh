#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: verify-release-tag-ref.sh EVENT WORKFLOW_REF WORKFLOW_REF_NAME RECOVERY_TAG SERVER_URL REPOSITORY SOURCE_SHA REMOTE_OBJECT_SHA REMOTE_PEELED_SHA CANONICAL_MAIN_SHA
EOF
  exit 2
}

fail() {
  printf 'release tag verification failed: %s\n' "$*" >&2
  exit 1
}

valid_object_id() {
  [[ "$1" =~ ^[0-9a-f]{40}$ || "$1" =~ ^[0-9a-f]{64}$ ]]
}

[[ $# -eq 10 ]] || usage

event="$1"
workflow_ref="$2"
workflow_ref_name="$3"
recovery_tag="$4"
server_url="${5%/}"
repository="$6"
source_sha="$7"
remote_object_sha="$8"
remote_peeled_sha="$9"
canonical_main_sha="${10}"
# A release tag is trusted when Forgejo verifies its signature against a GPG
# key registered on the tagger's Forgejo account. Only the synthetic test
# harness may substitute the HTTP client.
curl_bin="${CODEWIRE_RELEASE_TAG_CURL:-curl}"
if [[ "$curl_bin" != curl ]]; then
  [[ "${CODEWIRE_RELEASE_TAG_TEST_MODE:-0}" == 1 ]] ||
    fail "release tag HTTP overrides are accepted only by the synthetic test harness"
fi
[[ -n "${GITEA_TOKEN:-}" ]] ||
  fail "Forgejo API token is required to read the release tag verification"

case "$event" in
  push)
    [[ -z "$recovery_tag" ]] ||
      fail "tag-push selection must not include a recovery tag"
    if [[ ! "$workflow_ref" =~ ^refs/tags/(v[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
      fail "push ref must be an exact semver tag, got '$workflow_ref'"
    fi
    tag="${BASH_REMATCH[1]}"
    [[ "$workflow_ref_name" == "$tag" ]] ||
      fail "ref name '$workflow_ref_name' does not match tag '$tag'"
    ;;
  workflow_dispatch)
    [[ "$workflow_ref" == "refs/heads/main" ]] ||
      fail "recovery dispatch must run from refs/heads/main, got '$workflow_ref'"
    [[ "$workflow_ref_name" == "main" ]] ||
      fail "recovery dispatch ref name must be main, got '$workflow_ref_name'"
    if [[ ! "$recovery_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      fail "recovery tag must be exact semver, got '$recovery_tag'"
    fi
    tag="$recovery_tag"
    ;;
  *)
    fail "unsupported release event '$event'"
    ;;
esac

# The canonical Forgejo instance has one public and one internal Tailnet
# name; runners register against the internal one. Nothing else is trusted.
case "$server_url" in
  https://git.example.invalid|https://forgejo.example.invalid) ;;
  *) fail "server must be canonical Forgejo, got '$server_url'" ;;
esac
[[ "$repository" == "codewire/codewire" ]] ||
  fail "repository must be codewire/codewire, got '$repository'"
valid_object_id "$source_sha" || fail "release source is not a Git object ID"
valid_object_id "$canonical_main_sha" ||
  fail "canonical main is not a Git object ID"
valid_object_id "$remote_object_sha" ||
  fail "canonical Gitea tag '$tag' is missing or invalid"
valid_object_id "$remote_peeled_sha" ||
  fail "canonical Gitea tag '$tag' must be annotated and peel to a commit"
[[ "$remote_object_sha" != "$remote_peeled_sha" ]] ||
  fail "canonical Gitea tag '$tag' has no distinct annotated tag object"

tag_ref="refs/tags/$tag"
[[ "$(git cat-file -t "$tag_ref" 2>/dev/null)" == tag ]] ||
  fail "canonical Gitea tag '$tag' is not an available annotated tag object"
signed_tag_name="$(git cat-file tag "$tag_ref" |
  awk '$1 == "tag" && NF == 2 { print $2; exit } /^$/ { exit }')"
[[ "$signed_tag_name" == "$tag" ]] ||
  fail "canonical Gitea tag ref does not match its signed tag name"
[[ "$(git rev-parse --verify "$tag_ref")" == "$remote_object_sha" ]] ||
  fail "local release tag object does not match canonical Gitea"

[[ "$source_sha" == "$remote_peeled_sha" ]] ||
  fail "canonical tag '$tag' does not peel to release source"
git cat-file -e "${source_sha}^{commit}" 2>/dev/null ||
  fail "release source commit is unavailable in the control repository"
git cat-file -e "${canonical_main_sha}^{commit}" 2>/dev/null ||
  fail "canonical main commit is unavailable in the control repository"
git merge-base --is-ancestor "$source_sha" "$canonical_main_sha" ||
  fail "canonical tag '$tag' is not reachable from canonical main"

umask 077
verify_home="$(mktemp -d "${RUNNER_TEMP:-/tmp}/codewire-release-tag.XXXXXX")"
cleanup() {
  rm -rf -- "$verify_home"
}
trap cleanup EXIT
auth_config="$verify_home/forgejo.curl"
printf 'header = "Authorization: token %s"\n' "$GITEA_TOKEN" >"$auth_config"
unset GITEA_TOKEN
tag_record="$verify_home/tag.json"
tag_api="${server_url}/api/v1/repos/${repository}/git/tags/${remote_object_sha}"
if ! http_status="$("$curl_bin" --config "$auth_config" --silent --show-error \
    --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 \
    --output "$tag_record" --write-out '%{http_code}' "$tag_api" 2>/dev/null)"; then
  fail "Forgejo release tag lookup failed for '$tag'"
fi
[[ "$http_status" == 200 ]] ||
  fail "Forgejo release tag lookup for '$tag' returned HTTP $http_status"
if ! verified_record="$(jq -er \
    --arg tag "$tag" --arg object "$remote_object_sha" --arg commit "$source_sha" '
      select(type == "object"
        and .tag == $tag and .sha == $object
        and .object.type == "commit" and .object.sha == $commit)
      | [(.verification.verified == true), (.verification.signer.username // "")]
      | @tsv' "$tag_record" 2>/dev/null)"; then
  fail "Forgejo release tag record for '$tag' does not match the canonical tag"
fi
IFS=$'\t' read -r verified signer <<<"$verified_record"
[[ "$verified" == true ]] ||
  fail "release tag '$tag' is not signed by a GPG key verified by Forgejo"

printf 'release tag verified: tag=%s commit=%s forgejo_signer=%s\n' \
  "$tag" "$source_sha" "${signer:-unknown}"
