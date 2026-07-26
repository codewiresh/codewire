#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CANONICAL_SIGNING_FINGERPRINT='E66EACD85E979D3A10C5744AACB59B76E29853EA'

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
public_key="${CODEWIRE_RELEASE_TAG_PUBLIC_KEY:-$ROOT/keys/production-release.asc}"
expected_fingerprint="${CODEWIRE_RELEASE_TAG_SIGNING_FINGERPRINT:-$CANONICAL_SIGNING_FINGERPRINT}"

if [[ "$public_key" != "$ROOT/keys/production-release.asc" ||
  "$expected_fingerprint" != "$CANONICAL_SIGNING_FINGERPRINT" ]]; then
  [[ "${CODEWIRE_RELEASE_TAG_TEST_MODE:-0}" == 1 ]] ||
    fail "release tag trust overrides are accepted only by the synthetic test harness"
fi
[[ -f "$public_key" && ! -L "$public_key" ]] ||
  fail "release tag public key must be one regular file"
[[ "$expected_fingerprint" =~ ^[0-9A-F]{40}$ ]] ||
  fail "release tag fingerprint must be one uppercase primary fingerprint"

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

[[ "$server_url" == "https://git.example.invalid" ]] ||
  fail "server must be canonical Gitea, got '$server_url'"
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
verify_status="$verify_home/verify.status"
cleanup() {
  rm -rf -- "$verify_home"
}
trap cleanup EXIT
mkdir -m 0700 "$verify_home/gnupg"
public_records="$verify_home/public.records"
GNUPGHOME="$verify_home/gnupg" gpg --batch --with-colons \
  --import-options show-only --import "$public_key" >"$public_records" 2>/dev/null ||
  fail "release tag public key is not valid OpenPGP"
public_count="$(awk -F: '$1 == "pub" { count++ } END { print count + 0 }' "$public_records")"
public_fingerprint="$(awk -F: '$1 == "pub" { primary = 1; next } primary && $1 == "fpr" { print $10; exit }' "$public_records")"
[[ "$public_count" == 1 && "$public_fingerprint" == "$expected_fingerprint" ]] ||
  fail "release tag public key does not match the expected primary fingerprint"
GNUPGHOME="$verify_home/gnupg" gpg --batch --import "$public_key" >/dev/null 2>&1 ||
  fail "release tag public key could not be imported"
if ! GNUPGHOME="$verify_home/gnupg" git \
  -c gpg.format=openpgp -c gpg.program=gpg \
  verify-tag --raw "$tag_ref" >"$verify_status" 2>&1; then
  fail "release tag signature is invalid"
fi
valid_fingerprints="$(awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3 }' "$verify_status")"
[[ "$valid_fingerprints" == "$expected_fingerprint" ]] ||
  fail "release tag was not signed by the expected primary key"

printf 'release tag verified: tag=%s commit=%s signer=%s\n' \
  "$tag" "$source_sha" "$expected_fingerprint"
