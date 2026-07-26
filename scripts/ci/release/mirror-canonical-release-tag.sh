#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: mirror-canonical-release-tag.sh SOURCE_REMOTE MIRROR_REMOTE TAG_REF

Fetches an exact annotated release-tag object from SOURCE_REMOTE into an
isolated ref and pushes that object to MIRROR_REMOTE. The checkout's local tag
ref is never trusted or rewritten.
EOF
}

die() {
  printf 'mirror-canonical-release-tag: %s\n' "$*" >&2
  exit 1
}

if [ "$#" -ne 3 ] || [ "${1:-}" = '--help' ] || [ "${1:-}" = '-h' ]; then
  usage
  [ "$#" -eq 1 ] && exit 0
  exit 2
fi

source_remote="$1"
mirror_remote="$2"
tag_ref="$3"
[[ "$tag_ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "tag ref must be refs/tags/vMAJOR.MINOR.PATCH: $tag_ref"

source_refs="$(
  git ls-remote --tags "$source_remote" "$tag_ref" "${tag_ref}^{}"
)"
source_object="$(
  awk -v ref="$tag_ref" '$2 == ref { print $1 }' <<<"$source_refs"
)"
source_target="$(
  awk -v ref="${tag_ref}^{}" '$2 == ref { print $1 }' <<<"$source_refs"
)"
[[ "$source_object" =~ ^[0-9a-f]{40}$ ]] ||
  die "canonical tag object is missing: $tag_ref"
[[ "$source_target" =~ ^[0-9a-f]{40}$ ]] ||
  die "canonical tag is not annotated: $tag_ref"
[ "$source_object" != "$source_target" ] ||
  die "canonical tag object is not distinct from its target: $tag_ref"

scratch_ref="refs/codewire-mirror/${tag_ref#refs/tags/}"
cleanup() {
  git update-ref -d "$scratch_ref" >/dev/null 2>&1 || true
}
trap cleanup EXIT

git fetch --no-tags --force "$source_remote" \
  "+${tag_ref}:${scratch_ref}" >/dev/null
fetched_object="$(git rev-parse "$scratch_ref")"
fetched_target="$(git rev-parse "${scratch_ref}^{}")"
[ "$(git cat-file -t "$scratch_ref")" = tag ] ||
  die "fetched canonical ref is not an annotated tag object: $tag_ref"
[ "$fetched_object" = "$source_object" ] ||
  die "fetched tag object does not match canonical source: $tag_ref"
[ "$fetched_target" = "$source_target" ] ||
  die "fetched tag target does not match canonical source: $tag_ref"

mirror_refs="$(
  git ls-remote --tags "$mirror_remote" "$tag_ref" "${tag_ref}^{}"
)"
mirror_object="$(
  awk -v ref="$tag_ref" '$2 == ref { print $1 }' <<<"$mirror_refs"
)"
mirror_target="$(
  awk -v ref="${tag_ref}^{}" '$2 == ref { print $1 }' <<<"$mirror_refs"
)"

if [ -z "$mirror_object" ]; then
  printf 'mirror: pushing canonical annotated %s\n' "$tag_ref"
  git push "$mirror_remote" "$scratch_ref:$tag_ref"
  exit 0
fi

[ -n "$mirror_target" ] || mirror_target="$mirror_object"
[ "$mirror_target" = "$source_target" ] ||
  die "refusing to overwrite $tag_ref: canonical target $source_target differs from mirror target $mirror_target"
[ "$mirror_object" = "$source_object" ] ||
  die "refusing to overwrite $tag_ref: mirror does not contain the canonical annotated tag object"

printf 'mirror: canonical annotated %s is already current\n' "$tag_ref"
