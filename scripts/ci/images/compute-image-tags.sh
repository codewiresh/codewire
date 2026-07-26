#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 6 ]; then
  echo "Usage: $0 REGISTRY IMAGE SOURCE_SHA RELEASE_TAG REF REF_NAME" >&2
  exit 2
fi

registry="$1"
image="$2"
source_sha="$3"
release_tag="$4"
ref="$5"
ref_name="$6"

[[ "$source_sha" =~ ^[0-9a-f]{40}$ || "$source_sha" =~ ^[0-9a-f]{64}$ ]] || {
  echo "image tag computation requires an exact source object ID" >&2
  exit 1
}
if [ -n "$release_tag" ] && [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid release tag: $release_tag" >&2
  exit 1
fi
printf '%s/codewire/%s:%s\n' "$registry" "$image" "$source_sha"
if [ -n "$release_tag" ]; then
  printf '%s/codewire/%s:%s\n' "$registry" "$image" "$release_tag"
  exit 0
fi

case "$ref" in
  refs/tags/v*)
    printf '%s/codewire/%s:%s\n' "$registry" "$image" "${ref_name:-${ref#refs/tags/}}"
    ;;
esac
