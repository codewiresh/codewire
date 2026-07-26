#!/usr/bin/env bash
# Mirror local tags without rewriting an existing remote tag that already
# resolves to the same object.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: mirror-git-tags.sh REMOTE

Pushes missing local tags to REMOTE. Existing remote tags are left unchanged
when their fully peeled target matches the local tag. A tag whose target
differs fails closed and is never overwritten.
EOF
}

if [ "$#" -ne 1 ] || [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  [ "$#" -eq 1 ] && exit 0
  exit 2
fi

remote="$1"

declare -A remote_objects=()
declare -A remote_targets=()

while read -r object ref; do
  [ -n "${object:-}" ] && [ -n "${ref:-}" ] || continue
  case "$ref" in
    refs/tags/*'^{}')
      remote_targets["${ref%\^\{\}}"]="$object"
      ;;
    refs/tags/*)
      remote_objects["$ref"]="$object"
      ;;
  esac
done < <(git ls-remote --tags "$remote")

while IFS= read -r local_ref; do
  [ -n "$local_ref" ] || continue

  local_object="$(git rev-parse "$local_ref")"
  local_target="$(git rev-parse "${local_ref}^{}")"
  remote_object="${remote_objects[$local_ref]-}"

  if [ -z "$remote_object" ]; then
    echo "mirror: pushing missing $local_ref"
    git push "$remote" "$local_ref:$local_ref"
    continue
  fi

  remote_target="${remote_targets[$local_ref]-$remote_object}"
  if [ "$remote_target" != "$local_target" ]; then
    echo "error: refusing to overwrite $local_ref: local target $local_target differs from remote target $remote_target" >&2
    exit 1
  fi

  if [ "$remote_object" != "$local_object" ]; then
    echo "mirror: $local_ref already resolves to $local_target; preserving the remote tag object"
  else
    echo "mirror: $local_ref is already current"
  fi
done < <(git for-each-ref --format='%(refname)' refs/tags)
