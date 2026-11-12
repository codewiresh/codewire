# shellcheck shell=sh disable=SC2154
# Variables such as cw are set by src/common.sh, which scripts/build.sh puts above this step.
# Safe to retry: an environment that is already gone counts as removed.
if ! "$cw" "--$placement" rm "$name" -y >&2; then
  inventory="$("$cw" "--$placement" ls --output json)" ||
    die "could not remove $name, nor list environments to see whether it is gone"
  ! printf '%s' "$inventory" | grep -q "\"name\": *\"$name\"" ||
    die "could not remove $name"
fi
