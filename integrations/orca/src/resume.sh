# shellcheck shell=sh disable=SC2154
# Variables such as cw are set by src/common.sh, which scripts/build.sh puts above this step.
require_ssh_setup
resolve_root
"$cw" "--$placement" start "$name" >&2
emit_target "$root"
