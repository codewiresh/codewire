# shellcheck shell=sh disable=SC2154
# Variables such as cw are set by src/common.sh, which scripts/build.sh puts above this step.
# Stopping keeps the environment's disk; resume starts it again.
"$cw" "--$placement" stop "$name" >&2
