# shellcheck shell=sh disable=SC2154
# Variables such as cw are set by src/common.sh, which scripts/build.sh puts above this step.
# A cloud sandbox that clones this project's origin, so only what is pushed
# goes in. Private repositories use your Codewire Git access; no credential
# from this machine is sent.
require_ssh_setup
resolve_root

trap '[ -n "${ok:-}" ] || "$cw" --cloud rm "$name" -y >/dev/null 2>&1 || true' EXIT
trap 'exit 1' INT TERM
# A project's codewire.yaml chooses the image; without one, use Codewire's
# workspace image, since the cloud does not pick one for a repository yet.
image=""
[ -f codewire.yaml ] || image="--image workspace"
# The clone has every branch of origin, so Orca can base its worktree on any.
# shellcheck disable=SC2086 # $image is empty or two words.
"$cw" --cloud create "$url::$root" --name "$name" $image -y >&2
ssh -o BatchMode=yes "$host" "git -C $(q "$root") rev-parse --verify -q HEAD >/dev/null" </dev/null >&2 ||
  die "the sandbox has no checkout at $root"

emit_target "$root"
ok=1
