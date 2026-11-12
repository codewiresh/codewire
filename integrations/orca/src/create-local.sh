# shellcheck shell=sh disable=SC2154
# Variables such as cw are set by src/common.sh, which scripts/build.sh puts above this step.
# A local VM from the committed state of this checkout. The clone never mounts
# the project, so the VM cannot change files that Git on this machine runs.
require_ssh_setup
resolve_root

trap '[ -n "${ok:-}" ] || "$cw" --local rm "$name" -y >/dev/null 2>&1 || true' EXIT
trap 'exit 1' INT TERM
# No Mesh network: a saved selection whose Mesh is down would fail the create.
# No credential profile: one with a GitHub connection rewrites the remote URLs
# Git reports, and Orca would no longer match the VM's checkout to this
# project (#3997 retires that rewrite).
"$cw" --local create --path . --path-mode clone --name "$name" --no-network -y >&2

# Orca bases the workspace's worktree on a branch, and the clone has only a
# detached HEAD: send this checkout's branches and remote-tracking refs over
# the same SSH host. No credential is involved.
GIT_SSH_COMMAND="ssh -o BatchMode=yes" git push --quiet "$host:$root" \
  'refs/heads/*:refs/heads/*' 'refs/remotes/*:refs/remotes/*' </dev/null >&2 ||
  die "could not copy this checkout's branches into the VM"

# Orca matches the VM's checkout to this project by its Git remotes, and the
# clone has none. Credentials in http(s) URLs stay on this machine. A remote's
# HEAD arrives as a plain ref, so it is made symbolic again, as it is here.
setup=""
for remote in $(git remote); do
  url="$(git remote get-url "$remote" | sed -E 's#^(https?://)[^/@]*@#\1#')"
  setup="$setup git -C $(q "$root") remote add $(q "$remote") $(q "$url") &&"
  if head="$(git symbolic-ref -q "refs/remotes/$remote/HEAD")"; then
    setup="$setup git -C $(q "$root") update-ref -d $(q "refs/remotes/$remote/HEAD") &&"
    setup="$setup git -C $(q "$root") symbolic-ref $(q "refs/remotes/$remote/HEAD") $(q "$head") &&"
  fi
done
# The VM's checkout is at this checkout's commit; put it on the same branch.
if branch="$(git symbolic-ref -q --short HEAD)"; then
  setup="$setup git -C $(q "$root") checkout -q $(q "$branch") &&"
fi
ssh -o BatchMode=yes "$host" "$setup git -C $(q "$root") rev-parse --verify -q HEAD >/dev/null" </dev/null >&2 ||
  die "the VM has no checkout at $root"

emit_target "$root"
ok=1
