# shellcheck shell=sh disable=SC2154
# Variables such as placement are set above this file; see scripts/build.sh.
set -eu
# Shared by every step. scripts/build.sh puts `placement=local` or
# `placement=cloud` above it, and the step's own script below it.

die() { printf 'codewire: %s\n' "$*" >&2; exit 1; }

# Single-quotes a value for the remote shell.
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# Orca's instance id (orca-<uuid>) names the environment. destroy can get it
# only from the lifecycle JSON on stdin, when the create never returned.
name="${ORCA_VM_INSTANCE_ID:-}"
if [ -z "$name" ] && [ "${ORCA_VM_MODE:-}" = destroy ]; then
  name="$(sed -n 's/.*"instanceId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi
case "$name" in
  orca-*[!a-z0-9-]* | orca-) die "unexpected Orca instance id: $name" ;;
  orca-*) ;;
  *) die "no Orca instance id in ORCA_VM_INSTANCE_ID" ;;
esac
host="cw-$placement-$name"

# Orca started from a desktop launcher may not have the login shell's PATH.
cw="$(command -v cw 2>/dev/null || true)"
for candidate in "$HOME/.local/bin/cw" /usr/local/bin/cw /opt/homebrew/bin/cw; do
  [ -z "$cw" ] && [ -x "$candidate" ] && cw="$candidate"
done
[ -n "$cw" ] || die "cw is not installed; see https://codewire.sh/docs/install/"
# The path goes into an OpenSSH ProxyCommand and a JSON string unquoted.
case "$cw" in
  *[!A-Za-z0-9/._+-]*) die "cw is at a path with spaces or quotes, which Orca's SSH command cannot carry: $cw" ;;
esac

# Orca dials the host through the block `cw setup ssh` writes, which supplies
# the user and the environment's recorded host key.
require_ssh_setup() {
  config="$(ssh -G "$host" 2>/dev/null || true)"
  if ! printf '%s\n' "$config" | grep -qi '^proxycommand .* shell --stdio' ||
    ! printf '%s\n' "$config" | grep -qi '^knownhostscommand '; then
    die "the Codewire SSH hosts are not set up or are out of date; run \`cw setup ssh\`"
  fi
}

# The checkout Orca works in. A local VM clones this project to /workspace; a
# cloud sandbox clones origin to /workspace/<repository>. Sets url for cloud.
# shellcheck disable=SC2034 # root is read by the steps that call this.
resolve_root() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not a Git repository: $PWD"
  if [ "$placement" = local ]; then
    root=/workspace
    return
  fi
  url="$(git remote get-url origin 2>/dev/null)" ||
    die "this repository has no origin remote for the sandbox to clone"
  case "$url" in
    http://* | https://* | ssh://* | git@*:*) ;;
    *) die "origin is not a URL a cloud sandbox can clone: $url" ;;
  esac
  url="$(printf '%s' "$url" | sed -E 's#^(https?://)[^/@]*@#\1#')"
  repo="$(basename "$url" .git)"
  case "$repo" in
    '' | *[!A-Za-z0-9._-]*) die "cannot name a checkout after origin: $url" ;;
  esac
  root="/workspace/$repo"
}

# Prints the one JSON object Orca reads from create and resume.
emit_target() { # project_root
  printf '{"schemaVersion":1,"connection":{"type":"ssh","projectRoot":"%s","target":{"label":"%s","host":"%s","port":22,"username":"codewire","proxyCommand":"%s --%s shell --stdio %%n"}}}\n' \
    "$1" "$name" "$host" "$cw" "$placement"
}
