#!/usr/bin/env bash
# End-to-end test of one recipe against real Codewire environments, driven the
# way Orca drives it: create, dial the exact target it printed, suspend,
# resume, dial again, destroy with the instance id only on stdin, and check
# that nothing is left. Needs a signed-in cw for cloud and `cw setup ssh`.
# Usage: integrations/orca/scripts/test-recipe.sh local
#        integrations/orca/scripts/test-recipe.sh cloud [PUBLIC_REPO_URL]
set -euo pipefail
plugin="$(cd "$(dirname "$0")/.." && pwd)"
placement="${1:-}"
case "$placement" in local | cloud) ;; *) echo "usage: $0 local|cloud [PUBLIC_REPO_URL]" >&2; exit 2 ;; esac
recipe="$plugin/recipes/$placement.json"
cmd() { jq -er --arg k "$1" '.[$k]' "$recipe"; }

work="$(mktemp -d "${TMPDIR:-/tmp}/orca-codewire-test.XXXXXX")"
id="orca-$(uuidgen | tr '[:upper:]' '[:lower:]')"
cleanup() { cw "--$placement" rm "$id" -y >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

step() { printf '\n== %s\n' "$*" >&2; }
fail() { printf 'FAIL: %b\n' "$*" >&2; exit 1; }
run() { # step, with stdin passed through
  (cd "$repo" && ORCA_VM_INSTANCE_ID="${2-$id}" ORCA_VM_MODE="$1" sh -c "$(cmd "$1")")
}

repo="$work/demo repo"
if [ "$placement" = local ]; then
  git init -q -b main "$repo"
  git -C "$repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "recipe test"
  git -C "$repo" remote add origin https://github.com/example/demo-repo.git
  # Credentials in a remote URL must not reach the VM.
  git -C "$repo" remote add fork https://user:s3cret-token@github.com/fork/demo-repo.git
  head="$(git -C "$repo" rev-parse HEAD)"
  remotes="$(git -C "$repo" remote -v | sed 's#user:s3cret-token@##')"
  root=/workspace
else
  url="${2:-https://github.com/codewiresh/examples.git}"
  git init -q -b main "$repo"
  git -C "$repo" remote add origin "$url"
  head="$(git ls-remote "$url" HEAD | cut -f1)"
  root="/workspace/$(basename "$url" .git)"
fi
selection_before="$(cw current --output json)"

dial() { # result-file command: runs command over exactly the emitted target
  local t
  t="$(jq -c .connection.target "$1")"
  ssh -o BatchMode=yes -o "ProxyCommand=$(jq -r .proxyCommand <<<"$t")" \
    -p "$(jq -r .port <<<"$t")" -- "$(jq -r .username <<<"$t")@$(jq -r .host <<<"$t")" "$2" </dev/null
}

check_result() { # file
  [ "$(wc -l <"$1" | tr -d ' ')" = 1 ] || fail "stdout must be exactly one line:\n$(cat "$1")"
  jq -e --arg root "$root" '.schemaVersion == 1 and .connection.type == "ssh"
    and .connection.projectRoot == $root and .connection.target.username == "codewire"' \
    "$1" >/dev/null || fail "unexpected result: $(cat "$1")"
  got="$(dial "$1" "git -C '$root' rev-parse HEAD")" || fail "could not dial $(cat "$1")"
  [ "$got" = "$head" ] || fail "checkout is at $got, expected $head"
  if [ "$placement" = local ]; then
    got="$(dial "$1" "git -C '$root' remote -v")"
    [ "$got" = "$remotes" ] || fail "remotes differ:\n$got\nexpected:\n$remotes"
    fs="$(dial "$1" "findmnt -no FSTYPE --target '$root'")"
    case "$fs" in ext4 | xfs | btrfs) ;; *) fail "$root is on $fs, not the VM's own disk" ;; esac
    # Orca bases the workspace on a branch: the checkout is on this one.
    got="$(dial "$1" "git -C '$root' symbolic-ref --short HEAD")"
    [ "$got" = main ] || fail "the VM's checkout is on '$got', expected main"
  fi
  echo "ok: $(cat "$1")" >&2
}

step "create $id"
time run create >"$work/create.json"
check_result "$work/create.json"
selection_after="$(cw current --output json)"
[ "$selection_after" = "$selection_before" ] ||
  fail "create changed the selected environment:\nbefore: $selection_before\nafter:  $selection_after"

step suspend
run suspend >"$work/suspend.out"
[ ! -s "$work/suspend.out" ] || fail "suspend wrote to stdout"
state="$(cw "--$placement" ls --output json | jq -r --arg n "$id" '.[] | select(.name == $n) | .state')"
[ "$state" = stopped ] || fail "state after suspend is '$state', expected stopped"

step resume
run resume >"$work/resume.json"
check_result "$work/resume.json"

step "destroy (instance id from stdin only)"
printf '{"instanceId":"%s"}' "$id" | run destroy ""
step "destroy again"
printf '{"instanceId":"%s"}' "$id" | run destroy "" || fail "a second destroy failed"
! cw "--$placement" ls --output json | jq -e --arg n "$id" 'any(.[]; .name == $n)' >/dev/null ||
  fail "$id still exists after destroy"

printf '\nPASS %s\n' "$placement" >&2
