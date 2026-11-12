#!/usr/bin/env bash
# Runs every recipe step the way Orca does (sh -c in the project, ORCA_* in the
# environment) against stub `cw` and `ssh`, and checks what each step prints
# and runs. Needs bash, jq and git; shellcheck when it is installed.
# Usage: integrations/orca/tests/test-recipes.sh
set -euo pipefail
plugin="$(cd "$(dirname "$0")/.." && pwd)"

"$plugin/scripts/build.sh" --check

work="$(mktemp -d "${TMPDIR:-/tmp}/orca-recipes.XXXXXX")"
trap 'rm -rf "$work"' EXIT
stub="$work/bin"
log="$work/calls"
mkdir "$stub"
passed=0

fail() { printf 'FAIL: %s\n' "$*" >&2; [ ! -s "$log" ] || sed 's/^/  call: /' "$log" >&2; exit 1; }
ok() { passed=$((passed + 1)); printf 'ok   %s\n' "$*"; }

# STUB_CREATE, STUB_RM and STUB_SSH set an exit status; STUB_LS is the
# inventory `cw ls --output json` prints; STUB_NO_SETUP hides the SSH block;
# STUB_PUSH_FAIL refuses
# the push into the VM, whose checkout `ssh` serves from STUB_VM.
cat >"$stub/cw" <<'EOF'
#!/bin/sh
printf 'cw %s\n' "$*" >>"$STUB_LOG"
case " $* " in
  *" create "*) exit "${STUB_CREATE:-0}" ;;
  *" rm "*) exit "${STUB_RM:-0}" ;;
  *" ls "*) printf '%s\n' "${STUB_LS:-[]}" ;;
esac
EOF
cat >"$stub/ssh" <<'EOF'
#!/bin/sh
if [ "$1" = -G ]; then
  [ -n "${STUB_NO_SETUP:-}" ] && exit 0
  printf 'proxycommand /usr/bin/cw --local shell --stdio %%n\nknownhostscommand /usr/bin/cw ssh known-hosts %%H\n'
  exit 0
fi
printf 'ssh %s\n' "$*" >>"$STUB_LOG"
case "$*" in
  *git-receive-pack*)
    [ -z "${STUB_PUSH_FAIL:-}" ] || exit 1
    exec git-receive-pack "$STUB_VM"
    ;;
esac
exit "${STUB_SSH:-0}"
EOF
chmod +x "$stub/cw" "$stub/ssh"
# A stub that cannot run, as under a noexec TMPDIR, would let the steps reach
# the real cw and ssh and create real environments: stop first.
for tool in cw ssh; do
  [ "$(PATH="$stub:$PATH" command -v "$tool")" = "$stub/$tool" ] || {
    echo "test-recipes: the stub $tool in $stub cannot run (a noexec TMPDIR?); set TMPDIR to a directory that allows executing files" >&2
    exit 1
  }
done

repo="$work/demo-repo"
git init -q -b main "$repo"
git -C "$repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m test
git -C "$repo" remote add origin https://user:s3cret@github.com/example/demo-repo.git
git -C "$repo" remote add upstream git@github.com:upstream/demo-repo.git
git -C "$repo" update-ref refs/remotes/origin/main HEAD
git -C "$repo" symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main
# The VM's checkout as a clone leaves it: the commit, detached, no branches.
vm="$work/vm-checkout"
git clone -q "$repo" "$vm"
git -C "$vm" checkout -q --detach
git -C "$vm" update-ref -d refs/heads/main
git -C "$vm" remote remove origin

id=orca-0b0e8f4e-1c55-4f0e-9a51-6a3c3d4c2f10

run() { # placement step [dir], with stdin passed through
  local placement="$1" step="$2" dir="${3:-$repo}"
  : >"$log"
  (cd "$dir" && env PATH="$stub:$PATH" STUB_LOG="$log" STUB_VM="$vm" ORCA_VM_MODE="$step" \
    sh -c "$(jq -r --arg s "$step" '.[$s]' "$plugin/recipes/$placement.json")")
}

expect_target() { # file placement root
  [ "$(wc -l <"$1" | tr -d ' ')" = 1 ] || fail "$2: stdout is not exactly one line: $(cat "$1")"
  jq -e --arg host "cw-$2-$id" --arg root "$3" --arg proxy "$stub/cw --$2 shell --stdio %n" '
    . == {schemaVersion: 1, connection: {type: "ssh", projectRoot: $root,
      target: {label: ($host | ltrimstr("cw-local-") | ltrimstr("cw-cloud-")), host: $host,
               port: 22, username: "codewire", proxyCommand: $proxy}}}' "$1" >/dev/null ||
    fail "$2: unexpected target: $(cat "$1")"
}

called() { grep -qF -- "$1" "$log" || fail "expected a call containing: $1"; }
not_called() { ! grep -qF -- "$1" "$log" || fail "unexpected call containing: $1"; }

# Create.
ORCA_VM_INSTANCE_ID="$id" run local create >"$work/out"
expect_target "$work/out" local /workspace
called "cw --local create --path . --path-mode clone --name $id --no-network -y"
called "remote add 'origin' 'https://github.com/example/demo-repo.git'"
called "remote add 'upstream' 'git@github.com:upstream/demo-repo.git'"
called "symbolic-ref 'refs/remotes/origin/HEAD' 'refs/remotes/origin/main'"
called "checkout -q 'main'"
not_called s3cret
not_called " rm "
for ref in refs/heads/main refs/remotes/origin/main; do
  [ "$(git -C "$vm" rev-parse -q --verify "$ref")" = "$(git -C "$repo" rev-parse HEAD)" ] ||
    fail "the VM's checkout has no $ref"
done
not_called "--profile"
ok "local create clones the project with no profile, sends its branches and remotes without credentials, and prints the target"

ORCA_VM_INSTANCE_ID="$id" run cloud create >"$work/out"
expect_target "$work/out" cloud /workspace/demo-repo
called "cw --cloud create https://github.com/example/demo-repo.git::/workspace/demo-repo --name $id --image workspace -y"
not_called s3cret
ok "cloud create clones origin without its credentials and prints the target"

# Create failures clean up after themselves and print nothing.
for placement in local cloud; do
  if STUB_CREATE=1 ORCA_VM_INSTANCE_ID="$id" run "$placement" create >"$work/out" 2>/dev/null; then
    fail "$placement create succeeded when cw create failed"
  fi
  [ ! -s "$work/out" ] || fail "$placement: a failed create printed: $(cat "$work/out")"
  called "cw --$placement rm $id -y"
  if STUB_SSH=255 ORCA_VM_INSTANCE_ID="$id" run "$placement" create >"$work/out" 2>/dev/null; then
    fail "$placement create succeeded when the environment could not be reached"
  fi
  called "cw --$placement rm $id -y"
done
if STUB_PUSH_FAIL=1 ORCA_VM_INSTANCE_ID="$id" run local create >"$work/out" 2>/dev/null; then
  fail "local create succeeded when its branches could not be sent"
fi
[ ! -s "$work/out" ] || fail "a local create whose push failed printed: $(cat "$work/out")"
called "cw --local rm $id -y"
ok "a create that fails removes the environment and prints no target"

# Refusals before anything is created.
refused() { # message placement step [dir], ORCA_* and STUB_* from the caller
  local message="$1"; shift
  if run "$@" >"$work/out" 2>"$work/err"; then fail "expected a refusal: $message"; fi
  grep -qF -- "$message" "$work/err" || fail "expected '$message', got: $(cat "$work/err")"
  not_called "create"
}
STUB_NO_SETUP=1 ORCA_VM_INSTANCE_ID="$id" refused "run \`cw setup ssh\`" local create
ORCA_VM_INSTANCE_ID=bad refused "no Orca instance id" local create
ORCA_VM_INSTANCE_ID="orca-x;rm" refused "unexpected Orca instance id" local create
mkdir "$work/plain"
ORCA_VM_INSTANCE_ID="$id" refused "not a Git repository" local create "$work/plain"
git init -q "$work/no-origin"
ORCA_VM_INSTANCE_ID="$id" refused "no origin remote" cloud create "$work/no-origin"
ok "create refuses without the SSH block, a valid instance id, a repository or an origin"

# Suspend and resume.
ORCA_VM_INSTANCE_ID="$id" run local suspend >"$work/out"
[ ! -s "$work/out" ] || fail "suspend printed: $(cat "$work/out")"
called "cw --local stop $id"
ORCA_VM_INSTANCE_ID="$id" run cloud resume >"$work/out"
expect_target "$work/out" cloud /workspace/demo-repo
called "cw --cloud start $id"
ok "suspend stops quietly; resume starts and prints the target again"

# Destroy, with the instance id only in the lifecycle JSON.
printf '{"instanceId":"%s","recipeId":"codewire-local"}' "$id" | run local destroy >"$work/out"
called "cw --local rm $id -y"
[ ! -s "$work/out" ] || fail "destroy printed: $(cat "$work/out")"
printf '{"instanceId":"%s"}' "$id" | STUB_RM=1 run cloud destroy >/dev/null 2>&1 ||
  fail "destroy of an environment that is already gone failed"
if printf '{"instanceId":"%s"}' "$id" |
  STUB_RM=1 STUB_LS="[{\"name\": \"$id\"}]" run cloud destroy >/dev/null 2>&1; then
  fail "destroy succeeded while the environment still exists"
fi
ok "destroy reads the id from stdin, is safe to retry, and fails while the environment remains"

# Lint the scripts exactly as Orca runs them.
if command -v shellcheck >/dev/null; then
  for placement in local cloud; do
    for step in create suspend resume destroy; do
      jq -r --arg s "$step" '.[$s]' "$plugin/recipes/$placement.json" >"$work/$placement-$step.sh"
      shellcheck -s sh "$work/$placement-$step.sh" || fail "shellcheck: $placement $step"
    done
  done
  ok "shellcheck passes for every step"
fi

printf 'PASS: %d checks\n' "$passed"
