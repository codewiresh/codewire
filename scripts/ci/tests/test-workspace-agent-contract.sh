#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CONTRACT="$ROOT/scripts/ci/verify/workspace-agent-contract.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/workspace-agent-contract-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/cgroup" "$work/ssh/usr/sbin" "$work/system-sbin"
case "$(uname -m)" in
  x86_64) multiarch=x86_64-linux-gnu ;;
  aarch64) multiarch=aarch64-linux-gnu ;;
  *) printf 'unsupported test architecture\n' >&2; exit 1 ;;
esac
mkdir -p "$work/ssh/usr/lib/$multiarch"
touch "$work/ssh/usr/lib/$multiarch/libwrap.so.0"
fixture_uid="$(id -u)"

fail() {
  printf '[test-workspace-agent-contract] ERROR: %s\n' "$*" >&2
  exit 1
}

cat >"$work/bin/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -un) printf 'codewire\n' ;;
  -u) printf '1000\n' ;;
  -g) printf '%s\n' "${FAKE_CODEWIRE_GID:-1000}" ;;
  *) printf 'codewire\n' ;;
esac
EOF
cat >"$work/bin/getent" <<'EOF'
#!/bin/sh
[ "$*" = 'passwd codewire' ] || exit 99
printf 'codewire:x:1000:%s:Codewire:/home/codewire:/bin/bash\n' "${FAKE_CODEWIRE_PASSWD_GID:-1000}"
EOF
cat >"$work/bin/agent" <<'EOF'
#!/bin/sh
if [ "${FAIL_AGENT:-}" = "$(basename "$0")" ]; then
  exit 42
fi
if [ "$(basename "$0")" = codex ]; then
  printf 'codex-cli %s\n' "${FAKE_CODEX_VERSION:-0.149.0}"
else
  printf '%s test-version\n' "$(basename "$0")"
fi
EOF
cat >"$work/bin/npm" <<'EOF'
#!/bin/sh
if [ "$*" = "config get allow-scripts" ]; then
  printf '@anthropic-ai/claude-code\n'
  exit 0
fi
case "$*" in
  'config get prefix') printf '/home/codewire/.npm-global\n' ;;
  'install --global --dry-run --ignore-scripts --no-audit --no-fund @openai/codex@0.149.0')
    [ -f "$FAKE_PREFIX_STATE" ] || exit 254
    printf 'npm dry-run OK\n' ;;
  '--version') printf 'npm test-version\n' ;;
  *) exit 97 ;;
esac
EOF
cat >"$work/bin/mkdir" <<'EOF'
#!/bin/sh
# The host-side fake must never create a real workspace user's home directory.
[ "$*" = '-p /home/codewire/.npm-global/lib' ] || exit 99
printf 'lib-prepared\n' >"$FAKE_PREFIX_STATE"
EOF
chmod +x "$work/bin/id" "$work/bin/getent" "$work/bin/agent" "$work/bin/npm" "$work/bin/mkdir"
cat >"$work/ssh/usr/sbin/sshd" <<'EOF'
#!/bin/sh
[ "$*" = -V ] || exit 99
case "$LD_LIBRARY_PATH" in "$FAKE_SSH_ROOT/usr/lib/"*) ;; *) exit 98 ;; esac
[ "${FAIL_SSH_LOADER:-false}" = false ] || exit 127
printf 'OpenSSH_9.6p1, synthetic loader fixture\n' >&2
EOF
cat >"$work/bin/find" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${FAIL_SSH_FIND:-false}" = false ]] || exit 42
[[ "$1" == "$FAKE_SSH_ROOT" ]] || exit 99
# Host tests cannot chown files to root. Translate only the expected uid in the
# real find predicate; permission, key-file and unexpected-owner checks remain.
args=("$@")
for ((i=0; i<${#args[@]}-1; i++)); do
  if [[ "${args[i]}" == -uid && "${args[i+1]}" == 0 ]]; then
    args[i+1]="${FAKE_SSH_EXPECTED_UID:-$FAKE_FIXTURE_UID}"
  fi
done
exec /usr/bin/find "${args[@]}"
EOF
chmod +x "$work/bin/find" "$work/ssh/usr/sbin/sshd"
chmod -R go-w "$work/ssh"
for agent in codex claude gemini kimi pi aider; do
  ln -s agent "$work/bin/$agent"
done
for tool in cw docker dockerd docker-compose gh git go gopls hcloud \
  node bun bun""x pnpm yarn python3 pipx poetry uv cargo rustc psql protoc; do
  ln -s agent "$work/bin/$tool"
done

run_contract() {
  env PATH="$work/bin:$PATH" \
    CODEWIRE_CGROUP_ROOT="$work/cgroup" \
    CODEWIRE_BIN_ROOT="$work/bin" \
    CODEWIRE_SSH_FIXTURE_ROOT="$work/ssh" \
    CODEWIRE_SYSTEM_SBIN_ROOT="$work/system-sbin" \
    CODEWIRE_EXPECTED_PIDS_MAX=2048 \
    FAKE_CODEWIRE_GID="${FAKE_CODEWIRE_GID:-1000}" \
    FAKE_CODEWIRE_PASSWD_GID="${FAKE_CODEWIRE_PASSWD_GID:-1000}" \
    FAIL_AGENT="${FAIL_AGENT:-}" \
    FAKE_CODEX_VERSION="${FAKE_CODEX_VERSION:-0.149.0}" \
    FAKE_PREFIX_STATE="$work/prefix-state" \
    FAKE_FIXTURE_UID="$fixture_uid" \
    FAKE_SSH_EXPECTED_UID="${FAKE_SSH_EXPECTED_UID:-$fixture_uid}" \
    FAKE_SSH_ROOT="$work/ssh" \
    FAIL_SSH_LOADER="${FAIL_SSH_LOADER:-false}" \
    FAIL_SSH_FIND="${FAIL_SSH_FIND:-false}" \
    bash "$CONTRACT" "$@"
}

printf '8\n' >"$work/cgroup/pids.current"
printf '2048\n' >"$work/cgroup/pids.max"
printf 'max 0\n' >"$work/cgroup/pids.events"
run_contract >"$work/success.out" 2>"$work/success.err"
[[ ! -s "$work/success.err" ]] || fail 'successful contract emitted failure evidence'
grep -Fxq 'codex-cli 0.149.0' "$work/success.out" || fail 'agent checks did not run'
grep -Fxq 'npm dry-run OK' "$work/success.out" || fail 'Codex install-plan check did not run'
grep -Fxq 'workspace image verification: inert SSH fixture contract passed' "$work/success.out" ||
  fail 'prepared SSH fixture was not checked'

if FAKE_CODEWIRE_GID=1001 run_contract >"$work/process-gid.out" 2>"$work/process-gid.err"; then
  fail 'process GID drift was accepted'
fi
if FAKE_CODEWIRE_PASSWD_GID=1001 run_contract >"$work/passwd-gid.out" 2>"$work/passwd-gid.err"; then
  fail 'passwd GID drift was accepted'
fi

for ssh_failure in missing-server writable-server wrong-owner host-key system-server missing-library loader find; do
  (
    case "$ssh_failure" in
      missing-server) chmod -x "$work/ssh/usr/sbin/sshd" ;;
      writable-server) chmod o+w "$work/ssh/usr/sbin/sshd" ;;
      wrong-owner) FAKE_SSH_EXPECTED_UID=4294967294 ;;
      host-key) touch "$work/ssh/ssh_host_ed25519_key" ;;
      system-server) touch "$work/system-sbin/sshd" ;;
      missing-library) mv "$work/ssh/usr/lib/$multiarch/libwrap.so.0" "$work/libwrap.saved" ;;
      loader) FAIL_SSH_LOADER=true ;;
      find) FAIL_SSH_FIND=true ;;
    esac
    if run_contract >"$work/ssh-failure.out" 2>"$work/ssh-failure.err"; then
      fail "invalid prepared SSH fixture was accepted: $ssh_failure"
    fi
  )
  chmod 0755 "$work/ssh/usr/sbin/sshd"
  rm -f "$work/ssh/ssh_host_ed25519_key" "$work/system-sbin/sshd"
  if [[ -e "$work/libwrap.saved" ]]; then
    mv "$work/libwrap.saved" "$work/ssh/usr/lib/$multiarch/libwrap.so.0"
  fi
done

if FAKE_CODEX_VERSION=0.145.0 run_contract >"$work/stale.out" 2>"$work/stale.err"; then
  fail 'stale Codex version was accepted'
fi
for argument in --unknown '--mounted-home-agents extra'; do
  set +e
  # shellcheck disable=SC2086 # Deliberately exercise both one and two arguments.
  run_contract $argument >"$work/argument.out" 2>"$work/argument.err"
  status=$?
  set -e
  [[ "$status" -eq 2 ]] || fail 'invalid contract arguments were accepted'
done

printf '1\n' >"$work/cgroup/pids.max"
: >"$work/cgroup/pids.events"
for i in $(seq 1 20); do
  printf 'event_%02d %d\n' "$i" "$i" >>"$work/cgroup/pids.events"
done
set +e
run_contract >"$work/mismatch.out" 2>"$work/mismatch.err"
status=$?
set -e
[[ "$status" -eq 1 ]] || fail "pids.max mismatch returned $status instead of 1"
[[ ! -s "$work/mismatch.out" ]] || fail 'pids.max mismatch reached agent checks'
[[ "$(wc -l <"$work/mismatch.err")" -eq 18 ]] ||
  fail 'PID evidence was not bounded to two counters and 16 event lines'
if grep -Ev '^workspace image verification: (pids\.current|pids\.max|pids\.events)=' "$work/mismatch.err" | grep -q .; then
  fail 'failure output contained non-PID evidence'
fi

printf '2048\n' >"$work/cgroup/pids.max"
printf 'max 3\n' >"$work/cgroup/pids.events"
set +e
FAIL_AGENT=codex run_contract >"$work/agent-failure.out" 2>"$work/agent-failure.err"
status=$?
set -e
[[ "$status" -eq 42 ]] || fail "agent failure status was not preserved: $status"
grep -Fxq 'workspace image verification: pids.current=8' "$work/agent-failure.err" ||
  fail 'agent failure omitted pids.current'
grep -Fxq 'workspace image verification: pids.max=2048' "$work/agent-failure.err" ||
  fail 'agent failure omitted pids.max'
grep -Fxq 'workspace image verification: pids.events=max 3' "$work/agent-failure.err" ||
  fail 'agent failure omitted pids.events'

echo 'workspace agent PID contract: OK'
