#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CONTRACT="$ROOT/scripts/ci/verify/workspace-agent-contract.sh"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/workspace-agent-contract-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/cgroup"

fail() {
  printf '[test-workspace-agent-contract] ERROR: %s\n' "$*" >&2
  exit 1
}

cat >"$work/bin/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -un) printf 'codewire\n' ;;
  -u) printf '1000\n' ;;
  *) printf 'codewire\n' ;;
esac
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
chmod +x "$work/bin/id" "$work/bin/agent" "$work/bin/npm" "$work/bin/mkdir"
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
    CODEWIRE_EXPECTED_PIDS_MAX=2048 \
    FAIL_AGENT="${FAIL_AGENT:-}" \
    FAKE_CODEX_VERSION="${FAKE_CODEX_VERSION:-0.149.0}" \
    FAKE_PREFIX_STATE="$work/prefix-state" \
    bash "$CONTRACT" "$@"
}

printf '8\n' >"$work/cgroup/pids.current"
printf '2048\n' >"$work/cgroup/pids.max"
printf 'max 0\n' >"$work/cgroup/pids.events"
run_contract >"$work/success.out" 2>"$work/success.err"
[[ ! -s "$work/success.err" ]] || fail 'successful contract emitted failure evidence'
grep -Fxq 'codex-cli 0.149.0' "$work/success.out" || fail 'agent checks did not run'
grep -Fxq 'npm dry-run OK' "$work/success.out" || fail 'Codex install-plan check did not run'

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
