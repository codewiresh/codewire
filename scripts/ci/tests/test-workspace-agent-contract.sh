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
printf 'codewire\n'
EOF
cat >"$work/bin/agent" <<'EOF'
#!/bin/sh
if [ "${FAIL_AGENT:-}" = "$(basename "$0")" ]; then
  exit 42
fi
printf '%s test-version\n' "$(basename "$0")"
EOF
cat >"$work/bin/npm" <<'EOF'
#!/bin/sh
printf 'npm dry-run OK\n'
EOF
chmod +x "$work/bin/id" "$work/bin/agent" "$work/bin/npm"
for agent in codex claude gemini kimi pi aider; do
  ln -s agent "$work/bin/$agent"
done

run_contract() {
  env PATH="$work/bin:$PATH" \
    CODEWIRE_CGROUP_ROOT="$work/cgroup" \
    CODEWIRE_EXPECTED_PIDS_MAX=2048 \
    FAIL_AGENT="${FAIL_AGENT:-}" \
    bash "$CONTRACT"
}

printf '8\n' >"$work/cgroup/pids.current"
printf '2048\n' >"$work/cgroup/pids.max"
printf 'max 0\n' >"$work/cgroup/pids.events"
run_contract >"$work/success.out" 2>"$work/success.err"
[[ ! -s "$work/success.err" ]] || fail 'successful contract emitted failure evidence'
grep -Fxq 'codex test-version' "$work/success.out" || fail 'agent checks did not run'
grep -Fxq 'npm dry-run OK' "$work/success.out" || fail 'Codex update check did not run'

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
