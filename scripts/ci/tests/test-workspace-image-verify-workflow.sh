#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/workspace-image-verify.yaml"
readonly VERIFY="$ROOT/scripts/ci/verify/verify-workspace-image.sh"
readonly HELPER="$ROOT/scripts/ci/images/build-local-image.sh"
readonly AGENT_CONTRACT="$ROOT/scripts/ci/verify/workspace-agent-contract.sh"

fail() {
  printf '[test-workspace-image-verify-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$WORKFLOW" ]] || fail 'workspace-image verification workflow is missing'
[[ -x "$VERIFY" ]] || fail 'workspace-image verification script is not executable'
[[ -x "$HELPER" ]] || fail 'local Buildx image helper is missing'
[[ -x "$AGENT_CONTRACT" ]] || fail 'workspace agent contract is missing'
grep -q '^  pull_request:$' "$WORKFLOW" || fail 'verification must run for pull requests'
if grep -q '^  push:$\|^  workflow_dispatch:$\|secrets\.' "$WORKFLOW"; then
  fail 'verification must be pull-request-only and credential-free'
fi
grep -qF 'permissions:' "$WORKFLOW" || fail 'workflow does not declare permissions'
grep -qF 'contents: read' "$WORKFLOW" || fail 'workflow does not use read-only contents permission'
grep -qF 'scripts/ci/verify/verify-workspace-image.sh' "$WORKFLOW" ||
  fail 'workflow does not invoke the image verifier'
if grep -Eq 'docker (buildx )?build.*--push|docker push' "$VERIFY"; then
  fail 'verification must not publish an image'
fi
grep -qF 'scripts/ci/images/build-local-image.sh' "$VERIFY" ||
  fail 'verification does not use the isolated local-image helper'
grep -qF 'scripts/ci/tests/test-build-local-image.sh' "$WORKFLOW" ||
  fail 'workflow does not run the mocked helper contract'
grep -qF 'scripts/ci/tests/test-workspace-agent-contract.sh' "$WORKFLOW" ||
  fail 'workflow does not run the mocked PID/agent contract'
grep -qF 'scripts/ci/verify/rehearse-build-local-image.sh' "$WORKFLOW" ||
  fail 'workflow does not run the real no-load/load rehearsal'
grep -qF -- '--pids-limit=2048' "$VERIFY" ||
  fail 'nested workspace verification does not declare its PID limit'
grep -qF -- 'docker_bin" run --rm --interactive --pids-limit=2048' "$VERIFY" ||
  fail 'workspace verifier does not attach the streamed agent contract'
grep -qF 'scripts/ci/verify/workspace-agent-contract.sh' "$VERIFY" ||
  fail 'workspace verifier does not stream the PID/agent contract into the image'
# shellcheck disable=SC2016 # Match the literal in-container shell contract.
grep -qF 'IFS= read -r actual_pids_max < "$cgroup_root/pids.max"' "$AGENT_CONTRACT" ||
  fail 'workspace verification does not prove pids.max with a shell builtin'
grep -qF 'pids.current pids.max' "$AGENT_CONTRACT" ||
  fail 'workspace failure evidence omits bounded PID counters'
# shellcheck disable=SC2016 # Match the literal in-container shell contract.
grep -qF '"$cgroup_root/pids.events"' "$AGENT_CONTRACT" ||
  fail 'workspace failure evidence omits pids.events'
for agent in codex claude gemini kimi pi aider; do
  grep -qF "$agent" "$AGENT_CONTRACT" || fail "verification omits $agent"
done
grep -qF 'test -O' "$AGENT_CONTRACT" || fail 'verification does not prove user ownership'
grep -qF 'npm update --global --dry-run @openai/codex' "$AGENT_CONTRACT" ||
  fail 'verification does not prove the user-scoped Codex update path'

echo 'workspace-image verification workflow contract: OK'
