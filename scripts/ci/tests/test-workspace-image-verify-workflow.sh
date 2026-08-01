#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/workspace-image-verify.yaml"
readonly VERIFY="$ROOT/scripts/ci/verify/verify-workspace-image.sh"

fail() {
  printf '[test-workspace-image-verify-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$WORKFLOW" ]] || fail 'workspace-image verification workflow is missing'
[[ -x "$VERIFY" ]] || fail 'workspace-image verification script is not executable'
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
grep -qF 'docker buildx build' "$VERIFY" ||
  fail 'verification does not use the explicit Buildx invocation'
grep -qF -- '--load' "$VERIFY" ||
  fail 'verification does not load the built image for local inspection'
for agent in codex claude gemini kimi pi aider; do
  grep -qF "$agent" "$VERIFY" || fail "verification omits $agent"
done
grep -qF 'test -O' "$VERIFY" || fail 'verification does not prove user ownership'
grep -qF 'npm update --global --dry-run @openai/codex' "$VERIFY" ||
  fail 'verification does not prove the user-scoped Codex update path'

echo 'workspace-image verification workflow contract: OK'
