#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/dev-deployment-smoke-receipt.yaml"

fail() {
  printf '[test-dev-deployment-smoke-receipt] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$WORKFLOW" ]] || fail "receipt workflow is missing"
if grep -qE '^permissions:' "$WORKFLOW"; then
  fail "receipt workflow relies on ignored GitHub permissions syntax"
fi
grep -Fq '    runs-on: ci-lite' "$WORKFLOW" ||
  fail "receipt does not use the credential-free validation profile"
grep -Fq '  workflow_dispatch:' "$WORKFLOW" ||
  fail "receipt is not an explicit deploy callback"
for input in source_sha deploy_commit deploy_run_id smoke_status; do
  grep -Fq "      $input:" "$WORKFLOW" ||
    fail "receipt input $input is missing"
done
grep -Fq '[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]' "$WORKFLOW" ||
  fail "source SHA is not closed-schema validated"
grep -Fq '[[ "$DEPLOY_COMMIT" =~ ^[0-9a-f]{40}$ ]]' "$WORKFLOW" ||
  fail "deploy commit is not closed-schema validated"
grep -Fq '[[ "$DEPLOY_RUN_ID" =~ ^[1-9][0-9]*$ ]]' "$WORKFLOW" ||
  fail "deploy run ID is not closed-schema validated"
grep -Fq '[[ "$SMOKE_STATUS" == "success" ]]' "$WORKFLOW" ||
  fail "failed deploy smoke does not make the receipt visibly red"

for forbidden in \
  'https://git.example.invalid/noel/actions-checkout@' \
  'kubectl' \
  'Infisical' \
  'CODEWIRE_DEV_' \
  'secrets.' \
  'vars.' \
  'http://' \
  'https://' \
  'gitea-upload-artifact'; do
  if grep -Fq "$forbidden" "$WORKFLOW"; then
    fail "receipt workflow crossed into execution/configuration: $forbidden"
  fi
done

printf '[test-dev-deployment-smoke-receipt] receipt boundary passed\n'
