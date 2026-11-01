#!/usr/bin/env bash
# The Dev smoke receipt is green only for a passing deploy-owned smoke. A
# failed smoke and a promotion that never committed a release (#3820) both
# fail it, naming what failed. The job has no checkout, so this runs the
# workflow's own validation step, extracted from the file.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/dev-deployment-smoke-receipt.yaml"
readonly TEST_SOURCE='1111111111111111111111111111111111111111'
readonly TEST_DEPLOY_COMMIT='2222222222222222222222222222222222222222'

fail() {
  printf '[test-dev-deployment-smoke-receipt] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The `run: |` block of the "Validate immutable receipt" step, dedented.
python3 -I - "$WORKFLOW" >"$work/validate.sh" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
step = next(i for i, line in enumerate(lines) if line.strip() == "- name: Validate immutable receipt")
run = next(i for i in range(step, len(lines)) if lines[i].strip() == "run: |")
indent = len(lines[run]) - len(lines[run].lstrip())
body = []
for line in lines[run + 1:]:
    if line.strip() and len(line) - len(line.lstrip()) <= indent:
        break
    body.append(line)
width = min(len(line) - len(line.lstrip()) for line in body if line.strip())
print("\n".join(line[width:] for line in body))
PY
grep -q 'promotion_failure' "$work/validate.sh" || fail 'the validation step was not extracted'
grep -qE '^ +- promotion_failure$' "$WORKFLOW" || fail 'smoke_status does not offer promotion_failure'

# receipt STATUS [SOURCE]: runs the step; prints its exit status, then output.
receipt() {
  local status=0
  SOURCE_SHA="${2:-$TEST_SOURCE}" DEPLOY_COMMIT="$TEST_DEPLOY_COMMIT" DEPLOY_RUN_ID=32261 \
    SMOKE_STATUS="$1" bash "$work/validate.sh" >"$work/out" 2>&1 || status=$?
  printf '%s\n' "$status"
}

[[ "$(receipt success)" == 0 ]] || fail "a passing smoke failed the receipt: $(cat "$work/out")"
grep -qF "Deploy run 32261 reported success for source $TEST_SOURCE at deploy commit $TEST_DEPLOY_COMMIT." "$work/out" ||
  fail 'a passing receipt did not name its run, source and deploy commit'

[[ "$(receipt failure)" == 1 ]] || fail 'a failed smoke passed the receipt'
grep -qF '::error::deploy-owned dev smoke failed' "$work/out" || fail 'a failed smoke did not say so'

[[ "$(receipt promotion_failure)" == 1 ]] || fail 'a failed promotion passed the receipt'
grep -qF "::error::deploy run 32261 did not promote source $TEST_SOURCE; Dev stays on its previous source" "$work/out" ||
  fail "a failed promotion did not name its run and source: $(cat "$work/out")"

[[ "$(receipt skipped)" == 2 ]] || fail 'an unknown status was accepted'
[[ "$(receipt success 0000000000000000000000000000000000000000)" != 0 ]] ||
  fail 'the zero source SHA was accepted'

printf '[test-dev-deployment-smoke-receipt] success, smoke failure and promotion failure receipts passed\n'
