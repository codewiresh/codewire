#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly WORKFLOW="$ROOT/.gitea/workflows/source-approval.yml"

fail() {
  printf '[test-source-approval-workflow] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -f "$WORKFLOW" ]] || fail 'source-approval workflow is missing'
grep -Fq 'runs-on: ci-lite' "$WORKFLOW" ||
  fail 'source approval does not use the credential-free validation profile'
grep -Fq 'EXPECTED_SUPPLYCHAIN: ee0abebcd79661e59b02a22688d929dffa4b9506' \
  "$WORKFLOW" || fail 'sealed Supplychain revision changed without review'
grep -Fq 'Candidate files are scanned as data only' "$WORKFLOW" ||
  fail 'candidate-as-data boundary is undocumented'
if grep -Fq -- '--osv-offline' "$WORKFLOW"; then
  fail 'workflow requests an incomplete ecosystem-specific offline database'
fi

for input in \
  '.supplychain/source-policy.json' \
  '.gitleaks.toml' \
  '.supplychain/bun-baseline.json'; do
  [[ -f "$ROOT/$input" && ! -L "$ROOT/$input" ]] ||
    fail "canonical source-approval input is not a regular file: $input"
  git -C "$ROOT" ls-files --error-unmatch "$input" >/dev/null ||
    fail "canonical source-approval input is not tracked: $input"
  grep -Fq "\$GITHUB_WORKSPACE/.source-approval-base/$input" "$WORKFLOW" ||
    fail "protected base does not own $input"
done
grep -Fq '[[ -f "$source" && ! -L "$source" ]]' "$WORKFLOW" ||
  fail 'trusted policy inputs do not reject symlinks and missing files'
grep -Fq -- '--source-policy="$source_policy"' "$WORKFLOW" ||
  fail 'source policy is not passed explicitly'
grep -Fq -- '--gitleaks-config="$gitleaks_config"' "$WORKFLOW" ||
  fail 'reviewed Gitleaks policy is not passed explicitly'
grep -Fq -- '--baseline="$bun_baseline"' "$WORKFLOW" ||
  fail 'reviewed Bun baseline is not passed explicitly'
readonly INSTALL_COMMAND=install
if grep -Eq "npm (ci|${INSTALL_COMMAND})|bun ${INSTALL_COMMAND}|cargo (build|run|test)|docker (build|run)" \
    "$WORKFLOW"; then
  fail 'source approval executes a candidate build or dependency installer'
fi

printf '[test-source-approval-workflow] PASS\n'
