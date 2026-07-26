#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

fail=0

active_paths=(
  ".gitea/**"
  "apps/**/Dockerfile"
  "apps/**/Dockerfile.*"
  "apps/dashboard/playwright.config.ts"
  "deployments/**/*.yaml"
  "deployments/**/*.yml"
  "Dockerfile"
  "Dockerfile.*"
  "Makefile"
  "package.json"
  "packages/**/*.json"
  "scripts/**"
  ":(exclude)scripts/checks/security/audit-js-supply-chain.sh"
)

is_ignored_line() {
  local line="$1"
  case "$line" in
    *":#"*|*" skipped "*|*"skip "*)
      return 0
      ;;
  esac
  return 1
}

report_matches() {
  local label="$1"
  local pattern="$2"
  shift 2
  local out
  if out="$(git grep -nE "$pattern" -- "${active_paths[@]}" "$@" 2>/dev/null)"; then
    echo "supply-chain audit: $label" >&2
    echo "$out" >&2
    fail=1
  fi
}

report_matches "dynamic package runners are not allowed in active paths" \
  '(^|[^[:alnum:]_-])(npx|bunx)([^[:alnum:]_-]|$)'

while IFS= read -r line; do
  if is_ignored_line "$line"; then
    continue
  fi
  if [[ "$line" != *"--ignore-scripts"* ]]; then
    echo "supply-chain audit: bun install must use --ignore-scripts: $line" >&2
    fail=1
  fi
done < <(git grep -nE 'bun install([^#]|$)' -- "${active_paths[@]}" 2>/dev/null || true)

while IFS= read -r line; do
  if is_ignored_line "$line"; then
    continue
  fi
  if [[ "$line" != *"--ignore-scripts"* ]]; then
    echo "supply-chain audit: npm ci must use --ignore-scripts: $line" >&2
    fail=1
  fi
done < <(git grep -nE 'npm ci([^#]|$)' -- "${active_paths[@]}" 2>/dev/null || true)

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "supply-chain audit: OK"
