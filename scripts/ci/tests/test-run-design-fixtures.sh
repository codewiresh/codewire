#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUNNER="$ROOT/scripts/ci/verify/run-design-fixtures.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/design-fixtures-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
  printf '[test-run-design-fixtures] ERROR: %s\n' "$*" >&2
  exit 1
}

# Write a Playwright JSON report with one spec per "project:status" argument.
report() {
  local name="$1"
  shift
  python3 - "$TMP/$name.json" "$@" <<'PY'
import json
import sys

path, *results = sys.argv[1:]
specs = []
for index, result in enumerate(results):
    project, status = result.split(":")
    specs.append({
        "title": f"case {index}",
        "file": "ssr-dashboard.fixture.ssr.ts",
        "tests": [{"projectName": project, "status": status}],
    })
with open(path, "w", encoding="utf-8") as handle:
    json.dump({"suites": [{"title": "fixture", "specs": specs, "suites": []}], "errors": []}, handle)
PY
}

accepts() {
  local name="$1"
  "$RUNNER" --check-report "$TMP/$name.json" >"$TMP/$name.out" 2>&1 ||
    fail "$name was rejected: $(cat "$TMP/$name.out")"
}

rejects() {
  local name="$1" expected="$2"
  if "$RUNNER" --check-report "$TMP/$name.json" >"$TMP/$name.out" 2>&1; then
    fail "$name was accepted"
  fi
  grep -Fq -- "$expected" "$TMP/$name.out" ||
    fail "$name did not report '$expected': $(cat "$TMP/$name.out")"
}

report passing design-fixtures-desktop:expected design-fixtures-mobile:expected
accepts passing
report flaky design-fixtures-desktop:flaky design-fixtures-mobile:expected
accepts flaky
grep -Fq 'design-fixtures-desktop 1 passed, 1 flaky' "$TMP/flaky.out" || fail 'flaky tests were not reported'

report empty
rejects empty 'design-fixtures-desktop ran no passing tests'
report one-project design-fixtures-desktop:expected
rejects one-project 'design-fixtures-mobile ran no passing tests'
report skipped design-fixtures-desktop:expected design-fixtures-mobile:expected design-fixtures-mobile:skipped
rejects skipped 'design-fixtures-mobile skipped'
report failed design-fixtures-desktop:unexpected design-fixtures-desktop:expected design-fixtures-mobile:expected
rejects failed 'design-fixtures-desktop unexpected'
report foreign design-fixtures-desktop:expected design-fixtures-mobile:expected dashboard-ssr-desktop:expected
rejects foreign "unexpected project 'dashboard-ssr-desktop'"
printf '{not json' >"$TMP/unreadable.json"
rejects unreadable 'unreadable Playwright report'
python3 -c 'import json,sys; json.dump({"suites": [], "errors": [{"message": "config failed\nstack"}]}, open(sys.argv[1], "w"))' "$TMP/errors.json"
rejects errors 'run error: config failed'
if "$RUNNER" unexpected-argument >"$TMP/usage.out" 2>&1; then
  fail 'runner accepted an unexpected argument'
fi

printf '[test-run-design-fixtures] report judgement: pass, flaky, empty, missing project, skipped, failed, foreign project, unreadable and run errors\n'
