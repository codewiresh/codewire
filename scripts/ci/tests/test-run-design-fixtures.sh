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

# Write a Playwright JSON report with one spec per "project:status[:untagged]"
# argument. A mobile-project spec carries the @mobile tag unless untagged; the
# report names a tag without its "@".
report() {
  local name="$1"
  shift
  python3 - "$TMP/$name.json" "$@" <<'PY'
import json
import sys

path, *results = sys.argv[1:]
specs = []
for index, result in enumerate(results):
    project, status, *untagged = result.split(":")
    specs.append({
        "title": f"case {index}",
        "file": "ssr-dashboard.fixture.ssr.ts",
        "tags": ["mobile"] if project == "design-fixtures-mobile" and not untagged else [],
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
# The mobile project runs only the tests tagged @mobile
# (e2e/helpers/design-fixtures-mobile.ts): an untagged one there means its
# grep was lost, and every fixture test runs twice again.
report untagged design-fixtures-desktop:expected design-fixtures-mobile:expected design-fixtures-mobile:expected:untagged
rejects untagged 'design-fixtures-mobile ran a test without @mobile'
report foreign design-fixtures-desktop:expected design-fixtures-mobile:expected dashboard-ssr-desktop:expected
rejects foreign "unexpected project 'dashboard-ssr-desktop'"
printf '{not json' >"$TMP/unreadable.json"
rejects unreadable 'unreadable Playwright report'
python3 -c 'import json,sys; json.dump({"suites": [], "errors": [{"message": "config failed\nstack"}]}, open(sys.argv[1], "w"))' "$TMP/errors.json"
rejects errors 'run error: config failed'
# The network decision (#3043): a private namespace whenever unshare -rn can
# bring its loopback up, otherwise a loud host-network fallback with the reason.
stubs="$TMP/stubs"
mkdir -p "$stubs/failing" "$stubs/working"
printf '#!/bin/sh\necho "unshare: unshare failed: Operation not permitted" >&2\nexit 1\n' >"$stubs/failing/unshare"
printf '#!/bin/sh\nexit 0\n' >"$stubs/working/unshare"
printf '#!/bin/sh\nexit 0\n' >"$stubs/working/ip"
cp "$stubs/working/ip" "$stubs/failing/ip"
chmod +x "$stubs"/*/*
[ "$(PATH="$stubs/failing:$PATH" "$RUNNER" --network)" = 'network namespace unavailable: unshare: unshare failed: Operation not permitted; running on the host network' ] ||
  fail 'a failing user namespace did not fall back loudly with its reason'
[ "$(PATH="$stubs/working:$PATH" "$RUNNER" --network)" = 'private network namespace (loopback only)' ] ||
  fail 'a working user namespace was not used'
if unshare -rn ip link set lo up 2>/dev/null; then
  [ "$("$RUNNER" --network)" = 'private network namespace (loopback only)' ] ||
    fail 'this runner can create a network namespace but the gate would not use it'
fi
grep -Fq 'exec unshare -rn env CODEWIRE_DESIGN_FIXTURES_NETNS=inside' "$RUNNER" ||
  fail 'the gate does not enter the network namespace it decides on'
DESIGN_FIXTURES_NETWORK='network namespace unavailable: reason; running on the host network' "$RUNNER" --check-report "$TMP/passing.json" >"$TMP/fallback.out" 2>&1 ||
  fail 'a host-network run was rejected'
grep -Fq '[design-fixtures] WARNING: network namespace unavailable: reason; running on the host network' "$TMP/fallback.out" ||
  fail 'the host-network fallback is missing from the run summary'
DESIGN_FIXTURES_NETWORK='private network namespace (loopback only)' "$RUNNER" --check-report "$TMP/passing.json" >"$TMP/private.out" 2>&1 ||
  fail 'a private-network run was rejected'
grep -Fq '[design-fixtures] network: private network namespace (loopback only)' "$TMP/private.out" ||
  fail 'the private network is missing from the run summary'

if "$RUNNER" unexpected-argument >"$TMP/usage.out" 2>&1; then
  fail 'runner accepted an unexpected argument'
fi

printf '[test-run-design-fixtures] report judgement: pass, flaky, network namespace and fallback, empty, missing project, skipped, failed, untagged mobile, foreign project, unreadable and run errors\n'
