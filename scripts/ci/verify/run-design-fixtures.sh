#!/usr/bin/env bash
# Run every editable design-fixture browser spec against the static design
# server with the pinned Chromium: every test at desktop width, and the tests
# tagged @mobile at mobile width too. The specs skip when CODEWIRE_DESIGN_ORIGIN
# is unset, so this runner owns their gate: it fails when a test fails, when
# any test is skipped, when the mobile project runs an untagged test, or when
# either viewport project runs nothing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PLAYWRIGHT="$ROOT/apps/dashboard/node_modules/.bin/playwright"
PROJECTS=(design-fixtures-desktop design-fixtures-mobile)

log() {
  printf '[design-fixtures] %s\n' "$*"
}

die() {
  printf '[design-fixtures] ERROR: %s\n' "$*" >&2
  exit 1
}

# Judge a Playwright JSON report. Flaky tests pass after a retry and are
# reported; anything unexpected, skipped or missing fails the gate.
check_report() {
  python3 - "$1" "${PROJECTS[@]}" <<'PY'
import json
import os
import sys
from collections import Counter

report_path, *projects = sys.argv[1:]
try:
    with open(report_path, encoding="utf-8") as handle:
        report = json.load(handle)
except (OSError, ValueError) as error:
    sys.exit(f"[design-fixtures] ERROR: unreadable Playwright report: {error}")

outcomes = {project: Counter() for project in projects}
failures = []


def walk(suite):
    for spec in suite.get("specs", []):
        for test in spec.get("tests", []):
            project = test.get("projectName")
            status = test.get("status")
            if project not in outcomes:
                failures.append(f"unexpected project {project!r} ran {spec.get('title')!r}")
                continue
            outcomes[project][status] += 1
            # Only the fixture tests that look at the mobile width run there
            # (apps/dashboard/e2e/helpers/design-fixtures-mobile.ts). The
            # report names a tag without its "@".
            if project == "design-fixtures-mobile" and "mobile" not in spec.get("tags", []):
                failures.append(f"{project} ran a test without @mobile: {spec.get('file')} › {spec.get('title')}")
            if status != "expected" and status != "flaky":
                failures.append(f"{project} {status}: {spec.get('file')} › {spec.get('title')}")
    for child in suite.get("suites", []):
        walk(child)


for suite in report.get("suites", []):
    walk(suite)
for error in report.get("errors", []):
    failures.append(f"run error: {str(error.get('message', error)).splitlines()[0]}")

summary = []
for project in projects:
    counts = outcomes[project]
    passed = counts["expected"] + counts["flaky"]
    if passed == 0:
        failures.append(f"{project} ran no passing tests")
    summary.append(f"{project} {passed} passed, {counts['flaky']} flaky")
print("[design-fixtures] " + "; ".join(summary))
network = os.environ.get("DESIGN_FIXTURES_NETWORK", "")
if network.startswith("network namespace unavailable"):
    print(f"[design-fixtures] WARNING: {network}")
elif network:
    print(f"[design-fixtures] network: {network}")
if failures:
    for failure in failures[:40]:
        print(f"[design-fixtures] ERROR: {failure}", file=sys.stderr)
    sys.exit(1)
PY
}

# A failed run keeps its JSON report, whose results carry each test's
# browser log (DEBUG=pw:browser, kept out of the job log by --quiet), and its
# test results: error contexts, screenshots and the light trace of every
# failing test (apps/dashboard/playwright.config.ts). Standard uploads the
# folder on failure, so a stall such as #4678's arrives with the browser's
# side of it. A passing run leaves no folder.
readonly DIAGNOSTICS="$ROOT/.tmp/design-fixture-diagnostics"
keep_diagnostics() {
  local work="$1" out="$2" status="$3"
  rm -rf -- "$out"
  [ "$status" != 0 ] || return 0
  mkdir -p "$out"
  [ ! -f "$work/report.json" ] || cp "$work/report.json" "$out/"
  [ ! -d "$work/test-results" ] || cp -R "$work/test-results" "$out/"
  log "kept the failed run's report and traces in $out"
}

if [ "${1:-}" = --keep-diagnostics ]; then
  [ "$#" -eq 4 ] || die "usage: $0 --keep-diagnostics <work-dir> <out-dir> <status>"
  keep_diagnostics "$2" "$3" "$4"
  exit
fi

if [ "${1:-}" = --check-report ]; then
  [ "$#" -eq 2 ] || die "usage: $0 --check-report <playwright-json-report>"
  check_report "$2"
  exit
fi
# A host bridge network appearing or disappearing (docker network create or
# rm, Compose projects, Kind) makes Chromium fail the loopback connections it
# is opening with net::ERR_NETWORK_CHANGED, and a page loses its scripts
# (#3043). So the server and browser run in their own network namespace,
# which sees only its own loopback. Where one cannot be made, the run says so
# in its summary and uses the host network.
readonly PRIVATE_NETWORK="private network namespace (loopback only)"

network_decision() {
  local reason=""
  if ! command -v unshare >/dev/null 2>&1; then
    reason="unshare is not installed"
  elif ! command -v ip >/dev/null 2>&1; then
    reason="ip (iproute2) is not installed"
  elif ! reason="$(unshare -rn ip link set lo up 2>&1)"; then
    reason="$(printf '%s\n' "${reason:-unshare -rn failed}" | head -n 1)"
  else
    printf '%s\n' "$PRIVATE_NETWORK"
    return
  fi
  printf 'network namespace unavailable: %s; running on the host network\n' "$reason"
}

if [ "${1:-}" = --network ]; then
  [ "$#" -eq 1 ] || die "usage: $0 --network"
  network_decision
  exit
fi
[ "$#" -eq 0 ] || die "usage: $0 [--check-report <playwright-json-report> | --network | --keep-diagnostics <work-dir> <out-dir> <status>]"

# shellcheck source=scripts/ci/verify/playwright-browser-runtime.sh
source "$ROOT/scripts/ci/verify/playwright-browser-runtime.sh"

[ -x "$PLAYWRIGHT" ] || die "dashboard Playwright dependencies are missing; run PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 bun install --frozen-lockfile --ignore-scripts"

chromium="$(resolve_pinned_playwright_chromium "$ROOT")"
prepare_playwright_browser_runtime "$chromium" "$ROOT"

# Chromium is resolved first: fetching it may need the host network.
if [ "${CODEWIRE_DESIGN_FIXTURES_NETNS:-}" = inside ]; then
  ip link set lo up || die "the private network namespace has no loopback"
  network="$PRIVATE_NETWORK"
else
  network="$(network_decision)"
  if [ "$network" = "$PRIVATE_NETWORK" ]; then
    log "running in a $network"
    exec unshare -rn env CODEWIRE_DESIGN_FIXTURES_NETNS=inside PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chromium" \
      bash "$ROOT/scripts/ci/verify/run-design-fixtures.sh"
  fi
  log "WARNING: $network"
fi
export DESIGN_FIXTURES_NETWORK="$network"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/design-fixtures.XXXXXX")"
server_pid=""
# shellcheck disable=SC2329 # Invoked by the EXIT trap.
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT

# A dedicated range keeps the review preview on 4174 free and lets concurrent
# checks from other worktrees each take the next free port.
# Create the log before the server starts: the background child opens its
# redirection asynchronously, and a missing file would fail the first read.
: >"$work/server.log"
python3 "$ROOT/scripts/dev/design-system-server.py" --port 4180-4199 >"$work/server.log" 2>&1 &
server_pid=$!
origin=""
for _ in $(seq 1 100); do
  origin="$(sed -n 's|^Codewire design system: \(http://127\.0\.0\.1:[0-9]*\)/reference/fixtures/$|\1|p' "$work/server.log")"
  [ -z "$origin" ] || break
  kill -0 "$server_pid" 2>/dev/null || die "design server exited: $(cat "$work/server.log")"
  sleep 0.1
done
[ -n "$origin" ] || die "design server did not report its origin within ten seconds"
curl -fsS "$origin/reference/fixtures/index.html" >/dev/null
log "serving fixtures at $origin"

# Eight workers (infra#1534): each spec opens its own page on the static
# server and shares no state with another, so the fixtures run side by side
# (main run 23934: 562 tests took 2.1 min on four).
project_args=()
for project in "${PROJECTS[@]}"; do
  project_args+=("--project=$project")
done

status=0
(
  cd "$ROOT"
  PLAYWRIGHT_SKIP_SHARED_SETUP=1 \
    PLAYWRIGHT_BASE_URL="$origin" \
    CODEWIRE_DESIGN_ORIGIN="$origin" \
    PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$chromium" \
    CODEWIRE_PLAYWRIGHT_USE_DEV_SHM="$CODEWIRE_PLAYWRIGHT_USE_DEV_SHM" \
    PLAYWRIGHT_JSON_OUTPUT_FILE="$work/report.json" \
    CODEWIRE_PLAYWRIGHT_FAILURE_TRACE=1 \
    DEBUG=pw:browser \
    "$PLAYWRIGHT" test --config apps/dashboard/playwright.config.ts \
      "${project_args[@]}" --retries=0 --forbid-only --reporter=line,json --quiet \
      --output="$work/test-results" \
      --workers="${CODEWIRE_DESIGN_FIXTURE_WORKERS:-8}"
) || status=$?

check_report "$work/report.json" || status=1
keep_diagnostics "$work" "$DIAGNOSTICS" "$status"
exit "$status"
