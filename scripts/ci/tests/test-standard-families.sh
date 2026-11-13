#!/usr/bin/env bash
# shellcheck disable=SC2034 # The eval'd runner functions read SELECTION.
# Standard verification (infra#1534):
# - A Rust package's tests leave Standard only when the Rust / transport
#   packages shard runs them in the same run. For each Standard family that
#   runs a package's tests (Contracts: codewire-proto and codewire-admin-proto;
#   Web: codewire-dashboard-web), the selector's own output for pull request
#   and main push paths decides it, and wherever Standard skips a package,
#   the shard's own package arguments (rust_package_args) name it.
# - Web runs side by side with the other families in order; the first
#   failure stops the rest. Contracts is not a Standard family: it runs in its
#   own job beside Standard (infra#1534).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly RUNNER="$ROOT/scripts/ci/verify/run-product-verification.sh"
readonly SELECTOR="$ROOT/scripts/ci/select/select-verification.sh"
CASES=0

fail() {
  printf '[test-standard-families] ERROR: %s\n' "$*" >&2
  exit 1
}

work="$(mktemp -d "${TMPDIR:-/tmp}/test-standard-families.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

runner_function() {
  awk -v name="$1" '$0 == name "() {" { on = 1 } on { print } on && $0 == "}" { exit }' "$RUNNER"
}
for function in selected rust_package_args rust_packages_shard_covers standard_families \
    run_standard_in_order run_standard; do
  [ -n "$(runner_function "$function")" ] || fail "the runner has no $function"
  eval "$(runner_function "$function")"
done
# shellcheck source=scripts/ci/verify/side-by-side.sh
source "$ROOT/scripts/ci/verify/side-by-side.sh"

# coverage_case NAME EVENT PATH... EXPECTED: EXPECTED lists, for each Standard
# package whose family the paths select, "package:skip" (the shard runs it) or
# "package:run" (Standard runs it).
coverage_case() {
  local name="$1" event="$2" ref paths selection decisions="" package family args
  shift 2
  local expected="${*: -1}"
  set -- "${@:1:$#-1}"
  ref='refs/pull/1/merge'
  [ "$event" = push ] && ref='refs/heads/main'
  paths="$work/$name.paths"
  printf '%s\n' "$@" > "$paths"
  selection="$(cd "$ROOT" && env -u GITHUB_OUTPUT -u GITHUB_EVENT_PATH GITHUB_EVENT_NAME="$event" \
    GITHUB_REF="$ref" "$SELECTOR" "$paths" 2>/dev/null | sed -n 's/^selection=//p')"
  [ -n "$selection" ] || fail "$name: the selector gave no selection"
  SELECTION="$selection"
  for package in codewire-proto:contracts codewire-admin-proto:contracts codewire-dashboard-web:web; do
    family="${package#*:}" package="${package%%:*}"
    selected "$family" || continue
    if rust_packages_shard_covers "$package"; then
      # The shard runs run_rust when rust is selected, with these packages.
      selected rust || fail "$name: $package skipped without the Rust selection"
      (cd "$ROOT" && rust_package_args rust_pkg_ && printf '%s\n' "${RUST_PACKAGE_ARGS[@]}") > "$work/args"
      args="$(cat "$work/args")"
      grep -qxF -- --workspace <<<"$args" || grep -qxF -- "$package" <<<"$args" ||
        fail "$name: $package skipped, but the packages shard runs only: $(tr '\n' ' ' <<<"$args")"
      decisions+="$package:skip "
    else
      decisions+="$package:run "
    fi
  done
  [ "${decisions% }" = "$expected" ] || fail "$name: decisions '${decisions% }', expected '$expected'"
  CASES=$((CASES + 1))
}

coverage_case pr-proto pull_request proto/codewire/v1/environment.proto \
  'codewire-proto:skip codewire-admin-proto:run codewire-dashboard-web:skip'
coverage_case pr-admin-proto pull_request crates/codewire-admin-proto/src/lib.rs \
  'codewire-proto:run codewire-admin-proto:skip'
coverage_case pr-dashboard-template pull_request crates/codewire-dashboard-web/templates/base.html \
  'codewire-dashboard-web:skip'
coverage_case pr-dashboard-app pull_request apps/dashboard/src/app.ts \
  'codewire-dashboard-web:run'
coverage_case push-proto push proto/codewire/v1/environment.proto \
  'codewire-proto:skip codewire-admin-proto:run codewire-dashboard-web:skip'
coverage_case push-dashboard-app push apps/dashboard/src/app.ts \
  'codewire-dashboard-web:run'
coverage_case push-workspace push Cargo.lock proto/codewire/v1/environment.proto apps/dashboard/src/app.ts \
  'codewire-proto:skip codewire-admin-proto:skip codewire-dashboard-web:skip'

# Without the Rust selection nothing is skipped, whatever package tokens say.
SELECTION='|valid:v3|rust_workspace|rust_pkg_codewire_proto|complete|'
if rust_packages_shard_covers codewire-proto; then fail 'a package was skipped without the Rust selection'; fi
CASES=$((CASES + 1))

# The runner skips each package only through the predicate.
grep -qF 'if rust_packages_shard_covers "$package"; then' "$RUNNER" || fail 'Contracts skips without the predicate'
grep -qF 'if rust_packages_shard_covers codewire-dashboard-web; then' "$RUNNER" || fail 'Web skips without the predicate'

# Order: Web beside the others, which run in order; Contracts never runs here.
# wait_for TEST: poll until TEST holds, bounded so a broken runner fails the
# case instead of hanging it.
wait_for() {
  local deadline=$((SECONDS + 120))
  until eval "$1"; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.05
  done
}
run_standard_family() {
  echo "$1 start $(date +%s%N)" >> "$work/order"
  sleep "${FAMILY_SECONDS:-0}"
  # WEB_HOLD: Web runs until it is stopped, so whether it was stopped is an
  # ordering fact, not a race against a timer.
  if [ "$1" = web ] && [ -n "${WEB_HOLD:-}" ]; then
    wait_for '[ -e "$work/release-web" ]' || true
  fi
  if [ "$1" = "${FAIL_FAMILY:-none}" ]; then
    # Fail only once Web is running beside this family.
    [ -z "${WEB_HOLD:-}" ] || wait_for 'grep -q "^web start " "$work/order"' || true
    return 1
  fi
  # A real family is a list of commands: one that fails before the last
  # fails the family only while errexit holds (run 44624: three failed
  # design fixtures, then passing audits, and Web passed).
  if [ "$1" = "${FAIL_STEP_FAMILY:-none}" ]; then
    false
  fi
  echo "$1 end $(date +%s%N)" >> "$work/order"
}
at() { sed -n "s/^$1 $2 //p" "$work/order"; }
: > "$work/order"
SELECTION='|valid:v3|contracts|contracts_proto|web|go_support|sdk_go|sdk_python|complete|'
FAMILY_SECONDS=1 run_standard > "$work/out" 2>&1 || fail "run_standard failed: $(cat "$work/out")"
for family in web go-support sdk-go sdk-python; do
  [ -n "$(at "$family" end)" ] || fail "$family did not run"
done
[ -z "$(at contracts start)" ] || fail 'Contracts ran in Standard'
[ "$(at web start)" -lt "$(at go-support end)" ] || fail 'Web did not run beside the other families'
[ "$(at go-support end)" -le "$(at sdk-go start)" ] && [ "$(at sdk-go end)" -le "$(at sdk-python start)" ] ||
  fail 'the other families did not run in order'
CASES=$((CASES + 1))

: > "$work/order"
SELECTION='|valid:v3|sdk_ts|complete|'
run_standard > "$work/out" 2>&1 || fail "run_standard failed: $(cat "$work/out")"
[ "$(cut -d' ' -f1-2 "$work/order" | tr '\n' ' ')" = 'sdk-ts start sdk-ts end ' ] || fail 'an unselected family ran'
CASES=$((CASES + 1))

# Contracts alone selects no Standard family: Standard does nothing.
: > "$work/order"
SELECTION='|valid:v3|contracts|contracts_proto|complete|'
run_standard > "$work/out" 2>&1 || fail "run_standard failed: $(cat "$work/out")"
[ ! -s "$work/order" ] || fail "Standard ran a family for Contracts alone: $(cat "$work/order")"
grep -qF 'Contracts runs in its own job' "$work/out" || fail 'Standard did not say where Contracts runs'
CASES=$((CASES + 1))

# The first failure stops the rest: Web, still running beside it, is stopped,
# and the families after the failed one in order never start. Each failure
# case runs run_standard in the background, as CI runs it, never as a
# condition: a condition turns errexit off for everything it calls.
: > "$work/order"
SELECTION='|valid:v3|web|go_support|sdk_go|complete|'
rm -f "$work/release-web"
status=0
FAIL_FAMILY=go-support WEB_HOLD=1 run_standard > "$work/out" 2>&1 &
wait "$!" || status=$?
[ "$status" -ne 0 ] || fail 'a failed family passed'
[ -n "$(at web start)" ] && [ -z "$(at web end)" ] || fail 'Web was not stopped after the first failure'
[ -z "$(at sdk-go start)" ] || fail 'a family started after the first failure'
CASES=$((CASES + 1))

# A failed command inside a family fails it, though later commands pass.
for family in web sdk-go; do
  : > "$work/order"
  SELECTION='|valid:v3|web|sdk_go|complete|'
  status=0
  FAIL_STEP_FAMILY="$family" run_standard > "$work/out" 2>&1 &
  wait "$!" || status=$?
  [ "$status" -ne 0 ] || fail "$family passed after one of its commands failed: $(cat "$work/out")"
  [ -z "$(at "$family" end)" ] || fail "$family ran on after one of its commands failed"
  CASES=$((CASES + 1))
done

printf '[test-standard-families] %s cases passed\n' "$CASES"
