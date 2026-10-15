#!/usr/bin/env bash
# Execute delivery-superseded.sh in real shallow checkouts of a synthetic
# history:
#   deployed -- built -- head        (canonical main)
#          \-- stray                 (never on main)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly SCRIPT="$ROOT/scripts/ci/deploy/delivery-superseded.sh"

fail() {
  printf '[test-delivery-superseded] ERROR: %s\n' "$*" >&2
  exit 1
}

bash -n "$SCRIPT"
[[ -x "$SCRIPT" ]] || fail "delivery-superseded.sh is not executable"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/delivery-superseded.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

fixture_git() {
  git -c user.name=fixture -c user.email=fixture@example.invalid -c init.defaultBranch=main \
    -c commit.gpgsign=false "$@"
}
fixture_git init -q "$work/origin"
git -C "$work/origin" config uploadpack.allowAnySHA1InWant true
fixture_commit() {
  fixture_git -C "$work/origin" commit -q --allow-empty -m "$1"
  git -C "$work/origin" rev-parse HEAD
}
deployed_sha="$(fixture_commit deployed)"
fixture_git -C "$work/origin" checkout -q -b stray
stray_sha="$(fixture_commit stray)"
fixture_git -C "$work/origin" checkout -q main
built_sha="$(fixture_commit built)"
head_sha="$(fixture_commit head)"
: "$deployed_sha"

now="$(date +%s)"
fresh=$((now - 600))
stale=$((now - 2700))

# A depth-1 checkout of one commit, as the hosted job has.
checkout() {
  local name="$1" sha="$2" dir="$work/checkout-$1"
  fixture_git init -q "$dir"
  fixture_git -C "$dir" remote add origin "file://$work/origin"
  fixture_git -C "$dir" -c protocol.file.allow=always fetch -q --depth=1 origin "$sha"
  fixture_git -C "$dir" checkout -q FETCH_HEAD
  printf '%s\n' "$dir"
}

# run_script NAME SHA COMMITTED_AT ARGUMENT... -> exit status; output in $work/NAME.*
run_script() {
  local name="$1" sha="$2" committed_at="$3" dir
  shift 3
  dir="$(checkout "$name" "$sha")"
  : >"$work/$name.output"
  (
    cd "$dir"
    env GITHUB_SHA="$sha" GITHUB_OUTPUT="$work/$name.output" \
      CODEWIRE_DEPLOYED_SOURCE_COMMITTED_AT="$committed_at" \
      CODEWIRE_SUPERSEDED_POLL_SECONDS=1 \
      GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=protocol.file.allow GIT_CONFIG_VALUE_0=always \
      "$SCRIPT" "$@" >"$work/$name.out" 2>&1
  )
}

expect_check() {
  local name="$1" sha="$2" committed_at="$3" want="$4"
  run_script "$name" "$sha" "$committed_at" check ||
    fail "$name: check failed instead of deciding"
  [[ "$(cat "$work/$name.output")" == "stop=$want" ]] ||
    fail "$name: expected stop=$want, got '$(cat "$work/$name.output")'"
}

expect_check canonical-head "$head_sha" "$fresh" false
expect_check superseded "$built_sha" "$fresh" true
grep -Fq "main is now $head_sha" "$work/superseded.out" ||
  fail "a stop does not name the newer canonical main"
# Dev must keep moving under steady merges: never stop when it is stale.
expect_check stale-dev "$built_sha" "$stale" false
grep -Fq 'at least 45 minutes old' "$work/stale-dev.out" ||
  fail "a stale-Dev delivery does not say why it continues"
for unknown in '' not-a-time 0 -5; do
  expect_check "unknown-age-${unknown:-empty}" "$built_sha" "$unknown" false
done
# Never stop for a commit main does not descend from.
expect_check stray "$stray_sha" "$fresh" false

# A stopped build ends its whole process group, runs the command's EXIT trap,
# and reports a clean stop.
cat >"$work/long-build.sh" <<'SH'
#!/usr/bin/env bash
trap 'echo cleaned >"$MARKER"' EXIT
sleep 300 &
echo "$!" >"$CHILD_PID"
wait
SH
chmod 0755 "$work/long-build.sh"
started=$SECONDS
MARKER="$work/stopped.marker" CHILD_PID="$work/stopped.child" \
  run_script stopped "$built_sha" "$fresh" run -- "$work/long-build.sh" ||
  fail "a stopped build did not end cleanly"
((SECONDS - started < 60)) || fail "a superseded build was not stopped promptly"
[[ "$(cat "$work/stopped.output")" == stop=true ]] || fail "a stopped build did not report stop=true"
[[ "$(cat "$work/stopped.marker" 2>/dev/null)" == cleaned ]] ||
  fail "a stopped build did not run its cleanup"
if kill -0 "$(cat "$work/stopped.child")" 2>/dev/null; then
  fail "a stopped build left a child process running"
fi
grep -Fq 'nothing from it is signed or dispatched' "$work/stopped.out" ||
  fail "a stopped build does not say what it skipped"

# A build that is never superseded finishes with its own status.
# shellcheck disable=SC2016 # The command expands MARKER itself.
MARKER="$work/finished.marker" \
  run_script finished "$head_sha" "$fresh" run -- bash -c 'sleep 2; echo built >"$MARKER"' ||
  fail "a current build did not finish"
[[ "$(cat "$work/finished.output")" == stop=false && "$(cat "$work/finished.marker")" == built ]] ||
  fail "a current build was stopped or lost"
if run_script failed "$head_sha" "$fresh" run -- bash -c 'exit 3'; then
  fail "a failed build was reported as success"
fi
run_script failed-status "$head_sha" "$fresh" run -- bash -c 'exit 3' || status=$?
[[ "${status:-0}" == 3 ]] || fail "a failed build did not keep its exit status"
# Stale Dev keeps a superseded build running to completion.
# shellcheck disable=SC2016 # The command expands MARKER itself.
MARKER="$work/stale.marker" \
  run_script stale-run "$built_sha" "$stale" run -- bash -c 'sleep 3; echo built >"$MARKER"' ||
  fail "a stale-Dev build did not finish"
[[ "$(cat "$work/stale-run.output")" == stop=false && "$(cat "$work/stale.marker")" == built ]] ||
  fail "a stale-Dev build was stopped"

# Main moving during the build stops it.
cat >"$work/moving-build.sh" <<'SH'
#!/usr/bin/env bash
sleep 2
git -C "$ORIGIN" -c user.name=fixture -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false commit -q --allow-empty -m newer
sleep 300
SH
chmod 0755 "$work/moving-build.sh"
ORIGIN="$work/origin" run_script moved "$head_sha" "$fresh" run -- "$work/moving-build.sh" ||
  fail "a build superseded while running did not stop cleanly"
[[ "$(cat "$work/moved.output")" == stop=true ]] || fail "a build superseded while running kept going"

# An unreadable main never stops a delivery.
git -C "$work/origin" update-ref -d refs/heads/main
expect_check unreadable-main "$built_sha" "$fresh" false

for bad in '' 'run' 'run --' 'check extra' 'unknown'; do
  # shellcheck disable=SC2086 # The argument lists are the point.
  if GITHUB_SHA="$head_sha" GITHUB_OUTPUT="$work/bad.output" "$SCRIPT" $bad >/dev/null 2>&1; then
    fail "usage '$bad' was accepted"
  fi
done

printf '[test-delivery-superseded] superseded-delivery stop contract passed\n'
