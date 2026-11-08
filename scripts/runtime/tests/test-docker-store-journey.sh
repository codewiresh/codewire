#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/docker-store-tests.XXXXXX")"
trap 'rm -rf "$TEST_TMP"' EXIT
export ROOT TEST_TMP

fail() { printf 'docker-store journey tests: %s\n' "$*" >&2; exit 1; }

# These fixtures prove CLI orchestration and fail-closed receipt handling.
# They never count as actual Docker/containerd or Dev acceptance evidence.
cat >"$TEST_TMP/host-fixture.sh" <<'FIXTURE'
set -euo pipefail
set --
source "$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
ENV_ID=source123
DOCKER_STORE_SOURCE_ID=source123
SMOKE_EXISTING_ENV_ID=''
SMOKE_KEEP_ENV=0
SMOKE_TIMEOUT_SECONDS=8
SMOKE_TTL=2h
EXPECTED_RUNTIME_CLASS=commodity
TMPDIR_SMOKE="$TEST_TMP/work"
mkdir -p "$TMPDIR_SMOKE"
printf '[]\n' >"$TEST_TMP/snapshots"
printf '0\n' >"$TEST_TMP/clock"
log() { printf '%s\n' "$*" >>"$TEST_TMP/events"; }
die() { log "$*"; exit 1; }
seconds_now() { local n; n="$(cat "$TEST_TMP/clock")"; echo "$((n + 1))" >"$TEST_TMP/clock"; echo "$n"; }
sleep() { :; }
wait_until() { log wait-stopped; }
wait_environment() { log "wait-running $ENV_ID"; [[ "$CASE" != source-readiness-failure ]] || return 23; }
wait_for_cw_run() { log "session-ready $ENV_ID"; }
collect_failure_diagnostics() { :; }
stop_peer_relay_packet_diagnostics() { :; }
report_acceptance_failure() { log "acceptance-failure $1"; }
docker_store_run_guest() {
  log "guest $ENV_ID $1 $2"
  if [[ "$CASE:$1" == parent-primary-timeout:seed ]]; then return 23; fi
  if [[ "$CASE" == fork-failure && "$ENV_ID" == fork456 && "$1" == verify ]]; then return 23; fi
}
snapshot_row() {
  jq -n --arg id "$1" --arg source "$2" --arg state "$3" \
    '{id:$id,name:"docker-store-source123",source_environment_id:$source,state:$state,location:"platform"}'
}
cw_with_timeout() {
  local id state source creator org name
  shift
  log "cw $*"
  case "$*" in
    '--cloud snapshot ls --output json')
      if [[ -f "$TEST_TMP/capture-observed" && "$CASE" == capture-failure && "$(jq -r '.[0].state // empty' "$TEST_TMP/snapshots")" == capturing ]]; then
        snapshot_row snapshot789 source123 ready | jq -s '.' >"$TEST_TMP/snapshots"
      fi
      if [[ "$(jq -r '.[0].state // empty' "$TEST_TMP/snapshots")" == capturing ]]; then touch "$TEST_TMP/capture-observed"; fi
      if [[ -f "$TEST_TMP/delete-observed" && "$CASE" != snapshot-delete-timeout ]]; then printf '[]\n' >"$TEST_TMP/snapshots"; fi
      if [[ "$(jq -r '.[0].state // empty' "$TEST_TMP/snapshots")" == deleting ]]; then touch "$TEST_TMP/delete-observed"; fi
      log "snapshot-inventory $(jq -r '[.[].state] | join(",")' "$TEST_TMP/snapshots")"
      cat "$TEST_TMP/snapshots"
      ;;
    '--cloud snapshot create '*)
      [[ "$CASE" != snapshot-failure ]] || return 24
      state=ready; source=source123
      [[ "$CASE" != capture-failure && "$CASE" != capture-timeout ]] || state=capturing
      [[ "$CASE" != source-mismatch ]] || source=other
      snapshot_row snapshot789 "$source" "$state" | jq -s '.' >"$TEST_TMP/snapshots"
      if [[ "$CASE" == ambiguous-capture ]]; then
        snapshot_row snapshot-other other ready | jq -s '.' >"$TEST_TMP/other"
        jq -s 'add' "$TEST_TMP/snapshots" "$TEST_TMP/other" >"$TEST_TMP/both"; mv "$TEST_TMP/both" "$TEST_TMP/snapshots"
      fi
      case "$CASE" in capture-failure|capture-timeout|ambiguous-capture|source-mismatch) return 24 ;; esac
      if [[ "$CASE" == wrong-source ]]; then source=other; fi
      if [[ "$CASE" == failed-snapshot ]]; then state=failed; fi
      snapshot_row snapshot789 "$source" "$state"
      ;;
    '--cloud snapshot rm '*)
      jq 'map(.state="deleting")' "$TEST_TMP/snapshots" >"$TEST_TMP/next"; mv "$TEST_TMP/next" "$TEST_TMP/snapshots"
      ;;
    '--cloud ls --all --output json')
      if [[ -f "$TEST_TMP/fork-created" ]]; then
        printf '[{"id":"fork456","name":"docker-store-fork-source123","placement":"platform"}'
        if [[ "$CASE" == ambiguous-fork ]]; then printf ',{"id":"fork-other","name":"docker-store-fork-source123","placement":"platform"}'; fi
        printf ']\n'
      else printf '[]\n'; fi
      ;;
    '--cloud info '*)
      id="$3"; creator=creator123; org=org123
      if [[ "$id" == source123 ]]; then name=source123; else name=docker-store-fork-source123; fi
      if [[ "$id" == fork456 && "$CASE" == fork-owner-mismatch ]]; then creator=other; fi
      if [[ "$id" == fork456 && "$CASE" == fork-org-mismatch ]]; then org=other; fi
      printf '{"id":"%s","name":"%s","org_id":"%s","created_by":"%s"}\n' "$id" "$name" "$org" "$creator"
      ;;
    '--cloud create '*)
      [[ "$CASE" != fork-before-failure ]] || return 27
      touch "$TEST_TMP/fork-created"
      case "$CASE" in fork-create-failure|ambiguous-fork|fork-owner-mismatch|fork-org-mismatch) return 27 ;; esac
      if [[ "$CASE" == malformed-fork ]]; then printf '{"id":'; return 0; fi
      if [[ "$CASE" == same-identity ]]; then id=source123; else id=fork456; fi
      printf '{"id":"%s","name":"docker-store-fork-source123","org_id":"org123","created_by":"creator123"}\n' "$id"
      ;;
    '--cloud rm --yes '*)
      printf 'removing\n' >"$TEST_TMP/env-$4"
      ;;
    'report '* )
      id="$2"; state=running
      if [[ -f "$TEST_TMP/env-$id" ]]; then state="$(cat "$TEST_TMP/env-$id")"; fi
      if [[ "$state" == removing ]]; then
        if [[ -f "$TEST_TMP/report-$id" && "$CASE:$id" != fork-delete-timeout:fork456 && "$CASE:$id" != source-delete-timeout:source123 && "$CASE:$id" != parent-source-timeout:source123 && "$CASE:$id" != parent-primary-timeout:source123 ]]; then state=destroyed; fi
        touch "$TEST_TMP/report-$id"
      fi
      log "environment-report $id $state"
      printf '{"environment":{"id":"%s","state":"%s"}}\n' "$id" "$state"
      ;;
  esac
}
if [[ "$CASE" == preexisting-snapshot ]]; then
  snapshot_row snapshot-preexisting source123 ready | jq -s '.' >"$TEST_TMP/snapshots"
fi
if [[ "$CASE" == parent-source-timeout || "$CASE" == parent-primary-timeout || "$CASE" == source-readiness-failure || "$CASE" == source-create-failure ]]; then
  trap cleanup EXIT
else
  trap 'primary=$?; cleanup_rc=0; cleanup_docker_store_journey || cleanup_rc=1; cleanup_docker_store_source || cleanup_rc=1; if [[ "$primary" == 0 ]]; then primary=$cleanup_rc; fi; log "exit $primary source=$ENV_ID fork=$DOCKER_STORE_FORK_ID snapshot=$DOCKER_STORE_SNAPSHOT_ID attempted=$DOCKER_STORE_SNAPSHOT_ATTEMPTED fork_attempted=$DOCKER_STORE_FORK_ATTEMPTED"; exit "$primary"' EXIT
fi
if [[ "$CASE" == preexisting-fork ]]; then touch "$TEST_TMP/fork-created"; fi
if [[ "$CASE" == source-readiness-failure || "$CASE" == source-create-failure ]]; then
  DOCKER_STORE_SOURCE_ID=''
  SMOKE_ONLY_PHASES=(docker-store)
  prepare_cli() { :; }
  create_environment() {
    if [[ "$CASE" == source-create-failure ]]; then log source-created-before-CLI-failure; return 29; fi
    ENV_ID=source123
  }
  if [[ "$CASE" == source-create-failure ]]; then ENV_ID=''; SMOKE_NAME=source-unique-123; fi
  record_environment_artifact() { :; }
  main
else
  run_docker_store_journey
fi
FIXTURE

host_case() {
  local name="$1" expected="$2" rc=0
  rm -rf "$TEST_TMP/work"
  rm -f "$TEST_TMP"/env-* "$TEST_TMP"/report-* "$TEST_TMP/capture-observed" "$TEST_TMP/delete-observed" "$TEST_TMP/fork-created"
  : >"$TEST_TMP/events"
  CASE="$name" bash "$TEST_TMP/host-fixture.sh" >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
  [[ ! -s "$TEST_TMP/err" ]] || { cat "$TEST_TMP/err" >&2; fail "$name emitted unexpected fixture stderr"; }
  if [[ "$rc" != "$expected" ]]; then
    cat "$TEST_TMP/err" >&2; tail -20 "$TEST_TMP/events" >&2
    fail "$name exited $rc, expected $expected"
  fi
}

host_case success 0
python3 - <<'PYTEST'
import os
from pathlib import Path
lines=(Path(os.environ['TEST_TMP'])/'events').read_text().splitlines()
guests=[line for line in lines if line.startswith('guest ')]
assert guests == ['guest source123 seed source123', 'guest source123 verify source123',
                  'guest fork456 verify source123', 'guest fork456 fork-write source123',
                  'guest source123 verify source123', 'guest source123 cleanup source123'],guests
assert not any('--cloud restart' in line for line in lines)
assert sum('--cloud stop source123' in line for line in lines)==2
assert sum('--cloud snapshot create source123' in line for line in lines)==1
assert any('--cloud create --snapshot snapshot789' in line and '--no-network' in line for line in lines)
assert 'snapshot-inventory deleting' in lines
assert lines.index('cw --cloud snapshot rm snapshot789') < lines.index('snapshot-inventory deleting')
for resource in ['fork456','source123']:
    assert lines.index(f'cw --cloud rm --yes {resource}') < lines.index(f'environment-report {resource} removing') < lines.index(f'environment-report {resource} destroyed')
assert 'exit 0 source=source123 fork= snapshot= attempted=0 fork_attempted=0' in lines
PYTEST
printf 'docker-store test: stop/start, isolated fork and terminal cleanup passed\n'

host_case fork-failure 23
grep -qx 'environment-report fork456 destroyed' "$TEST_TMP/events" || fail 'failed fork removal not observed'
grep -qx 'environment-report source123 destroyed' "$TEST_TMP/events" || fail 'failed fork lost source cleanup'
grep -q '^exit 23 source=source123 fork= snapshot= attempted=0 fork_attempted=0$' "$TEST_TMP/events" || fail 'failed fork lost primary failure'
printf 'docker-store test: partial fork failure preserves primary failure and source cleanup\n'

for creation_case in snapshot-failure capture-failure capture-timeout ambiguous-capture source-mismatch; do
  host_case "$creation_case" 24
  ! grep -q '^cw --cloud create ' "$TEST_TMP/events" || fail 'forked after failed capture'
  if [[ "$creation_case" == capture-failure ]]; then
    grep -qx 'cw --cloud snapshot rm snapshot789' "$TEST_TMP/events" || fail 'orphan after create-wait failure was not recovered'
    grep -q 'attempted=0 fork_attempted=0$' "$TEST_TMP/events" || fail 'recovered capture did not observe removal'
  else
    ! grep -q '^cw --cloud snapshot rm ' "$TEST_TMP/events" || fail 'deleted unresolved capture'
    grep -q 'attempted=1 fork_attempted=0$' "$TEST_TMP/events" || fail 'unresolved capture tracking was cleared'
  fi
done
printf 'docker-store test: post-create failure recovery, capturing timeout and ambiguous ownership (5 cases)\n'

host_case preexisting-snapshot 1
! grep -q '^cw --cloud snapshot create\|^cw --cloud snapshot rm' "$TEST_TMP/events" || fail 'pre-existing snapshot was changed'
printf 'docker-store test: pre-existing snapshot name refuses capture and deletion\n'

for receipt_case in wrong-source failed-snapshot same-identity; do
  host_case "$receipt_case" 1
  if [[ "$receipt_case" != same-identity ]]; then ! grep -q '^cw --cloud create ' "$TEST_TMP/events" || fail 'forked invalid snapshot receipt'; fi
  [[ "$(grep -c '^cw --cloud rm --yes source123$' "$TEST_TMP/events")" == 1 ]] || fail 'invalid receipt deleted source as a fork'
done
printf 'docker-store test: invalid capture/fork receipts refuse lifecycle continuation (3 cases)\n'

for removal_case in snapshot-delete-timeout fork-delete-timeout source-delete-timeout; do
  host_case "$removal_case" 1
  case "$removal_case" in
    snapshot-delete-timeout) grep -q 'snapshot=snapshot789 attempted=1 fork_attempted=0$' "$TEST_TMP/events" || fail 'deleting snapshot ACK cleared tracking' ;;
    fork-delete-timeout) grep -q 'fork=fork456' "$TEST_TMP/events" || fail 'removing fork ACK cleared tracking' ;;
    source-delete-timeout) grep -qx 'Docker cleanup incomplete: environment source123 is not confirmed destroyed' "$TEST_TMP/events" || fail 'source ACK counted as cleanup' ;;
  esac
done
printf 'docker-store test: snapshot, fork and source ACKs cannot count as terminal cleanup (3 cases)\n'
host_case parent-source-timeout 1
grep -qx 'acceptance-failure 1' "$TEST_TMP/events" || fail 'parent EXIT handler hid unresolved source cleanup'
printf 'docker-store test: actual commodity EXIT handler fails on unresolved fresh source cleanup\n'
host_case parent-primary-timeout 23
grep -qx 'acceptance-failure 23' "$TEST_TMP/events" || fail 'parent EXIT handler lost primary failure'
printf 'docker-store test: actual EXIT handler retains primary failure when source cleanup also fails\n'

for fork_case in fork-create-failure malformed-fork ambiguous-fork fork-owner-mismatch fork-org-mismatch fork-before-failure; do
  expected=27; [[ "$fork_case" != malformed-fork ]] || expected=1
  host_case "$fork_case" "$expected"
  ! grep -q '^guest fork456 ' "$TEST_TMP/events" || fail 'recovered ownership became journey success'
  if [[ "$fork_case" == fork-create-failure || "$fork_case" == malformed-fork ]]; then
    grep -qx 'environment-report fork456 destroyed' "$TEST_TMP/events" || fail 'owned fork after create failure was not removed'
    grep -q 'fork_attempted=0$' "$TEST_TMP/events" || fail 'confirmed fork removal retained pending attempt'
  else
    ! grep -q '^cw --cloud rm --yes fork' "$TEST_TMP/events" || fail 'deleted an unverified fork'
    grep -q 'fork_attempted=1$' "$TEST_TMP/events" || fail 'unresolved fork tracking was cleared'
  fi
done
printf 'docker-store test: failed/malformed fork creation recovers only uniquely owned metadata (6 cases)\n'
host_case preexisting-fork 1
! grep -q '^cw --cloud create\|^cw --cloud rm --yes fork' "$TEST_TMP/events" || fail 'pre-existing fork name was changed'
printf 'docker-store test: pre-existing fork name refuses creation and deletion\n'
host_case source-readiness-failure 23
grep -qx 'environment-report source123 destroyed' "$TEST_TMP/events" || fail 'source was not tracked before readiness failure'
printf 'docker-store test: actual main tracks fresh source before readiness/core\n'
host_case source-create-failure 29
! grep -q '^cw --cloud rm ' "$TEST_TMP/events" || fail 'unverified source identity caused deletion'
grep -qx 'Docker cleanup incomplete: source source-unique-123 has no verified ID (TTL 2h); preserved' "$TEST_TMP/events" || fail 'uncertain source creation omitted ownership/TTL evidence'
grep -qx 'acceptance-failure 29' "$TEST_TMP/events" || fail 'uncertain source cleanup replaced primary failure'
printf 'docker-store test: source create failure without receipt preserves name/TTL and original failure\n'

cat >"$TEST_TMP/backend-fixture.sh" <<'FIXTURE'
set -eu
. "$ROOT/scripts/runtime/dev/docker-store-guest.sh"
DOCKER_HOST=unix:///var/run/docker/docker.sock
ds_mode="$MODE"
docker() {
  case "$*" in
    'context show') printf 'default\n' ;;
    'info --format {{.Driver}}') printf '%s\n' "$DRIVER" ;;
    'info --format {{range .DriverStatus}}{{if eq (index . 0) "driver-type"}}{{index . 1}}{{end}}{{end}}') printf '%s\n' "$STATUS" ;;
    'info --format {{.DockerRootDir}}') printf '%s\n' "${DATA_ROOT:-/var/lib/docker}" ;;
    *) echo unexpected-docker-operation >&2; exit 99 ;;
  esac
}
docker_store_backend
FIXTURE

backend_case() {
  local mode="$1" driver="$2" status="$3" expected="$4" rc=0
  MODE="$mode" DRIVER="$driver" STATUS="$status" sh "$TEST_TMP/backend-fixture.sh" >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
  [[ "$rc" == "$expected" ]] || fail "backend $mode/$driver exited $rc, expected $expected"
}
backend_case containerd overlayfs io.containerd.snapshotter.v1 0
backend_case containerd overlayfs null 1
backend_case containerd vfs null 1
backend_case vfs vfs null 1
backend_case vfs overlayfs '[["driver-type","io.containerd.snapshotter.v1"]]' 1
printf 'docker-store test: actual backend/store identity fails closed (5 cases)\n'

cat >"$TEST_TMP/managed-root-fixture.sh" <<'FIXTURE'
set -eu
. "$ROOT/scripts/runtime/dev/docker-store-guest.sh"
printf 'containerd-overlayfs-v1\n' >"$TEST_TMP/managed-marker"
if [ "$CASE" = marker ]; then printf 'invalid-marker\n' >"$TEST_TMP/managed-marker"; fi
stat() {
  case "$*" in
    '-f -c %T /') if [ "$CASE" = good-unknown ]; then echo UNKNOWN; else echo overlayfs; fi ;;
    '-f -c %t /') if [ "$CASE" = root-magic ]; then echo 1021994; else echo 794c7630; fi ;;
    '-f -c %t /managed-store') if [ "$CASE" = managed-magic ]; then echo 1021994; else echo ef53; fi ;;
    *) exit 99 ;;
  esac
}
test() {
  if [ "$*" = '-d /managed-store/io.containerd.snapshotter.v1.overlayfs' ]; then
    [ "$CASE" != missing-directory ]
  else
    command test "$@"
  fi
}
cmp() {
  [ "$*" = '-s - /store-version' ] || exit 99
  command cmp -s - "$TEST_TMP/managed-marker"
}
# Execute the exact script passed to the real Docker child, with only its
# filesystem observations replaced. No alternate check implementation.
eval "$(docker_store_managed_root_script)"
FIXTURE
for managed_case in good good-unknown root-magic managed-magic missing-directory marker; do
  rc=0
  CASE="$managed_case" sh "$TEST_TMP/managed-root-fixture.sh" >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
  expected=1; [[ "$managed_case" != good && "$managed_case" != good-unknown ]] || expected=0
  [[ "$rc" == "$expected" ]] || fail "managed root $managed_case exited$rc, expected$expected"
  grep -q '^docker-store managed-root root-type=.* root-magic=[0-9a-f]* managed-magic=.* snapshotter-directory=.* marker-match=' "$TEST_TMP/out" || fail 'managed root facts were not captured before rejection'
  case "$managed_case" in
    good|good-unknown) [[ ! -s "$TEST_TMP/err" ]] || fail 'valid managed root was rejected' ;;
    root-magic) grep -qx 'docker-store: container root is not overlayfs' "$TEST_TMP/err" || fail 'root magic rejection lost its label' ;;
    managed-magic) grep -qx 'docker-store: managed containerd root is not ext4' "$TEST_TMP/err" || fail 'managed filesystem rejection lost its label' ;;
    missing-directory) grep -qx 'docker-store: managed containerd overlayfs directory absent' "$TEST_TMP/err" || fail 'missing snapshotter rejection lost its label' ;;
    marker) grep -qx 'docker-store: Docker format marker mismatch' "$TEST_TMP/err" || fail 'marker rejection lost its label' ;;
  esac
done
printf 'docker-store test: actual managed root predicates retain rejection with finite diagnostics (6 cases)\n'

rc=0
sh -ec '. "$ROOT/scripts/runtime/dev/docker-store-guest.sh"; docker_store_guest cleanup "../../other-data" containerd' >"$TEST_TMP/out" 2>"$TEST_TMP/err" || rc=$?
[[ "$rc" == 1 ]] || fail 'malformed fixture identity reached cleanup'
printf 'docker-store test: invalid fixture identity refuses cleanup\n'

# Extraction uses the production generator; the shell checks the actual
# emitted guest script, rather than a separately maintained fixture copy.
bash -ec '
  source "$ROOT/scripts/runtime/dev/docker-store-journey.sh"
  shell_quote() { printf "%q" "$1"; }
  run_cw_session_script() { printf "%s\n" "$1"; }
  docker_store_run_guest core abc123
' >"$TEST_TMP/guest.sh"
sh -n "$TEST_TMP/guest.sh"
printf 'docker-store test: production guest script parses with POSIX sh\n'
# Execute the actual normal Docker phase with its session transport stubbed.
# This catches an optional-only core check, wrong runtime default, or a skip
# that still mutates Docker; it does not run a real container.
cat >"$TEST_TMP/normal-fixture.sh" <<'FIXTURE'
set -euo pipefail
set --
source "$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
ENV_ID=source123
EXPECTED_RUNTIME_CLASS="$RUNTIME"
SMOKE_SKIP_DOCKER="$SKIP_DOCKER"
run_docker_store_core() { printf 'core\n' >>"$TEST_TMP/normal-events"; }
run_cw_session_script() {
  printf 'session\n' >>"$TEST_TMP/normal-events"
  printf '%s\n' "$1" >>"$TEST_TMP/normal-guests"
}
run_docker_smoke
FIXTURE
for runtime in commodity confidential; do
  : >"$TEST_TMP/normal-events"; : >"$TEST_TMP/normal-guests"
  RUNTIME="$runtime" SKIP_DOCKER=0 bash "$TEST_TMP/normal-fixture.sh" >"$TEST_TMP/out" 2>"$TEST_TMP/err"
  if [[ "$runtime" == commodity ]]; then
    [[ "$(head -1 "$TEST_TMP/normal-events")" == core ]] || fail 'normal commodity phase did not run core first'
    grep -q '^expected_driver=.*overlayfs'  "$TEST_TMP/normal-guests" || fail 'commodity driver is not overlayfs'
  else
    ! grep -qx core "$TEST_TMP/normal-events" || fail 'confidential runtime ran modern commodity checks'
    grep -q '^expected_driver=.*vfs'  "$TEST_TMP/normal-guests" || fail 'confidential driver was changed'
  fi
done
: >"$TEST_TMP/normal-events"
RUNTIME=commodity SKIP_DOCKER=1 bash "$TEST_TMP/normal-fixture.sh" >"$TEST_TMP/out" 2>"$TEST_TMP/err"
[[ ! -s "$TEST_TMP/normal-events" ]] || fail 'Docker skip still invoked guest/core'
printf 'docker-store test: normal commodity, confidential and skip behavior passed (3 cases)\n'
printf 'docker-store journey fixture tests: 41 passed\n'
