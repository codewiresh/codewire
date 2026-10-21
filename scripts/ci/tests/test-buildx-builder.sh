#!/usr/bin/env bash
# The shared owned-builder removal (scripts/ci/images/buildx-builder.sh) against
# a synthetic Docker that keeps each builder object as a file. No Docker daemon,
# builder or network is used.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/buildx-builder-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
fail() { echo "buildx builder removal: $*" >&2; exit 1; }

builder=codewire-test-builder
node="$builder-node"
mkdir "$work/bin" "$work/state"
cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
# Each present object is a file in FAKE_STATE. FAKE_MODE selects the behaviour.
set -uo pipefail
state="${FAKE_STATE:?}"
printf '%s\n' "$*" >>"$state/calls"
case "$1 $2" in
  'buildx rm')
    case "${FAKE_MODE:?}" in
      ok) rm -f "$state/builder" "$state/container" "$state/volume" ;;
      gone) rm -f "$state/builder" "$state/container" "$state/volume"
        echo 'ERROR: failed to remove one or more builders' >&2; exit 73 ;;
      # The client gives up while the daemon still deletes the state volume.
      deleting) rm -f "$state/builder" "$state/container"; exit 73 ;;
      persists|unknown) echo 'ERROR: failed to remove one or more builders' >&2; exit 73 ;;
      hang) sleep 30 ;;
    esac
    ;;
  'buildx inspect')
    [[ "$FAKE_MODE" != unknown ]] || { echo 'ERROR: Cannot connect to the Docker daemon' >&2; exit 1; }
    [[ -e "$state/builder" ]] || { echo "ERROR: no builder \"$3\" found" >&2; exit 1; }
    echo "Name: $3"
    ;;
  'container inspect')
    [[ "$FAKE_MODE" != unknown ]] || { echo 'Cannot connect to the Docker daemon' >&2; exit 1; }
    [[ -e "$state/container" ]] || { echo "Error response from daemon: No such container: ${*: -1}" >&2; exit 1; }
    printf '%064d\n' 1
    ;;
  'volume inspect')
    [[ "$FAKE_MODE" != unknown ]] || { echo 'Cannot connect to the Docker daemon' >&2; exit 1; }
    [[ -e "$state/volume" ]] || { echo "Error response from daemon: get ${*: -1}: no such volume" >&2; exit 1; }
    echo "${*: -1}"
    ;;
  'rm --force') [[ "$FAKE_MODE" == persists ]] || rm -f "$state/container" ;;
  'volume rm')
    # A second request waits for the daemon's own deletion to finish.
    [[ "$FAKE_MODE" != persists ]] || { echo 'Error response from daemon: volume is in use' >&2; exit 1; }
    rm -f "$state/volume"
    ;;
  *) echo "unexpected fake docker command: $*" >&2; exit 99 ;;
esac
EOF
chmod 0755 "$work/bin/docker"

# shellcheck source=scripts/ci/images/buildx-builder.sh
source "$ROOT/scripts/ci/images/buildx-builder.sh"

# run_case MODE EXPECTED_STATUS: remove a builder whose three objects exist.
run_case() {
  local mode="$1" expected="$2" status=0
  rm -rf "$work/state" && mkdir "$work/state"
  : >"$work/state/builder"; : >"$work/state/container"; : >"$work/state/volume"
  FAKE_STATE="$work/state" FAKE_MODE="$mode" \
    buildx_builder_remove "$work/bin/docker" "$builder" "$node" 'test cleanup' \
    >"$work/$mode.out" 2>&1 || status=$?
  [[ "$status" == "$expected" ]] || { cat "$work/$mode.out" >&2; fail "$mode exited $status, expected $expected"; }
}

run_case ok 0
[[ "$(cat "$work/state/calls")" == "buildx rm --force $builder" ]] ||
  fail 'a successful removal probed or retried'
[[ ! -s "$work/ok.out" ]] || fail 'a successful removal printed a diagnostic'

# #2990: Buildx reports failure although Docker removed every object.
run_case gone 0
grep -Eqx 'test cleanup: phase=builder-removal status=73 confirmed-absent=true elapsed_seconds=[0-9]+' \
  "$work/gone.out" || fail 'confirmed-absent removal was not reported'

# The client gave up while the daemon still deleted the state volume: the
# exact volume is removed again, which waits for the daemon, and nothing else.
run_case deleting 0
grep -qx "volume rm buildx_buildkit_${node}_state" "$work/state/calls" ||
  fail 'the remaining state volume was not removed again'
! grep -Eq "^(rm --force .*|buildx rm --force $builder)$" <(sed 1d "$work/state/calls") ||
  fail 'objects Docker reported missing were removed again'
grep -q 'confirmed-absent=true' "$work/deleting.out" || fail 'finished deletion was not confirmed'

# An object that survives a removal round is named, with the first status.
run_case persists 73
grep -Eqx "test cleanup: phase=builder-removal status=73 elapsed_seconds=[0-9]+ persists: builder $builder, container buildx_buildkit_$node, volume buildx_buildkit_${node}_state" \
  "$work/persists.out" || fail 'persisting objects were not named'
grep -q '^test cleanup: builder-removal output: ERROR' "$work/persists.out" ||
  fail 'the failed removal output was not kept'
[[ "$(grep -c "^buildx rm --force $builder$" "$work/state/calls")" == 2 ]] ||
  fail 'a removal without progress retried more than one round'

# Only Docker's own not-found answer proves an object absent.
run_case unknown 73
grep -q 'persists: builder' "$work/unknown.out" || fail 'an unreachable daemon was taken as absence'

# A hung Docker request is bounded; the hang is not mistaken for absence.
started=$SECONDS
BUILDX_BUILDER_REQUEST_SECONDS=1 run_case hang 124
(( SECONDS - started < 20 )) || fail 'a hung removal request was not bounded'

# Only a plain owned builder and node name reach Docker.
rm -f "$work/state/calls"
status=0
FAKE_STATE="$work/state" FAKE_MODE=ok buildx_builder_remove "$work/bin/docker" 'x;rm -rf /' "$node" t \
  >/dev/null 2>&1 || status=$?
[[ "$status" == 2 && ! -e "$work/state/calls" ]] || fail 'an unsafe builder name reached Docker'

# buildx_builder_cap applies the workstation CPU ceiling only under bin/heavy.
printf '#!/bin/sh\necho "$*" >>"%s/cpu-calls"\n' "$work" >"$work/bin/codewire-cpu"
chmod 0755 "$work/bin/codewire-cpu"
rm -f "$work/cpu-calls"
(PATH="$work/bin:$PATH"; unset CODEWIRE_CPU_SLICE; buildx_builder_cap b) ||
  fail 'buildx_builder_cap failed outside bin/heavy'
[[ ! -e "$work/cpu-calls" ]] || fail 'buildx_builder_cap ran codewire-cpu outside bin/heavy'
(PATH="$work/bin:$PATH" CODEWIRE_CPU_SLICE=cwvmtest.slice buildx_builder_cap b) ||
  fail 'buildx_builder_cap failed under bin/heavy'
[[ "$(cat "$work/cpu-calls")" == apply ]] || fail 'buildx_builder_cap did not apply the CPU ceiling'
# Both builder-creation paths cap their builder right after it bootstraps.
grep -A1 -- '--bootstrap >/dev/null$' "$ROOT/scripts/ci/images/build-kind-images.sh" |
  grep -qx 'buildx_builder_cap "$builder"' || fail 'the Kind image build does not cap its builder'
grep -A1 -- 'buildx inspect "$builder" --bootstrap' "$ROOT/scripts/ci/images/workspace-cache.sh" |
  grep -qx '  buildx_builder_cap "$builder"' || fail 'the workspace cache build does not cap its builder'

echo 'buildx builder removal: success, confirmed-absent, waited deletion, persisting, unknown, hung, unsafe-name and CPU-cap cases passed'
