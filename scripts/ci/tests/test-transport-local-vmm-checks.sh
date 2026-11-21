#!/usr/bin/env bash
# run_transport's local-vmm checks (run-product-verification.sh): the Darwin
# check and the guest's initramfs proof run through run_builds_side_by_side,
# at once under a shared jobserver and one after another without. Nothing
# else runs between their start and their end, in the checks stage or in
# `all`; every failure is the stage's, whether or not the caller has set -e
# on; and no check is left running when the stage returns (infra#1534, A5a).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/test-transport-local-vmm-checks.XXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT
fail() { echo "test-transport-local-vmm-checks: $*" >&2; exit 1; }

body="$TMP/run_transport.sh"
awk '/^run_transport\(\) \{/,/^}/' "$ROOT/scripts/ci/verify/run-product-verification.sh" >"$body"
grep -q '^run_transport() {' "$body" || fail 'run_transport was not found'

# Each fake check records its PID and when it starts and ends, takes its
# SLEEP_ variable's seconds (default one), and exits with its FAIL_ variable.
mkdir -p "$TMP/tree/scripts/ci/verify"
for name in check-darwin-cross build-local-vmm-initramfs; do
  cat >"$TMP/tree/scripts/ci/verify/$name.sh" <<EOF
#!/usr/bin/env bash
echo "\$\$" >"\$CHECKS_LOG.$name.pid"
printf 'start $name %s\n' "\$(date +%s.%N)" >>"\$CHECKS_LOG"
sleep "\${SLEEP_${name//-/_}:-1}"
printf 'end $name %s\n' "\$(date +%s.%N)" >>"\$CHECKS_LOG"
exit "\${FAIL_${name//-/_}:-0}"
EOF
  chmod +x "$TMP/tree/scripts/ci/verify/$name.sh"
done

# The stage's helpers, stubbed for the local VMM and the guest probe, on a
# runner that can run the guest's fixtures.
cat >"$TMP/stubs.sh" <<'EOF'
selected() { [[ "$1" == transport_pkg_codewire_local_vmm || "$1" == transport_pkg_codewire_vmm_guest_probe ]]; }
rust_shard() { [ "$1" = local-vmm ]; }
check_shard_stage() { return 0; }
shard_stage() { [ "$RUST_SHARD_STAGE" = all ] || [ "$RUST_SHARD_STAGE" = "$1" ]; }
static_guest_proof_runs() { return 0; }
privileged_mount_namespace_available() { return 0; }
python3() { return 0; }
# A fixture takes half a second, so a check started before it would show.
shard_test() {
  printf 'start fixture %s\n' "$(date +%s.%N)" >>"$CHECKS_LOG"; sleep 0.5
  printf 'end fixture %s\n' "$(date +%s.%N)" >>"$CHECKS_LOG"; return "${FAIL_FIXTURE:-0}"
}
run_rust_packages() { echo 'the packages shard ran' >&2; return 99; }
run_derp_contract() { echo 'the DERP contract ran' >&2; return 99; }
EOF
# run_stage MODE STAGE [CARGO_MAKEFLAGS]: the local-vmm shard in its own bash.
# MODE errexit runs it as a command under set -e; MODE condition calls it left
# of ||, where set -e is off. Prints the stage's exit status.
run_stage() {
  : >"$TMP/checks.log"
  rm -f "$TMP"/checks.log.*.pid
  local status=0
  (
    cd "$TMP/tree"
    CHECKS_LOG="$TMP/checks.log" CARGO_MAKEFLAGS="${3:-}" RUST_SHARD_STAGE="$2" MODE="$1" \
      SIDE_BY_SIDE="$ROOT/scripts/ci/verify/side-by-side.sh" STUBS="$TMP/stubs.sh" BODY="$body" \
      bash -c '
        set -uo pipefail
        source "$SIDE_BY_SIDE"; source "$STUBS"; source "$BODY"
        if [ "$MODE" = errexit ]; then set -e; run_transport; exit 0; fi
        status=0; run_transport || status=$?; exit "$status"'
  ) >"$TMP/stage.out" 2>&1 || status=$?
  echo "$status"
}
# NAME was stopped: it started and never reached its end.
stopped() {
  [ -n "$(at start "$1")" ] || fail "$2: $1 never started"
  [ -z "$(at end "$1")" ] || fail "$2: $1 ran to its end instead of being stopped"
}
at() { awk -v kind="$1" -v name="$2" '$1 == kind && $2 == name { print $3 }' "$TMP/checks.log"; }
before() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'; }
# No check is still running once the stage has returned. A zombie has exited:
# a stopped check's orphan is reparented to PID 1, which in CI's job
# container is `tail -f /dev/null` and never reaps it, so kill -0 alone would
# call it running (run 67685).
none_left() {
  local pid state
  for pid in "$TMP"/checks.log.*.pid; do
    [ -e "$pid" ] || continue
    state="$(ps -o stat= -p "$(cat "$pid")" 2>/dev/null || true)"
    [[ -z "$state" || "$state" == Z* ]] || fail "$1: $(basename "$pid" .pid) still runs after the stage returned"
  done
}

# Under a jobserver: both run, at once.
[ "$(run_stage errexit checks --jobserver-auth=3,4)" = 0 ] || fail "a green stage failed: $(cat "$TMP/stage.out")"
if ! before "$(at start build-local-vmm-initramfs)" "$(at end check-darwin-cross)" ||
    ! before "$(at start check-darwin-cross)" "$(at end build-local-vmm-initramfs)"; then
  fail "under a jobserver the checks ran one after another: $(cat "$TMP/checks.log")"
fi

# Without one: one after another.
[ "$(run_stage errexit checks)" = 0 ] || fail 'a green serial stage failed'
if before "$(at start build-local-vmm-initramfs)" "$(at end check-darwin-cross)" &&
    before "$(at start check-darwin-cross)" "$(at end build-local-vmm-initramfs)"; then
  fail "without a jobserver the checks overlapped: $(cat "$TMP/checks.log")"
fi

# A failing Darwin check fails the stage, with set -e on or off, and stops the
# proof beside it, which would otherwise outlast it by far.
for mode in errexit condition; do
  [ "$(FAIL_check_darwin_cross=7 SLEEP_build_local_vmm_initramfs=30 run_stage "$mode" checks --jobserver-auth=3,4)" != 0 ] ||
    fail "a failing Darwin check did not fail the stage ($mode)"
  stopped build-local-vmm-initramfs "a failing Darwin check ($mode)"
  none_left "a failing Darwin check ($mode)"
done

# A failing proof fails the stage, stops the Darwin check and leaves nothing
# running.
[ "$(FAIL_build_local_vmm_initramfs=5 SLEEP_check_darwin_cross=30 run_stage errexit checks --jobserver-auth=3,4)" != 0 ] ||
  fail 'a failing proof did not fail the stage'
stopped check-darwin-cross 'a failing proof'
none_left 'a failing proof'

# In `all`, the guest's fixtures run before either check starts, so a failing
# fixture fails the stage with no check ever started.
[ "$(run_stage errexit all --jobserver-auth=3,4)" = 0 ] || fail "a green all stage failed: $(cat "$TMP/stage.out")"
fixtures_end="$(awk '$1 == "end" && $2 == "fixture" { last = $3 } END { print last }' "$TMP/checks.log")"
for name in check-darwin-cross build-local-vmm-initramfs; do
  before "$fixtures_end" "$(at start "$name")" ||
    fail "in all $name started before the fixtures ended: $(cat "$TMP/checks.log")"
done
# (Under set -e, as CI runs it: a fixture's failure has always relied on it.)
[ "$(FAIL_FIXTURE=3 run_stage errexit all --jobserver-auth=3,4)" != 0 ] ||
  fail 'a failing fixture did not fail the stage'
sleep 0.5
if compgen -G "$TMP/checks.log.*.pid" >/dev/null; then
  fail "a check started beside a failing fixture: $(cat "$TMP/checks.log")"
fi

echo 'test-transport-local-vmm-checks: side by side under a jobserver, one after another without, after the fixtures, every failure kept, nothing left running'
