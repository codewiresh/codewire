#!/usr/bin/env bash
# Hermetic tests for scripts/runtime/dev/smoke-dev-transport-matrix.sh: the
# runtime smoke it drives, kubectl and cw are local fakes, so nothing reaches
# dev. They prove what an unattended run needs (codewire#3827): the deployed
# dev is tested without changing it; every node the run cordons is uncordoned
# on success, failure, the time bound and a signal, and a node left cordoned
# by a killed run is recovered; the environment is removed on failure when
# asked; a failure names the tailnet path that broke; and every failed exit
# names its step, so a failure can never come back unnamed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MATRIX="$ROOT/scripts/runtime/dev/smoke-dev-transport-matrix.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-transport-matrix-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"
API_KEY="cw_$(printf '0%.0s' {1..64})"
CASES=0

cleanup() {
  local stray
  # A straggler only outlives a failed group-kill assertion; never leave it.
  for stray in "$TEST_TMP"/case-*/state/stray.pid; do
    [[ -s "$stray" ]] && kill -KILL "$(cat "$stray")" 2>/dev/null || true
  done
  rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT

fail() {
  printf 'transport matrix tests: %s\n' "$*" >&2
  exit 1
}

FAKE_ROOT="$TEST_TMP/root"
FAKE_BIN="$TEST_TMP/bin"
mkdir -p "$FAKE_ROOT/scripts/runtime/dev" "$FAKE_BIN"
cp "$MATRIX" "$FAKE_ROOT/scripts/runtime/dev/smoke-dev-transport-matrix.sh"

# The runtime smoke the matrix drives. FAKE_SCENARIO picks its outcome; it
# records its arguments, its transport inputs and the node state it ran with.
cat >"$FAKE_ROOT/scripts/runtime/dev/smoke-dev-candidate.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="${FAKE_STATE:?}"
# A hang traps TERM before any setup, so the matrix's bound, which starts when
# it launches this script, always finds the handler however slowly a loaded
# guest runs what follows (#4309). candidate.started says it is in place.
if [[ "${FAKE_SCENARIO:?}" == hang ]]; then
  # Stand in for the smoke's own cleanup: report the stage, then exit.
  trap 'printf term >"$state/candidate.term"; printf "[runtime-smoke] acceptance-failure stage=direct-udp class=signal\n" >&2; exit 143' TERM
fi
printf '%s\n' "$@" >"$state/candidate.args"
printf 'transport=%s relay_matrix=%s derp=%s keep_env=%s cw_bin=%s skip_kube=%s name=%s\n' \
  "$EXPECTED_TAILNET_PATH_TRANSPORT" "$SMOKE_PEER_RELAY_MATRIX" "$SMOKE_DERP_FALLBACK" \
  "$SMOKE_KEEP_ENV" "${CW_BIN:-}" "$SMOKE_SKIP_KUBE" "$SMOKE_NAME" >"$state/candidate.env"
# A straggler in the smoke's process group that ignores SIGTERM.
if [[ "${FAKE_STRAY:-0}" == 1 ]]; then
  ( trap '' TERM; exec sleep 300 ) &
  printf '%s' "$!" >"$state/stray.pid"
fi
for node in "$state"/nodes/*; do
  printf '%s unschedulable=%s\n' "$(basename "$node")" "$(cat "$node/unschedulable")"
done >"$state/candidate.nodes"
evidence="$(mktemp -d "${SMOKE_TMP_PARENT:?}/codewire-runtime-smoke.XXXXXX")"
mkdir -p "$evidence/cw-config"
cp "$FAKE_CW" "$evidence/cw"
printf '[runtime-smoke] environment id env-0123\n' >&2
case "${FAKE_SCENARIO:?}" in
  pass)
    printf '{}\n' >"$evidence/tailnet-doctor.json"
    printf '{}\n' >"$evidence/tailnet-doctor-peer-relay.json"
    printf 'tailnet-ssh-ok\n' >"$evidence/ssh-tailnet.out"
    printf 'tailnet-peer-relay-ssh-ok\n' >"$evidence/ssh-tailnet-peer-relay.out"
    printf 'tailnet-derp-ssh-ok\n' >"$evidence/ssh-tailnet-derp.out"
    printf 'websocket-ssh-ok\n' >"$evidence/ssh-websocket.out"
    printf '[runtime-smoke] runtime smoke passed for env-0123\n' >&2
    printf '[runtime-smoke] kept smoke environment env-0123\n' >&2
    printf '[runtime-smoke] kept evidence directory %s\n' "$evidence" >&2
    ;;
  fail-relay)
    printf '[runtime-smoke] ERROR: tailnet doctor probe failed (expect=peer_relay, failed probe=expected, step=path)\n' >&2
    printf '[runtime-smoke] acceptance-failure stage=udp-relay class=assertion\n' >&2
    printf '[runtime-smoke] kept smoke environment env-0123\n' >&2
    printf '[runtime-smoke] kept failed-smoke evidence directory %s\n' "$evidence" >&2
    exit 1
    ;;
  hang)
    printf '[runtime-smoke] kept failed-smoke evidence directory %s\n' "$evidence" >&2
    : >"$state/candidate.started"
    sleep 60 &
    wait $!
    ;;
esac
EOF
chmod 0755 "$FAKE_ROOT/scripts/runtime/dev/smoke-dev-candidate.sh"

# cw, answering as the real one does: `info` resolves only live environments,
# so it fails once `rm` has run, and `report` reads the exact ID, deleted or not
# (its environment has no desired_state). Any other command fails the run.
# FAKE_CW_RM_FAILS refuses `rm`; FAKE_CW_NEVER_DESTROYED keeps the report short
# of destroyed.
FAKE_CW="$TEST_TMP/cw"
cat >"$FAKE_CW" <<'EOF'
#!/usr/bin/env bash
state="${FAKE_STATE:?}"
shift 2  # --server URL
case "$1" in
  rm)
    [[ "${FAKE_CW_RM_FAILS:-0}" != 1 ]] || exit 1
    printf '%s\n' "$3" >>"$state/cw-rm"
    ;;
  info)
    if [[ -s "$state/cw-rm" ]]; then
      printf 'platform environment "%s" not found\n' "$2" >&2
      exit 1
    fi
    printf '{"state":"running","desired_state":"running"}\n'
    ;;
  report)
    if [[ -s "$state/cw-rm" && "${FAKE_CW_NEVER_DESTROYED:-0}" != 1 ]]; then
      printf '{"environment":{"id":"%s","state":"destroyed"}}\n' "$2"
    else
      printf '{"environment":{"id":"%s","state":"destroying"}}\n' "$2"
    fi
    ;;
  *) exit 97 ;;
esac
EOF
chmod 0755 "$FAKE_CW"

# kubectl over a node table in $FAKE_STATE/nodes/<name>/{unschedulable,
# annotation}. FAKE_UNCORDON_FAILS names a node whose uncordon is refused.
cat >"$FAKE_BIN/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="${FAKE_STATE:?}"
printf '%s\n' "$*" >>"$state/kubectl.log"
args=()
while (($# > 0)); do
  case "$1" in
    --context) shift 2 ;;
    --request-timeout=*) shift ;;
    *) args+=("$1"); shift ;;
  esac
done
set -- "${args[@]}"
node_json() {
  local node="$1" dir="$state/nodes/$1"
  jq -n --arg name "$node" --arg unschedulable "$(cat "$dir/unschedulable")" \
    --arg annotation "$(cat "$dir/annotation" 2>/dev/null || true)" '{
      metadata: ({name: $name} + (if $annotation == "" then {} else
        {annotations: {"codewire.sh/transport-matrix-cordon": $annotation}} end)),
      spec: (if $unschedulable == "true" then {unschedulable: true} else {} end)
    }'
}
case "$1 $2" in
  "get nodes")
    for dir in "$state"/nodes/*; do node_json "$(basename "$dir")"; done | jq -s '{items: .}'
    ;;
  "get node")
    [[ "$(cat "$state/nodes/$3/unschedulable")" == true ]] && printf 'true'
    exit 0
    ;;
  "patch node")
    node="$3" patch="$6"
    unschedulable="$(jq -r '.spec.unschedulable' <<<"$patch")"
    if [[ "$unschedulable" != true && "${FAKE_UNCORDON_FAILS:-}" == "$node" ]]; then
      exit 1
    fi
    [[ "$unschedulable" == true ]] && printf true >"$state/nodes/$node/unschedulable" ||
      printf false >"$state/nodes/$node/unschedulable"
    annotation="$(jq -r '.metadata.annotations["codewire.sh/transport-matrix-cordon"] // ""' <<<"$patch")"
    printf '%s' "$annotation" >"$state/nodes/$node/annotation"
    ;;
  "delete namespace") printf '%s\n' "$3" >>"$state/deleted-namespaces" ;;
  *) exit 98 ;;
esac
EOF
chmod 0755 "$FAKE_BIN/kubectl"

# new_case NAME [NODE=UNSCHEDULABLE[:ANNOTATION]...]: a fresh state directory
# with these runtime nodes.
new_case() {
  local name="$1" spec node rest
  shift
  CASE="$TEST_TMP/case-$name"
  mkdir -p "$CASE/state/nodes" "$CASE/tmp"
  for spec in "$@"; do
    node="${spec%%=*}"
    rest="${spec#*=}"
    mkdir -p "$CASE/state/nodes/$node"
    printf '%s' "${rest%%:*}" >"$CASE/state/nodes/$node/unschedulable"
    if [[ "$rest" == *:* ]]; then
      printf '%s' "${rest#*:}" >"$CASE/state/nodes/$node/annotation"
    fi
  done
  CASES=$((CASES + 1))
}

# run_matrix SCENARIO [ENV=VALUE...] -- [matrix args...]: run the matrix in
# the current case; its stderr is $CASE/err and its status $CASE/rc.
run_matrix() {
  local scenario="$1"
  shift
  local -a env_args=()
  while (($# > 0)) && [[ "$1" != -- ]]; do
    env_args+=("$1")
    shift
  done
  [[ $# -gt 0 ]] && shift
  local rc=0
  env -i PATH="$FAKE_BIN:/usr/bin:/bin" HOME="$CASE" TMPDIR="$CASE/tmp" \
    KUBECONFIG="$CASE/no-kubeconfig" \
    FAKE_STATE="$CASE/state" FAKE_SCENARIO="$scenario" FAKE_CW="$FAKE_CW" \
    CODEWIRE_DEV_SMOKE_API_KEY="$API_KEY" \
    SMOKE_TMP_PARENT="$CASE/tmp" \
    MATRIX_DESTROY_TIMEOUT_SECONDS=10 \
    "${env_args[@]}" \
    timeout 120 "$FAKE_ROOT/scripts/runtime/dev/smoke-dev-transport-matrix.sh" "$@" \
    >/dev/null 2>"$CASE/err" || rc=$?
  printf '%s' "$rc" >"$CASE/rc"
}

case_rc() { cat "$CASE/rc"; }
# Whether PID still runs. A killed process stays a zombie until something
# reaps it, and kill -0 succeeds on a zombie; in a CI job container whose
# PID 1 never reaps, an orphan killed by the matrix stays one for good.
process_running() {
  local state
  state="$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -d' ' -f1)" || return 1
  [[ -n "$state" && "$state" != Z ]]
}
# Whether PID stops running. The matrix ends its smoke's process group with
# SIGKILL, which the kernel delivers and finishes asynchronously: on a starved
# guest the stray can still read as running just after the matrix exits
# (#4137). The bound is a hang guard; a stray nothing killed still fails.
stops_running() {
  local _
  for _ in $(seq 1 600); do
    process_running "$1" || return 0
    sleep 0.1
  done
  return 1
}
node_state() { printf '%s:%s' "$(cat "$CASE/state/nodes/$1/unschedulable")" "$(cat "$CASE/state/nodes/$1/annotation" 2>/dev/null || true)"; }
last_error() { grep -F '[transport-matrix] ERROR:' "$CASE/err" | tail -n 1; }
exit_line() { grep -F '[transport-matrix] exit-failure' "$CASE/err" | tail -n 1; }
show_err() { sed 's/[[:cntrl:]]//g' "$CASE/err" >&2; }

# The deployed dev, unchanged: no candidate image, no shared-dev override, no
# namespace, and the smoke asserts direct UDP, the UDP relay and DERP.
new_case current-dev-pass
run_matrix pass MATRIX_CORDON_OTHER_RUNTIME_NODES=0 -- --current-dev --cleanup-on-failure
[[ "$(case_rc)" == 0 ]] || { show_err; fail "current-dev pass exited $(case_rc)"; }
[[ "$(cat "$CASE/state/candidate.args")" == $'--current-dev\n--\n--keep\n--skip-docker' ]] ||
  fail "current-dev run changed dev: $(tr '\n' ' ' <"$CASE/state/candidate.args")"
grep -Fq 'transport=direct_udp relay_matrix=1 derp=1 keep_env=1 cw_bin=' "$CASE/state/candidate.env" ||
  fail "current-dev run does not assert direct UDP, the UDP relay and DERP"
[[ "$(cat "$CASE/state/cw-rm")" == env-0123 ]] || fail "current-dev pass did not remove its environment"
[[ ! -e "$CASE/state/deleted-namespaces" ]] || fail "current-dev run deleted a namespace"
if grep -Eq '^(.* )?(patch|cordon|uncordon|annotate)( |$)' "$CASE/state/kubectl.log" 2>/dev/null; then
  fail "a run without cordoning changed a node"
fi
grep -Fq 'transport matrix passed for env-0123: direct_udp, udp_relay, derp_relay, websocket' "$CASE/err" ||
  fail "current-dev pass did not name every path"
grep -Eq 'skip_kube=0 name=transport-matrix-[0-9]{14}$' "$CASE/state/candidate.env" ||
  fail "the smoke did not get the run's environment name: $(cat "$CASE/state/candidate.env")"
# 2400 s bound + 600 s to stop + 120 s removal + 10 s destroy wait + 62 s.
grep -Fq 'worst case with cleanup 3192s' "$CASE/err" ||
  fail "the run did not log its worst case with cleanup"

# Nothing the smoke started outlives the run: the matrix kills the smoke's
# process group, which timeout leads, even after the smoke itself exited.
new_case stray-after-pass
run_matrix pass MATRIX_CORDON_OTHER_RUNTIME_NODES=0 FAKE_STRAY=1 -- --current-dev
[[ "$(case_rc)" == 0 ]] || { show_err; fail "stray pass exited $(case_rc)"; }
[[ -s "$CASE/state/stray.pid" ]] || fail "the stray fixture did not start"
stops_running "$(cat "$CASE/state/stray.pid")" ||
  fail "a process in the smoke's group outlived a passing run"

# A supplied cw is used instead of a cargo build, and removes the environment.
new_case supplied-cw
run_matrix pass MATRIX_CORDON_OTHER_RUNTIME_NODES=0 CW_BIN="$FAKE_CW" -- --current-dev
[[ "$(case_rc)" == 0 ]] || { show_err; fail "supplied-cw pass exited $(case_rc)"; }
grep -Fq "cw_bin=$FAKE_CW" "$CASE/state/candidate.env" || fail "the smoke did not get the supplied CW_BIN"
[[ -z "$(exit_line)" ]] || fail "a passing run printed an exit-failure line"

# Every failed exit ends with one line naming its step, and the line holds no
# ID or path. A cleanup failure after a pass says the legs passed.
new_case cleanup-wait-names-itself
run_matrix pass MATRIX_CORDON_OTHER_RUNTIME_NODES=0 CW_BIN="$FAKE_CW" FAKE_CW_NEVER_DESTROYED=1 \
  MATRIX_DESTROY_TIMEOUT_SECONDS=1 -- --current-dev
[[ "$(case_rc)" == 1 ]] || { show_err; fail "a cleanup timeout exited $(case_rc)"; }
[[ "$(exit_line)" == '[transport-matrix] exit-failure step=cleanup cleanup=wait legs=passed' ]] ||
  { show_err; fail "a cleanup timeout did not name itself: $(exit_line)"; }

new_case cleanup-request-names-itself
run_matrix pass MATRIX_CORDON_OTHER_RUNTIME_NODES=0 CW_BIN="$FAKE_CW" FAKE_CW_RM_FAILS=1 -- --current-dev
[[ "$(case_rc)" == 1 ]] || { show_err; fail "a refused rm exited $(case_rc)"; }
[[ "$(exit_line)" == '[transport-matrix] exit-failure step=cleanup cleanup=request legs=passed' ]] ||
  { show_err; fail "a refused rm did not name itself: $(exit_line)"; }

new_case setup-names-itself
run_matrix pass CODEWIRE_DEV_SMOKE_API_KEY= -- --current-dev
[[ "$(case_rc)" == 1 ]] || { show_err; fail "a missing key exited $(case_rc)"; }
[[ "$(exit_line)" == '[transport-matrix] exit-failure step=setup cleanup=ok legs=unproven' ]] ||
  { show_err; fail "a setup failure did not name itself: $(exit_line)"; }

# A failed path is named on the last line; --cleanup-on-failure removes the
# environment and keeps the evidence.
new_case relay-failure-cleanup
run_matrix fail-relay MATRIX_CORDON_OTHER_RUNTIME_NODES=0 -- --current-dev --cleanup-on-failure
[[ "$(case_rc)" == 1 ]] || fail "a relay failure exited $(case_rc)"
last_error | grep -Fq 'transport matrix failed: path=udp_relay stage=udp-relay class=assertion' ||
  { show_err; fail "a relay failure did not name its path"; }
[[ "$(cat "$CASE/state/cw-rm")" == env-0123 ]] || fail "--cleanup-on-failure kept the environment"
grep -Fq 'kept failed transport matrix evidence directory' "$CASE/err" || fail "failure evidence was not kept"
[[ "$(exit_line)" == '[transport-matrix] exit-failure step=smoke cleanup=ok legs=unproven' ]] ||
  { show_err; fail "a relay failure's exit line is wrong: $(exit_line)"; }

# Without it, a failure keeps the environment for debugging, as before.
new_case relay-failure-keep
run_matrix fail-relay MATRIX_CORDON_OTHER_RUNTIME_NODES=0 -- --current-dev
[[ "$(case_rc)" == 1 ]] || fail "a kept relay failure exited $(case_rc)"
[[ ! -e "$CASE/state/cw-rm" ]] || fail "a failure without --cleanup-on-failure removed the environment"
grep -Fq 'kept smoke environment env-0123' "$CASE/err" || fail "the kept environment was not named"

# Cordoning: the other schedulable runtime nodes are cordoned and annotated for
# the run, then restored; a node someone else cordoned is left alone.
new_case cordon-pass node-a=false node-b=false node-c=true
run_matrix pass EXPECTED_NODE=node-a -- --current-dev --cleanup-on-failure
[[ "$(case_rc)" == 0 ]] || { show_err; fail "cordoned pass exited $(case_rc)"; }
grep -Fqx 'node-b unschedulable=true' "$CASE/state/candidate.nodes" || fail "node-b was not cordoned during the run"
grep -Fqx 'node-a unschedulable=false' "$CASE/state/candidate.nodes" || fail "the target node was cordoned"
[[ "$(node_state node-b)" == 'false:' ]] || fail "node-b was not restored: $(node_state node-b)"
[[ "$(node_state node-c)" == 'true:' ]] || fail "a node cordoned by someone else changed: $(node_state node-c)"

# ... and restored on failure.
new_case cordon-failure node-a=false node-b=false
run_matrix fail-relay EXPECTED_NODE=node-a -- --current-dev --cleanup-on-failure
[[ "$(case_rc)" == 1 ]] || fail "cordoned failure exited $(case_rc)"
[[ "$(node_state node-b)" == 'false:' ]] || fail "node-b stayed cordoned after a failure"

# An uncordon that keeps failing fails the run and names the node.
new_case uncordon-fails node-a=false node-b=false
run_matrix pass EXPECTED_NODE=node-a FAKE_UNCORDON_FAILS=node-b MATRIX_CLEANUP_ATTEMPTS=2 -- --current-dev
[[ "$(case_rc)" == 1 ]] || fail "a failed uncordon exited $(case_rc)"
grep -Fq 'runtime node node-b is still cordoned' "$CASE/err" || fail "a failed uncordon did not name the node"

# The bound: the smoke gets SIGTERM, the failure names the stage it was in,
# and the nodes and environment are restored. The fake traps TERM before its
# setup, so only bash starting it can race the bound; 10 s leaves a loaded
# guest room for that, where 2 s did not (#4309).
new_case time-bound node-a=false node-b=false
run_matrix hang EXPECTED_NODE=node-a MATRIX_TIMEOUT_SECONDS=10 MATRIX_KILL_AFTER_SECONDS=10 -- --current-dev --cleanup-on-failure
[[ "$(case_rc)" == 1 ]] || fail "a bounded run exited $(case_rc)"
[[ -s "$CASE/state/candidate.term" ]] || fail "the bound did not signal the smoke"
last_error | grep -Fq 'path=direct_udp stage=direct-udp class=signal after MATRIX_TIMEOUT_SECONDS=10' ||
  { show_err; fail "a bounded run did not name its path and the bound"; }
[[ "$(node_state node-b)" == 'false:' ]] || fail "node-b stayed cordoned after the bound"
[[ "$(cat "$CASE/state/cw-rm")" == env-0123 ]] || fail "the bounded run kept its environment"

# A signal: forwarded to the smoke, then the same cleanup.
new_case sigterm node-a=false node-b=false
(
  env -i PATH="$FAKE_BIN:/usr/bin:/bin" HOME="$CASE" TMPDIR="$CASE/tmp" \
    KUBECONFIG="$CASE/no-kubeconfig" \
    FAKE_STATE="$CASE/state" FAKE_SCENARIO=hang FAKE_CW="$FAKE_CW" FAKE_STRAY=1 \
    CODEWIRE_DEV_SMOKE_API_KEY="$API_KEY" SMOKE_TMP_PARENT="$CASE/tmp" \
    MATRIX_DESTROY_TIMEOUT_SECONDS=10 MATRIX_KILL_AFTER_SECONDS=5 EXPECTED_NODE=node-a \
    "$FAKE_ROOT/scripts/runtime/dev/smoke-dev-transport-matrix.sh" --current-dev --cleanup-on-failure \
    >/dev/null 2>"$CASE/err" &
  matrix_pid=$!
  # A hang guard for the fake smoke to start, not a speed expectation (#4137).
  for _ in $(seq 1 600); do
    [[ -e "$CASE/state/candidate.started" ]] && break
    sleep 0.1
  done
  [[ -e "$CASE/state/candidate.started" ]] || { kill "$matrix_pid"; exit 90; }
  kill -TERM "$matrix_pid"
  rc=0
  wait "$matrix_pid" || rc=$?
  printf '%s' "$rc" >"$CASE/rc"
)
[[ "$(case_rc)" == 143 ]] || { show_err; fail "a signalled run exited $(case_rc)"; }
grep -Fq 'interrupted; cleaning up' "$CASE/err" || fail "the signal was not handled by the matrix"
[[ -s "$CASE/state/candidate.term" ]] || fail "the signal was not forwarded to the smoke"
[[ "$(node_state node-b)" == 'false:' ]] || fail "node-b stayed cordoned after a signal"
[[ "$(cat "$CASE/state/cw-rm")" == env-0123 ]] || fail "the signalled run kept its environment"
stops_running "$(cat "$CASE/state/stray.pid")" ||
  fail "a process in the smoke's group outlived a signalled run"

# A node a killed run left cordoned is recovered by the next run.
new_case stale-cordon node-a=false node-b=true:1000:killed-run
run_matrix pass EXPECTED_NODE=node-a -- --current-dev
[[ "$(case_rc)" == 0 ]] || { show_err; fail "a run after a killed one exited $(case_rc)"; }
grep -Fq 'uncordoning runtime node node-b, left cordoned by interrupted transport matrix run killed-run' "$CASE/err" ||
  fail "the interrupted run's cordon was not recovered"
grep -Fqx 'node-b unschedulable=true' "$CASE/state/candidate.nodes" || fail "node-b was not cordoned for this run"
[[ "$(node_state node-b)" == 'false:' ]] || fail "node-b was not restored: $(node_state node-b)"

# Two runs never share the runtime nodes.
new_case live-cordon node-a=false "node-b=true:$(date -u +%s):other-run"
run_matrix pass EXPECTED_NODE=node-a -- --current-dev
[[ "$(case_rc)" == 1 ]] || fail "a run beside a live one exited $(case_rc)"
grep -Fq 'cordoned by transport matrix run other-run' "$CASE/err" || fail "the live run was not named"
[[ ! -e "$CASE/state/candidate.args" ]] || fail "the smoke ran beside a live run"
[[ "$(node_state node-b)" == "true:$(cat "$CASE/state/nodes/node-b/annotation")" && -s "$CASE/state/nodes/node-b/annotation" ]] ||
  fail "the live run's cordon changed"

# A target that is not a runtime node would cordon every runtime node.
new_case unknown-target node-a=false node-b=false
run_matrix pass EXPECTED_NODE=node-x -- --current-dev
[[ "$(case_rc)" == 1 ]] || fail "an unknown target exited $(case_rc)"
grep -Fq 'EXPECTED_NODE node-x is not a runtime node' "$CASE/err" || fail "the unknown target was not named"
[[ "$(node_state node-a)" == 'false:' && "$(node_state node-b)" == 'false:' ]] ||
  fail "an unknown target cordoned a node"

# Candidate-only options are refused against the deployed dev.
new_case current-dev-namespace
run_matrix pass MATRIX_CORDON_OTHER_RUNTIME_NODES=0 -- --current-dev --sandbox-namespace dev-sandboxes
[[ "$(case_rc)" == 1 ]] || fail "--current-dev accepted --sandbox-namespace"
[[ ! -e "$CASE/state/candidate.args" ]] || fail "the smoke ran with a refused option"

# The candidate target keeps its behaviour: images on the shared dev control
# plane, a temporary namespace, deleted once the environment is gone.
new_case candidate-pass
run_matrix pass MATRIX_CORDON_OTHER_RUNTIME_NODES=0 MATRIX_DAEMON_TAG=tag-1 -- --sandbox-namespace dev-sbx-transport-test
[[ "$(case_rc)" == 0 ]] || { show_err; fail "candidate pass exited $(case_rc)"; }
[[ "$(tr '\n' ' ' <"$CASE/state/candidate.args")" == '--image services --image daemon --skip-build --tag tag-1 --force-shared-dev --sandbox-namespace dev-sbx-transport-test --keep-namespace -- --keep --skip-docker ' ]] ||
  fail "candidate arguments changed: $(tr '\n' ' ' <"$CASE/state/candidate.args")"
[[ "$(cat "$CASE/state/deleted-namespaces")" == dev-sbx-transport-test ]] ||
  fail "candidate pass did not delete its temporary namespace"

# A failed candidate run keeps its namespace unless asked to clean up.
new_case candidate-failure
run_matrix fail-relay MATRIX_CORDON_OTHER_RUNTIME_NODES=0 MATRIX_DAEMON_TAG=tag-1 -- --sandbox-namespace dev-sbx-transport-test
[[ "$(case_rc)" == 1 ]] || fail "candidate failure exited $(case_rc)"
[[ ! -e "$CASE/state/deleted-namespaces" ]] || fail "a failed candidate run deleted its namespace"
grep -Fq 'kept temporary sandbox namespace dev-sbx-transport-test' "$CASE/err" || fail "the kept namespace was not named"

# --current-dev with SMOKE_SKIP_KUBE=1 is the unattended target: like Dev
# acceptance it holds no Kubernetes identity. The real matrix, candidate
# smoke and CI wrapper run here on a PATH with no kubectl; only the runtime
# smoke at the end of the chain is a fake.
REAL_ROOT="$TEST_TMP/real-root"
TOOLS="$TEST_TMP/tools"
mkdir -p "$REAL_ROOT/scripts/runtime/dev" "$REAL_ROOT/scripts/ci/verify" "$TOOLS"
cp "$MATRIX" "$REAL_ROOT/scripts/runtime/dev/smoke-dev-transport-matrix.sh"
cp "$ROOT/scripts/runtime/dev/smoke-dev-candidate.sh" "$REAL_ROOT/scripts/runtime/dev/smoke-dev-candidate.sh"
cp "$ROOT/scripts/ci/verify/runtime-dev-commodity-smoke.sh" "$REAL_ROOT/scripts/ci/verify/runtime-dev-commodity-smoke.sh"
cat >"$REAL_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="${FAKE_STATE:?}"
printf '%s\n' "$@" >"$state/smoke.args"
printf 'transport=%s relay_matrix=%s derp=%s skip_kube=%s name=%s\n' \
  "$EXPECTED_TAILNET_PATH_TRANSPORT" "$SMOKE_PEER_RELAY_MATRIX" "$SMOKE_DERP_FALLBACK" \
  "$SMOKE_SKIP_KUBE" "$SMOKE_NAME" >"$state/smoke.env"
evidence="$(mktemp -d "${SMOKE_TMP_PARENT:?}/codewire-runtime-smoke.XXXXXX")"
mkdir -p "$evidence/cw-config"
cp "$FAKE_CW" "$evidence/cw"
printf '{}\n' >"$evidence/tailnet-doctor.json"
printf '{}\n' >"$evidence/tailnet-doctor-peer-relay.json"
printf 'tailnet-ssh-ok\n' >"$evidence/ssh-tailnet.out"
printf 'tailnet-peer-relay-ssh-ok\n' >"$evidence/ssh-tailnet-peer-relay.out"
printf 'tailnet-derp-ssh-ok\n' >"$evidence/ssh-tailnet-derp.out"
printf 'websocket-ssh-ok\n' >"$evidence/ssh-websocket.out"
printf '[runtime-smoke] environment id env-0123\n' >&2
printf '[runtime-smoke] kept evidence directory %s\n' "$evidence" >&2
EOF
chmod 0755 "$REAL_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
for tool in bash env timeout jq awk sed grep date mktemp basename dirname tr cut cat \
    chmod mkdir rm cp sleep head tail sort seq id stat wc find; do
  ln -s "$(command -v "$tool")" "$TOOLS/$tool"
done
[[ ! -e "$TOOLS/kubectl" ]] && ! PATH="$TOOLS" command -v kubectl >/dev/null ||
  fail "the no-Kubernetes PATH has kubectl"

run_real_matrix() {
  local rc=0
  env -i PATH="$TOOLS" HOME="$CASE" TMPDIR="$CASE/tmp" \
    FAKE_STATE="$CASE/state" FAKE_CW="$FAKE_CW" \
    CODEWIRE_DEV_SMOKE_API_KEY="$API_KEY" SMOKE_TMP_PARENT="$CASE/tmp" \
    CODEWIRE_SERVER_URL=https://dev.example.invalid \
    EXPECTED_CODEWIRE_DEV_SERVER_URL=https://dev.example.invalid \
    EXPECTED_TAILNET_DIRECT_UDP_LB_IP=192.0.2.10 \
    EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE=zone-a \
    EXPECTED_TAILNET_PEER_RELAY_ENDPOINT=192.0.2.20:41641 \
    MATRIX_DESTROY_TIMEOUT_SECONDS=10 SMOKE_SKIP_KUBE=1 \
    "$@" \
    timeout 120 "$REAL_ROOT/scripts/runtime/dev/smoke-dev-transport-matrix.sh" --current-dev --cleanup-on-failure \
    >/dev/null 2>"$CASE/err" || rc=$?
  printf '%s' "$rc" >"$CASE/rc"
}

new_case no-kubernetes
run_real_matrix MATRIX_CORDON_OTHER_RUNTIME_NODES=0
[[ "$(case_rc)" == 0 ]] || { show_err; fail "--current-dev without Kubernetes exited $(case_rc)"; }
# The smoke's own output is in the matrix's log of it.
smoke_log="$(find "$CASE/tmp" -path '*codewire-transport-matrix.*/initial-direct-derp-websocket.log')"
grep -Fq 'SMOKE_SKIP_KUBE=1: no Kubernetes runtime preflight' "$smoke_log" ||
  fail "the candidate smoke did not skip its Kubernetes preflight"
grep -Fq 'running application-only commodity smoke' "$smoke_log" ||
  fail "the CI wrapper did not run the application-only smoke"
grep -Eq '^transport=direct_udp relay_matrix=1 derp=1 skip_kube=1 name=transport-matrix-[0-9]{14}$' \
  "$CASE/state/smoke.env" || fail "the runtime smoke got the wrong inputs: $(cat "$CASE/state/smoke.env")"
[[ "$(tr '\n' ' ' <"$CASE/state/smoke.args")" == '--timeout-seconds 900 --keep --skip-docker ' ]] ||
  fail "the runtime smoke got the wrong arguments: $(tr '\n' ' ' <"$CASE/state/smoke.args")"
[[ "$(cat "$CASE/state/cw-rm")" == env-0123 ]] || fail "the run without Kubernetes kept its environment"
grep -Fq 'transport matrix passed for env-0123: direct_udp, udp_relay, derp_relay, websocket' "$CASE/err" ||
  fail "the run without Kubernetes did not pass every path"

# Cordoning is the one thing the unattended matrix itself needs kubectl for.
new_case no-kubernetes-cordon
run_real_matrix MATRIX_CORDON_OTHER_RUNTIME_NODES=1 EXPECTED_NODE=node-a
[[ "$(case_rc)" == 1 ]] || fail "cordoning without kubectl exited $(case_rc)"
grep -Fq 'missing required command: kubectl' "$CASE/err" || fail "cordoning did not require kubectl"
[[ ! -e "$CASE/state/smoke.args" ]] || fail "the smoke ran though cordoning could not"

printf 'transport matrix tests passed (%d cases; no live calls)\n' "$CASES"
