#!/usr/bin/env bash
# The kill test that sets each memory tier's commodity Pod overhead (#3718; design
# 2026-11-01-commodity-workspace-direct-io §4). For each shape it runs rounds at each
# overhead step, from the largest down, and records per round: whether the VM
# survived, peak host dirty + writeback, and peak VMM + virtiofsd + shim memory.
#
# A cell stops at its first lost round, since it can no longer hold every round, and
# a shape stops descending there: a smaller margin is assumed no safer. Results are
# one JSON line per round under --results, and a rerun skips rounds already there.
#
# The value for a shape is the smallest step that held every round, and no less than
# the worst peak seen plus 25%, rounded up to 128 MiB.
#
# Usage:
#   kill-test-overhead-matrix.sh run    [options]   rounds, then the decision
#   kill-test-overhead-matrix.sh plan   [options]   what run would do; touches nothing
#   kill-test-overhead-matrix.sh decide [options]   the decision from --results alone
#   kill-test-overhead-matrix.sh real   [options]   the confirming real-workload round
#                                                   per tier, at the deployed overhead:
#                                                   load-dev-sandbox-capacity.sh, one
#                                                   sandbox, --workload real
#
# Options:
#   --shapes LIST     workspace+DinD GiB (default 4+2,8+4,16+4,32+4)
#   --steps LIST      overheads, largest first (default 1Gi,768Mi,512Mi,384Mi,256Mi)
#   --rounds N        rounds the deciding step must hold (default 10)
#   --screen-rounds N rounds per step while descending (default: --rounds); only the
#                     smallest step that holds them runs the full --rounds
#   --results DIR     where rounds are recorded (required for run and decide)
#   --max-hours H     stop starting rounds after this long (default 12)
#   --all-cells       run every cell, without stopping at the first loss
#
# KILL_TEST_ROUND names the command that runs one round. It is called as
#   ROUND MAIN_GIB SECOND_GIB OVERHEAD
# and prints one JSON object with: survived (bool), seconds, peak_dirty_writeback_mib,
# peak_host_processes_mib (both may be null when not measured) and evidence (string).
set -euo pipefail

SHAPES="4+2,8+4,16+4,32+4"
STEPS="1Gi,768Mi,512Mi,384Mi,256Mi"
ROUNDS=10
SCREEN_ROUNDS=""
RESULTS=""
MAX_HOURS=12
ALL_CELLS=0
KILL_TEST_ROUND="${KILL_TEST_ROUND:-}"
# Rough round length for planning, as kill-test-round.sh runs one: the writers'
# time, about 20 s per GiB to fill RAM, and about 90 s to start and remove the Pod.
# As the round: the real workload's budget is longer.
WRITE_SECONDS="${KILL_TEST_WRITE_SECONDS:-$([[ "${KILL_TEST_WORKLOAD:-fill}" == real ]] && echo 2400 || echo 120)}"

log() { printf '[kill-test] %s\n' "$*" >&2; }
die() { printf '[kill-test] ERROR: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

mib() { # 1Gi | 768Mi -> MiB
  case "$1" in
    *Gi) echo $(( ${1%Gi} * 1024 )) ;;
    *Mi) echo "${1%Mi}" ;;
    *) die "not a size: $1" ;;
  esac
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --shapes) SHAPES="${2:?}"; shift 2 ;;
      --steps) STEPS="${2:?}"; shift 2 ;;
      --rounds) ROUNDS="${2:?}"; shift 2 ;;
      --screen-rounds) SCREEN_ROUNDS="${2:?}"; shift 2 ;;
      --results) RESULTS="${2:?}"; shift 2 ;;
      --max-hours) MAX_HOURS="${2:?}"; shift 2 ;;
      --all-cells) ALL_CELLS=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  local shape step previous=""
  for shape in ${SHAPES//,/ }; do
    [[ "$shape" =~ ^[1-9][0-9]*\+[1-9][0-9]*$ ]] || die "a shape looks like 8+4, not $shape"
  done
  for step in ${STEPS//,/ }; do
    [[ "$step" =~ ^[1-9][0-9]*(Mi|Gi)$ ]] || die "a step looks like 512Mi or 1Gi, not $step"
    if [[ -n "$previous" ]] && (( $(mib "$step") >= $(mib "$previous") )); then
      die "--steps go from the largest down"
    fi
    previous="$step"
  done
  [[ "$ROUNDS" =~ ^[1-9][0-9]*$ ]] || die "--rounds must be a positive integer"
  : "${SCREEN_ROUNDS:=$ROUNDS}"
  if ! [[ "$SCREEN_ROUNDS" =~ ^[1-9][0-9]*$ ]] || ((SCREEN_ROUNDS > ROUNDS)); then
    die "--screen-rounds must be a positive integer no more than --rounds"
  fi
  [[ "$MAX_HOURS" =~ ^[1-9][0-9]*$ ]] || die "--max-hours must be a positive integer"
}

results_file() { echo "$RESULTS/rounds.jsonl"; }

# The recorded rounds of one cell, oldest first.
cell_rounds() { # SHAPE STEP
  local file; file="$(results_file)"
  [[ -s "$file" ]] || return 0
  jq -c --arg shape "$1" --arg step "$2" 'select(.shape == $shape and .overhead == $step)' "$file"
}

round_seconds() { # MAIN_GIB SECOND_GIB
  echo $(( WRITE_SECONDS + $1 * 20 + 90 ))
}

plan() {
  local shape main second rounds_max=0 rounds_min=0 seconds_max=0 seconds_min=0 per steps
  steps="$(wc -w <<<"${STEPS//,/ }")"
  printf 'Shapes %s; steps %s; %s rounds per step, %s at the deciding one; results in %s\n' \
    "$SHAPES" "$STEPS" "$SCREEN_ROUNDS" "$ROUNDS" "${RESULTS:-(none)}"
  for shape in ${SHAPES//,/ }; do
    main="${shape%+*}" second="${shape#*+}"
    per="$(round_seconds "$main" "$second")"
    # Fewest: the largest step loses its first round. Most: every cell runs in full.
    rounds_min=$((rounds_min + 1)); seconds_min=$((seconds_min + per))
    rounds_max=$((rounds_max + steps * SCREEN_ROUNDS + (ROUNDS - SCREEN_ROUNDS) * steps))
    seconds_max=$((seconds_max + (steps * SCREEN_ROUNDS + (ROUNDS - SCREEN_ROUNDS) * steps) * per))
    printf '  %-6s about %s s per round\n' "$shape" "$per"
  done
  printf 'Rounds: %s to %s; about %s min to %s h. Stops starting rounds after %s h.\n' \
    "$rounds_min" "$rounds_max" $((seconds_min / 60)) $((seconds_max / 3600)) "$MAX_HOURS"
}

# One round, recorded with its cell. A round command that fails or prints something
# other than its JSON is recorded as unknown, never as survived.
record_round() { # SHAPE STEP ROUND
  local main="${1%+*}" second="${1#*+}" out status line
  set +e
  out="$("$KILL_TEST_ROUND" "$main" "$second" "$2" 2>"$RESULTS/round.err")"
  status=$?
  set -e
  if line="$(jq -ce 'select(type == "object" and (.survived | type) == "boolean")' <<<"$out" 2>/dev/null)" && ((status == 0 || status == 1)); then
    :
  elif line="$(jq -ce --argjson status "$status" 'select(type == "object" and .survived == null) | .evidence = "unknown (exit \($status)): \(.evidence)"' <<<"$out" 2>/dev/null)"; then
    :
  else
    line="$(jq -cn --arg error "$(tail -c 400 "$RESULTS/round.err")" --argjson status "$status" \
      '{survived: null, seconds: null, peak_dirty_writeback_mib: null, peak_host_processes_mib: null,
        evidence: "round failed to run (exit \($status)): \($error)"}')"
  fi
  jq -c --arg shape "$1" --arg step "$2" --argjson round "$3" --arg at "$(date -u +%FT%TZ)" \
    '{shape: $shape, overhead: $step, round: $round, at: $at} + .' <<<"$line" >>"$(results_file)"
  jq -r '"\(.shape) \(.overhead) round \(.round): " + (if .survived == true then "survived" elif .survived == false then "LOST" else "unknown" end)
    + " after \(.seconds // "?") s; dirty+writeback \(.peak_dirty_writeback_mib // "?") MiB, host processes \(.peak_host_processes_mib // "?") MiB"' \
    <<<"$(tail -1 "$(results_file)")" >&2
}

# Runs a cell's rounds up to COUNT, reusing recorded ones, and sets CELL to held,
# lost, unknown or stopped (past --max-hours). It stops at the first loss unless
# --all-cells. An unknown round runs again; its record stays as evidence.
run_cell() { # SHAPE STEP COUNT
  local round recorded lost=0
  for (( round = 1; round <= $3; round++ )); do
    recorded="$(cell_rounds "$1" "$2" | jq -s --argjson round "$round" 'map(select(.round == $round)) | last')"
    if [[ "$recorded" == null || "$(jq -r '.survived' <<<"$recorded")" == null ]]; then
      if (( $(date +%s) >= DEADLINE )); then log "stopping: past --max-hours"; CELL=stopped; return; fi
      record_round "$1" "$2" "$round"
      recorded="$(tail -1 "$(results_file)")"
    fi
    case "$(jq -r '.survived' <<<"$recorded")" in
      null) log "$1 $2 round $round is unknown; rerun to retry it"; CELL=unknown; return ;;
      false) lost=1; ((ALL_CELLS)) || { CELL=lost; return; } ;;
    esac
  done
  if ((lost)); then CELL=lost; else CELL=held; fi
}

# Per shape: descend with --screen-rounds per step until a step loses, then take the
# smallest step that held to the full --rounds; if it loses there, the next larger.
run() {
  [[ -n "$RESULTS" ]] || die "--results is required"
  [[ -n "$KILL_TEST_ROUND" && -x "$KILL_TEST_ROUND" ]] || die "KILL_TEST_ROUND must name an executable round command"
  mkdir -p "$RESULTS"
  touch "$(results_file)"
  DEADLINE=$(( $(date +%s) + MAX_HOURS * 3600 ))
  local shape step held i
  for shape in ${SHAPES//,/ }; do
    held=()
    for step in ${STEPS//,/ }; do
      run_cell "$shape" "$step" "$SCREEN_ROUNDS"
      case "$CELL" in
        stopped) decide; return ;;
        unknown) continue 2 ;;
        held) held+=("$step") ;;
        lost) ((ALL_CELLS)) || { log "$shape lost a round at $step; not descending further"; break; } ;;
      esac
    done
    ((SCREEN_ROUNDS < ROUNDS)) || continue
    for (( i = ${#held[@]} - 1; i >= 0; i-- )); do
      log "$shape: confirming ${held[i]} over $ROUNDS rounds"
      run_cell "$shape" "${held[i]}" "$ROUNDS"
      case "$CELL" in
        stopped) decide; return ;;
        held|unknown) break ;;
        lost) log "$shape lost at ${held[i]} past the screen; trying the next larger step" ;;
      esac
    done
  done
  decide
}

# Per shape: the cells, and the value the rule gives.
decide() {
  [[ -s "$(results_file)" ]] || die "no rounds recorded in $(results_file)"
  jq -rs --arg shapes "$SHAPES" --arg steps "$STEPS" --argjson rounds "$ROUNDS" '
    def mib: if endswith("Gi") then (.[:-2] | tonumber * 1024) else (.[:-2] | tonumber) end;
    def up128: (. / 128 | ceil) * 128;
    . as $all
    | ($steps | split(",")) as $order
    | ($shapes | split(","))[] as $shape
    | [$all[] | select(.shape == $shape and .survived != null)] as $done
    | [$order[] as $step
        | [$done[] | select(.overhead == $step)] as $cell
        | {step: $step, ran: ($cell | length), survived: ([$cell[] | select(.survived)] | length)}] as $cells
    # Only rounds that measured both: a missing number is unknown, never zero.
    | ([$done[] | select(.peak_dirty_writeback_mib != null and .peak_host_processes_mib != null)
        | .peak_dirty_writeback_mib + .peak_host_processes_mib] | max // null) as $peak
    | ([$cells[] | select(.ran == $rounds and .survived == $rounds) | .step | mib] | min // null) as $held
    | (if $peak == null then null else ($peak * 1.25 | up128) end) as $floor
    | "\($shape): "
      + ([$cells[] | select(.ran > 0) | "\(.step) \(.survived)/\(.ran)"] | join(", "))
      + "\n  worst peak (dirty+writeback + host processes): \($peak // "not measured") MiB"
      + " (dirty+writeback \([$done[] | .peak_dirty_writeback_mib // empty] | max // "?"), host processes \([$done[] | .peak_host_processes_mib // empty] | max // "?"))"
      + "\n  smallest step holding \($rounds)/\($rounds): " + (if $held == null then "none" else "\($held) MiB" end)
      + "\n  value: " + (if $held == null then "none: no step held every round"
          elif $floor == null then "\($held) MiB, but no peak was measured to check it against"
          elif $floor > $held then "\($floor) MiB (the peak rule raises it above \($held); not tested at that size)"
          else "\($held) MiB" end)' "$(results_file)"
}

# A shape's capacity-tool name: the product shapes with these workspace sizes.
tier_shape() { # SHAPE
  case "$1" in
    4+2) echo small ;;
    8+4) echo default ;;
    16+4) echo large ;;
    32+4) echo xlarge ;;
    *) return 1 ;;
  esac
}

real() {
  [[ -n "$RESULTS" ]] || die "--results is required"
  local shape tool
  tool="$(dirname "${BASH_SOURCE[0]}")/load-dev-sandbox-capacity.sh"
  mkdir -p "$RESULTS/real"
  for shape in ${SHAPES//,/ }; do
    tier_shape "$shape" >/dev/null || die "no product shape for $shape"
  done
  for shape in ${SHAPES//,/ }; do
    log "real-workload round, $shape ($(tier_shape "$shape"))"
    LOAD_TMP_PARENT="$RESULTS/real/$shape" "$tool" --shape "$(tier_shape "$shape")" --steps 1 \
      --workload real --hold-seconds 900 --ssh-sample 1 "${REAL_TOOL_ARGS[@]}" \
      >"$RESULTS/real/$shape.log" 2>&1 || true
    grep -E 'Stopped:|lost|replaced|OOM|did not run|LESS LOAD' "$RESULTS/real/$shape.log" | tail -3 >&2 || true
  done
}

main() {
  local command="${1:-}"
  [[ "$#" -gt 0 ]] && shift
  case "$command" in
    run) parse_args "$@"; run ;;
    plan) parse_args "$@"; plan ;;
    decide) parse_args "$@"; [[ -n "$RESULTS" ]] || die "--results is required"; decide ;;
    real)
      # Options after -- go to the capacity tool, such as --cw-bin.
      local own=()
      REAL_TOOL_ARGS=()
      while [[ "$#" -gt 0 && "$1" != -- ]]; do own+=("$1"); shift; done
      [[ "${1:-}" == -- ]] && { shift; REAL_TOOL_ARGS=("$@"); }
      parse_args "${own[@]}"
      real ;;
    -h|--help|"") usage ;;
    *) die "unknown command: $command" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
