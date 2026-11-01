#!/usr/bin/env bash
# Offline contract for the overhead kill test (#3718): which rounds it runs, how it
# records them, and the value its rule gives. A fake round stands in for the Pod.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MATRIX="$ROOT/scripts/runtime/dev/kill-test-overhead-matrix.sh"
fail() { printf 'test-kill-test-overhead-matrix: %s\n' "$*" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

bash -n "$MATRIX"
"$MATRIX" --help | grep -F 'The kill test that sets each memory tier' >/dev/null || fail "help is missing"

refuses() { # MESSAGE ARGS...
  local message="$1"; shift
  if out="$("$MATRIX" "$@" 2>&1)"; then fail "accepted: $*"; fi
  grep -F -- "$message" <<<"$out" >/dev/null || fail "wrong refusal for $*: $out"
}
refuses 'a shape looks like 8+4' plan --shapes 8x4
refuses 'from the largest down' plan --steps 512Mi,1Gi
refuses 'a step looks like' plan --steps 1G
refuses '--rounds must be' plan --rounds 0
refuses 'KILL_TEST_ROUND must name' run --results "$work/none"

# The plan touches nothing and gives the bounds.
out="$(KILL_TEST_ROUND=/nonexistent "$MATRIX" plan --shapes 4+2 --steps 1Gi,512Mi --rounds 10)"
grep -F 'Rounds: 1 to 20' <<<"$out" >/dev/null || fail "plan bounds: $out"

# A fake round: survives at or above the margin a shape needs, with fixed peaks.
cat >"$work/round" <<'SH'
#!/usr/bin/env bash
main="$1" second="$2" overhead="$3"
case "$overhead" in *Gi) mib=$(( ${overhead%Gi} * 1024 )) ;; *Mi) mib=${overhead%Mi} ;; esac
needs=$(( main >= 16 ? 700 : 400 ))
echo "$main $second $overhead" >>"$CALLS"
survived=$([[ "$mib" -ge "$needs" ]] && echo true || echo false)
printf '{"survived":%s,"seconds":60,"peak_dirty_writeback_mib":300,"peak_host_processes_mib":%s,"evidence":"fake"}\n' \
  "$survived" "$(( main >= 16 ? 280 : 90 ))"
SH
chmod 755 "$work/round"
export KILL_TEST_ROUND="$work/round" CALLS="$work/calls"

decision="$("$MATRIX" run --shapes 8+4,16+4 --steps 1Gi,768Mi,512Mi,384Mi --rounds 3 --results "$work/r1" 2>/dev/null)"
# 8+4 holds down to 512Mi; 384Mi loses its first round and the shape stops there.
[[ "$(grep -c '^8 4 ' "$CALLS")" == 10 ]] || fail "8+4 rounds: $(grep -c '^8 4 ' "$CALLS")"
# 16+4 holds at 1Gi and 768Mi; 512Mi loses its first round.
[[ "$(grep -c '^16 4 ' "$CALLS")" == 7 ]] || fail "16+4 rounds: $(grep -c '^16 4 ' "$CALLS")"
grep -F '8+4: 1Gi 3/3, 768Mi 3/3, 512Mi 3/3, 384Mi 0/1' <<<"$decision" >/dev/null || fail "8+4 cells: $decision"
# Worst peak 390 MiB: +25% = 487.5, up to 512. The held step is 512, so 512.
grep -F 'value: 512 MiB' <<<"$decision" >/dev/null || fail "8+4 value: $decision"
# 16+4: worst peak 580 MiB, +25% = 725, up to 768; held 768.
grep -F 'value: 768 MiB' <<<"$decision" >/dev/null || fail "16+4 value: $decision"

# A rerun skips every recorded round.
: >"$CALLS"
"$MATRIX" run --shapes 8+4,16+4 --steps 1Gi,768Mi,512Mi,384Mi --rounds 3 --results "$work/r1" >/dev/null 2>&1
[[ ! -s "$CALLS" ]] || fail "a rerun ran recorded rounds again: $(wc -l <"$CALLS")"

# The peak rule can raise the value above the held step, and says it wasn't tested.
cat >"$work/round-hot" <<'SH'
#!/usr/bin/env bash
printf '{"survived":true,"seconds":60,"peak_dirty_writeback_mib":500,"peak_host_processes_mib":200,"evidence":"fake"}\n'
SH
chmod 755 "$work/round-hot"
decision="$(KILL_TEST_ROUND="$work/round-hot" "$MATRIX" run --shapes 4+2 --steps 1Gi,512Mi --rounds 2 --results "$work/r2" 2>/dev/null)"
# 700 * 1.25 = 875, up to 896, above the held 512.
grep -F 'value: 896 MiB (the peak rule raises it above 512; not tested at that size)' <<<"$decision" >/dev/null ||
  fail "peak rule: $decision"

# A round that fails to run is unknown, never survived, and is retried next time.
cat >"$work/round-broken" <<'SH'
#!/usr/bin/env bash
echo "kubectl: connection refused" >&2
exit 3
SH
chmod 755 "$work/round-broken"
KILL_TEST_ROUND="$work/round-broken" "$MATRIX" run --shapes 4+2 --steps 1Gi --rounds 2 --results "$work/r3" >/dev/null 2>&1
[[ "$(jq -r '.survived' "$work/r3/rounds.jsonl")" == null ]] || fail "a broken round was not unknown"
grep -F 'connection refused' "$work/r3/rounds.jsonl" >/dev/null || fail "a broken round lost its reason"
[[ "$(wc -l <"$work/r3/rounds.jsonl")" == 1 ]] || fail "it went on past an unknown round"
decision="$("$MATRIX" decide --shapes 4+2 --steps 1Gi --rounds 2 --results "$work/r3" 2>/dev/null)"
grep -F 'value: none' <<<"$decision" >/dev/null || fail "an unknown round decided a value: $decision"
cp "$work/round" "$work/round-fixed"
KILL_TEST_ROUND="$work/round-fixed" "$MATRIX" run --shapes 4+2 --steps 1Gi --rounds 2 --results "$work/r3" >/dev/null 2>&1
[[ "$(jq -s '[.[] | select(.survived == true)] | length' "$work/r3/rounds.jsonl")" == 2 ]] || fail "the unknown round was not retried"

# A round that reports its own unknown keeps its evidence and peaks.
cat >"$work/round-unknown" <<'SH'
#!/usr/bin/env bash
echo '{"survived":null,"seconds":60,"peak_dirty_writeback_mib":0,"peak_host_processes_mib":140,"peak_shmem_mib":9000,"evidence":"shmem peaked short"}'
exit 2
SH
chmod 755 "$work/round-unknown"
KILL_TEST_ROUND="$work/round-unknown" "$MATRIX" run --shapes 4+2 --steps 1Gi --rounds 1 --results "$work/r4" >/dev/null 2>&1 || true
[[ "$(jq -c '[.survived, .peak_host_processes_mib]' "$work/r4/rounds.jsonl")" == '[null,140]' ]] || fail "an unknown round lost its peaks"
grep -F 'unknown (exit 2): shmem peaked short' "$work/r4/rounds.jsonl" >/dev/null || fail "an unknown round lost its evidence"

# Screening: 2 rounds per step while descending, then the smallest step that held runs
# the full 4. A fake that loses its 3rd round at 512Mi sends the confirm up to 768Mi.
cat >"$work/round-screen" <<'SH'
#!/usr/bin/env bash
case "$3" in *Gi) mib=$(( ${3%Gi} * 1024 )) ;; *Mi) mib=${3%Mi} ;; esac
echo "$3" >>"$CALLS"
n="$(grep -cx "$3" "$CALLS")"
survived=true
[[ "$mib" -lt 512 ]] && survived=false
[[ "$mib" == 512 && "$n" -ge 3 ]] && survived=false
printf '{"survived":%s,"seconds":1,"peak_dirty_writeback_mib":100,"peak_host_processes_mib":100,"evidence":"fake"}\n' "$survived"
SH
chmod 755 "$work/round-screen"
: >"$CALLS"
decision="$(KILL_TEST_ROUND="$work/round-screen" "$MATRIX" run --shapes 4+2 --steps 1Gi,768Mi,512Mi,384Mi \
  --rounds 4 --screen-rounds 2 --results "$work/r5" 2>/dev/null)"
# Screen: 1Gi 2, 768Mi 2, 512Mi 2, 384Mi 1 (lost). Confirm 512Mi: rounds 3 lost.
# Then 768Mi: rounds 3 and 4.
[[ "$(tr '\n' ' ' <"$CALLS")" == "1Gi 1Gi 768Mi 768Mi 512Mi 512Mi 384Mi 512Mi 768Mi 768Mi " ]] ||
  fail "screening order: $(tr '\n' ' ' <"$CALLS")"
grep -F '4+2: 1Gi 2/2, 768Mi 4/4, 512Mi 2/3, 384Mi 0/1' <<<"$decision" >/dev/null || fail "screen cells: $decision"
grep -F 'smallest step holding 4/4: 768 MiB' <<<"$decision" >/dev/null || fail "screen decision: $decision"
refuses '--screen-rounds must be' plan --rounds 3 --screen-rounds 4

# Not measured is said, not taken as zero.
cat >"$work/round-blind" <<'SH'
#!/usr/bin/env bash
printf '{"survived":true,"seconds":60,"peak_dirty_writeback_mib":null,"peak_host_processes_mib":null,"evidence":"fake"}\n'
SH
chmod 755 "$work/round-blind"
decision="$(KILL_TEST_ROUND="$work/round-blind" "$MATRIX" run --shapes 4+2 --steps 1Gi --rounds 1 --results "$work/r4" 2>/dev/null)"
grep -F 'but no peak was measured' <<<"$decision" >/dev/null || fail "an unmeasured peak: $decision"

echo "kill test overhead matrix tests: ok"
