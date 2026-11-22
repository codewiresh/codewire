#!/usr/bin/env bash
# build-once compiles its heavy units one at a time across every target folder
# (heavy-unit-rustc.sh, codewire#5776): two codewire_proto compiles never
# overlap, other units still run at once, the wrapper hands every compile to
# the one it stands in front of, and peak-rss.py reports a tree's memory and
# keeps its command's exit status.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WRAPPER="$ROOT/scripts/ci/setup/heavy-unit-rustc.sh"
PEAK="$ROOT/scripts/ci/setup/peak-rss.py"
fail() { echo "test-heavy-unit-rustc: $*" >&2; exit 1; }
work="$(mktemp -d "${TMPDIR:-/tmp}/heavy-unit.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# A stand-in compiler: records when it starts and ends, and holds for 1 s.
cat > "$work/rustc" <<'EOF'
#!/usr/bin/env bash
printf 'start unit %s\n' "$(date +%s.%N)" >> "$LOG"
sleep 1
printf 'end unit %s\n' "$(date +%s.%N)" >> "$LOG"
EOF
chmod +x "$work/rustc"

overlapping() { # LOG: 0 when two compiles ran at the same time, 1 when not, 2 on a bad log
  python3 -I - "$1" <<'PY'
import sys
lines = [line.split() for line in open(sys.argv[1])]
if len(lines) != 4 or any(len(fields) != 3 for fields in lines):
    sys.exit(2)
starts = sorted(float(l.split()[2]) for l in open(sys.argv[1]) if l.startswith("start"))
ends = sorted(float(l.split()[2]) for l in open(sys.argv[1]) if l.startswith("end"))
# Serial when each compile starts after the previous one ended.
sys.exit(0 if any(starts[i + 1] < ends[i] for i in range(len(starts) - 1)) else 1)
PY
}

expect_overlap() { # WANT MESSAGE: overlapping's exit status must be WANT
  local got=0
  overlapping "$work/log" || got=$?
  [ "$got" -eq "$1" ] || fail "$2 (overlap check returned $got)"
}

run_two() { # CRATE: two compiles of CRATE at once through the wrapper, under the lock
  : > "$work/log"
  for _ in 1 2; do
    LOG="$work/log" BUILD_ONCE_HEAVY_LOCK="$work/lock" "$WRAPPER" "$work/rustc" --crate-name "$1" &
  done
  wait
}

run_two codewire_proto
expect_overlap 1 'two codewire_proto compiles overlapped under the lock'
run_two codewire_cli
expect_overlap 0 'two ordinary units were made to wait for each other'

: > "$work/log"
LOG="$work/log" BUILD_ONCE_HEAVY_LOCK="$work/lock" "$WRAPPER" "$work/rustc" --crate-name=codewire_proto &
LOG="$work/log" BUILD_ONCE_HEAVY_LOCK="$work/lock" "$WRAPPER" "$work/rustc" --crate-name codewire_proto &
wait
expect_overlap 1 'the --crate-name=NAME spelling escaped the lock'

# A compile that leaves a process behind (an sccache client starting its
# server) does not keep the lock: the next heavy compile still runs at once.
printf '#!/usr/bin/env bash\nsleep 30 >/dev/null 2>&1 &\necho "$!" > "%s/leftover.pid"\n' "$work" > "$work/spawner"
chmod +x "$work/spawner"
BUILD_ONCE_HEAVY_LOCK="$work/lock" "$WRAPPER" "$work/spawner" --crate-name codewire_proto
status=0
timeout 5 env BUILD_ONCE_HEAVY_LOCK="$work/lock" "$WRAPPER" true --crate-name codewire_proto || status=$?
kill "$(cat "$work/leftover.pid")" 2>/dev/null || true
[ "$status" -eq 0 ] || fail 'a process left behind by one heavy compile kept the lock from the next'

# The wrapper hands every compile, heavy or not, to the next wrapper.
cat > "$work/next" <<'EOF'
#!/usr/bin/env bash
echo "next: $*"
EOF
chmod +x "$work/next"
out="$(BUILD_ONCE_HEAVY_NEXT_WRAPPER="$work/next" BUILD_ONCE_HEAVY_LOCK="$work/lock" "$WRAPPER" rustc --crate-name codewire_proto x.rs)"
[ "$out" = "next: rustc --crate-name codewire_proto x.rs" ] || fail "the next wrapper did not get the compile: $out"
out="$(BUILD_ONCE_HEAVY_NEXT_WRAPPER="$work/next" "$WRAPPER" rustc --crate-name codewire_cli)"
[ "$out" = "next: rustc --crate-name codewire_cli" ] || fail "an ordinary unit skipped the next wrapper: $out"
# Without a lock (outside build-once) a heavy unit simply runs.
out="$(env -u BUILD_ONCE_HEAVY_LOCK -u BUILD_ONCE_HEAVY_NEXT_WRAPPER "$WRAPPER" echo --crate-name codewire_proto)"
[ "$out" = "--crate-name codewire_proto" ] || fail "without a lock the compile did not run: $out"

# peak-rss.py: a child holding about 200 MiB for 3 s reads as at least 150,
# and the command's exit status comes back unchanged.
python3 "$PEAK" "$work/rss" -- python3 -c 'import time; b = bytearray(200 * 1024 * 1024); time.sleep(3)'
[ "$(cat "$work/rss")" -ge 150 ] || fail "peak-rss.py read $(cat "$work/rss") MiB for a 200 MiB child"
status=0
python3 "$PEAK" "$work/rss" -- sh -c 'exit 3' || status=$?
[ "$status" -eq 3 ] || fail "peak-rss.py returned $status for a command that exited 3"

# build-once puts the wrapper in front of every leg's and the checks' compiles,
# and logs each one's peak beside its finish line.
once="$ROOT/scripts/ci/setup/build-once.sh"
[ "$(grep -c '^  heavy_unit_wrapper$' "$once")" -eq 2 ] || fail 'build-once does not wrap both the legs and the checks'
sed -n '/^checks() {/,/^}/p' "$once" | grep -A1 '^  unset RUSTC_WRAPPER$' | grep -q '^  heavy_unit_wrapper$' ||
  fail 'the checks drop the heavy-unit wrapper with the compiler cache'
grep -q 'peak-rss.py" "$logs/$name.rss"' "$once" || fail 'a leg runs without its peak measured'
grep -q 'peak-rss.py" "$logs/checks.rss"' "$once" || fail 'the checks run without their peak measured'

echo 'test-heavy-unit-rustc: codewire_proto one at a time, others at once, no lock kept by a leftover process, the next wrapper kept, peaks measured'
