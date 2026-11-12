#!/usr/bin/env bash
# build-once's lean_archive (infra#2471): an archive's ELF files lose their
# debug sections, every path, mode and non-ELF file stays as nextest wrote it,
# the result is a zstd tar at the same path, and an archive that does not
# unpack is kept as built.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/test-lean-archive.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
fail() { echo "test-build-once-lean-archive: $*" >&2; exit 1; }

# shellcheck source=/dev/null
source <(sed -n '/^lean_archive() {$/,/^}$/p' "$ROOT/scripts/ci/setup/build-once.sh")
declare -F lean_archive >/dev/null || fail 'lean_archive was not found in build-once.sh'

src="$work/src"
mkdir -p "$src/target/debug/deps" "$src/target/nextest"
printf '{"rust-build-meta":{}}' > "$src/target/nextest/binaries-metadata.json"
cp "$(type -P true)" "$src/target/debug/deps/tests-0123"
printf 'debug-info-payload' > "$work/payload"
objcopy --add-section .debug_info="$work/payload" "$src/target/debug/deps/tests-0123"
cp "$(type -P false)" "$src/target/debug/deps/other-4567"
chmod 0755 "$src/target/debug/deps/tests-0123" "$src/target/debug/deps/other-4567"
chmod 0640 "$src/target/nextest/binaries-metadata.json"
# Each listing is read whole before grep -q looks at it: under pipefail, grep
# leaving early kills the writer with SIGPIPE and fails the pipeline.
sections="$(readelf -S "$src/target/debug/deps/tests-0123")"
grep -q '\.debug_info' <<<"$sections" || fail 'the fixture has no debug section'
(cd "$src" && tar -c target | zstd -q -o "$work/archive.tar.zst")

RUNNER_TEMP="$work" lean_archive "$work/archive.tar.zst" > "$work/log"
grep -q '^build-once: test archive slimmed: 2 ELF files stripped of debug information, ' "$work/log" ||
  fail "no slimming line: $(cat "$work/log")"
mkdir "$work/out"
zstd -dcq "$work/archive.tar.zst" | tar -x -p -C "$work/out"
sections="$(readelf -S "$work/out/target/debug/deps/tests-0123")"
grep -q '\.debug' <<<"$sections" && fail 'a debug section survived'
"$work/out/target/debug/deps/tests-0123" || fail 'the stripped binary no longer runs'
cmp -s "$src/target/nextest/binaries-metadata.json" "$work/out/target/nextest/binaries-metadata.json" ||
  fail 'the nextest metadata changed'
[ "$(cd "$src" && find target -printf '%P %m\n' | sort)" = "$(cd "$work/out" && find target -printf '%P %m\n' | sort)" ] ||
  fail 'the archive paths or modes changed'
listing="$(zstd -dcq "$work/archive.tar.zst" | tar -t)"
grep -q '^\./' <<<"$listing" && fail 'the archive gained a ./ prefix'

# An archive that does not unpack is kept as built, with a warning.
printf 'not an archive' > "$work/bad.tar.zst"
RUNNER_TEMP="$work" lean_archive "$work/bad.tar.zst" > "$work/bad.log"
[ "$(cat "$work/bad.tar.zst")" = 'not an archive' ] || fail 'a broken archive was changed'
grep -q '::warning::build-once: the test archive did not unpack' "$work/bad.log" || fail 'a broken archive gave no warning'
echo 'test-build-once-lean-archive: ELF files stripped, paths, modes and metadata kept, a broken archive kept'
