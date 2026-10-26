#!/usr/bin/env bash
# fetch-test-archive.sh --extract (infra#1534): the download streams through
# the hash into tar. Only bytes that hash to the digest leave a folder and
# ready=true; a download that fails part way is fetched again to a file; a
# store without the archive is a miss with --or-build; bytes that hash right
# but do not unpack fail the job.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FETCH="$ROOT/scripts/ci/setup/fetch-test-archive.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/test-fetch-extract.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

fail() {
  echo "test-fetch-test-archive-extract: $*" >&2
  exit 1
}

store="$work/store/v1/archives"
mkdir -p "$store" "$work/src/target/nextest" "$work/src/target/debug/deps" "$work/bin"
printf '{}' > "$work/src/target/nextest/binaries-metadata.json"
chmod 0664 "$work/src/target/nextest/binaries-metadata.json"
head -c 300000 /dev/urandom > "$work/src/target/debug/deps/tests-0123"
chmod 0700 "$work/src/target/debug/deps/tests-0123"
tar -C "$work/src" -cf - target | zstd -q -o "$work/archive.tar.zst"
good="$(sha256sum "$work/archive.tar.zst" | cut -d' ' -f1)"
cp "$work/archive.tar.zst" "$store/$good"

# Under a strict umask, so the archive's own modes must survive it, as
# nextest's own extraction keeps them.
fetch() {
  : > "$work/out"
  (
    umask 077
    GITHUB_OUTPUT="$work/out" ARCHIVE_STORE_URL="file://$work/store" RUNNER_TEMP="$work" \
      PATH="${FETCH_PATH:-$PATH}" "$FETCH" "$@" > "$work/fetch.log" 2>&1
  )
}

# A stored archive streams into its folder, exactly as tar wrote it.
fetch --or-build --extract "$good" "$work/x/tests" || fail "a stored archive did not extract: $(cat "$work/fetch.log")"
grep -qx 'ready=true' "$work/out" || fail 'an extracted archive is not ready'
cmp -s "$work/src/target/debug/deps/tests-0123" "$work/x/tests/target/debug/deps/tests-0123" ||
  fail 'an extracted binary differs'
[ -x "$work/x/tests/target/debug/deps/tests-0123" ] || fail 'an extracted binary lost its mode'
[ "$(stat -c %a "$work/x/tests/target/nextest/binaries-metadata.json")" = 664 ] ||
  fail 'an extracted file lost its archived mode'
[ ! -e "$work/x/tests.partial" ] || fail 'a finished extraction left its partial folder'
[ -z "$(find "$work" -maxdepth 1 -name 'fetch-test-archive.*')" ] || fail 'the fetch left its work folder'

# A download that fails part way is fetched again to a file and extracted
# from it. The stand-in curl writes half the archive to stdout and fails; with
# -o it is the real curl.
cat > "$work/bin/curl" <<EOF
#!/usr/bin/env bash
for arg in "\$@"; do
  [ "\$arg" = -o ] && exec "$(command -v curl)" "\$@"
done
head -c 1000 "$work/archive.tar.zst"
exit 18
EOF
chmod +x "$work/bin/curl"
FETCH_PATH="$work/bin:$PATH" fetch --or-build --extract "$good" "$work/x/again" ||
  fail "a failed stream was not fetched again: $(cat "$work/fetch.log")"
grep -q 'streamed download failed (curl 18); fetching it to a file' "$work/fetch.log" ||
  fail 'the second fetch gave no reason'
grep -qx 'ready=true' "$work/out" || fail 'the second fetch is not ready'
cmp -s "$work/src/target/debug/deps/tests-0123" "$work/x/again/target/debug/deps/tests-0123" ||
  fail 'the second fetch extracted different bytes'

# A store without the archive is a miss the job builds through.
absent="$(printf 'absent' | sha256sum | cut -d' ' -f1)"
fetch --or-build --extract "$absent" "$work/x/absent" || fail 'an evicted archive failed instead of building'
grep -qx 'ready=false' "$work/out" || fail 'an evicted archive was not a miss'
[ ! -e "$work/x/absent" ] && [ ! -e "$work/x/absent.partial" ] || fail 'a miss left a folder behind'

# Bytes that do not hash to the digest leave nothing and fail, even unpacked.
cp "$work/archive.tar.zst" "$store/$absent"
if fetch --or-build --extract "$absent" "$work/x/tampered"; then fail 'a tampered archive was accepted'; fi
grep -q 'hashes to' "$work/fetch.log" || fail 'a tampered archive gave no reason'
! grep -q 'ready=' "$work/out" || fail 'a tampered archive reported readiness'
[ ! -e "$work/x/tampered" ] && [ ! -e "$work/x/tampered.partial" ] || fail 'a tampered archive left a folder'

# Bytes that hash right but are no zstd tar fail the job.
printf 'not an archive' > "$work/junk"
junk="$(sha256sum "$work/junk" | cut -d' ' -f1)"
cp "$work/junk" "$store/$junk"
if fetch --or-build --extract "$junk" "$work/x/junk"; then fail 'an archive that does not unpack was accepted'; fi
grep -q 'did not unpack' "$work/fetch.log" || fail 'an archive that does not unpack gave no reason'
[ ! -e "$work/x/junk" ] && [ ! -e "$work/x/junk.partial" ] || fail 'an archive that does not unpack left a folder'

echo 'fetch-test-archive --extract tests: OK'
