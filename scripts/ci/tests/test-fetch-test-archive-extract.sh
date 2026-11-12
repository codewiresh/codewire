#!/usr/bin/env bash
# fetch-test-archive.sh --extract (infra#1534): the download streams through
# the hash into tar. Only bytes that hash to the digest leave a folder and
# ready=true; a download that fails part way is fetched again to a file; a
# store without the archive is a miss with --or-build on a guest big enough to
# build, and fails at once on a medium one; bytes that hash right but do not
# unpack fail the job. The guest's memory comes from a fixture, never this
# host's.
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

printf 'MemTotal:       70254592 kB\n' > "$work/meminfo-warm"
printf 'MemTotal:        8170496 kB\n' > "$work/meminfo-medium"

# Under a strict umask, so the archive's own modes must survive it, as
# nextest's own extraction keeps them.
fetch() {
  : > "$work/out"
  (
    umask 077
    GITHUB_OUTPUT="$work/out" ARCHIVE_STORE_URL="file://$work/store" RUNNER_TEMP="$work" \
      CODEWIRE_CI_MEMINFO="${MEMINFO:-$work/meminfo-warm}" GITHUB_SHA=0123abcd \
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
# On a medium guest the same miss fails at once, naming the head (infra#2471).
if MEMINFO="$work/meminfo-medium" fetch --or-build --extract "$absent" "$work/x/absent-medium"; then
  fail 'a medium guest built in place'
fi
grep -q 'test archive missing for 0123abcd: .*rerun Build test archives' "$work/fetch.log" ||
  fail 'a medium guest gave no fail-fast reason'
[ ! -e "$work/x/absent-medium" ] && [ ! -e "$work/x/absent-medium.partial" ] || fail 'a medium miss left a folder behind'

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

# No digest for this job, which builds in place (#4031): the compile job was
# skipped, or it succeeded and reported its workspace archive but built no
# leg for this job's selection.
for compile in 'skipped:' "success:$good"; do
  COMPILE_RESULT="${compile%%:*}" COMPILE_ARCHIVE_SHA256="${compile#*:}" \
    fetch --or-build '' "$work/x/unbuilt.tar" ||
    fail "a job with no archive for it failed (compile ${compile%%:*}): $(cat "$work/fetch.log")"
  grep -qx 'ready=false' "$work/out" || fail "a job with no archive for it was not a miss (compile ${compile%%:*})"
  grep -q 'no archive was built for this job' "$work/fetch.log" ||
    fail "a job with no archive for it gave no reason (compile ${compile%%:*})"
done

# The compile job succeeded but reported no digest at all, not even the
# workspace archive's: its outputs were lost, as when the run was rerun while
# the compile job's previous task still ran and that task's success completed
# the new attempt with no build (#4141, run 42471). The job fails instead of
# building the whole workspace on a guest sized for tests, and names the rerun
# that builds again, not the one that just lost the outputs.
for mode in '' --extract; do
  # shellcheck disable=SC2086 # An empty mode adds no argument.
  if COMPILE_RESULT=success COMPILE_ARCHIVE_SHA256='' fetch --or-build $mode '' "$work/x/lost$mode"; then
    fail "lost compile outputs did not fail${mode:+ with $mode}"
  fi
  grep -qF 'its previous task was still running (#4141)' "$work/fetch.log" ||
    fail "lost compile outputs did not say why${mode:+ with $mode}: $(cat "$work/fetch.log")"
  grep -qF 'rerun the whole run with scripts/dev/orchestrator/rerun-run.sh' "$work/fetch.log" ||
    fail "lost compile outputs did not name the rerun that builds again${mode:+ with $mode}"
  ! grep -q 'ready=' "$work/out" || fail "lost compile outputs reported readiness${mode:+ with $mode}"
done

echo 'fetch-test-archive --extract tests: OK'
