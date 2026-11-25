#!/usr/bin/env bash
# scripts/ci/setup/pinned-tool.sh with a stand-in fetcher: a kept download is
# reused, a changed or linked one is fetched again, and a runner without the
# build disk keeps nothing between jobs. No network is used.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="$ROOT/scripts/ci/setup/pinned-tool.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/pinned-tool-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
fail() { echo "pinned-tool: $*" >&2; exit 1; }

printf 'the pinned bytes\n' >"$work/payload"
digest="$(sha256sum "$work/payload" | cut -c1-64)"
cat >"$work/fetch" <<'FETCH'
#!/usr/bin/env bash
printf '%s\n' "$1" >>"$FETCH_CALLS"
cp "$FETCH_PAYLOAD" "$3"
FETCH
chmod +x "$work/fetch"
export PINNED_TOOL_FETCH="$work/fetch" FETCH_CALLS="$work/calls" FETCH_PAYLOAD="$work/payload"
url=https://example.invalid/tool.tar.xz
calls() { if [ -f "$work/calls" ]; then wc -l <"$work/calls"; else echo 0; fi; }

mkdir "$work/disk" "$work/job"
run() { BUILD_ONCE_TREE="$work/disk" RUNNER_TEMP="$work/job" "$TOOL" "$url" "$1"; }
kept="$work/disk/tools/$digest"
path="$(run "$digest" 2>/dev/null)"
[ "$path" = "$work/job/pinned-tools/$digest" ] || fail "the printed path is not the job-local copy: $path"
cmp -s "$path" "$work/payload" && cmp -s "$kept" "$work/payload" || fail 'the copy or the kept file is not the pinned bytes'
[ "$(calls)" -eq 1 ] || fail 'the first use did not fetch'

run "$digest" >/dev/null 2>&1
[ "$(calls)" -eq 1 ] || fail 'a kept, matching download was fetched again'

# The kept file is never what the caller reads: changing it after a use
# leaves the job's copy as checked.
path="$(run "$digest" 2>/dev/null)"
printf 'swapped\n' >"$kept"
cmp -s "$path" "$work/payload" || fail 'the printed file follows the shared kept file'

run "$digest" >/dev/null 2>"$work/err"
[ "$(calls)" -eq 2 ] || fail 'a changed kept file was used without fetching again'
grep -q 'does not match its digest' "$work/err" || fail 'the refetch is unexplained'
cmp -s "$kept" "$work/payload" || fail 'the refetch did not restore the kept pinned bytes'

rm -f -- "$kept"
ln -s "$work/payload" "$kept"
run "$digest" >/dev/null 2>&1
[ "$(calls)" -eq 3 ] && [ ! -L "$kept" ] || fail 'a linked kept file was followed'

rm -f -- "$kept"
mkdir "$kept"
run "$digest" >/dev/null 2>&1 || fail 'a directory at the kept path failed the run'
[ -f "$kept" ] && cmp -s "$kept" "$work/payload" || fail 'a directory at the kept path was not replaced'

mkdir "$work/disk2" "$work/elsewhere"
ln -s "$work/elsewhere" "$work/disk2/tools"
if BUILD_ONCE_TREE="$work/disk2" RUNNER_TEMP="$work/job" "$TOOL" "$url" "$digest" >/dev/null 2>&1; then
  fail 'a linked tools folder was used'
fi

mkdir "$work/temp"
path="$(env -u BUILD_ONCE_TREE RUNNER_TEMP="$work/temp" "$TOOL" "$url" "$digest" 2>/dev/null)"
[ "$path" = "$work/temp/pinned-tools/$digest" ] || fail "without the build disk it is not job-local: $path"

if run not-a-digest >/dev/null 2>&1; then
  fail 'a malformed digest was accepted'
fi

grep -cF 'zig_tar="$(scripts/ci/setup/pinned-tool.sh "$zig_url" "$ZIG_X86_64_LINUX_SHA256")"' \
  "$ROOT/.gitea/workflows/ci.yaml" | grep -qx 2 || fail 'ci.yaml does not take zig through pinned-tool.sh in both jobs'

echo 'pinned-tool: kept and reused through a checked job-local copy, refetched when changed or linked, a linked tools folder refused, job-local without the build disk, malformed digest refused'
