#!/usr/bin/env bash
# The fast push check's ShellCheck step judges a changed script the way the
# policy check does: together with the scripts it sources. A variable that a
# sourced file reads is used; a variable nothing reads still fails the push.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/push-check-shellcheck.XXXXXX")"
trap 'rm -rf "$work"' EXIT

fail() {
  printf '[test-push-check-shellcheck] ERROR: %s\n' "$*" >&2
  exit 1
}

command -v shellcheck >/dev/null || fail 'shellcheck is required'
command -v jq >/dev/null || fail 'jq is required'

repo="$work/repo"
mkdir -p "$repo/scripts/dev" "$repo/scripts/ci/verify" "$repo/scripts/fixture"
install -m 755 "$ROOT/scripts/dev/preflight-push.sh" "$repo/scripts/dev/preflight-push.sh"
# preflight-push.sh sources the workstation lock (#4215); the fixture's lock is
# its own, never the workstation's.
install -m 644 "$ROOT/scripts/dev/preflight-lock.sh" "$repo/scripts/dev/preflight-lock.sh"
export PREFLIGHT_LOCK_FILE="$work/preflight.lock"
# It also sources the CPU slice helper; the fixture counts as inside a build
# slot, so its steps never queue for the workstation's.
install -m 644 "$ROOT/scripts/dev/cpu-slice.sh" "$repo/scripts/dev/cpu-slice.sh"
export CODEWIRE_CPU_SLOT=fixture
install -m 644 "$ROOT/scripts/ci/verify/shellcheck-baseline.sh" \
  "$repo/scripts/ci/verify/shellcheck-baseline.sh"
install -m 755 "$ROOT/scripts/ci/verify/check-shell-scripts.sh" \
  "$repo/scripts/ci/verify/check-shell-scripts.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$repo/scripts/dev/preflight-environment.sh"
chmod 755 "$repo/scripts/dev/preflight-environment.sh"

cat >"$repo/scripts/fixture/greeting.sh" <<'SH'
# shellcheck shell=bash
greet() {
  printf '%s\n' "$GREETING"
}
SH
cat >"$repo/scripts/fixture/caller.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
GREETING=hello
# shellcheck source=scripts/fixture/greeting.sh
source "$(dirname "${BASH_SOURCE[0]}")/greeting.sh"
greet
SH
cat >"$repo/scripts/fixture/unused.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
NOBODY_READS_THIS=1
printf 'done\n'
SH

# push_check PATH...: run the push check on exactly these changed paths,
# started from outside the repository like a hook from another directory.
push_check() {
  printf '%s\n' "$@" >"$work/changed"
  (cd "$work" && "$repo/scripts/dev/preflight-push.sh" "$work/changed" HEAD "$work/ran") \
    >"$work/out" 2>&1
}

push_check scripts/fixture/caller.sh ||
  { cat "$work/out" >&2; fail 'a variable read by a sourced script was reported unused'; }
grep -qx shellcheck "$work/ran" || fail 'the push check did not run ShellCheck'

if push_check scripts/fixture/unused.sh; then
  fail 'a variable nothing reads passed the push check'
fi
grep -Fq 'check-shell-scripts: ShellCheck findings differ from the reviewed baseline' "$work/out" ||
  fail 'an unused variable did not fail as a ShellCheck finding'
grep -Fq 'SC2034' "$work/out" || fail 'the failure did not name the finding'

# Every push leaves its timings beside the lock: one line per step and one
# for the whole check, pass or fail, with the seconds waited and run.
times="$work/preflight-times.tsv"
timed_line() {
  grep -Eq "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z	$1	$2	[0-9]+	[0-9]+	$repo\$" "$times"
}
[ "$(grep -c . "$times")" -eq 6 ] ||
  { cat "$times" >&2; fail 'two push checks did not log environment, shellcheck and total each'; }
timed_line shellcheck pass || fail 'a passing step was not timed'
timed_line total pass || fail 'a passing push check was not timed as a whole'
timed_line shellcheck fail || fail 'a failing step was not timed'
timed_line total fail || fail 'a failing push check was not timed as a whole'
PREFLIGHT_TIMES_FILE="$work/no-such-directory/times.tsv" push_check scripts/fixture/caller.sh ||
  { cat "$work/out" >&2; fail 'a timing log that cannot be written failed the push check'; }

# A pull request checks only the scripts changed since its base (#3119 A7),
# with the same rule; a base the checkout lacks checks every script.
git_fixture() {
  git -C "$repo" -c user.name=fixture -c user.email=fixture@example.invalid \
    -c commit.gpgsign=false "$@"
}
changed_since() {
  (cd "$work" && "$repo/scripts/ci/verify/check-shell-scripts.sh" --changed-since "$1") \
    >"$work/out" 2>&1
}
git_fixture init -q
git_fixture add -A
git_fixture commit -q -m base
base="$(git -C "$repo" rev-parse HEAD)"
changed_since "$base" || { cat "$work/out" >&2; fail 'an unchanged pull request failed ShellCheck'; }
grep -Fq 'ShellCheck: no script changed since' "$work/out" || fail 'an unchanged pull request checked scripts'
printf 'printf "%%s\\n" changed\n' >>"$repo/scripts/fixture/caller.sh"
git_fixture commit -q -am 'change the clean caller'
changed_since "$base" || { cat "$work/out" >&2; fail 'a clean changed script failed ShellCheck'; }
grep -Fq 'ShellCheck of 1 script(s) changed since' "$work/out" ||
  fail 'the pull request did not check exactly its changed script'
printf 'printf "%%s\\n" changed\n' >>"$repo/scripts/fixture/unused.sh"
git_fixture commit -q -am 'change the script with a finding'
if changed_since "$base"; then
  fail 'a changed script with an unreviewed finding passed'
fi
grep -Fq 'SC2034' "$work/out" || fail 'the changed-script failure did not name the finding'
if changed_since "$(printf '%040d' 0)"; then
  fail 'an unknown base passed although a script has a finding'
fi
grep -Fq 'is not in this checkout; checking every script' "$work/out" ||
  fail 'an unknown base did not fall back to every script'

printf '[test-push-check-shellcheck] sourced use passes, unused variable fails, pull requests check changed scripts\n'
