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
install -m 644 "$ROOT/scripts/ci/verify/shellcheck-baseline.sh" \
  "$repo/scripts/ci/verify/shellcheck-baseline.sh"
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
grep -Fq 'push-check: ShellCheck findings differ from the reviewed baseline' "$work/out" ||
  fail 'an unused variable did not fail as a ShellCheck finding'
grep -Fq 'SC2034' "$work/out" || fail 'the failure did not name the finding'

printf '[test-push-check-shellcheck] sourced use passes, unused variable fails\n'
