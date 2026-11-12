#!/usr/bin/env bash
# Runs bin/codewire.sh the way herdr does (HERDR_* in the environment) against
# stub `cw` and `herdr`, and checks the commands it runs. Needs bash and jq;
# and ShellCheck when it is installed.
# Usage: integrations/herdr/tests/test-plugin.sh
set -euo pipefail
plugin="$(cd "$(dirname "$0")/.." && pwd)"
script="$plugin/bin/codewire.sh"

work="$(mktemp -d "${TMPDIR:-/tmp}/herdr-codewire.XXXXXX")"
trap 'rm -rf "$work"' EXIT
stub="$work/bin"
log="$work/calls"
mkdir "$stub"
passed=0

fail() { printf 'FAIL: %s\n' "$*" >&2; [ ! -s "$log" ] || sed 's/^/  call: /' "$log" >&2; exit 1; }
ok() { passed=$((passed + 1)); printf 'ok   %s\n' "$*"; }

# STUB_LS is what `cw ls --output json` prints; STUB_STATUS is every stub's exit status.
cat >"$stub/cw" <<'EOF'
#!/bin/sh
printf 'cw %s\n' "$*" >>"$STUB_LOG"
case " $* " in *" ls "*) printf '%s\n' "${STUB_LS:-[]}" ;; esac
exit "${STUB_STATUS:-0}"
EOF
cat >"$stub/herdr" <<'EOF'
#!/bin/sh
printf 'herdr %s\n' "$*" >>"$STUB_LOG"
exit "${STUB_STATUS:-0}"
EOF
chmod +x "$stub/cw" "$stub/herdr"
# A stub that cannot run, as under a noexec TMPDIR, would let the actions reach
# the real cw and create real environments: stop first.
[ "$(PATH="$stub:$PATH" command -v cw)" = "$stub/cw" ] || {
  echo "test-plugin: the stub cw in $stub cannot run (a noexec TMPDIR?); set TMPDIR to a directory that allows executing files" >&2
  exit 1
}

run() { # args..., with stdin passed through
  : >"$log"
  env PATH="$stub:$PATH" STUB_LOG="$log" HERDR_BIN_PATH="$stub/herdr" HERDR_PLUGIN_ID=codewire \
    HERDR_WORKSPACE_ID=w1 HERDR_PANE_ID=w1:p1 sh "$script" "$@"
}
expect() { # exact call
  grep -qxF -- "$1" "$log" || fail "expected the call: $1"
}
no_calls() { [ ! -s "$log" ] || fail "expected no calls"; }

# Actions open the matching pane where it belongs.
run open environments </dev/null
expect "herdr plugin pane open --plugin codewire --entrypoint environments --focus"
run open shell </dev/null
expect "herdr plugin pane open --plugin codewire --entrypoint shell --focus --workspace w1"
run open agent </dev/null
expect "herdr plugin pane open --plugin codewire --entrypoint agent --focus --env HERDR_AGENT=claude --workspace w1"
run open doctor </dev/null
expect "herdr plugin pane open --plugin codewire --entrypoint doctor --focus --target-pane w1:p1 --direction right"
ok "actions open the environments overlay, shell and agent tabs, and the doctor split"

# The environments overlay.
inventory='[{"type":"sandbox","name":"app","placement":"local","state":"running"},
            {"type":"sandbox","name":"web","placement":"cloud","state":"stopped"}]'
printf '2a\n' | STUB_LS="$inventory" run pane environments >"$work/out"
grep -q '2  cloud  web' "$work/out" || fail "the list does not show web: $(cat "$work/out")"
expect "herdr plugin pane open --plugin codewire --entrypoint agent --focus --env CW_ENV=web --env CW_PLACEMENT=cloud --env HERDR_AGENT=claude --workspace w1"
printf '1s\n' | STUB_LS="$inventory" run pane environments >/dev/null
expect "herdr plugin pane open --plugin codewire --entrypoint shell --focus --env CW_ENV=app --env CW_PLACEMENT=local --workspace w1"
ok "choosing 2a opens Claude Code in web, 1s a shell in app"

for answer in x 1 s 3s 1x 1sa; do
  if printf '%s\n' "$answer" | STUB_LS="$inventory" run pane environments >/dev/null 2>&1; then
    fail "answer '$answer' was accepted"
  fi
  ! grep -q '^herdr' "$log" || fail "answer '$answer' opened a pane"
done
printf '\n' | STUB_LS="$inventory" run pane environments >/dev/null || fail "Enter did not cancel cleanly"
! grep -q '^herdr' "$log" || fail "Enter opened a pane"
ok "anything but a listed number with s or a opens nothing; Enter cancels"

printf '\n' | STUB_LS='[]' run pane environments >"$work/out" 2>&1 || true
grep -q 'No environments yet' "$work/out" || fail "no hint for an empty list: $(cat "$work/out")"
ok "an empty list says how to create an environment"

# Panes for one environment, or the selected one.
CW_ENV=web CW_PLACEMENT=cloud run pane shell </dev/null
expect "cw --cloud shell web"
CW_ENV=app CW_PLACEMENT=local run pane agent </dev/null
expect "cw --local run claude --in app"
run pane shell </dev/null
expect "cw shell"
run pane agent </dev/null
expect "cw run claude"
ok "shell and agent panes use cw shell and cw run claude, with or without an environment"

if printf '\n' | STUB_STATUS=3 CW_ENV=web CW_PLACEMENT=cloud run pane shell >"$work/out" 2>&1; then
  fail "a failed cw shell exited zero"
fi
grep -q 'exited with status 3' "$work/out" || fail "a failed pane did not say so: $(cat "$work/out")"
if CW_PLACEMENT=elsewhere run pane shell </dev/null >/dev/null 2>&1; then fail "an unknown placement ran"; fi
no_calls
ok "a failure stays on screen; an unknown placement runs nothing"

if command -v shellcheck >/dev/null; then
  shellcheck -s sh "$script" || fail "shellcheck"
  ok "shellcheck passes"
fi

printf 'PASS: %d checks\n' "$passed"
