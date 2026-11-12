#!/usr/bin/env bash
# The cw shell terminal journey (#4332): drives `cw shell` in a real
# terminal, a private tmux server, and proves the shell behaves as ssh into a
# normal Linux box would from that terminal.
#
#   test-cw-shell-terminal.sh [--cw PATH] [--claude] ENV [CW_FLAG]...
#
#   test-cw-shell-terminal.sh my-app --cloud --server https://codewire-dev.sh
#   test-cw-shell-terminal.sh --cw target/debug/cw my-vm --local
#
# CW_FLAGs go before `shell`, as cw's global flags. For each TERM of
# xterm-kitty, xterm-256color and one no system knows, it checks:
#   - the remote size equals the tmux pane's, at start and after a resize;
#   - `clear` clears the screen with no "unknown terminal type";
#   - TERM stays as sent where terminfo exists (the client's entry is sent),
#     and an unknown one falls back to xterm-256color with cw's notice;
#   - vim's status and command lines, and htop's key bar, sit on the last
#     rows before and after a resize (htop only where it is installed).
# Then a `cw shell --durable` is detached and reattached from a terminal of a
# new size, and the remote size follows.
#
# --claude also starts Claude Code in each shell and checks that it fills the
# terminal, its input box on the last rows, before and after a resize, as it
# does by default in the workspace image. It runs with a new CLAUDE_CONFIG_DIR
# and a synthetic API key, so the environment's home is not touched and no
# login is needed; it needs Claude Code installed there.
#
# Prints PASS or FAIL per check and exits 1 if any failed. Needs tmux, and
# infocmp for the client's own entries. The environment must be running and
# its shell should start without asking anything (a zsh with no ~/.zshrc
# asks).
set -euo pipefail

cw=cw
claude=0
while :; do
  case "${1-}" in
    --cw) cw=$(realpath -- "$2"); shift 2 ;;
    --claude) claude=1; shift ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] || { sed -n '2,25p' "$0" >&2; exit 2; }
env_name=$1
shift
flags=("$@")
command -v tmux >/dev/null || { echo "tmux is required" >&2; exit 2; }

socket="cw-term-$$"
tm() { tmux -L "$socket" -f /dev/null "$@"; }
cleanup() { tm kill-server 2>/dev/null || true; }
trap cleanup EXIT

failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }
check() { # check NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then pass "$1: $3"; else fail "$1: expected $2, got $3"; fi
}

pane() { tm capture-pane -p -t journey; }
pane_size() { tm display-message -p -t journey '#{pane_width}x#{pane_height}'; }
pane_height() { tm display-message -p -t journey '#{pane_height}'; }
send() { tm send-keys -t journey -l "$1"; tm send-keys -t journey Enter; }

# Waits up to $2 seconds for the pane to show a line matching $1.
wait_for() {
  local deadline=$((SECONDS + $2))
  while [ $SECONDS -lt "$deadline" ]; do
    if pane | grep -qE "$1"; then return 0; fi
    sleep 0.5
  done
  return 1
}

# Asks the remote shell for "COLSxLINES TERM" and sets `answer` to it. The
# command line holds $((n+0)), so only the answer matches <qN:...>.
asked=0
answer=
ask() {
  asked=$((asked + 1))
  local n=$asked
  send "printf '<q%s:%sx%s %s>\\n' \$(($n+0)) \"\$(tput cols)\" \"\$(tput lines)\" \"\$TERM\""
  if wait_for "<q$n:" 20; then
    answer=$(pane | grep -oE "<q$n:[^>]*>" | tail -1 | sed -E "s/<q$n:(.*)>/\\1/")
  else
    answer="no answer"
  fi
}

# Waits until the remote size matches the pane, as SIGWINCH may lag a resize.
size_settles() {
  local want deadline=$((SECONDS + 15))
  want=$(pane_size)
  while :; do
    ask
    if [ "${answer%% *}" = "$want" ] || [ $SECONDS -ge "$deadline" ]; then break; fi
    sleep 1
  done
  check "$1" "$want" "${answer%% *}"
}

# The 0-based row of the last pane line matching $1, or -1.
row_of() { pane | grep -nE "$1" | tail -1 | cut -d: -f1 | awk '{print $1 - 1}' | grep . || echo -1; }

# Waits up to 15 s for the last line matching $2 to sit $3 rows above the
# pane's bottom, as a program redraws after it starts or a resize.
row_settles() {
  local want row deadline=$((SECONDS + 15))
  while :; do
    want=$(($(pane_height) - 1 - $3))
    row=$(row_of "$2")
    if [ "$row" = "$want" ] || [ $SECONDS -ge "$deadline" ]; then break; fi
    sleep 0.5
  done
  check "$1" "$want" "$row"
}

start() { # start TERM [cw args...]
  local term=$1
  shift
  tm kill-session -t journey 2>/dev/null || true
  tm new-session -d -s journey -x 120 -y 40 \
    "env TERM=$term $(printf '%q ' "$cw" "${flags[@]}" "$@"); echo cw-exited-\$?; sleep 600"
  tm set-option -t journey status off >/dev/null
  # The shell is ready once it answers.
  local deadline=$((SECONDS + 90))
  ask
  while [ "$answer" = "no answer" ] && [ $SECONDS -lt "$deadline" ]; do ask; done
}

journey() { # journey TERM EXPECTED_REMOTE_TERM
  local term=$1 expected=$2
  echo "== TERM=$term"
  start "$term" shell "$env_name"
  ask
  check "$term: remote TERM" "$expected" "${answer#* }"
  if [ "$expected" != "$term" ]; then
    if pane | grep -qF "[cw] this environment has no terminfo for $term"; then
      pass "$term: cw says it fell back"
    else
      fail "$term: no fallback notice"
    fi
  fi
  size_settles "$term: size at start"
  tm resize-window -t journey -x 90 -y 25
  size_settles "$term: size after a resize"

  send "printf 'before-clear\\n'; clear; printf '<cleared:%s>\\n' \$((7*6))"
  if wait_for '<cleared:42>' 20; then
    if pane | grep -qiE 'unknown terminal|before-clear$'; then
      fail "$term: clear left the screen or failed: $(pane | grep -iE 'unknown terminal|before-clear$' | head -1)"
    else
      pass "$term: clear cleared the screen"
    fi
  else
    fail "$term: clear did not finish"
  fi

  send "vim -Nu NONE --cmd 'set laststatus=2 shortmess+=F' cw-term-journey.txt"
  if wait_for 'cw-term-journey.txt' 20; then
    row_settles "$term: vim status line row" 'cw-term-journey.txt' 1
    tm resize-window -t journey -x 100 -y 30
    row_settles "$term: vim status line row after a resize" 'cw-term-journey.txt' 1
  else
    fail "$term: vim did not start"
  fi
  tm send-keys -t journey Escape
  send ":q!"
  sleep 1

  send "command -v htop >/dev/null && htop || printf '<no-%s>\\n' htop"
  wait_for '<no-htop>|F1' 20 || true
  if pane | grep -qF '<no-htop>'; then
    echo "SKIP  $term: htop is not installed here"
  else
    row_settles "$term: htop key bar row" 'F1' 0
    tm resize-window -t journey -x 120 -y 40
    row_settles "$term: htop key bar row after a resize" 'F1' 0
    tm send-keys -t journey q
    sleep 1
  fi
  [ "$claude" = 1 ] && claude_fills "$term"
  send "exit"
  if wait_for 'cw-exited-0' 30; then pass "$term: exit ended cw shell"; else fail "$term: cw shell did not end on exit"; fi
}

# Claude Code's input box sits on the last rows: its mode line ("shift+tab
# to cycle") is the bottom row, as the inline renderer would put it under
# the welcome text instead.
claude_fills() {
  local term=$1 deadline
  send "d=\$(mktemp -d); printf '{\"hasCompletedOnboarding\":true,\"theme\":\"dark\",\"projects\":{\"%s\":{\"hasTrustDialogAccepted\":true,\"hasCompletedProjectOnboarding\":true}}}' \"\$PWD\" >\"\$d/.claude.json\"; CLAUDE_CONFIG_DIR=\$d ANTHROPIC_API_KEY=sk-ant-cw-journey-synthetic claude; rm -rf \"\$d\""
  deadline=$((SECONDS + 90))
  while [ $SECONDS -lt "$deadline" ]; do
    if pane | grep -qF 'shift+tab to cycle'; then break; fi
    if pane | grep -qF 'Detected a custom API key'; then
      tm send-keys -t journey Up; sleep 0.5; tm send-keys -t journey Enter
    elif pane | grep -qE 'Allow external CLAUDE.md|trust this folder'; then
      tm send-keys -t journey Enter
    fi
    sleep 2
  done
  if ! pane | grep -qF 'shift+tab to cycle'; then
    fail "$term: Claude Code did not start: $(pane | grep -v '^$' | tail -3 | tr '\n' '|')"
    tm send-keys -t journey C-c C-c
    sleep 2
    return
  fi
  row_settles "$term: Claude Code's mode line row" 'shift\+tab to cycle' 0
  pane | grep -v '^$' | sed 's/^/        | /' | tail -6
  tm resize-window -t journey -x 90 -y 25
  row_settles "$term: Claude Code's mode line row after a resize" 'shift\+tab to cycle' 0
  # Quit Claude Code (Ctrl-C twice) and wait until its screen is gone, so
  # nothing meant for the shell is typed into it.
  deadline=$((SECONDS + 30))
  while pane | grep -qF 'shift+tab to cycle' && [ $SECONDS -lt "$deadline" ]; do
    tm send-keys -t journey C-c C-c
    sleep 3
  done
  if pane | grep -qF 'shift+tab to cycle'; then
    fail "$term: Claude Code did not quit"
  else
    ask
  fi
}

journey xterm-kitty xterm-kitty
journey xterm-256color xterm-256color
journey cw-no-such-term xterm-256color

# The running sessions' IDs, one per line.
running() {
  "$cw" "${flags[@]}" ls "$env_name" --output json |
    python3 -I -c 'import json, sys
for s in json.load(sys.stdin):
    if s["state"] == "Running": print(s["session_id"])'
}

echo "== cw shell --durable, detached and reattached at a new size"
before=$(running)
start xterm-256color shell --durable "$env_name"
session=$(comm -13 <(sort <<<"$before") <(running | sort) | head -1)
if [ -z "$session" ]; then
  fail "durable: no new running session"
else
  tm send-keys -t journey C-b d
  if wait_for 'cw-exited-0' 20; then pass "durable: detached"; else fail "durable: did not detach"; fi
  tm kill-session -t journey
  tm new-session -d -s journey -x 110 -y 35 \
    "env TERM=xterm-256color $(printf '%q ' "$cw" "${flags[@]}" attach "$env_name" --session "$session"); sleep 600"
  tm set-option -t journey status off >/dev/null
  sleep 3
  size_settles "durable: size after reattaching"
  send "exit"
  sleep 2
fi

if [ "$failures" -gt 0 ]; then
  echo "$failures checks failed"
  exit 1
fi
echo "all checks passed"
