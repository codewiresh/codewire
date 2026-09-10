#!/bin/sh
# Synthetic-only pinned-output fixture. It cannot contact any provider.
set -eu

fixture_root=${CODEX_HOME%/*}

if [ "${1-}" = native ]; then
  printf '%s\n' "$$" > "$fixture_root/native.pid"
  # Split even ANSI escape sequences across writes, as a piped npm/native pair
  # may do. Only these typed challenge fields may escape the enrollment owner.
  fixture_version=0.149.0
  if [ -f "$fixture_root/codex-0.153.4" ]; then fixture_version=0.153.4; fi
  printf '\nWelcome to Codex [v\033[9'
  printf '0m%s\033[0m]\n\033[90mOpenAI\047s command-line coding agent\033[0m\n\n' "$fixture_version"
  printf 'Follow these steps to sign in with ChatGPT using device code authorization:\n\n'
  printf '1. Open this link in your browser and sign in to your account\n   \033[94mhttps://auth.openai.com/codex/device\033[0m\n\n'
  printf '2. Enter this one-time code \033[90m(expires in 15 minutes)\033[0m\n   \033[94mABCD-EFGH\033[0m\n\n'
  printf '\033[90mContinue only if you started this login in Codex. If a website or another person gave you this code, cancel.\033[0m\n\n'
  printf 'synthetic stderr must not escape the owner\n' >&2
  if [ -f "$fixture_root/invalid-output" ]; then printf 'synthetic unexpected output\n'; fi
  while [ ! -f "$fixture_root/release" ]; do sleep 0.02; done
  umask 077
  cp "$fixture_root/synthetic-auth.fixture.json" "$CODEX_HOME/auth.json"
  printf 'synthetic private log\n' > "$CODEX_HOME/codex-login.log"
  printf 'done\n' > "$fixture_root/native.finished"
  if [ -f "$fixture_root/fail-after-result" ]; then exit 42; fi
  exit 0
fi

[ "$HOME" = "$CODEX_HOME" ] || exit 20
[ "$XDG_CONFIG_HOME" = "$CODEX_HOME" ] || exit 21
[ "$XDG_CACHE_HOME" = "$CODEX_HOME" ] || exit 22
[ "$TMPDIR" = "$CODEX_HOME" ] || exit 23
[ "$(pwd -P)" = "$CODEX_HOME" ] || exit 24
[ "$PATH" = /usr/bin:/bin ] || exit 25
[ -z "${OPENAI_API_KEY+x}" ] || exit 26
[ -z "${GH_TOKEN+x}" ] || exit 27
[ -z "${XDG_RUNTIME_DIR+x}" ] || exit 28
[ -z "${RUST_LOG+x}" ] || exit 29

case "${1-}" in
login)
  [ "$#" -eq 4 ] || exit 30
  [ "$2" = --device-auth ] || exit 31
  [ "$3" = -c ] || exit 32
  [ "$4" = 'cli_auth_credentials_store="file"' ] || exit 33
  printf '%s\n' "$$" > "$fixture_root/wrapper.pid"
  /bin/sh "$0" native &
  native_pid=$!
  wait "$native_pid"
  ;;
logout)
  [ "$#" -eq 3 ] || exit 34
  [ "$2" = -c ] || exit 35
  [ "$3" = 'cli_auth_credentials_store="file"' ] || exit 36
  printf 'logout\n' >> "$fixture_root/logout.called"
  rm -f "$CODEX_HOME/auth.json"
  ;;
*) exit 37 ;;
esac
