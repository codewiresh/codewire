#!/bin/sh
set -eu

case "${1-}" in
login)
  [ "$#" -eq 4 ] || exit 20
  [ "$2" = "--device-auth" ] || exit 21
  [ "$3" = "-c" ] || exit 22
  [ "$4" = 'cli_auth_credentials_store="file"' ] || exit 23
  [ "$HOME" = "$CODEX_HOME" ] || exit 24
  [ "$XDG_CONFIG_HOME" = "$CODEX_HOME" ] || exit 25
  [ "$XDG_CACHE_HOME" = "$CODEX_HOME" ] || exit 26
  [ "$TMPDIR" = "$CODEX_HOME" ] || exit 27
  [ "$(pwd -P)" = "$CODEX_HOME" ] || exit 28
  [ "$PATH" = "/usr/bin:/bin" ] || exit 29
  [ -z "${OPENAI_API_KEY+x}" ] || exit 30
  fixture_root=${CODEX_HOME%/*}
  [ -f "$fixture_root/synthetic-auth.fixture.json" ] || exit 31
  printf '\nWelcome to Codex [v\033[90m0.149.0\033[0m]\n\033[90mOpenAI\047s command-line coding agent\033[0m\n\n'
  printf 'Follow these steps to sign in with ChatGPT using device code authorization:\n\n'
  printf '1. Open this link in your browser and sign in to your account\n   \033[94mhttps://auth.openai.com/codex/device\033[0m\n\n'
  printf '2. Enter this one-time code \033[90m(expires in 15 minutes)\033[0m\n   \033[94mSYNTH-ETIC\033[0m\n\n'
  printf '\033[90mContinue only if you started this login in Codex. If a website or another person gave you this code, cancel.\033[0m\n\n'
  umask 077
  cp "$fixture_root/synthetic-auth.fixture.json" "$CODEX_HOME/auth.json"
  ;;
logout)
  [ "$#" -eq 3 ] || exit 32
  [ "$2" = "-c" ] || exit 33
  [ "$3" = 'cli_auth_credentials_store="file"' ] || exit 34
  printf 'logout\n' >> "${CODEX_HOME%/*}/logout.called"
  rm -f "$CODEX_HOME/auth.json"
  ;;
*) exit 35 ;;
esac
