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
  [ -f "$CODEX_HOME/synthetic-auth.fixture.json" ] || exit 31
  umask 077
  cp "$CODEX_HOME/synthetic-auth.fixture.json" "$CODEX_HOME/auth.json"
  rm -f "$CODEX_HOME/synthetic-auth.fixture.json"
  ;;
logout)
  [ "$#" -eq 3 ] || exit 32
  [ "$2" = "-c" ] || exit 33
  [ "$3" = 'cli_auth_credentials_store="file"' ] || exit 34
  rm -f "$CODEX_HOME/auth.json"
  ;;
*) exit 35 ;;
esac
