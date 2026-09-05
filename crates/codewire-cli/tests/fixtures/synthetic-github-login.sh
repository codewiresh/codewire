#!/bin/sh
set -eu

case "${1-}:${2-}" in
auth:login)
  [ "$#" -eq 9 ] || exit 20
  [ "$3" = "--hostname" ] || exit 21
  [ "$4" = "github.com" ] || exit 22
  [ "$5" = "--git-protocol" ] || exit 23
  [ "$6" = "https" ] || exit 24
  [ "$7" = "--web" ] || exit 25
  [ "$8" = "--insecure-storage" ] || exit 26
  [ "$9" = "--skip-ssh-key" ] || exit 27
  [ "$HOME" = "$GH_CONFIG_DIR" ] || exit 28
  [ "$XDG_CONFIG_HOME" = "$GH_CONFIG_DIR" ] || exit 29
  [ "$XDG_CACHE_HOME" = "$GH_CONFIG_DIR" ] || exit 30
  [ "$TMPDIR" = "$GH_CONFIG_DIR" ] || exit 31
  [ "$(pwd -P)" = "$GH_CONFIG_DIR" ] || exit 32
  [ "$PATH" = "/usr/bin:/bin" ] || exit 33
  [ -z "${GH_TOKEN+x}" ] || exit 34
  [ -z "${GITHUB_TOKEN+x}" ] || exit 35
  umask 077
  printf '%s' 'isolated-login' >"$GH_CONFIG_DIR/hosts.yml"
  ;;
auth:token)
  [ "$#" -eq 4 ] || exit 36
  [ "$3" = "--hostname" ] || exit 37
  [ "$4" = "github.com" ] || exit 38
  [ -f "$GH_CONFIG_DIR/hosts.yml" ] || exit 39
  printf '%s\n' 'synthetic-github-oauth-material'
  ;;
*) exit 40 ;;
esac
