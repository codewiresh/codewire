#!/bin/sh
# Synthetic pinned-output fixture: no network, owner configuration or tokens.
set -eu
fixture_root=${GH_CONFIG_DIR%/*}

[ "$HOME" = "$GH_CONFIG_DIR" ] || exit 20
[ "$XDG_CONFIG_HOME" = "$HOME" ] || exit 21
[ "$XDG_CACHE_HOME" = "$HOME" ] || exit 22
[ "$XDG_STATE_HOME" = "$HOME" ] || exit 23
[ "$XDG_DATA_HOME" = "$HOME" ] || exit 24
[ "$TMPDIR" = "$HOME" ] || exit 25
[ "$(pwd -P)" = "$HOME" ] || exit 26
[ "$PATH" = /usr/bin:/bin ] || exit 27
[ "$DBUS_SESSION_BUS_ADDRESS" = "unix:path=$HOME/no-keyring.sock" ] || exit 28
[ ! -e "$HOME/no-keyring.sock" ] || exit 29
[ "$GH_PROMPT_DISABLED" = 1 ] || exit 30
[ "$GH_NO_UPDATE_NOTIFIER" = 1 ] || exit 31
[ "$GH_NO_EXTENSION_UPDATE_NOTIFIER" = 1 ] || exit 32
[ "$NO_COLOR" = 1 ] || exit 33
[ "$CLICOLOR" = 0 ] || exit 34
[ "$TERM" = dumb ] || exit 35
for forbidden in GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN GH_HOST GH_DEBUG \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy XDG_RUNTIME_DIR \
  GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM SSH_AUTH_SOCK BROWSER GH_BROWSER RUST_LOG; do
  if env | /bin/grep -q "^${forbidden}="; then exit 36; fi
done

case "${1-}" in
--version)
  [ "$#" -eq 1 ] || exit 40
  printf '%s\n' "$$" > "$fixture_root/version.pid"
  if [ -f "$fixture_root/block-version" ]; then while :; do sleep 0.02; done; fi
  if [ -f "$fixture_root/wrong-version" ]; then printf 'gh version 9.0.0\n'; exit 0; fi
  printf 'gh version 2.97.0 (2026-07-20)\nhttps://github.com/cli/cli/releases/tag/v2.97.0\n'
  ;;
auth)
  [ "$#" -eq 9 ] || exit 41
  [ "$2" = login ] && [ "$3" = --hostname ] && [ "$4" = github.com ] || exit 42
  [ "$5" = --git-protocol ] && [ "$6" = https ] || exit 43
  [ "$7" = --web ] && [ "$8" = --insecure-storage ] && [ "$9" = --skip-ssh-key ] || exit 44
  printf '%s\n' "$$" > "$fixture_root/wrapper.pid"
  /bin/sh "$0" native &
  wait "$!"
  ;;
native)
  printf '%s\n' "$$" > "$fixture_root/native.pid"
  if [ -f "$fixture_root/unexpected-stdout" ]; then printf 'synthetic unexpected output\n'; fi
  printf '\n! First copy your one-time code: ABCD-EFGH\n' >&2
  printf 'To continue, open this URL in your web browser: https://github.com/login/device\n' >&2
  while [ ! -f "$fixture_root/release" ]; do sleep 0.02; done
  umask 077
  cp "$fixture_root/hosts.fixture.yml" "$GH_CONFIG_DIR/hosts.yml"
  if [ -f "$fixture_root/world-readable" ]; then chmod 644 "$GH_CONFIG_DIR/hosts.yml"; fi
  if [ -f "$fixture_root/result-link" ]; then
    mv "$GH_CONFIG_DIR/hosts.yml" "$GH_CONFIG_DIR/result.yml"
    ln -s result.yml "$GH_CONFIG_DIR/hosts.yml"
  fi
  printf 'synthetic private log\n' > "$GH_CONFIG_DIR/login.log"
  printf '✓ Authentication complete.\n- gh config set -h github.com git_protocol https\n' >&2
  printf '✓ Configured git protocol\n! Authentication credentials saved in plain text\n' >&2
  printf '✓ Logged in as synthetic-user\n' >&2
  printf 'done\n' > "$fixture_root/native.finished"
  if [ -f "$fixture_root/fail-after-result" ]; then exit 42; fi
  ;;
*) printf 'unexpected\n' > "$fixture_root/unexpected-command"; exit 45 ;;
esac
