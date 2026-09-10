#!/bin/sh
# Runs only inside the isolated image verifier with public synthetic fixtures.
set -eu
umask 077
stage=runtime-metadata
trap 'status=$?; if [ "$status" -ne 0 ]; then printf "SSH image contract failed: %s\n" "$stage" >&2; fi' EXIT
test "$(id -u)" = 65532
test "$(stat -f -c %T /run/codewire-credentials)" = tmpfs
test "$(stat -c '%a %u %g %h' /usr/local/libexec/codewire/ssh-askpass)" = '755 0 0 1'
test -f /usr/share/doc/openssh-client/copyright
test -f /usr/share/doc/libssl3/copyright
test -f /usr/share/common-licenses/Apache-2.0
test ! -e /usr/bin/ssh
test ! -e /usr/bin/ssh-keygen
test ! -e /usr/sbin/sshd

stage=loader-closure
for tool in /usr/bin/ssh-agent /usr/bin/ssh-add; do
  libraries="$(ldd "$tool")"
  case "$libraries" in *'not found'*) exit 1 ;; esac
done

SSH_AUTH_SOCK=/run/codewire-credentials/agent.sock
SSH_ASKPASS=/usr/local/libexec/codewire/ssh-askpass
SSH_ASKPASS_REQUIRE=force
DISPLAY=codewire-synthetic
CODEWIRE_SSH_ASKPASS_FIFO=/run/codewire-credentials/passphrase
export SSH_AUTH_SOCK SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY CODEWIRE_SSH_ASKPASS_FIFO
agent_pid=''
writer_pid=''
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    printf 'SSH image contract failed: %s\n' "$stage" >&2
  fi
  for pid in "$writer_pid" "$agent_pid"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || :
      wait "$pid" 2>/dev/null || :
    fi
  done
}
trap cleanup EXIT
trap 'exit 1' INT TERM
/usr/bin/ssh-agent -D -a "$SSH_AUTH_SOCK" >/dev/null 2>&1 &
stage=agent-start
agent_pid=$!
attempt=0
while [ ! -S "$SSH_AUTH_SOCK" ]; do
  kill -0 "$agent_pid"
  attempt=$((attempt + 1))
  test "$attempt" -le 100
  sleep 0.02
done
mkfifo "$CODEWIRE_SSH_ASKPASS_FIFO"
# This is the existing repository fixture's public test-only passphrase.
(printf '%s\n' 'codewire-synthetic-passphrase-only' >"$CODEWIRE_SSH_ASKPASS_FIFO") &
writer_pid=$!
stage=encrypted-key-import
/usr/bin/ssh-add -q - </fixture/key
wait "$writer_pid"
writer_pid=''
# Stock ssh-add verifies an actual agent signature against this exact public key.
stage=signature-verification
/usr/bin/ssh-add -T /fixture/key.pub
test "$(/usr/bin/ssh-add -L)" = "$(cat /fixture/key.pub)"
stage=child-drain
kill "$agent_pid"
# OpenSSH9.2 cleanup_handler removes its socket then exits2 on SIGTERM;
# it does not leave the default signal exit143. Still require actual reap and
# the socket/tmpfs cleanup assertions below (upstream ssh-agent.c).
wait "$agent_pid" || test "$?" -eq 2
agent_pid=''
test ! -S "$SSH_AUTH_SOCK"
rm "$CODEWIRE_SSH_ASKPASS_FIFO"
test -z "$(ls -A /run/codewire-credentials)"
printf 'packaged encrypted-key import, signature verification and child drain passed\n'
